package authority

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"howlchangeops/internal/approval"
)

const EnrollmentSchema = "howlchangeops.enrollment/v1"
const MaxEnrollmentBytes = 65536

var (
	ErrEnrollmentInvalid = errors.New("enrollment configuration invalid")
	ErrKeyNotFound       = errors.New("enrolled key not found")
	ErrKeyAlreadyExists  = errors.New("enrolled key already exists")
)

type EnrollmentKey struct {
	Owner            string `json:"owner"`
	PublicKey        string `json:"public_key"`
	Revoked          bool   `json:"revoked"`
	RevokedAt        string `json:"revoked_at,omitempty"`
	RevocationReason string `json:"revocation_reason,omitempty"`
}

type EnrollmentConfig struct {
	Schema   string                   `json:"schema"`
	Audience string                   `json:"audience,omitempty"`
	Keys     map[string]EnrollmentKey `json:"keys"`
}

// GenerateKey generates an Ed25519 keypair and a deterministic key ID.
func GenerateKey() (ed25519.PrivateKey, ed25519.PublicKey, string, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, "", err
	}
	hash := sha256.Sum256(pub)
	keyID := fmt.Sprintf("key-%s", hex.EncodeToString(hash[:8]))
	return priv, pub, keyID, nil
}

// LoadEnrollment reads and validates an enrollment configuration file.
func LoadEnrollment(path string) (*EnrollmentConfig, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrEnrollmentInvalid
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > MaxEnrollmentBytes {
		return nil, ErrEnrollmentInvalid
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 || !utf8.Valid(data) {
		return nil, ErrEnrollmentInvalid
	}
	var cfg EnrollmentConfig
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, ErrEnrollmentInvalid
	}
	if cfg.Schema != EnrollmentSchema || cfg.Keys == nil {
		return nil, ErrEnrollmentInvalid
	}
	return &cfg, nil
}

// SaveEnrollment writes the enrollment configuration file atomically with 0600 permissions.
func SaveEnrollment(path string, cfg *EnrollmentConfig) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || cfg == nil {
		return ErrEnrollmentInvalid
	}
	if cfg.Schema != EnrollmentSchema {
		cfg.Schema = EnrollmentSchema
	}
	if cfg.Keys == nil {
		cfg.Keys = make(map[string]EnrollmentKey)
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil || len(data) > MaxEnrollmentBytes {
		return ErrEnrollmentInvalid
	}
	data = append(data, '\n')
	dir := filepath.Dir(path)
	tmpFile, err := os.CreateTemp(dir, "enrollment-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmpFile.Name()
	defer os.Remove(tmpName)

	if err := tmpFile.Chmod(0600); err != nil {
		tmpFile.Close()
		return err
	}
	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		return err
	}
	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// EnrollKey registers a new public key in the configuration.
func (cfg *EnrollmentConfig) EnrollKey(keyID, owner string, pub ed25519.PublicKey) error {
	if keyID == "" || owner == "" || len(pub) != ed25519.PublicKeySize {
		return ErrEnrollmentInvalid
	}
	if cfg.Keys == nil {
		cfg.Keys = make(map[string]EnrollmentKey)
	}
	if _, exists := cfg.Keys[keyID]; exists {
		return ErrKeyAlreadyExists
	}
	cfg.Keys[keyID] = EnrollmentKey{
		Owner:     owner,
		PublicKey: base64.RawURLEncoding.EncodeToString(pub),
		Revoked:   false,
	}
	return nil
}

// RevokeKey marks an enrolled key as revoked.
func (cfg *EnrollmentConfig) RevokeKey(keyID, reason string) error {
	if cfg.Keys == nil {
		return ErrKeyNotFound
	}
	k, exists := cfg.Keys[keyID]
	if !exists {
		return ErrKeyNotFound
	}
	k.Revoked = true
	k.RevokedAt = time.Now().UTC().Format(time.RFC3339)
	k.RevocationReason = reason
	cfg.Keys[keyID] = k
	return nil
}

// ToEnrolledMap converts the configuration to the map required by approval.Verify.
func (cfg *EnrollmentConfig) ToEnrolledMap() (map[string]approval.Enrollment, error) {
	out := make(map[string]approval.Enrollment, len(cfg.Keys))
	for id, k := range cfg.Keys {
		pubBytes, err := base64.RawURLEncoding.DecodeString(k.PublicKey)
		if err != nil || len(pubBytes) != ed25519.PublicKeySize {
			// Also try standard encoding for compatibility
			pubBytes, err = base64.StdEncoding.DecodeString(k.PublicKey)
			if err != nil || len(pubBytes) != ed25519.PublicKeySize {
				return nil, fmt.Errorf("invalid public key for %s: %w", id, ErrEnrollmentInvalid)
			}
		}
		out[id] = approval.Enrollment{
			Owner:     k.Owner,
			PublicKey: ed25519.PublicKey(pubBytes),
			Revoked:   k.Revoked,
		}
	}
	return out, nil
}

// NewFileStateSource returns a StateSource that loads enrollment from an absolute file.
func NewFileStateSource(path string, signerAvailable bool) StateSource {
	return func(ctx context.Context) (Snapshot, error) {
		cfg, err := LoadEnrollment(path)
		if err != nil {
			return Snapshot{}, err
		}
		enrolled, err := cfg.ToEnrolledMap()
		if err != nil {
			return Snapshot{}, err
		}
		return Snapshot{
			Enrolled:        enrolled,
			Now:             time.Now().UTC(),
			SignerAvailable: signerAvailable,
		}, nil
	}
}
