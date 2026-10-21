// Package approval verifies signed approval claims. It does not authenticate a
// human, protect enrollment, consume nonces, or perform actions. A protected
// executor must provide those boundaries before using a verified approval.
package approval

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
	"unicode/utf8"
)

const Schema = "howlchangeops.independent-approval/v1"
const MaxEnvelopeBytes = 16384
const MaxLifetime = 10 * time.Minute
const domain = "howlchangeops.independent-approval/v1\x00"

// Binding must be computed from the executor's immutable request snapshot.
// ParametersDigest covers every effectful parameter, not only the action name.
type Binding struct {
	Audience         string `json:"audience"`
	DecisionID       string `json:"decision_id"`
	DecisionDigest   string `json:"decision_digest"`
	EvidenceDigest   string `json:"evidence_digest"`
	Target           string `json:"target"`
	Action           string `json:"action"`
	Revision         string `json:"revision"`
	ParametersDigest string `json:"parameters_digest"`
}

type Claims struct {
	Schema     string  `json:"schema"`
	KeyID      string  `json:"key_id"`
	ApprovalID string  `json:"approval_id"`
	Nonce      string  `json:"nonce"`
	IssuedAt   string  `json:"issued_at"`
	ExpiresAt  string  `json:"expires_at"`
	Binding    Binding `json:"binding"`
}

type Envelope struct {
	Claims    Claims `json:"claims"`
	Signature string `json:"signature"`
}

// Enrollment must come from independently protected configuration. Caller
// supplied names and keys are not owner authentication.
type Enrollment struct {
	Owner     string
	PublicKey ed25519.PublicKey
	Revoked   bool
}

type Verified struct {
	Owner  string
	Claims Claims
}

var ErrInvalid = errors.New("independent approval invalid")

// SigningBytes specifies the wire protocol; it does not sign or access keys.
// Fixed structs and field order are intentional. Signers must use this exact
// UTF-8 JSON representation, with Go encoding/json escaping, after validation.
func SigningBytes(c Claims) []byte {
	data, _ := json.Marshal(c)
	return append([]byte(domain), data...)
}

func digest(s string) bool {
	if len(s) != 64 || strings.ToLower(s) != s {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func validBinding(b Binding) bool {
	for _, value := range []string{b.Audience, b.DecisionID, b.Target, b.Action, b.Revision} {
		if strings.TrimSpace(value) != value || value == "" || len(value) > 1024 || strings.ContainsAny(value, "\x00\r\n") {
			return false
		}
	}
	if len(b.Revision) != 40 && len(b.Revision) != 64 {
		return false
	}
	if _, err := hex.DecodeString(b.Revision); err != nil {
		return false
	}
	return digest(b.DecisionDigest) && digest(b.EvidenceDigest) && digest(b.ParametersDigest)
}

// Verify checks signature, exact request binding, enrollment and validity. It
// deliberately has no disk or network access. A successful return MUST be
// followed by atomic nonce/approval-ID reservation in a protected durable ledger
// before any effect. Repeated Verify calls alone do not prevent replay.
func Verify(data []byte, enrolled map[string]Enrollment, expected Binding, now time.Time) (Verified, error) {
	fail := func() (Verified, error) { return Verified{}, ErrInvalid }
	if len(data) == 0 || len(data) > MaxEnvelopeBytes || !utf8.Valid(data) || !validBinding(expected) {
		return fail()
	}
	var e Envelope
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil {
		return fail()
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return fail()
	}
	c := e.Claims
	if c.Schema != Schema || c.Binding != expected || !validBinding(c.Binding) || c.ApprovalID == "" || len(c.ApprovalID) > 128 || c.KeyID == "" {
		return fail()
	}
	// Canonical re-encoding rejects duplicate keys, nulls, case aliases, alternate
	// encodings and ambiguous JSON layouts. Outer whitespace is harmless.
	canonical, _ := json.Marshal(e)
	if !bytes.Equal(bytes.TrimSpace(data), canonical) {
		return fail()
	}
	nonce, err := base64.RawURLEncoding.DecodeString(c.Nonce)
	if err != nil || len(nonce) != 32 {
		return fail()
	}
	issued, err := time.Parse(time.RFC3339, c.IssuedAt)
	if err != nil {
		return fail()
	}
	expiry, err := time.Parse(time.RFC3339, c.ExpiresAt)
	if err != nil || !expiry.After(issued) || expiry.Sub(issued) > MaxLifetime || issued.After(now) || !now.Before(expiry) {
		return fail()
	}
	key, ok := enrolled[c.KeyID]
	if !ok || key.Revoked || key.Owner == "" || len(key.PublicKey) != ed25519.PublicKeySize {
		return fail()
	}
	sig, err := base64.RawURLEncoding.DecodeString(e.Signature)
	if err != nil || !ed25519.Verify(key.PublicKey, SigningBytes(c), sig) {
		return fail()
	}
	return Verified{Owner: key.Owner, Claims: c}, nil
}
