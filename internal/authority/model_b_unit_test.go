package authority

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"howlchangeops/internal/approval"
)

func TestEnrollmentLifecycle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "enrollment.json")

	priv, pub, keyID, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey error: %v", err)
	}
	if len(priv) != ed25519.PrivateKeySize || len(pub) != ed25519.PublicKeySize {
		t.Fatalf("invalid key size")
	}

	cfg := &EnrollmentConfig{
		Schema:   EnrollmentSchema,
		Audience: "test/audience",
		Keys:     make(map[string]EnrollmentKey),
	}
	if err := cfg.EnrollKey(keyID, "owner-alice", pub); err != nil {
		t.Fatalf("EnrollKey error: %v", err)
	}
	if err := SaveEnrollment(path, cfg); err != nil {
		t.Fatalf("SaveEnrollment error: %v", err)
	}

	loaded, err := LoadEnrollment(path)
	if err != nil {
		t.Fatalf("LoadEnrollment error: %v", err)
	}
	if len(loaded.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(loaded.Keys))
	}

	enrolledMap, err := loaded.ToEnrolledMap()
	if err != nil {
		t.Fatalf("ToEnrolledMap error: %v", err)
	}
	enrolled, ok := enrolledMap[keyID]
	if !ok || enrolled.Owner != "owner-alice" || enrolled.Revoked {
		t.Fatalf("unexpected enrolled key: %+v", enrolled)
	}

	// Test revocation
	if err := loaded.RevokeKey(keyID, "compromised"); err != nil {
		t.Fatalf("RevokeKey error: %v", err)
	}
	if err := SaveEnrollment(path, loaded); err != nil {
		t.Fatalf("SaveEnrollment after revoke error: %v", err)
	}
	reloaded, err := LoadEnrollment(path)
	if err != nil {
		t.Fatalf("LoadEnrollment error: %v", err)
	}
	if !reloaded.Keys[keyID].Revoked {
		t.Fatalf("expected key to be revoked")
	}

	// Test StateSource
	src := NewFileStateSource(path, true)
	snap, err := src(context.Background())
	if err != nil {
		t.Fatalf("StateSource error: %v", err)
	}
	if !snap.SignerAvailable || !snap.Enrolled[keyID].Revoked {
		t.Fatalf("StateSource snapshot mismatch: %+v", snap)
	}
}

func TestSignAndReview(t *testing.T) {
	priv, _, keyID, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey error: %v", err)
	}

	params := json.RawMessage(`{"value":"test-param"}`)
	paramsDigest := hash([]byte(`{"value":"test-param"}`))

	req := Request{
		Binding: approval.Binding{
			Audience:         "test/audience",
			DecisionID:       "dec-001",
			DecisionDigest:   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			EvidenceDigest:   "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			Target:           "howlcipher/howl",
			Action:           "synthetic_action",
			Revision:         "1111111111111111111111111111111111111111",
			ParametersDigest: paramsDigest,
		},
		Parameters: params,
	}

	summary, err := ReviewRequest(req)
	if err != nil {
		t.Fatalf("ReviewRequest error: %v", err)
	}
	if summary.DecisionID != "dec-001" || summary.Action != "synthetic_action" {
		t.Fatalf("unexpected review summary: %+v", summary)
	}

	envelopeBytes, err := SignRequest(req, priv, keyID, 5*time.Minute)
	if err != nil {
		t.Fatalf("SignRequest error: %v", err)
	}

	var env approval.Envelope
	if err := json.Unmarshal(envelopeBytes, &env); err != nil {
		t.Fatalf("unmarshal envelope error: %v", err)
	}
	if env.Claims.KeyID != keyID || env.Claims.Binding.DecisionID != "dec-001" {
		t.Fatalf("envelope claims mismatch: %+v", env.Claims)
	}
	if env.Signature == "" {
		t.Fatalf("signature empty")
	}
}

func TestDefaultAdaptersSynthetic(t *testing.T) {
	adapters := DefaultAdapters("")
	adapter, ok := adapters["synthetic_action"]
	if !ok {
		t.Fatalf("synthetic_action adapter not found")
	}
	req := Request{
		Binding:    approval.Binding{Action: "synthetic_action"},
		Parameters: json.RawMessage(`{"param":"hello"}`),
	}
	if err := adapter.Validate(req); err != nil {
		t.Fatalf("Validate error: %v", err)
	}
	payload, err := adapter.Run(context.Background(), req, "dec-001")
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	var res map[string]any
	if err := json.Unmarshal(payload, &res); err != nil {
		t.Fatalf("unmarshal payload error: %v", err)
	}
	if res["status"] != "SUCCESS" || res["decision_id"] != "dec-001" {
		t.Fatalf("unexpected result: %+v", res)
	}
}
