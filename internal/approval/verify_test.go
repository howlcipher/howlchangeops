package approval

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T) (Envelope, map[string]Enrollment, ed25519.PrivateKey, time.Time) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	c := Claims{Schema: Schema, KeyID: "synthetic-key", ApprovalID: "synthetic-approval", Nonce: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), IssuedAt: now.Add(-time.Minute).Format(time.RFC3339), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339), Binding: Binding{Audience: "synthetic-executor", DecisionID: "synthetic-decision", DecisionDigest: strings.Repeat("a", 64), EvidenceDigest: strings.Repeat("b", 64), Target: "synthetic/repository", Action: "record_release_ready", Revision: strings.Repeat("c", 40), ParametersDigest: strings.Repeat("d", 64)}}
	return Envelope{Claims: c}, map[string]Enrollment{"synthetic-key": {Owner: "synthetic-owner", PublicKey: pub}}, priv, now
}
func encode(t *testing.T, e Envelope, key ed25519.PrivateKey) []byte {
	t.Helper()
	e.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, SigningBytes(e.Claims)))
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func TestVerifyEnrollmentIdentityAndExactClaims(t *testing.T) {
	e, enrollment, key, now := fixture(t)
	out, err := Verify(encode(t, e, key), enrollment, e.Claims.Binding, now)
	if err != nil || out.Owner != "synthetic-owner" || out.Claims != e.Claims {
		t.Fatalf("verify: %+v %v", out, err)
	}
	// This module intentionally does not consume authorization. The protected
	// executor must persist atomic reservation before acting; docs prohibit using
	// this pure function as a replay guard.
	if _, err := Verify(encode(t, e, key), enrollment, e.Claims.Binding, now); err != nil {
		t.Fatal(err)
	}
}
func TestVerifyRejectsInvalidSignedClaims(t *testing.T) {
	cases := map[string]func(*Claims){
		"wrong schema":              func(c *Claims) { c.Schema = "unknown" },
		"unknown key":               func(c *Claims) { c.KeyID = "unknown" },
		"missing approval id":       func(c *Claims) { c.ApprovalID = "" },
		"missing nonce":             func(c *Claims) { c.Nonce = "" },
		"bad nonce":                 func(c *Claims) { c.Nonce = "not-a-32-byte-nonce" },
		"invalid issuance":          func(c *Claims) { c.IssuedAt = "not-time" },
		"future issuance":           func(c *Claims) { c.IssuedAt = "2026-10-21T12:00:01Z" },
		"invalid expiry":            func(c *Claims) { c.ExpiresAt = "not-time" },
		"expired at exact boundary": func(c *Claims) { c.ExpiresAt = "2026-10-21T12:00:00Z" },
		"negative validity":         func(c *Claims) { c.ExpiresAt = c.IssuedAt },
		"excessive lifetime":        func(c *Claims) { c.ExpiresAt = "2026-10-21T13:00:00Z" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			e, enrollment, key, now := fixture(t)
			expected := e.Claims.Binding
			mutate(&e.Claims)
			if _, err := Verify(encode(t, e, key), enrollment, expected, now); err == nil {
				t.Fatal("invalid claims accepted")
			}
		})
	}
}
func TestVerifyRejectsEveryBindingMismatch(t *testing.T) {
	cases := map[string]func(*Binding){
		"audience":        func(b *Binding) { b.Audience = "other" },
		"decision":        func(b *Binding) { b.DecisionID = "other" },
		"decision digest": func(b *Binding) { b.DecisionDigest = strings.Repeat("e", 64) },
		"evidence digest": func(b *Binding) { b.EvidenceDigest = strings.Repeat("e", 64) },
		"target":          func(b *Binding) { b.Target = "other/repo" },
		"action":          func(b *Binding) { b.Action = "other" },
		"revision":        func(b *Binding) { b.Revision = strings.Repeat("e", 40) },
		"parameters":      func(b *Binding) { b.ParametersDigest = strings.Repeat("e", 64) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			e, enrollment, key, now := fixture(t)
			expected := e.Claims.Binding
			mutate(&e.Claims.Binding)
			if _, err := Verify(encode(t, e, key), enrollment, expected, now); err == nil {
				t.Fatal("mismatched binding accepted")
			}
		})
	}
}
func TestVerifyRejectsUntrustedSignaturesAndEnrollment(t *testing.T) {
	for _, kind := range []string{"tampered", "wrong-key", "revoked", "empty-owner", "bad-public-key", "bad-signature", "missing-signature"} {
		t.Run(kind, func(t *testing.T) {
			e, enrollment, key, now := fixture(t)
			expected := e.Claims.Binding
			data := encode(t, e, key)
			switch kind {
			case "tampered":
				data = []byte(strings.Replace(string(data), "record_release_ready", "other", 1))
			case "wrong-key":
				pub, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				enrollment[e.Claims.KeyID] = Enrollment{Owner: "synthetic-owner", PublicKey: pub}
			case "revoked":
				entry := enrollment[e.Claims.KeyID]
				entry.Revoked = true
				enrollment[e.Claims.KeyID] = entry
			case "empty-owner":
				entry := enrollment[e.Claims.KeyID]
				entry.Owner = ""
				enrollment[e.Claims.KeyID] = entry
			case "bad-public-key":
				enrollment[e.Claims.KeyID] = Enrollment{Owner: "synthetic-owner", PublicKey: []byte("invalid")}
			case "bad-signature":
				e.Signature = "invalid"
				data, _ = json.Marshal(e)
			case "missing-signature":
				data, _ = json.Marshal(e)
			}
			if _, err := Verify(data, enrollment, expected, now); err == nil {
				t.Fatal("untrusted approval accepted")
			}
		})
	}
}
func TestVerifyRejectsMalformedOrAmbiguousInput(t *testing.T) {
	for _, kind := range []string{"unknown-field", "duplicate-field", "trailing-json", "null", "too-large", "bad-utf8", "pretty-json"} {
		t.Run(kind, func(t *testing.T) {
			e, enrollment, key, now := fixture(t)
			data := encode(t, e, key)
			switch kind {
			case "unknown-field":
				data = []byte(strings.Replace(string(data), `{"claims":`, `{"unknown":1,"claims":`, 1))
			case "duplicate-field":
				data = []byte(strings.Replace(string(data), `{"claims":`, `{"signature":"ignored","claims":`, 1))
			case "trailing-json":
				data = append(data, []byte(`{}`)...)
			case "null":
				data = []byte(`null`)
			case "too-large":
				data = make([]byte, MaxEnvelopeBytes+1)
			case "bad-utf8":
				data = []byte{0xff}
			case "pretty-json":
				var obj any
				if err := json.Unmarshal(data, &obj); err != nil {
					t.Fatal(err)
				}
				data, _ = json.MarshalIndent(obj, "", "  ")
			}
			if _, err := Verify(data, enrollment, e.Claims.Binding, now); err == nil {
				t.Fatal("malformed approval accepted")
			}
		})
	}
}
