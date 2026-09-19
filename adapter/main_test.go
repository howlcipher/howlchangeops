package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHowlFrameCompatibility_CurrentBinary(t *testing.T) {
	err := checkHowlFrameCompatibility()
	if err != nil {
		t.Fatalf("checkHowlFrameCompatibility failed with current howlframe: %v", err)
	}
}

func TestHowlFrameCompatibility_MissingBinary(t *testing.T) {
	orig := os.Getenv("HOWLFRAME_BIN")
	defer os.Setenv("HOWLFRAME_BIN", orig)

	os.Setenv("HOWLFRAME_BIN", "/path/that/does/not/exist/howlframe_missing")
	err := checkHowlFrameCompatibility()
	if err == nil {
		t.Fatal("expected error for missing howlframe binary, got nil")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected error to mention 'not found', got: %v", err)
	}
}

func TestHowlFrameCompatibility_IncompatibleVersion(t *testing.T) {
	orig := os.Getenv("HOWLFRAME_BIN")
	defer os.Setenv("HOWLFRAME_BIN", orig)

	tmpDir := t.TempDir()
	mockBin := filepath.Join(tmpDir, "mock_howlframe")
	script := "#!/bin/sh\necho 'HowlFrame 0.2.0'\necho 'HFBC format: 2'\n"
	if err := os.WriteFile(mockBin, []byte(script), 0755); err != nil {
		t.Fatalf("failed to write mock script: %v", err)
	}

	os.Setenv("HOWLFRAME_BIN", mockBin)
	err := checkHowlFrameCompatibility()
	if err == nil {
		t.Fatal("expected error for incompatible version 0.2.0, got nil")
	}
	if !strings.Contains(err.Error(), "incompatible HowlFrame version") {
		t.Errorf("expected 'incompatible HowlFrame version' in error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "found 0.2.0") {
		t.Errorf("expected 'found 0.2.0' in error, got: %v", err)
	}
}

func TestHowlFrameCompatibility_MalformedOutput(t *testing.T) {
	orig := os.Getenv("HOWLFRAME_BIN")
	defer os.Setenv("HOWLFRAME_BIN", orig)

	tmpDir := t.TempDir()
	mockBin := filepath.Join(tmpDir, "mock_howlframe")
	script := "#!/bin/sh\necho 'SomeOtherTool 1.0.0'\n"
	if err := os.WriteFile(mockBin, []byte(script), 0755); err != nil {
		t.Fatalf("failed to write mock script: %v", err)
	}

	os.Setenv("HOWLFRAME_BIN", mockBin)
	err := checkHowlFrameCompatibility()
	if err == nil {
		t.Fatal("expected error for malformed version output, got nil")
	}
	if !strings.Contains(err.Error(), "unrecognized howlframe version format") {
		t.Errorf("expected 'unrecognized howlframe version format' in error, got: %v", err)
	}
}

func TestHMACSignaturePreservation(t *testing.T) {
	key := []byte("secret_key_32_bytes_long_fixture")
	app := Approval{
		Schema:         "howlchangeops.approval/v1",
		ApprovalID:     "app-12345",
		DecisionID:     "dec-67890",
		DecisionDigest: "deadbeef1234",
		EvidenceDigest: "feedface5678",
		Repo:           "howlplane",
		Action:         "create_release_candidate",
		Revision:       "abcdef012345",
		Approver:       "william",
		IssuedAt:       "2026-09-18T20:00:00Z",
		ExpiresAt:      "2026-09-18T21:00:00Z",
		Nonce:          "nonce123",
	}

	sig := signApproval(app, key)
	if sig == "" {
		t.Fatal("expected non-empty HMAC signature")
	}

	// Tampering with payload fails validation
	tamperedApp := app
	tamperedApp.Action = "delete_all"
	tamperedSig := signApproval(tamperedApp, key)
	if tamperedSig == sig {
		t.Fatal("tampered approval generated identical signature")
	}

	// Tampering with key fails validation
	wrongKey := []byte("wrong_key_32_bytes_long_fixture!")
	wrongKeySig := signApproval(app, wrongKey)
	if wrongKeySig == sig {
		t.Fatal("different key generated identical signature")
	}
}
