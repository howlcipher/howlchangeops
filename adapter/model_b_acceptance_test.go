package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"howlchangeops/internal/approval"
	"howlchangeops/internal/authority"
)

func privateDir(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(home, ".howl-model-b-test-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// setupModelBFixture initializes a clean isolated Model B environment with an
// authority database, enrollment, and synthetic owner keys.
func setupModelBFixture(t *testing.T) (dir, dbPath, enrollPath, keyID string, priv ed25519.PrivateKey, pub ed25519.PublicKey) {
	t.Helper()
	dir = privateDir(t)

	dbPath = filepath.Join(dir, "authority.db")
	audience := "test/model_b/v1"
	l, err := authority.CreateLedger(dbPath, audience)
	if err != nil {
		t.Fatalf("CreateLedger failed: %v", err)
	}
	_ = l

	priv, pub, keyID, err = authority.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	enrollPath = filepath.Join(dir, "enrollment.json")
	cfg := &authority.EnrollmentConfig{
		Schema:   authority.EnrollmentSchema,
		Audience: audience,
		Keys:     make(map[string]authority.EnrollmentKey),
	}
	if err := cfg.EnrollKey(keyID, "owner-model-b", pub); err != nil {
		t.Fatalf("EnrollKey failed: %v", err)
	}
	if err := authority.SaveEnrollment(enrollPath, cfg); err != nil {
		t.Fatalf("SaveEnrollment failed: %v", err)
	}

	return dir, dbPath, enrollPath, keyID, priv, pub
}

// buildChangeOpsBinary builds the howlchangeops binary in a temp directory.
func buildChangeOpsBinary(t *testing.T) string {
	t.Helper()
	binDir := t.TempDir()
	binPath := filepath.Join(binDir, "howlchangeops")
	cmd := exec.Command("go", "build", "-o", binPath, ".")
	cmd.Dir = "."
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build howlchangeops: %v\n%s", err, string(out))
	}
	return binPath
}

func parseResultEnvelope(out []byte) (*result, error) {
	idx := bytes.Index(out, []byte("{\n  \"schema\": \"howl.result/v1\""))
	if idx < 0 {
		idx = bytes.Index(out, []byte("{\"schema\":\"howl.result/v1\""))
	}
	if idx < 0 {
		idx = bytes.Index(out, []byte("{"))
	}
	if idx < 0 {
		return nil, fmt.Errorf("no json found in output: %s", string(out))
	}
	var res result
	if err := json.Unmarshal(out[idx:], &res); err != nil {
		return nil, fmt.Errorf("failed to unmarshal result envelope: %w (raw: %s)", err, string(out))
	}
	return &res, nil
}

func createTestProposal(action, repo string) []byte {
	p := Proposal{
		Action:     action,
		Repo:       repo,
		Reason:     "Model B acceptance test proposal",
		Confidence: 1.0,
	}
	b, _ := json.Marshal(p)
	return b
}

// Criterion 1: An agent cannot mint its own valid authorization.
func TestModelBCriterion1_AgentCannotMintValidAuthorization(t *testing.T) {
	bin := buildChangeOpsBinary(t)
	dir, dbPath, enrollPath, _, _, _ := setupModelBFixture(t)
	audience := "test/model_b/v1"

	// Attacker agent generates its own keypair (not enrolled in authority)
	attackerPriv, _, attackerKeyID, _ := authority.GenerateKey()

	params := json.RawMessage(`{"action":"synthetic_action","repo":"test-repo","reason":"attacker proposal"}`)
	canonParams, err := authority.CanonicalParameters(params)
	if err != nil {
		t.Fatal(err)
	}

	req := authority.Request{
		Binding: approval.Binding{
			Audience:         audience,
			DecisionID:       "dec-forged-01",
			DecisionDigest:   strings.Repeat("a", 64),
			EvidenceDigest:   strings.Repeat("b", 64),
			Target:           "test-repo",
			Action:           "synthetic_action",
			Revision:         strings.Repeat("1", 40),
			ParametersDigest: authority.Hash(canonParams),
		},
		Parameters: canonParams,
	}

	reqFile := filepath.Join(dir, "req.json")
	reqBytes, _ := json.Marshal(req)
	os.WriteFile(reqFile, reqBytes, 0644)

	// Attacker tries to sign with their own key
	forgedEnvBytes, err := authority.SignRequest(req, attackerPriv, attackerKeyID, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	envFile := filepath.Join(dir, "forged_env.json")
	os.WriteFile(envFile, forgedEnvBytes, 0644)

	// Attempt execution via CLI authority execute
	cmd := exec.Command(bin, "authority", "execute", dbPath, audience, enrollPath, reqFile, envFile, "--json")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected forged authorization to be rejected, got success: %s", string(out))
	}

	res, err := parseResultEnvelope(out)
	if err != nil {
		t.Fatalf("output is not result envelope: %v (raw: %s)", err, string(out))
	}
	if res.Status != "denied" || res.Error == nil || res.Error.Code != "EXECUTION_DENIED" {
		t.Fatalf("unexpected result envelope: %+v", res)
	}
}

// Criterion 2: An agent cannot access the signing key.
func TestModelBCriterion2_AgentCannotAccessSigningKey(t *testing.T) {
	bin := buildChangeOpsBinary(t)
	dir, _, _, _, _, _ := setupModelBFixture(t)

	// Signing key is in a path the agent cannot read (mode 0000)
	secretDir := filepath.Join(dir, "protected_keys")
	os.MkdirAll(secretDir, 0700)
	keyFile := filepath.Join(secretDir, "owner_priv.key")
	os.WriteFile(keyFile, []byte("inaccessible-secret"), 0000)

	reqFile := filepath.Join(dir, "valid_req.json")
	params := json.RawMessage(`{"action":"synthetic_action","repo":"test-repo"}`)
	canonParams, _ := authority.CanonicalParameters(params)
	req := authority.Request{
		Binding: approval.Binding{
			Audience:         "test/model_b/v1",
			DecisionID:       "dec-secret-test",
			DecisionDigest:   strings.Repeat("a", 64),
			EvidenceDigest:   strings.Repeat("b", 64),
			Target:           "test-repo",
			Action:           "synthetic_action",
			Revision:         strings.Repeat("1", 40),
			ParametersDigest: authority.Hash(canonParams),
		},
		Parameters: canonParams,
	}
	reqBytes, _ := json.Marshal(req)
	os.WriteFile(reqFile, reqBytes, 0644)

	cmd := exec.Command(bin, "authority", "sign", reqFile, keyFile, "key-01", "--yes", "--json")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected sign to fail when key is unreadable, got: %s", string(out))
	}
	res, err := parseResultEnvelope(out)
	if err == nil {
		if res.Error == nil || res.Error.Code != "KEY_READ_FAILED" {
			t.Fatalf("expected KEY_READ_FAILED error code, got: %+v", res)
		}
	}
}

// Criterion 3: An agent cannot modify the executor's security policy.
func TestModelBCriterion3_AgentCannotModifySecurityPolicy(t *testing.T) {
	bin := buildChangeOpsBinary(t)
	dir, dbPath, enrollPath, keyID, priv, _ := setupModelBFixture(t)
	audience := "test/model_b/v1"

	// Propose an unapproved / arbitrary action not in the fixed adapter allowlist
	params := json.RawMessage(`{"cmd":"rm -rf /"}`)
	canonParams, _ := authority.CanonicalParameters(params)

	req := authority.Request{
		Binding: approval.Binding{
			Audience:         audience,
			DecisionID:       "dec-unauthorized-action",
			DecisionDigest:   strings.Repeat("a", 64),
			EvidenceDigest:   strings.Repeat("b", 64),
			Target:           "test-repo",
			Action:           "arbitrary_execution_action",
			Revision:         strings.Repeat("1", 40),
			ParametersDigest: authority.Hash(canonParams),
		},
		Parameters: canonParams,
	}

	reqFile := filepath.Join(dir, "req.json")
	reqBytes, _ := json.Marshal(req)
	os.WriteFile(reqFile, reqBytes, 0644)

	// Even if an envelope could be signed for this action:
	envBytes, _ := authority.SignRequest(req, priv, keyID, 5*time.Minute)
	envFile := filepath.Join(dir, "env.json")
	os.WriteFile(envFile, envBytes, 0644)

	cmd := exec.Command(bin, "authority", "execute", dbPath, audience, enrollPath, reqFile, envFile, "--json")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("arbitrary action must be rejected by fixed executor policy: %s", string(out))
	}
	res, err := parseResultEnvelope(out)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "blocked" || res.Error == nil || res.Error.Code != "INDEPENDENT_AUTHORIZATION_UNAVAILABLE" {
		t.Fatalf("expected unavailable protected deployment, got: %+v", res)
	}
}

// Criterion 4: An agent cannot bypass approval by calling a lower-level component.
func TestModelBCriterion4_AgentCannotBypassApproval(t *testing.T) {
	bin := buildChangeOpsBinary(t)
	dir, _, _, _, _, _ := setupModelBFixture(t)

	// Create a ChangeOps config with model_b
	cfgPath := filepath.Join(dir, "changeops-config.json")
	cfgContent := `{
		"authorization_model": "model_b",
		"repos": {
			"test-repo": {
				"path": "` + dir + `",
				"allowed_branches": ["main"],
				"allowed_actions": ["create_release_candidate"]
			}
		}
	}`
	os.WriteFile(cfgPath, []byte(cfgContent), 0644)

	env := append(os.Environ(),
		"HOWLCHANGEOPS_CONFIG="+cfgPath,
		"HOWLCHANGEOPS_BASE="+filepath.Join(dir, ".howlchangeops"),
	)

	// Attempt 1: calling approve in model_b mode must fail closed
	cmdApprove := exec.Command(bin, "approve", "dec-001", "--json")
	cmdApprove.Env = env
	cmdApprove.Dir = dir
	out, err := cmdApprove.CombinedOutput()
	if err == nil {
		t.Fatalf("howlchangeops approve must fail closed in model_b mode, got: %s", string(out))
	}
	res, err := parseResultEnvelope(out)
	if err != nil {
		t.Fatalf("output is not result envelope: %v (raw: %s)", err, string(out))
	}
	if res.Status != "blocked" || res.Error == nil || res.Error.Code != "INDEPENDENT_AUTHORIZATION_UNAVAILABLE" {
		t.Fatalf("expected INDEPENDENT_AUTHORIZATION_UNAVAILABLE on approve, got: %+v", res)
	}

	// Attempt 2: calling execute without authority ledger must fail closed
	cmdExec := exec.Command(bin, "execute", "dec-001", "--json")
	cmdExec.Env = env
	cmdExec.Dir = dir
	out, err = cmdExec.CombinedOutput()
	if err == nil {
		t.Fatalf("howlchangeops execute must fail closed when authority undeployed, got: %s", string(out))
	}
	res, err = parseResultEnvelope(out)
	if err != nil {
		t.Fatalf("output is not result envelope: %v (raw: %s)", err, string(out))
	}
	if res.Status != "blocked" || res.Error == nil || res.Error.Code != "INDEPENDENT_AUTHORIZATION_UNAVAILABLE" {
		t.Fatalf("expected INDEPENDENT_AUTHORIZATION_UNAVAILABLE on execute, got: %+v", res)
	}
}

// Criterion 5: Changed action parameters invalidate approval.
func TestModelBCriterion5_ChangedParametersInvalidateApproval(t *testing.T) {
	bin := buildChangeOpsBinary(t)
	dir, dbPath, enrollPath, keyID, priv, _ := setupModelBFixture(t)
	audience := "test/model_b/v1"

	originalParams := json.RawMessage(`{"action":"synthetic_action","repo":"test-repo","value":"original"}`)
	canonOriginal, _ := authority.CanonicalParameters(originalParams)

	req := authority.Request{
		Binding: approval.Binding{
			Audience:         audience,
			DecisionID:       "dec-param-tamper",
			DecisionDigest:   strings.Repeat("a", 64),
			EvidenceDigest:   strings.Repeat("b", 64),
			Target:           "test-repo",
			Action:           "synthetic_action",
			Revision:         strings.Repeat("1", 40),
			ParametersDigest: authority.Hash(canonOriginal),
		},
		Parameters: canonOriginal,
	}

	// Sign for original parameters
	envBytes, err := authority.SignRequest(req, priv, keyID, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	envFile := filepath.Join(dir, "env.json")
	os.WriteFile(envFile, envBytes, 0644)

	// Tamper parameters in request file
	tamperedParams := json.RawMessage(`{"action":"synthetic_action","repo":"test-repo","value":"tampered"}`)
	canonTampered, _ := authority.CanonicalParameters(tamperedParams)
	tamperedReq := req
	tamperedReq.Parameters = canonTampered

	tamperedReqFile := filepath.Join(dir, "tampered_req.json")
	tamperedBytes, _ := json.Marshal(tamperedReq)
	os.WriteFile(tamperedReqFile, tamperedBytes, 0644)

	cmd := exec.Command(bin, "authority", "execute", dbPath, audience, enrollPath, tamperedReqFile, envFile, "--json")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("tampered parameters must be rejected, got: %s", string(out))
	}
	var res result
	if err := json.Unmarshal(out, &res); err == nil {
		if res.Status != "denied" {
			t.Fatalf("expected denied status on tampered parameters, got: %+v", res)
		}
	}
}

// Criterion 6: Expired or replayed approvals are rejected.
func TestModelBCriterion6_ExpiredOrReplayedApprovalsRejected(t *testing.T) {
	bin := buildChangeOpsBinary(t)
	dir, dbPath, enrollPath, keyID, priv, _ := setupModelBFixture(t)
	audience := "test/model_b/v1"

	params := json.RawMessage(`{"action":"synthetic_action","repo":"test-repo","reason":"valid"}`)
	canonParams, _ := authority.CanonicalParameters(params)

	req := authority.Request{
		Binding: approval.Binding{
			Audience:         audience,
			DecisionID:       "dec-replay-test",
			DecisionDigest:   strings.Repeat("a", 64),
			EvidenceDigest:   strings.Repeat("b", 64),
			Target:           "test-repo",
			Action:           "synthetic_action",
			Revision:         strings.Repeat("1", 40),
			ParametersDigest: authority.Hash(canonParams),
		},
		Parameters: canonParams,
	}

	reqFile := filepath.Join(dir, "req.json")
	reqBytes, _ := json.Marshal(req)
	os.WriteFile(reqFile, reqBytes, 0644)

	// Sub-case A: First execution succeeds
	envBytes, err := authority.SignRequest(req, priv, keyID, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	envFile := filepath.Join(dir, "env.json")
	os.WriteFile(envFile, envBytes, 0644)

	cmd1 := exec.Command(bin, "authority", "execute", dbPath, audience, enrollPath, reqFile, envFile, "--json")
	cmd1.Dir = dir
	out1, err := cmd1.CombinedOutput()
	if err != nil {
		t.Fatalf("first execution failed: %v\n%s", err, string(out1))
	}

	first, err := parseResultEnvelope(out1)
	if err != nil {
		t.Fatal(err)
	}
	if first.Data["execution_kind"] != "synthetic" || first.Data["authorization_guarantee"] != "synthetic_protocol_only" {
		t.Fatalf("synthetic execution must not claim protected authorization: %+v", first)
	}

	// Sub-case B: Replay of the exact same approval on a different operation must be rejected
	req2 := req
	req2.Binding.DecisionID = "dec-replay-different"
	req2File := filepath.Join(dir, "req2.json")
	req2Bytes, _ := json.Marshal(req2)
	os.WriteFile(req2File, req2Bytes, 0644)

	cmdReplay := exec.Command(bin, "authority", "execute", dbPath, audience, enrollPath, req2File, envFile, "--json")
	cmdReplay.Dir = dir
	outReplay, err := cmdReplay.CombinedOutput()
	if err == nil {
		t.Fatalf("replayed approval on different decision must be rejected: %s", string(outReplay))
	}

	// Sub-case C: Expired approval must be rejected
	pastTime := time.Now().UTC().Add(-20 * time.Minute)
	expiredClaims := approval.Claims{
		Schema:     approval.Schema,
		KeyID:      keyID,
		ApprovalID: "app-expired",
		Nonce:      base64.RawURLEncoding.EncodeToString([]byte("12345678901234567890123456789012")),
		IssuedAt:   pastTime.Format(time.RFC3339),
		ExpiresAt:  pastTime.Add(5 * time.Minute).Format(time.RFC3339),
		Binding:    req.Binding,
	}
	sig := ed25519.Sign(priv, approval.SigningBytes(expiredClaims))
	expiredEnv := approval.Envelope{
		Claims:    expiredClaims,
		Signature: base64.RawURLEncoding.EncodeToString(sig),
	}
	expiredEnvBytes, _ := json.Marshal(expiredEnv)
	expiredEnvFile := filepath.Join(dir, "expired_env.json")
	os.WriteFile(expiredEnvFile, expiredEnvBytes, 0644)

	cmdExpired := exec.Command(bin, "authority", "execute", dbPath, audience, enrollPath, reqFile, expiredEnvFile, "--json")
	cmdExpired.Dir = dir
	outExpired, err := cmdExpired.CombinedOutput()
	if err == nil {
		t.Fatalf("expired approval must be rejected: %s", string(outExpired))
	}
}

// Criterion 7: Completed operations do not execute twice.
func TestModelBCriterion7_CompletedOperationsDoNotExecuteTwice(t *testing.T) {
	bin := buildChangeOpsBinary(t)
	dir, dbPath, enrollPath, keyID, priv, _ := setupModelBFixture(t)
	audience := "test/model_b/v1"

	params := json.RawMessage(`{"action":"synthetic_action","repo":"test-repo","tag":"v1.0"}`)
	canonParams, _ := authority.CanonicalParameters(params)

	req := authority.Request{
		Binding: approval.Binding{
			Audience:         audience,
			DecisionID:       "dec-once-only",
			DecisionDigest:   strings.Repeat("a", 64),
			EvidenceDigest:   strings.Repeat("b", 64),
			Target:           "test-repo",
			Action:           "synthetic_action",
			Revision:         strings.Repeat("1", 40),
			ParametersDigest: authority.Hash(canonParams),
		},
		Parameters: canonParams,
	}

	reqFile := filepath.Join(dir, "req.json")
	reqBytes, _ := json.Marshal(req)
	os.WriteFile(reqFile, reqBytes, 0644)

	envBytes1, _ := authority.SignRequest(req, priv, keyID, 5*time.Minute)
	envFile1 := filepath.Join(dir, "env1.json")
	os.WriteFile(envFile1, envBytes1, 0644)

	// First execution
	cmd1 := exec.Command(bin, "authority", "execute", dbPath, audience, enrollPath, reqFile, envFile1, "--json")
	cmd1.Dir = dir
	out1, err := cmd1.CombinedOutput()
	if err != nil {
		t.Fatalf("first execution failed: %v\n%s", err, string(out1))
	}
	res1, err := parseResultEnvelope(out1)
	if err != nil {
		t.Fatalf("first execution output invalid: %v (raw: %s)", err, string(out1))
	}
	receipt1, _ := json.Marshal(res1.Data["receipt_data"])

	// Even if owner signs a new approval for the same decision ID:
	envBytes2, _ := authority.SignRequest(req, priv, keyID, 5*time.Minute)
	envFile2 := filepath.Join(dir, "env2.json")
	os.WriteFile(envFile2, envBytes2, 0644)

	cmd2 := exec.Command(bin, "authority", "execute", dbPath, audience, enrollPath, reqFile, envFile2, "--json")
	cmd2.Dir = dir
	out2, err := cmd2.CombinedOutput()
	if err != nil {
		t.Fatalf("second execution (re-fetch receipt) failed: %v\n%s", err, string(out2))
	}
	res2, err := parseResultEnvelope(out2)
	if err != nil {
		t.Fatalf("second execution output invalid: %v (raw: %s)", err, string(out2))
	}
	receipt2, _ := json.Marshal(res2.Data["receipt_data"])

	// Receipts must match exactly and side effects must not execute twice
	if !bytes.Equal(receipt1, receipt2) {
		t.Fatalf("expected identical cached receipt, got: %s vs %s", string(receipt1), string(receipt2))
	}
}

// Criterion 8: Failed or interrupted operations retain truthful durable state.
func TestModelBCriterion8_InterruptedOperationsRetainTruthfulState(t *testing.T) {
	_, dbPath, enrollPath, keyID, priv, _ := setupModelBFixture(t)
	audience := "test/model_b/v1"

	l, err := authority.OpenLedger(dbPath, audience)
	if err != nil {
		t.Fatal(err)
	}

	params := json.RawMessage(`{"action":"synthetic_action","repo":"test-repo"}`)
	canonParams, _ := authority.CanonicalParameters(params)

	req := authority.Request{
		Binding: approval.Binding{
			Audience:         audience,
			DecisionID:       "dec-crash-test",
			DecisionDigest:   strings.Repeat("a", 64),
			EvidenceDigest:   strings.Repeat("b", 64),
			Target:           "test-repo",
			Action:           "synthetic_action",
			Revision:         strings.Repeat("1", 40),
			ParametersDigest: authority.Hash(canonParams),
		},
		Parameters: canonParams,
	}

	envBytes, _ := authority.SignRequest(req, priv, keyID, 5*time.Minute)
	stateSrc := authority.NewFileStateSource(enrollPath, true)

	// Failing adapter simulating crash / panic after reservation
	failingAdapters := map[string]authority.Adapter{
		"synthetic_action": {
			Validate: func(req authority.Request) error { return nil },
			Run: func(ctx context.Context, req authority.Request, id string) (json.RawMessage, error) {
				return nil, fmt.Errorf("simulated crash during execution")
			},
		},
	}

	exec, err := authority.NewExecutor(l, stateSrc, failingAdapters)
	if err != nil {
		t.Fatal(err)
	}

	// Execution fails
	_, err = exec.Execute(context.Background(), envBytes, req)
	if err == nil {
		t.Fatalf("expected execution to fail")
	}

	// Reopen ledger and verify truthful uncertain state: redispatch must refuse!
	l2, err := authority.OpenLedger(dbPath, audience)
	if err != nil {
		t.Fatal(err)
	}
	exec2, _ := authority.NewExecutor(l2, stateSrc, authority.DefaultAdapters(""))
	_, err = exec2.Execute(context.Background(), envBytes, req)
	if err == nil || !strings.Contains(err.Error(), "already reserved or uncertain") {
		t.Fatalf("re-dispatch on uncertain operation must refuse, got: %v", err)
	}
}

// Criterion 9: The executor fails closed when protected authority is unavailable.
func TestModelBCriterion9_ExecutorFailsClosedWhenAuthorityUnavailable(t *testing.T) {
	bin := buildChangeOpsBinary(t)
	dir, dbPath, enrollPath, keyID, priv, _ := setupModelBFixture(t)
	audience := "test/model_b/v1"

	params := json.RawMessage(`{"action":"synthetic_action","repo":"test-repo"}`)
	canonParams, _ := authority.CanonicalParameters(params)

	req := authority.Request{
		Binding: approval.Binding{
			Audience:         audience,
			DecisionID:       "dec-unavailable-test",
			DecisionDigest:   strings.Repeat("a", 64),
			EvidenceDigest:   strings.Repeat("b", 64),
			Target:           "test-repo",
			Action:           "synthetic_action",
			Revision:         strings.Repeat("1", 40),
			ParametersDigest: authority.Hash(canonParams),
		},
		Parameters: canonParams,
	}

	reqFile := filepath.Join(dir, "req.json")
	reqBytes, _ := json.Marshal(req)
	os.WriteFile(reqFile, reqBytes, 0644)

	envBytes, _ := authority.SignRequest(req, priv, keyID, 5*time.Minute)
	envFile := filepath.Join(dir, "env.json")
	os.WriteFile(envFile, envBytes, 0644)

	// Sub-case A: Nonexistent database fails closed
	cmdNoDB := exec.Command(bin, "authority", "execute", filepath.Join(dir, "nonexistent.db"), audience, enrollPath, reqFile, envFile, "--json")
	cmdNoDB.Dir = dir
	outNoDB, err := cmdNoDB.CombinedOutput()
	if err == nil {
		t.Fatalf("expected failure for nonexistent database: %s", string(outNoDB))
	}

	// Sub-case B: Revoked key fails closed
	cfg, err := authority.LoadEnrollment(enrollPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg.RevokeKey(keyID, "security incident")
	authority.SaveEnrollment(enrollPath, cfg)

	cmdRevoked := exec.Command(bin, "authority", "execute", dbPath, audience, enrollPath, reqFile, envFile, "--json")
	cmdRevoked.Dir = dir
	outRevoked, err := cmdRevoked.CombinedOutput()
	if err == nil {
		t.Fatalf("expected failure for revoked key: %s", string(outRevoked))
	}
	res, err := parseResultEnvelope(outRevoked)
	if err == nil {
		if res.Status != "denied" {
			t.Fatalf("expected denied status for revoked key: %+v", res)
		}
	}
}
