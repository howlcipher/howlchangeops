package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"howlchangeops/internal/approval"
	"howlchangeops/internal/authority"
)

func runAuthority(args []string) {
	progName := "howlchangeops"
	if len(args) < 1 {
		die("failed", "USAGE", "Usage: %s authority <init|keygen|enroll|revoke|review|sign|execute|status> [args...]", progName)
	}
	sub := args[0]
	subArgs := args[1:]

	switch sub {
	case "init":
		// Usage: authority init <db_path> <audience>
		if len(subArgs) < 2 {
			die("failed", "USAGE", "Usage: %s authority init <db_path> <audience>", progName)
		}
		dbPath, err := filepath.Abs(subArgs[0])
		if err != nil {
			die("failed", "INVALID_PATH", "Invalid db path: %v", err)
		}
		aud := subArgs[1]
		l, err := authority.CreateLedger(dbPath, aud)
		if err != nil {
			die("unavailable", "LEDGER_INIT_FAILED", "Failed to create authority ledger: %v", err)
		}
		_ = l
		succeed("ok", map[string]any{
			"status":   "initialized",
			"path":     dbPath,
			"audience": aud,
		})

	case "keygen":
		// Usage: authority keygen <key_id> <owner> <out_priv_file>
		if len(subArgs) < 3 {
			die("failed", "USAGE", "Usage: %s authority keygen <key_id> <owner> <out_priv_file>", progName)
		}
		keyID := subArgs[0]
		owner := subArgs[1]
		outPriv := subArgs[2]

		priv, pub, genKeyID, err := authority.GenerateKey()
		if err != nil {
			die("failed", "KEYGEN_FAILED", "Failed to generate key: %v", err)
		}
		if keyID == "" || keyID == "auto" {
			keyID = genKeyID
		}
		privB64 := base64.RawURLEncoding.EncodeToString(priv)
		pubB64 := base64.RawURLEncoding.EncodeToString(pub)

		if err := os.WriteFile(outPriv, []byte(privB64+"\n"), 0600); err != nil {
			die("failed", "WRITE_FAILED", "Failed to write private key: %v", err)
		}
		succeed("ok", map[string]any{
			"key_id":     keyID,
			"owner":      owner,
			"public_key": pubB64,
			"priv_file":  outPriv,
		})

	case "enroll":
		// Usage: authority enroll <config_file> <key_id> <owner> <pubkey_b64>
		if len(subArgs) < 4 {
			die("failed", "USAGE", "Usage: %s authority enroll <config_file> <key_id> <owner> <pubkey_b64>", progName)
		}
		cfgPath, err := filepath.Abs(subArgs[0])
		if err != nil {
			die("failed", "INVALID_PATH", "Invalid config path: %v", err)
		}
		keyID := subArgs[1]
		owner := subArgs[2]
		pubStr := subArgs[3]

		pubBytes, err := base64.RawURLEncoding.DecodeString(pubStr)
		if err != nil || len(pubBytes) != ed25519.PublicKeySize {
			pubBytes, err = base64.StdEncoding.DecodeString(pubStr)
			if err != nil || len(pubBytes) != ed25519.PublicKeySize {
				die("failed", "INVALID_KEY", "Invalid public key bytes: %v", err)
			}
		}

		cfg, err := authority.LoadEnrollment(cfgPath)
		if err != nil {
			// Initialize new if not existing
			cfg = &authority.EnrollmentConfig{
				Schema: authority.EnrollmentSchema,
				Keys:   make(map[string]authority.EnrollmentKey),
			}
		}
		if err := cfg.EnrollKey(keyID, owner, ed25519.PublicKey(pubBytes)); err != nil {
			die("failed", "ENROLL_FAILED", "Failed to enroll key: %v", err)
		}
		if err := authority.SaveEnrollment(cfgPath, cfg); err != nil {
			die("failed", "SAVE_FAILED", "Failed to save enrollment: %v", err)
		}
		succeed("ok", map[string]any{
			"status": "enrolled",
			"key_id": keyID,
			"owner":  owner,
		})

	case "revoke":
		// Usage: authority revoke <config_file> <key_id> <reason>
		if len(subArgs) < 3 {
			die("failed", "USAGE", "Usage: %s authority revoke <config_file> <key_id> <reason>", progName)
		}
		cfgPath, err := filepath.Abs(subArgs[0])
		if err != nil {
			die("failed", "INVALID_PATH", "Invalid config path: %v", err)
		}
		keyID := subArgs[1]
		reason := subArgs[2]

		cfg, err := authority.LoadEnrollment(cfgPath)
		if err != nil {
			die("failed", "LOAD_FAILED", "Failed to load enrollment: %v", err)
		}
		if err := cfg.RevokeKey(keyID, reason); err != nil {
			die("failed", "REVOKE_FAILED", "Failed to revoke key: %v", err)
		}
		if err := authority.SaveEnrollment(cfgPath, cfg); err != nil {
			die("failed", "SAVE_FAILED", "Failed to save enrollment: %v", err)
		}
		succeed("ok", map[string]any{
			"status": "revoked",
			"key_id": keyID,
			"reason": reason,
		})

	case "review":
		// Usage: authority review <request_file>
		if len(subArgs) < 1 {
			die("failed", "USAGE", "Usage: %s authority review <request_file>", progName)
		}
		reqData, err := os.ReadFile(subArgs[0])
		if err != nil {
			die("failed", "READ_FAILED", "Failed to read request file: %v", err)
		}
		var req authority.Request
		if err := json.Unmarshal(reqData, &req); err != nil {
			die("failed", "INVALID_REQUEST", "Failed to parse request JSON: %v", err)
		}
		summary, err := authority.ReviewRequest(req)
		if err != nil {
			die("failed", "INVALID_REQUEST", "Request verification failed: %v", err)
		}
		fmt.Fprintf(os.Stderr, "=== Protected Operation Review ===\n")
		fmt.Fprintf(os.Stderr, "Decision ID:       %s\n", summary.DecisionID)
		fmt.Fprintf(os.Stderr, "Target:            %s\n", summary.Target)
		fmt.Fprintf(os.Stderr, "Action:            %s\n", summary.Action)
		fmt.Fprintf(os.Stderr, "Revision:          %s\n", summary.Revision)
		fmt.Fprintf(os.Stderr, "Audience:          %s\n", summary.Audience)
		fmt.Fprintf(os.Stderr, "Parameters Digest: %s\n", summary.ParametersDigest)
		succeed("ok", map[string]any{
			"summary": summary,
		})

	case "sign":
		// Usage: authority sign <request_file> <privkey_file> <key_id> [out_envelope_file] [--yes|--deny]
		if len(subArgs) < 3 {
			die("failed", "USAGE", "Usage: %s authority sign <request_file> <privkey_file> <key_id> [out_envelope_file] [--yes|--deny]", progName)
		}
		reqFile := subArgs[0]
		privFile := subArgs[1]
		keyID := subArgs[2]
		outEnv := ""
		confirmed := false
		explicitDeny := false

		for _, a := range subArgs[3:] {
			if a == "--yes" || a == "-y" {
				confirmed = true
			} else if a == "--deny" {
				explicitDeny = true
			} else if outEnv == "" && !strings.HasPrefix(a, "-") {
				outEnv = a
			}
		}

		if explicitDeny {
			die("denied", "NOT_CONFIRMED", "DENIED: owner explicitly rejected operation")
		}

		reqData, err := os.ReadFile(reqFile)
		if err != nil {
			die("failed", "READ_FAILED", "Failed to read request file: %v", err)
		}
		var req authority.Request
		if err := json.Unmarshal(reqData, &req); err != nil {
			die("failed", "INVALID_REQUEST", "Failed to parse request: %v", err)
		}

		summary, err := authority.ReviewRequest(req)
		if err != nil {
			die("failed", "INVALID_REQUEST", "Review failed: %v", err)
		}

		if !confirmed {
			if !stdinIsTerminal() {
				die("blocked", "OWNER_CONFIRMATION_REQUIRED", "DENIED: signing %s requires owner confirmation; run at a terminal or pass --yes", summary.DecisionID)
			}
			fmt.Fprintf(os.Stderr, "Sign %s on %s at %.12s? [y/N] ", summary.Action, summary.Target, summary.Revision)
			if !confirmAtTerminal(os.Stdin) {
				die("denied", "NOT_CONFIRMED", "Decision %s signing rejected.", summary.DecisionID)
			}
		}

		privData, err := os.ReadFile(privFile)
		if err != nil {
			die("failed", "KEY_READ_FAILED", "Failed to read private key file: %v", err)
		}
		privStr := strings.TrimSpace(string(privData))
		privBytes, err := base64.RawURLEncoding.DecodeString(privStr)
		if err != nil || len(privBytes) != ed25519.PrivateKeySize {
			privBytes, err = base64.StdEncoding.DecodeString(privStr)
			if err != nil || len(privBytes) != ed25519.PrivateKeySize {
				die("failed", "INVALID_KEY", "Invalid private key bytes in %s", privFile)
			}
		}

		envBytes, err := authority.SignRequest(req, ed25519.PrivateKey(privBytes), keyID, 5*time.Minute)
		if err != nil {
			die("failed", "SIGN_FAILED", "Signing failed: %v", err)
		}

		if outEnv != "" {
			if err := os.WriteFile(outEnv, append(envBytes, '\n'), 0644); err != nil {
				die("failed", "WRITE_FAILED", "Failed to write envelope file: %v", err)
			}
		}
		var envObj approval.Envelope
		_ = json.Unmarshal(envBytes, &envObj)
		succeed("ok", map[string]any{
			"status":      "signed",
			"approval_id": envObj.Claims.ApprovalID,
			"key_id":      keyID,
			"envelope":    envObj,
		})

	case "execute":
		// Usage: authority execute <db_path> <audience> <enrollment_file> <request_file> <envelope_file>
		if len(subArgs) < 5 {
			die("failed", "USAGE", "Usage: %s authority execute <db_path> <audience> <enrollment_file> <request_file> <envelope_file>", progName)
		}
		dbPath, err := filepath.Abs(subArgs[0])
		if err != nil {
			die("failed", "INVALID_PATH", "Invalid db path: %v", err)
		}
		aud := subArgs[1]
		enrollPath, err := filepath.Abs(subArgs[2])
		if err != nil {
			die("failed", "INVALID_PATH", "Invalid enrollment path: %v", err)
		}
		reqFile := subArgs[3]
		envFile := subArgs[4]

		reqData, err := os.ReadFile(reqFile)
		if err != nil {
			die("failed", "READ_FAILED", "Failed to read request file: %v", err)
		}
		var req authority.Request
		if err := json.Unmarshal(reqData, &req); err != nil {
			die("failed", "INVALID_REQUEST", "Failed to parse request: %v", err)
		}

		envData, err := os.ReadFile(envFile)
		if err != nil {
			die("failed", "READ_FAILED", "Failed to read envelope file: %v", err)
		}

		l, err := authority.OpenLedger(dbPath, aud)
		if err != nil {
			die("unavailable", "AUTHORITY_UNAVAILABLE", "Failed to open authority ledger: %v", err)
		}

		stateSrc := authority.NewFileStateSource(enrollPath, true)
		executor, err := authority.NewExecutor(l, stateSrc, authority.DefaultAdapters(""))
		if err != nil {
			die("unavailable", "EXECUTOR_INIT_FAILED", "Failed to initialize executor: %v", err)
		}

		receipt, err := executor.Execute(context.Background(), envData, req)
		if err != nil {
			if errors.Is(err, authority.ErrConflict) {
				die("denied", "ALREADY_EXECUTED", "Operation conflict or already executed: %v", err)
			}
			if errors.Is(err, authority.ErrUncertain) {
				die("denied", "OPERATION_UNCERTAIN", "Operation reserved or uncertain; reconciliation required: %v", err)
			}
			if errors.Is(err, authority.ErrUnavailable) {
				die("unavailable", "AUTHORITY_UNAVAILABLE", "Authority unavailable: %v", err)
			}
			die("denied", "EXECUTION_DENIED", "Protected execution denied: %v", err)
		}

		succeed("ok", map[string]any{
			"status":       "executed",
			"decision_id":  receipt.OperationID,
			"approval_id":  receipt.ApprovalID,
			"owner":        receipt.Owner,
			"receipt_data": receipt,
		})

	case "status":
		// Usage: authority status <db_path> <audience> <enrollment_file>
		if len(subArgs) < 3 {
			die("failed", "USAGE", "Usage: %s authority status <db_path> <audience> <enrollment_file>", progName)
		}
		dbPath, _ := filepath.Abs(subArgs[0])
		aud := subArgs[1]
		enrollPath, _ := filepath.Abs(subArgs[2])

		l, lErr := authority.OpenLedger(dbPath, aud)
		cfg, eErr := authority.LoadEnrollment(enrollPath)

		status := "ready"
		if lErr != nil || eErr != nil {
			status = "not_ready"
		}
		keyCount := 0
		if cfg != nil {
			keyCount = len(cfg.Keys)
		}
		succeed("ok", map[string]any{
			"status":           status,
			"ledger_available": lErr == nil && l != nil,
			"enrolled_keys":    keyCount,
		})

	default:
		die("failed", "UNKNOWN_SUBCOMMAND", "Unknown authority subcommand: %s", sub)
	}
}

func executeModelB(dec Decision, cfg *Config) {
	ledgerPath := os.Getenv("HOWLCHANGEOPS_AUTHORITY_LEDGER")
	if ledgerPath == "" {
		die("blocked", "INDEPENDENT_AUTHORIZATION_UNAVAILABLE", "%s", "Model B protected executor is not deployed")
	}
	enrollPath := os.Getenv("HOWLCHANGEOPS_AUTHORITY_ENROLLMENT")
	if enrollPath == "" {
		die("unavailable", "ENROLLMENT_UNAVAILABLE", "%s", "HOWLCHANGEOPS_AUTHORITY_ENROLLMENT not set")
	}
	audience := os.Getenv("HOWLCHANGEOPS_AUTHORITY_AUDIENCE")
	if audience == "" {
		audience = "howlchangeops/authority/v1"
	}

	appFile := filepath.Join(approvalsDir, dec.ID+".json")
	appData, err := os.ReadFile(appFile)
	if err != nil {
		die("denied", "APPROVAL_MISSING", "DENIED: Approval envelope missing for decision %s: %v", dec.ID, err)
	}

	paramMap := map[string]any{
		"action": dec.Proposal.Action,
		"repo":   dec.Proposal.Repo,
		"reason": dec.Proposal.Reason,
	}
	rawParams, err := json.Marshal(paramMap)
	if err != nil {
		die("failed", "INVALID_PARAMETERS", "Failed to marshal parameters: %v", err)
	}
	canonParams, err := authority.CanonicalParameters(rawParams)
	if err != nil {
		die("failed", "INVALID_PARAMETERS", "Failed to canonicalize parameters: %v", err)
	}

	req := authority.Request{
		Binding: approval.Binding{
			Audience:         audience,
			DecisionID:       dec.ID,
			DecisionDigest:   dec.Digest,
			EvidenceDigest:   dec.RuntimeEvidence.EvidenceDigest,
			Target:           dec.Proposal.Repo,
			Action:           dec.Proposal.Action,
			Revision:         dec.Evidence.Revision,
			ParametersDigest: authority.Hash(canonParams),
		},
		Parameters: canonParams,
	}

	l, err := authority.OpenLedger(ledgerPath, audience)
	if err != nil {
		die("unavailable", "AUTHORITY_UNAVAILABLE", "Failed to open authority ledger: %v", err)
	}

	stateSrc := authority.NewFileStateSource(enrollPath, true)
	repoCfg := cfg.Repos[dec.Proposal.Repo]
	adapters := authority.DefaultAdapters(repoCfg.Path)

	executor, err := authority.NewExecutor(l, stateSrc, adapters)
	if err != nil {
		die("unavailable", "EXECUTOR_INIT_FAILED", "Failed to init executor: %v", err)
	}

	receipt, err := executor.Execute(context.Background(), appData, req)
	if err != nil {
		if errors.Is(err, authority.ErrConflict) {
			die("denied", "ALREADY_EXECUTED", "DENIED: Decision or approval already executed: %v", err)
		}
		if errors.Is(err, authority.ErrUncertain) {
			die("denied", "OPERATION_UNCERTAIN", "DENIED: Decision already reserved or uncertain; reconciliation required: %v", err)
		}
		if errors.Is(err, authority.ErrUnavailable) {
			die("unavailable", "AUTHORITY_UNAVAILABLE", "DENIED: Protected authority unavailable: %v", err)
		}
		die("denied", "APPROVAL_INVALID", "DENIED: Approval verification failed: %v", err)
	}

	// Persist receipt
	recBytes, _ := json.MarshalIndent(receipt, "", "  ")
	_ = os.WriteFile(filepath.Join(receiptsDir, dec.ID+".json"), recBytes, 0644)

	appendAudit(map[string]interface{}{
		"event":       "execute_model_b",
		"decision_id": dec.ID,
		"approval_id": receipt.ApprovalID,
		"owner":       receipt.Owner,
		"status":      "executed",
	})

	succeed("ok", map[string]any{
		"decision_id":  dec.ID,
		"approval_id":  receipt.ApprovalID,
		"owner":        receipt.Owner,
		"receipt_data": receipt,
		"status":       "executed",
	})
}
