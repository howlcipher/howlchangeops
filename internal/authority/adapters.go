package authority

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

var (
	ErrAdapterValidation = errors.New("adapter validation failed")
	ErrAdapterExecution  = errors.New("adapter execution failed")
)

// DefaultAdapters constructs the fixed allowlist of adapters supported by the protected executor.
func DefaultAdapters(repoPath string) map[string]Adapter {
	adapters := make(map[string]Adapter)

	// create_release_candidate creates a release candidate git tag.
	adapters["create_release_candidate"] = Adapter{
		Validate: func(req Request) error {
			if len(req.Binding.Revision) < 7 {
				return ErrAdapterValidation
			}
			return nil
		},
		Run: func(ctx context.Context, req Request, decisionID string) (json.RawMessage, error) {
			rev := req.Binding.Revision
			if len(rev) > 7 {
				rev = rev[:7]
			}
			tag := fmt.Sprintf("howlchangeops/rc-%s", rev)
			targetRepo := repoPath
			if targetRepo == "" {
				var p struct {
					Repo string `json:"repo"`
				}
				if err := json.Unmarshal(req.Parameters, &p); err == nil && p.Repo != "" {
					targetRepo = p.Repo
				}
			}
			if targetRepo != "" {
				cmd := exec.CommandContext(ctx, "git", "-C", targetRepo, "tag", "-a", tag, "-m", "HowlChangeOps RC", req.Binding.Revision)
				if out, err := cmd.CombinedOutput(); err != nil {
					// If tag already exists, verify it matches
					verifyCmd := exec.CommandContext(ctx, "git", "-C", targetRepo, "rev-parse", "-q", "--verify", fmt.Sprintf("refs/tags/%s^{commit}", tag))
					tagRev, vErr := verifyCmd.CombinedOutput()
					if vErr != nil || !strings.HasPrefix(string(tagRev), rev) {
						return nil, fmt.Errorf("%w: failed to create tag: %s (%v)", ErrAdapterExecution, string(out), err)
					}
				}
			}
			payload, _ := json.Marshal(map[string]any{
				"action":      "create_release_candidate",
				"status":      "SUCCESS",
				"tag":         tag,
				"decision_id": decisionID,
				"timestamp":   time.Now().UTC().Format(time.RFC3339),
			})
			return payload, nil
		},
	}

	// record_release_ready records release readiness.
	adapters["record_release_ready"] = Adapter{
		Validate: func(req Request) error {
			return nil
		},
		Run: func(ctx context.Context, req Request, decisionID string) (json.RawMessage, error) {
			payload, _ := json.Marshal(map[string]any{
				"action":      "record_release_ready",
				"status":      "READY",
				"decision_id": decisionID,
				"timestamp":   time.Now().UTC().Format(time.RFC3339),
			})
			return payload, nil
		},
	}

	// rollback_release_candidate removes a release candidate git tag.
	adapters["rollback_release_candidate"] = Adapter{
		Validate: func(req Request) error {
			return nil
		},
		Run: func(ctx context.Context, req Request, decisionID string) (json.RawMessage, error) {
			rev := req.Binding.Revision
			if len(rev) > 7 {
				rev = rev[:7]
			}
			tag := fmt.Sprintf("howlchangeops/rc-%s", rev)
			if repoPath != "" {
				cmd := exec.CommandContext(ctx, "git", "-C", repoPath, "tag", "-d", tag)
				_ = cmd.Run()
			}
			payload, _ := json.Marshal(map[string]any{
				"action":      "rollback_release_candidate",
				"status":      "ROLLED_BACK",
				"tag":         tag,
				"decision_id": decisionID,
				"timestamp":   time.Now().UTC().Format(time.RFC3339),
			})
			return payload, nil
		},
	}

	// synthetic_action is a pure deterministic adapter for test and staging verification.
	adapters["synthetic_action"] = Adapter{
		Validate: func(req Request) error {
			if len(req.Parameters) == 0 {
				return ErrAdapterValidation
			}
			return nil
		},
		Run: func(ctx context.Context, req Request, decisionID string) (json.RawMessage, error) {
			payload, _ := json.Marshal(map[string]any{
				"action":      "synthetic_action",
				"status":      "SUCCESS",
				"decision_id": decisionID,
				"parameters":  req.Parameters,
				"timestamp":   time.Now().UTC().Format(time.RFC3339),
			})
			return payload, nil
		},
	}

	return adapters
}
