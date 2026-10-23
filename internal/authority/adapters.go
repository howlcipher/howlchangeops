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

// resolveTargetRepo resolves the target repository path from repoPath or parameters.
func resolveTargetRepo(repoPath string, params json.RawMessage) (string, error) {
	targetRepo := repoPath
	if targetRepo == "" && len(params) > 0 {
		var p struct {
			Repo string `json:"repo"`
		}
		if err := json.Unmarshal(params, &p); err == nil && p.Repo != "" {
			targetRepo = p.Repo
		}
	}
	if strings.TrimSpace(targetRepo) == "" {
		return "", fmt.Errorf("%w: repository path must be explicitly resolved and non-empty", ErrAdapterValidation)
	}
	return targetRepo, nil
}

// verifyGitRepo checks that targetRepo is a valid git repository.
func verifyGitRepo(ctx context.Context, targetRepo string) error {
	cmd := exec.CommandContext(ctx, "git", "-C", targetRepo, "rev-parse", "--git-dir")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: target %s is not a valid git repository: %s (%v)", ErrAdapterExecution, targetRepo, strings.TrimSpace(string(out)), err)
	}
	return nil
}

// DefaultAdapters constructs the fixed allowlist of adapters supported by the protected executor.
func DefaultAdapters(repoPath string) map[string]Adapter {
	adapters := make(map[string]Adapter)

	// create_release_candidate creates a release candidate git tag.
	adapters["create_release_candidate"] = Adapter{
		Validate: func(req Request) error {
			if len(req.Binding.Revision) < 7 {
				return fmt.Errorf("%w: revision must be at least 7 characters", ErrAdapterValidation)
			}
			if repoPath == "" {
				var p struct {
					Repo string `json:"repo"`
				}
				if err := json.Unmarshal(req.Parameters, &p); err != nil || strings.TrimSpace(p.Repo) == "" {
					return fmt.Errorf("%w: repository path must be explicitly resolved in parameters", ErrAdapterValidation)
				}
			}
			return nil
		},
		Run: func(ctx context.Context, req Request, decisionID string) (json.RawMessage, error) {
			targetRepo, err := resolveTargetRepo(repoPath, req.Parameters)
			if err != nil {
				return nil, err
			}
			if err := verifyGitRepo(ctx, targetRepo); err != nil {
				return nil, err
			}

			// Verify that authorized revision exists in the target repository
			revCmd := exec.CommandContext(ctx, "git", "-C", targetRepo, "rev-parse", "-q", "--verify", fmt.Sprintf("%s^{commit}", req.Binding.Revision))
			revOut, err := revCmd.CombinedOutput()
			if err != nil {
				return nil, fmt.Errorf("%w: authorized revision %s does not exist in %s: %s (%v)", ErrAdapterExecution, req.Binding.Revision, targetRepo, strings.TrimSpace(string(revOut)), err)
			}
			targetCommit := strings.TrimSpace(string(revOut))

			rev := req.Binding.Revision
			if len(rev) > 7 {
				rev = rev[:7]
			}
			tag := fmt.Sprintf("howlchangeops/rc-%s", rev)

			// Check if tag already exists
			verifyCmd := exec.CommandContext(ctx, "git", "-C", targetRepo, "rev-parse", "-q", "--verify", fmt.Sprintf("refs/tags/%s^{commit}", tag))
			tagRevOut, vErr := verifyCmd.CombinedOutput()
			tagAlreadyExisted := false
			if vErr == nil {
				existingCommit := strings.TrimSpace(string(tagRevOut))
				if existingCommit == targetCommit || strings.HasPrefix(existingCommit, rev) {
					// Idempotent return: already in desired state
					tagAlreadyExisted = true
				} else {
					// Conflicting tag points to different commit
					return nil, fmt.Errorf("%w: conflicting tag %s exists pointing to %s (expected %s)", ErrAdapterExecution, tag, existingCommit, targetCommit)
				}
			}

			if !tagAlreadyExisted {
				cmd := exec.CommandContext(ctx, "git", "-C", targetRepo, "tag", "-a", tag, "-m", "HowlChangeOps RC", targetCommit)
				if out, err := cmd.CombinedOutput(); err != nil {
					return nil, fmt.Errorf("%w: failed to create tag %s: %s (%v)", ErrAdapterExecution, tag, strings.TrimSpace(string(out)), err)
				}
				// Verify created tag points to authorized commit
				postVerify := exec.CommandContext(ctx, "git", "-C", targetRepo, "rev-parse", "-q", "--verify", fmt.Sprintf("refs/tags/%s^{commit}", tag))
				postRev, postErr := postVerify.CombinedOutput()
				if postErr != nil || strings.TrimSpace(string(postRev)) != targetCommit {
					return nil, fmt.Errorf("%w: tag %s verification failed after creation: %s", ErrAdapterExecution, tag, strings.TrimSpace(string(postRev)))
				}
			}

			payload, _ := json.Marshal(map[string]any{
				"action":      "create_release_candidate",
				"status":      "SUCCESS",
				"tag":         tag,
				"commit":      targetCommit,
				"existing":    tagAlreadyExisted,
				"decision_id": decisionID,
				"timestamp":   time.Now().UTC().Format(time.RFC3339),
			})
			return payload, nil
		},
	}

	// record_release_ready records an owner-authorized release readiness decision.
	// It records the owner's determination for the bound target, revision, and evidence digest;
	// it does not perform automated test suite verification in this adapter.
	adapters["record_release_ready"] = Adapter{
		Validate: func(req Request) error {
			if strings.TrimSpace(req.Binding.Target) == "" {
				return fmt.Errorf("%w: target must be specified for record_release_ready", ErrAdapterValidation)
			}
			if len(req.Binding.Revision) < 7 {
				return fmt.Errorf("%w: revision must be at least 7 characters", ErrAdapterValidation)
			}
			return nil
		},
		Run: func(ctx context.Context, req Request, decisionID string) (json.RawMessage, error) {
			if strings.TrimSpace(decisionID) == "" {
				return nil, fmt.Errorf("%w: decision_id is required", ErrAdapterExecution)
			}
			payload, _ := json.Marshal(map[string]any{
				"action":          "record_release_ready",
				"status":          "RECORDED",
				"readiness":       "READY",
				"semantics":       "owner_authorized_decision_record",
				"target":          req.Binding.Target,
				"revision":        req.Binding.Revision,
				"evidence_digest": req.Binding.EvidenceDigest,
				"decision_id":     decisionID,
				"timestamp":       time.Now().UTC().Format(time.RFC3339),
			})
			return payload, nil
		},
	}

	// rollback_release_candidate removes a release candidate git tag.
	adapters["rollback_release_candidate"] = Adapter{
		Validate: func(req Request) error {
			if len(req.Binding.Revision) < 7 {
				return fmt.Errorf("%w: revision must be at least 7 characters", ErrAdapterValidation)
			}
			if repoPath == "" {
				var p struct {
					Repo string `json:"repo"`
				}
				if err := json.Unmarshal(req.Parameters, &p); err != nil || strings.TrimSpace(p.Repo) == "" {
					return fmt.Errorf("%w: repository path must be explicitly resolved in parameters", ErrAdapterValidation)
				}
			}
			return nil
		},
		Run: func(ctx context.Context, req Request, decisionID string) (json.RawMessage, error) {
			targetRepo, err := resolveTargetRepo(repoPath, req.Parameters)
			if err != nil {
				return nil, err
			}
			if err := verifyGitRepo(ctx, targetRepo); err != nil {
				return nil, err
			}

			rev := req.Binding.Revision
			if len(rev) > 7 {
				rev = rev[:7]
			}
			tag := fmt.Sprintf("howlchangeops/rc-%s", rev)

			// Check whether the tag exists in the repository
			checkCmd := exec.CommandContext(ctx, "git", "-C", targetRepo, "rev-parse", "-q", "--verify", fmt.Sprintf("refs/tags/%s^{commit}", tag))
			tagRevOut, err := checkCmd.CombinedOutput()
			if err != nil {
				// Tag is already absent: state transition is already reconciled
				payload, _ := json.Marshal(map[string]any{
					"action":      "rollback_release_candidate",
					"status":      "ALREADY_RECONCILED",
					"tag":         tag,
					"decision_id": decisionID,
					"reason":      "tag does not exist",
					"timestamp":   time.Now().UTC().Format(time.RFC3339),
				})
				return payload, nil
			}

			// Tag exists. Verify that it points to the authorized revision
			existingCommit := strings.TrimSpace(string(tagRevOut))
			if !strings.HasPrefix(existingCommit, rev) {
				return nil, fmt.Errorf("%w: tag %s points to %s, does not match authorized revision %s", ErrAdapterExecution, tag, existingCommit, rev)
			}

			// Delete the tag
			delCmd := exec.CommandContext(ctx, "git", "-C", targetRepo, "tag", "-d", tag)
			if delOut, delErr := delCmd.CombinedOutput(); delErr != nil {
				return nil, fmt.Errorf("%w: failed to delete tag %s: %s (%v)", ErrAdapterExecution, tag, strings.TrimSpace(string(delOut)), delErr)
			}

			// Verify tag was actually deleted
			verifyAbsence := exec.CommandContext(ctx, "git", "-C", targetRepo, "rev-parse", "-q", "--verify", fmt.Sprintf("refs/tags/%s", tag))
			if verifyAbsence.Run() == nil {
				return nil, fmt.Errorf("%w: tag %s still exists after deletion command", ErrAdapterExecution, tag)
			}

			payload, _ := json.Marshal(map[string]any{
				"action":         "rollback_release_candidate",
				"status":         "ROLLED_BACK",
				"tag":            tag,
				"decision_id":    decisionID,
				"deleted_commit": existingCommit,
				"timestamp":      time.Now().UTC().Format(time.RFC3339),
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
