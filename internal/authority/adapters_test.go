package authority

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"howlchangeops/internal/approval"
)

// setupSyntheticGitRepo creates an isolated temporary git repository with two commits.
func setupSyntheticGitRepo(t *testing.T) (string, string, string) {
	t.Helper()
	dir := t.TempDir()

	runGit := func(args ...string) string {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=Test",
			"GIT_AUTHOR_EMAIL=test@example.com",
			"GIT_COMMITTER_NAME=Test",
			"GIT_COMMITTER_EMAIL=test@example.com",
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v failed: %s (%v)", args, string(out), err)
		}
		return strings.TrimSpace(string(out))
	}

	runGit("init")
	runGit("config", "user.name", "Test")
	runGit("config", "user.email", "test@example.com")

	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("# Test Repo\n"), 0600); err != nil {
		t.Fatal(err)
	}
	runGit("add", "README.md")
	runGit("commit", "-m", "Initial commit")
	commit1 := runGit("rev-parse", "HEAD")

	if err := os.WriteFile(filepath.Join(dir, "file2.txt"), []byte("commit 2\n"), 0600); err != nil {
		t.Fatal(err)
	}
	runGit("add", "file2.txt")
	runGit("commit", "-m", "Second commit")
	commit2 := runGit("rev-parse", "HEAD")

	return dir, commit1, commit2
}

func TestCreateReleaseCandidateValidation(t *testing.T) {
	adapters := DefaultAdapters("")
	adapter := adapters["create_release_candidate"]

	// Missing repo and empty parameters
	reqNoRepo := Request{
		Binding: approval.Binding{
			Action:   "create_release_candidate",
			Revision: "1234567",
		},
	}
	if err := adapter.Validate(reqNoRepo); !errors.Is(err, ErrAdapterValidation) {
		t.Fatalf("expected ErrAdapterValidation for missing repo, got %v", err)
	}

	// Short revision
	reqShortRev := Request{
		Binding: approval.Binding{
			Action:   "create_release_candidate",
			Revision: "123",
		},
		Parameters: json.RawMessage(`{"repo":"/tmp/test"}`),
	}
	if err := adapter.Validate(reqShortRev); !errors.Is(err, ErrAdapterValidation) {
		t.Fatalf("expected ErrAdapterValidation for short revision, got %v", err)
	}
}

func TestCreateReleaseCandidateExecution(t *testing.T) {
	repoDir, commit1, commit2 := setupSyntheticGitRepo(t)
	adapters := DefaultAdapters(repoDir)
	adapter := adapters["create_release_candidate"]
	ctx := context.Background()

	// Non-existent revision
	reqBadRev := Request{
		Binding: approval.Binding{
			Action:   "create_release_candidate",
			Revision: "0000000000000000000000000000000000000000",
		},
	}
	if _, err := adapter.Run(ctx, reqBadRev, "dec-bad-rev"); !errors.Is(err, ErrAdapterExecution) {
		t.Fatalf("expected ErrAdapterExecution for non-existent revision, got %v", err)
	}

	// Valid creation
	reqValid := Request{
		Binding: approval.Binding{
			Action:   "create_release_candidate",
			Revision: commit1,
		},
	}
	rawReceipt, err := adapter.Run(ctx, reqValid, "dec-valid-1")
	if err != nil {
		t.Fatalf("expected successful tag creation, got %v", err)
	}
	var receipt map[string]any
	if err := json.Unmarshal(rawReceipt, &receipt); err != nil {
		t.Fatalf("unmarshal receipt: %v", err)
	}
	if receipt["status"] != "SUCCESS" || receipt["commit"] != commit1 || receipt["existing"] != false {
		t.Fatalf("unexpected receipt: %+v", receipt)
	}
	tag := fmt.Sprintf("howlchangeops/rc-%s", commit1[:7])
	if receipt["tag"] != tag {
		t.Fatalf("expected tag %s, got %v", tag, receipt["tag"])
	}

	// Verify tag in git repository actually points to commit1
	cmd := exec.Command("git", "-C", repoDir, "rev-parse", "-q", "--verify", fmt.Sprintf("refs/tags/%s^{commit}", tag))
	out, err := cmd.CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != commit1 {
		t.Fatalf("tag not properly created in git repo: out=%s err=%v", string(out), err)
	}

	// Idempotent creation: calling again returns SUCCESS with existing=true
	rawReceipt2, err := adapter.Run(ctx, reqValid, "dec-valid-2")
	if err != nil {
		t.Fatalf("expected idempotent tag creation, got %v", err)
	}
	var receipt2 map[string]any
	if err := json.Unmarshal(rawReceipt2, &receipt2); err != nil {
		t.Fatalf("unmarshal receipt2: %v", err)
	}
	if receipt2["status"] != "SUCCESS" || receipt2["existing"] != true {
		t.Fatalf("expected existing=true on idempotent run, got %+v", receipt2)
	}

	// Conflicting tag: tag exists pointing to commit1, but request is for commit2 with same short tag
	// To test conflict, manually point the tag for commit2's prefix to commit1
	conflictTag := fmt.Sprintf("howlchangeops/rc-%s", commit2[:7])
	tagCmd := exec.Command("git", "-C", repoDir, "tag", "-a", conflictTag, "-m", "Conflicting tag", commit1)
	if out, err := tagCmd.CombinedOutput(); err != nil {
		t.Fatalf("setup conflicting tag failed: %s (%v)", string(out), err)
	}

	reqConflict := Request{
		Binding: approval.Binding{
			Action:   "create_release_candidate",
			Revision: commit2,
		},
	}
	if _, err := adapter.Run(ctx, reqConflict, "dec-conflict"); !errors.Is(err, ErrAdapterExecution) {
		t.Fatalf("expected ErrAdapterExecution on conflicting tag, got %v", err)
	}
}

func TestRollbackReleaseCandidateValidationAndExecution(t *testing.T) {
	repoDir, commit1, commit2 := setupSyntheticGitRepo(t)
	adapters := DefaultAdapters("")
	adapter := adapters["rollback_release_candidate"]
	ctx := context.Background()

	// Missing repo
	reqNoRepo := Request{
		Binding: approval.Binding{
			Action:   "rollback_release_candidate",
			Revision: commit1,
		},
	}
	if err := adapter.Validate(reqNoRepo); !errors.Is(err, ErrAdapterValidation) {
		t.Fatalf("expected ErrAdapterValidation for missing repo, got %v", err)
	}

	// Param repo resolution
	paramWithRepo, _ := json.Marshal(map[string]string{"repo": repoDir})
	reqWithRepo := Request{
		Binding: approval.Binding{
			Action:   "rollback_release_candidate",
			Revision: commit1,
		},
		Parameters: paramWithRepo,
	}
	if err := adapter.Validate(reqWithRepo); err != nil {
		t.Fatalf("Validate failed with valid param repo: %v", err)
	}

	// Case 1: Tag does not exist -> ALREADY_RECONCILED
	rawReceipt1, err := adapter.Run(ctx, reqWithRepo, "dec-rb-none")
	if err != nil {
		t.Fatalf("unexpected error when tag does not exist: %v", err)
	}
	var receipt1 map[string]any
	if err := json.Unmarshal(rawReceipt1, &receipt1); err != nil {
		t.Fatalf("unmarshal receipt: %v", err)
	}
	if receipt1["status"] != "ALREADY_RECONCILED" {
		t.Fatalf("expected status ALREADY_RECONCILED, got %+v", receipt1)
	}

	// Case 2: Tag exists pointing to authorized commit -> ROLLED_BACK
	tag := fmt.Sprintf("howlchangeops/rc-%s", commit1[:7])
	cmd := exec.Command("git", "-C", repoDir, "tag", "-a", tag, "-m", "tag to delete", commit1)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("create tag failed: %s (%v)", string(out), err)
	}

	rawReceipt2, err := adapter.Run(ctx, reqWithRepo, "dec-rb-valid")
	if err != nil {
		t.Fatalf("unexpected error on valid rollback: %v", err)
	}
	var receipt2 map[string]any
	if err := json.Unmarshal(rawReceipt2, &receipt2); err != nil {
		t.Fatalf("unmarshal receipt: %v", err)
	}
	if receipt2["status"] != "ROLLED_BACK" || receipt2["deleted_commit"] != commit1 {
		t.Fatalf("expected ROLLED_BACK receipt, got %+v", receipt2)
	}

	// Verify tag is physically deleted from git repo
	verifyCmd := exec.Command("git", "-C", repoDir, "rev-parse", "-q", "--verify", fmt.Sprintf("refs/tags/%s", tag))
	if err := verifyCmd.Run(); err == nil {
		t.Fatalf("tag %s still exists in git repo after rollback", tag)
	}

	// Case 3: Tag exists but points to different revision -> REFUSAL (ErrAdapterExecution)
	// Create tag pointing to commit2, but request rollback for commit1 (whose short SHA differs)
	// Or create tag with commit1's prefix pointing to commit2
	mismatchTag := fmt.Sprintf("howlchangeops/rc-%s", commit1[:7])
	cmdMismatch := exec.Command("git", "-C", repoDir, "tag", "-a", mismatchTag, "-m", "mismatched commit", commit2)
	if out, err := cmdMismatch.CombinedOutput(); err != nil {
		t.Fatalf("create mismatch tag failed: %s (%v)", string(out), err)
	}

	if _, err := adapter.Run(ctx, reqWithRepo, "dec-rb-mismatch"); !errors.Is(err, ErrAdapterExecution) {
		t.Fatalf("expected ErrAdapterExecution on revision mismatch, got %v", err)
	}
}

func TestRecordReleaseReadySemantics(t *testing.T) {
	adapters := DefaultAdapters("")
	adapter := adapters["record_release_ready"]
	ctx := context.Background()

	// Missing target
	reqNoTarget := Request{
		Binding: approval.Binding{
			Action:   "record_release_ready",
			Revision: "1234567890abcdef",
		},
	}
	if err := adapter.Validate(reqNoTarget); !errors.Is(err, ErrAdapterValidation) {
		t.Fatalf("expected ErrAdapterValidation for missing target, got %v", err)
	}

	// Missing revision
	reqNoRev := Request{
		Binding: approval.Binding{
			Action: "record_release_ready",
			Target: "howlcipher/howlchangeops",
		},
	}
	if err := adapter.Validate(reqNoRev); !errors.Is(err, ErrAdapterValidation) {
		t.Fatalf("expected ErrAdapterValidation for missing revision, got %v", err)
	}

	// Valid request
	reqValid := Request{
		Binding: approval.Binding{
			Action:         "record_release_ready",
			Target:         "howlcipher/howlchangeops",
			Revision:       "1234567890abcdef",
			EvidenceDigest: "evidence-digest-12345",
			DecisionDigest: "decision-digest-67890",
		},
	}
	if err := adapter.Validate(reqValid); err != nil {
		t.Fatalf("Validate failed on valid request: %v", err)
	}

	rawReceipt, err := adapter.Run(ctx, reqValid, "dec-ready-1")
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	var receipt map[string]any
	if err := json.Unmarshal(rawReceipt, &receipt); err != nil {
		t.Fatalf("unmarshal receipt: %v", err)
	}
	if receipt["status"] != "RECORDED" || receipt["readiness"] != "READY" {
		t.Fatalf("expected status RECORDED and readiness READY, got %+v", receipt)
	}
	if receipt["semantics"] != "owner_authorized_decision_record" {
		t.Fatalf("expected semantics owner_authorized_decision_record, got %v", receipt["semantics"])
	}
	if receipt["target"] != "howlcipher/howlchangeops" || receipt["revision"] != "1234567890abcdef" {
		t.Fatalf("bound fields mismatch: %+v", receipt)
	}
	if receipt["evidence_digest"] != "evidence-digest-12345" || receipt["decision_id"] != "dec-ready-1" {
		t.Fatalf("bound digests mismatch: %+v", receipt)
	}
}
