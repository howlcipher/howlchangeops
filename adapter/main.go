package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Version is HowlChangeOps's own release version. Bumped alongside each
// tagged release; not derived from git state at build time.
const Version = "0.2.0"

// CompatibleHowlFrameVersion is the HowlFrame release this build's
// compiled policy (howlchangeops.hfbc) was built and verified against.
// HowlChangeOps consumes HowlFrame entirely through its public CLI, and
// accepts any patch release of this minor release whose HFBC format matches,
// checked at startup and execution pre-flight (HOWL-CANON-013).
const CompatibleHowlFrameVersion = "0.1.0"

// CompatibleHFBCFormat is the bytecode format howlchangeops.hfbc is built in.
const CompatibleHFBCFormat = "1"

func getHowlFrameBin() string {
	if bin := os.Getenv("HOWLFRAME_BIN"); bin != "" {
		return bin
	}
	return "howlframe"
}

func checkHowlFrameCompatibility() error {
	bin := getHowlFrameBin()
	cmd := exec.Command(bin, "--version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("howlframe binary %q not found or failed to execute: %w (output: %s)", bin, err, strings.TrimSpace(string(out)))
	}
	outputStr := string(out)
	lines := strings.Split(strings.TrimSpace(outputStr), "\n")
	if len(lines) == 0 {
		return fmt.Errorf("empty output from %s --version", bin)
	}
	firstLine := strings.TrimSpace(lines[0])
	fields := strings.Fields(firstLine)
	if len(fields) < 2 || fields[0] != "HowlFrame" {
		return fmt.Errorf("unrecognized howlframe version format: %q", firstLine)
	}
	version := strings.TrimPrefix(fields[1], "v")
	if !sameMinorRelease(version, CompatibleHowlFrameVersion) {
		return fmt.Errorf("incompatible HowlFrame version: found %s, require %s.x", version, minorRelease(CompatibleHowlFrameVersion))
	}
	// The compiled policy is HFBC; a runner that reports a different
	// bytecode format cannot load it, whatever its version says.
	for _, line := range lines[1:] {
		if format, ok := strings.CutPrefix(strings.TrimSpace(line), "HFBC format:"); ok {
			if strings.TrimSpace(format) != CompatibleHFBCFormat {
				return fmt.Errorf("incompatible HowlFrame bytecode: found HFBC format %s, require %s", strings.TrimSpace(format), CompatibleHFBCFormat)
			}
		}
	}
	return nil
}

// minorRelease returns "major.minor" of a version string.
func minorRelease(v string) string {
	parts := strings.SplitN(strings.TrimPrefix(v, "v"), ".", 3)
	if len(parts) < 2 {
		return v
	}
	return parts[0] + "." + parts[1]
}

// sameMinorRelease accepts any patch release of the HowlFrame minor release
// the policy was built against: HowlFrame is pre-1.0, so a minor bump may
// change the language, while patch releases may not.
func sameMinorRelease(found, want string) bool {
	parts := strings.SplitN(strings.TrimPrefix(found, "v"), ".", 3)
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		p, _, _ = strings.Cut(p, "-")
		if _, err := strconv.Atoi(p); err != nil {
			return false
		}
	}
	return minorRelease(found) == minorRelease(want)
}

type ConfigRepo struct {
	Path              string   `json:"path"`
	AllowedBranches   []string `json:"allowed_branches"`
	ValidationProfile string   `json:"validation_profile"`
	AllowedActions    []string `json:"allowed_actions"`
}

type Config struct {
	AuthorizationModel string                `json:"authorization_model,omitempty"`
	Repos              map[string]ConfigRepo `json:"repos"`
}

type Proposal struct {
	Action     string  `json:"action"`
	Repo       string  `json:"repo"`
	Reason     string  `json:"reason"`
	Confidence float64 `json:"confidence"`
}

type ValidationResult struct {
	Name            string `json:"name"`
	Status          string `json:"status"`
	StartedAt       string `json:"started_at"`
	FinishedAt      string `json:"finished_at"`
	ExitCode        int    `json:"exit_code"`
	Profile         string `json:"profile"`
	Revision        string `json:"revision"`
	OutputDigest    string `json:"output_digest"`
	TimedOut        bool   `json:"timed_out,omitempty"`
	OutputTruncated bool   `json:"output_truncated,omitempty"`
}

type RiskEvidence struct {
	ChangedFileCount          int  `json:"changed_file_count"`
	ContainsInfrastructure    bool `json:"contains_infrastructure_changes"`
	ContainsDependency        bool `json:"contains_dependency_changes"`
	ContainsCI                bool `json:"contains_ci_changes"`
	ContainsSecuritySensitive bool `json:"contains_security_sensitive_paths"`
}

type RemoteEvidence struct {
	Repo             string `json:"repo"`
	ExpectedBranch   string `json:"expected_branch"`
	RemoteHEAD       string `json:"remote_head"`
	LocalRemoteMatch bool   `json:"local_remote_match"`
	CIStatus         string `json:"ci_status"`
	ReleaseExists    bool   `json:"release_exists"`
	GatheredAt       string `json:"gathered_at"`
}

type EvidenceEnvelope struct {
	Remote                   RemoteEvidence              `json:"remote"`
	Schema                   string                      `json:"schema"`
	Repo                     string                      `json:"repo"`
	Revision                 string                      `json:"revision"`
	Branch                   string                      `json:"branch"`
	WorkingTree              string                      `json:"working_tree"`
	ValidationProfile        string                      `json:"validation_profile"`
	ValidationProfileVersion string                      `json:"validation_profile_version"`
	ConfigDigest             string                      `json:"config_digest"`
	GeneratedAt              string                      `json:"generated_at"`
	Checks                   map[string]ValidationResult `json:"checks"`
	Risk                     RiskEvidence                `json:"risk"`
}

type RuntimeEvidence struct {
	RemoteHEAD      string `json:"remote_head"`
	CurrentRevision string `json:"current_revision"`
	WorkingTree     string `json:"working_tree"`
	Approved        string `json:"approved"`
	CandidateExists string `json:"candidate_exists"`
	EvidenceDigest  string `json:"evidence_digest"`
	EvidenceAge     string `json:"evidence_age"`
}

type Gate struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

type Decision struct {
	ID              string           `json:"decision_id"`
	Proposal        Proposal         `json:"proposal"`
	Evidence        EvidenceEnvelope `json:"evidence"`
	RuntimeEvidence RuntimeEvidence  `json:"runtime_evidence"`
	Gates           []Gate           `json:"gates"`
	Result          string           `json:"result"`
	Reason          string           `json:"reason"`
	Digest          string           `json:"digest"`
}

type Approval struct {
	AuthorizationGuarantee string `json:"authorization_guarantee,omitempty"`
	Schema                 string `json:"schema"`
	ApprovalID             string `json:"approval_id"`
	DecisionID             string `json:"decision_id"`
	DecisionDigest         string `json:"decision_digest"`
	EvidenceDigest         string `json:"evidence_digest"`
	Repo                   string `json:"repo"`
	Action                 string `json:"action"`
	Revision               string `json:"revision"`
	Approver               string `json:"approver"`
	Confirmation           string `json:"confirmation"`
	IssuedAt               string `json:"issued_at"`
	ExpiresAt              string `json:"expires_at"`
	Nonce                  string `json:"nonce"`
	Signature              string `json:"signature"`
}

type ExecutionReceipt struct {
	AuthorizationGuarantee string `json:"authorization_guarantee,omitempty"`
	Schema                 string `json:"schema"`
	DecisionID             string `json:"decision_id"`
	ApprovalID             string `json:"approval_id"`
	Action                 string `json:"action"`
	Repo                   string `json:"repo"`
	Revision               string `json:"revision"`
	ExecutedAt             string `json:"executed_at"`
	Verification           string `json:"verification"`
	RollbackStatus         string `json:"rollback_status,omitempty"`
	ErrorMessage           string `json:"error_message,omitempty"`
}

var (
	baseDir      = ".howlchangeops"
	decisionsDir = filepath.Join(baseDir, "decisions")
	approvalsDir = filepath.Join(baseDir, "approvals")
	receiptsDir  = filepath.Join(baseDir, "receipts")
	historyFile  = filepath.Join(baseDir, "history.jsonl")
)

func initDirs() {
	if b := os.Getenv("HOWLCHANGEOPS_BASE"); b != "" {
		baseDir = b
	} else if b := os.Getenv("CHANGEOPS_BASE"); b != "" {
		baseDir = b
	} else if _, err := os.Stat(".howlchangeops"); err == nil {
		baseDir = ".howlchangeops"
	} else if _, err := os.Stat(".changeops"); err == nil {
		baseDir = ".changeops"
	}
	decisionsDir = filepath.Join(baseDir, "decisions")
	approvalsDir = filepath.Join(baseDir, "approvals")
	receiptsDir = filepath.Join(baseDir, "receipts")
	historyFile = filepath.Join(baseDir, "history.jsonl")

	os.MkdirAll(baseDir, 0755)
	os.MkdirAll(decisionsDir, 0755)
	os.MkdirAll(approvalsDir, 0755)
	os.MkdirAll(receiptsDir, 0755)
}

func loadConfig() (*Config, string, error) {
	home, _ := os.UserHomeDir()
	candidates := configCandidates(os.Getenv, home)
	var data []byte
	var err error
	for _, configFile := range candidates {
		if data, err = os.ReadFile(configFile); err == nil {
			break
		}
	}
	if err != nil {
		return nil, "", fmt.Errorf("no configuration found (looked in %s): %w", strings.Join(candidates, ", "), err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, "", err
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(data))
	return &cfg, digest, nil
}

func validateRepoIdentifier(name string) error {
	if name == "" {
		return fmt.Errorf("repository identifier cannot be empty")
	}
	if strings.Contains(name, "..") || strings.Contains(name, "/") || strings.Contains(name, "\\") {
		return fmt.Errorf("invalid repository identifier: path traversal detected")
	}
	for _, r := range name {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-') {
			return fmt.Errorf("invalid repository identifier character %q", r)
		}
	}
	return nil
}

func validateActionName(action string) error {
	if action == "" {
		return fmt.Errorf("action name cannot be empty")
	}
	if strings.ContainsAny(action, ";|&$`\n\r<>(){}") {
		return fmt.Errorf("invalid action name: prohibited shell metacharacters detected")
	}
	for _, r := range action {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-') {
			return fmt.Errorf("invalid action name character %q", r)
		}
	}
	return nil
}

func getApprovalKey() []byte {
	keyFile := os.Getenv("HOWLCHANGEOPS_APPROVAL_KEY_FILE")
	if keyFile == "" {
		keyFile = os.Getenv("CHANGEOPS_APPROVAL_KEY_FILE")
	}
	if keyFile == "" {
		return nil
	}
	key, err := os.ReadFile(keyFile)
	if err != nil {
		return nil
	}
	return key
}

func canonicalApprovalString(a Approval) string {
	payload := fmt.Sprintf("schema:%s|approval_id:%s|decision_id:%s|decision_digest:%s|evidence_digest:%s|repo:%s|action:%s|revision:%s|approver:%s|confirmation:%s|issued_at:%s|expires_at:%s|nonce:%s",
		a.Schema, a.ApprovalID, a.DecisionID, a.DecisionDigest, a.EvidenceDigest, a.Repo, a.Action, a.Revision, a.Approver, a.Confirmation, a.IssuedAt, a.ExpiresAt, a.Nonce)
	// Preserve old record verification while binding explicit guarantee on new records.
	if a.AuthorizationGuarantee != "" {
		payload += "|authorization_guarantee:" + a.AuthorizationGuarantee
	}
	return payload
}

func signApproval(a Approval, key []byte) string {
	payload := canonicalApprovalString(a)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(payload))
	return fmt.Sprintf("%x", mac.Sum(nil))
}

func computeEvidenceDigest(e EvidenceEnvelope) string {
	data, _ := json.Marshal(e)
	return fmt.Sprintf("%x", sha256.Sum256(data))
}

func computeDecisionDigest(d Decision) string {
	payload := fmt.Sprintf("%s|%s|%s|%s|%s", d.Proposal.Action, d.Proposal.Repo, d.Evidence.Revision, d.Result, computeEvidenceDigest(d.Evidence))
	return fmt.Sprintf("%x", sha256.Sum256([]byte(payload)))
}

func gitCommand(repoPath string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = repoPath
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func parseGitHubRepo(url string) string {
	url = strings.TrimSpace(url)
	url = strings.TrimSuffix(url, ".git")
	if strings.HasPrefix(url, "https://github.com/") {
		return strings.TrimPrefix(url, "https://github.com/")
	}
	if strings.HasPrefix(url, "git@github.com:") {
		return strings.TrimPrefix(url, "git@github.com:")
	}
	return ""
}

func runGH(dir string, args ...string) (string, error) {
	cmd := exec.Command("gh", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func gatherRemoteEvidence(repoPath string, branch string, rev string) RemoteEvidence {
	re := RemoteEvidence{
		ExpectedBranch: branch,
		GatheredAt:     time.Now().UTC().Format(time.RFC3339),
	}

	remoteURL, err := gitCommand(repoPath, "config", "--get", "remote.origin.url")
	if err != nil || remoteURL == "" {
		return re
	}

	repoName := parseGitHubRepo(remoteURL)
	if repoName == "" {
		return re
	}
	re.Repo = repoName

	shaOut, err := runGH(repoPath, "api", fmt.Sprintf("repos/%s/commits/%s", repoName, branch), "--jq", ".sha")
	if err == nil && shaOut != "" && !strings.Contains(shaOut, "not found") {
		re.RemoteHEAD = shaOut
		re.LocalRemoteMatch = (shaOut == rev)
	}

	statusOut, err := runGH(repoPath, "api", fmt.Sprintf("repos/%s/commits/%s/status", repoName, branch), "--jq", ".state")
	if err == nil && statusOut != "" && !strings.Contains(statusOut, "not found") {
		re.CIStatus = statusOut
	}

	tag := fmt.Sprintf("howlchangeops/rc-%s", rev[:7])
	_, err = runGH(repoPath, "release", "view", tag)
	if err != nil {
		legacyTag := fmt.Sprintf("changeops/rc-%s", rev[:7])
		_, err = runGH(repoPath, "release", "view", legacyTag)
	}
	if err == nil {
		re.ReleaseExists = true
	}

	return re
}

func computeRisk(repoPath string, rev string) RiskEvidence {
	out, err := gitCommand(repoPath, "diff-tree", "--no-commit-id", "--name-only", "-r", rev)
	if err != nil {
		return RiskEvidence{}
	}
	files := strings.Split(out, "\n")
	risk := RiskEvidence{
		ChangedFileCount: len(files),
	}
	for _, f := range files {
		if f == "" {
			continue
		}
		if strings.HasPrefix(f, "infra/") || strings.HasPrefix(f, "terraform/") || f == "Dockerfile" {
			risk.ContainsInfrastructure = true
		}
		if f == "go.mod" || f == "requirements.txt" || f == "package-lock.json" {
			risk.ContainsDependency = true
		}
		if strings.HasPrefix(f, ".github/workflows/") {
			risk.ContainsCI = true
		}
		if strings.Contains(f, "security") || strings.Contains(f, "auth") {
			risk.ContainsSecuritySensitive = true
		}
	}
	return risk
}

func gatherEvidence(repoID string, repoPath string, repoCfg ConfigRepo, configDigest string) (EvidenceEnvelope, RuntimeEvidence) {
	branch, _ := gitCommand(repoPath, "branch", "--show-current")
	rev, _ := gitCommand(repoPath, "rev-parse", "HEAD")
	status, _ := gitCommand(repoPath, "status", "--porcelain")
	workingTree := "dirty"
	if status == "" {
		workingTree = "clean"
	}

	freshRemote := gatherRemoteEvidence(repoPath, branch, rev)

	ev := EvidenceEnvelope{
		Schema:                   "howlchangeops.evidence/v1",
		Repo:                     repoID,
		Revision:                 rev,
		Branch:                   branch,
		WorkingTree:              workingTree,
		ValidationProfile:        repoCfg.ValidationProfile,
		ValidationProfileVersion: "1.0",
		ConfigDigest:             configDigest,
		Checks:                   make(map[string]ValidationResult),
		Risk:                     computeRisk(repoPath, rev),
		Remote:                   freshRemote,
	}

	cacheKey := fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s|%s", repoID, rev, repoCfg.ValidationProfile, configDigest))))
	cacheFile := filepath.Join(baseDir, fmt.Sprintf("evidence_%s.json", cacheKey))
	if cacheData, err := os.ReadFile(cacheFile); err == nil {
		var cachedEv EvidenceEnvelope
		if json.Unmarshal(cacheData, &cachedEv) == nil {
			if cachedEv.Revision == rev && cachedEv.ConfigDigest == configDigest && cachedEv.ValidationProfile == repoCfg.ValidationProfile && cachedEv.WorkingTree == "clean" && cachedEv.Checks["working_tree"].Status == "PASS" {
				ev = cachedEv
				ev.WorkingTree = workingTree // Update working tree
			}
		}
	}

	candidateExists := "false"
	tags, _ := gitCommand(repoPath, "tag", "-l", fmt.Sprintf("howlchangeops/rc-%s", rev[:7]))
	if tags == "" {
		tags, _ = gitCommand(repoPath, "tag", "-l", fmt.Sprintf("changeops/rc-%s", rev[:7]))
	}
	if tags != "" {
		candidateExists = "true"
	}

	rtEv := RuntimeEvidence{
		CurrentRevision: rev,
		WorkingTree:     workingTree,
		CandidateExists: candidateExists,
		Approved:        "false",
		RemoteHEAD:      freshRemote.RemoteHEAD,
		EvidenceDigest:  computeEvidenceDigest(ev),
	}
	if ev.GeneratedAt != "" {
		genTime, err := time.Parse(time.RFC3339, ev.GeneratedAt)
		if err == nil {
			rtEv.EvidenceAge = time.Since(genTime).Round(time.Second).String()
		}
	}

	return ev, rtEv
}

func runValidationCommand(name string, repoPath string, cmdName string, args ...string) ValidationResult {
	start := time.Now().UTC()
	cmd := exec.Command(cmdName, args...)
	cmd.Dir = repoPath
	out, err := cmd.CombinedOutput()

	status := "PASS"
	exitCode := 0
	if err != nil {
		status = "FAIL"
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		} else {
			exitCode = -1
		}
	}

	return ValidationResult{
		Name:         name,
		Status:       status,
		StartedAt:    start.Format(time.RFC3339),
		FinishedAt:   time.Now().UTC().Format(time.RFC3339),
		ExitCode:     exitCode,
		Profile:      "local",
		Revision:     "HEAD",
		OutputDigest: fmt.Sprintf("%x", sha256.Sum256(out)),
	}
}

func validate(repoID string, repoPath string, repoCfg ConfigRepo, configDigest string) error {
	if repoCfg.ValidationProfile != "go" && repoCfg.ValidationProfile != "python-stdlib" {
		return fmt.Errorf("unsupported validation profile %q: supported profiles are go and python-stdlib; configure validation_profile in config/howlchangeops-config.json", repoCfg.ValidationProfile)
	}
	if repoCfg.ValidationProfile == "python-stdlib" && runtime.GOOS == "windows" {
		return fmt.Errorf("python-stdlib is unsupported on Windows: process-group cancellation is unavailable")
	}
	revision, err := gitCommand(repoPath, "rev-parse", "--verify", "HEAD")
	if err != nil || len(revision) < 7 {
		return fmt.Errorf("validation requires a Git repository with a committed HEAD; check the configured repository path and create an initial commit")
	}
	status, err := gitCommand(repoPath, "status", "--porcelain")
	if err != nil || status != "" {
		return fmt.Errorf("validation requires a clean working tree; commit or restore repository changes before validating")
	}
	ev, _ := gatherEvidence(repoID, repoPath, repoCfg, configDigest)
	if ev.Revision != revision || ev.WorkingTree != "clean" {
		return fmt.Errorf("repository changed before validation; retry with a clean committed HEAD")
	}
	ev.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
	ev.Checks = make(map[string]ValidationResult)

	if repoCfg.ValidationProfile == "go" {
		fmt.Println("Running go test ./...")
		ev.Checks["test"] = runValidationCommand("go_test", repoPath, "go", "test", "./...")

		fmt.Println("Running go build ./...")
		ev.Checks["build"] = runValidationCommand("go_build", repoPath, "go", "build", "./...")
	}

	if repoCfg.ValidationProfile == "python-stdlib" {
		ev.Checks["test"] = runPythonCheck("python_unittest", repoPath, pythonTestHelper, 120*time.Second, 1024*1024)
		ev.Checks["build"] = runPythonCheck("python_compile", repoPath, pythonBuildHelper, 120*time.Second, 1024*1024)
	}

	// Passing checks are reusable only for the same clean committed snapshot.
	finalRevision, revisionErr := gitCommand(repoPath, "rev-parse", "--verify", "HEAD")
	finalStatus, statusErr := gitCommand(repoPath, "status", "--porcelain")
	snapshotChanged := revisionErr != nil || statusErr != nil || finalRevision != revision || finalStatus != ""
	ev.WorkingTree = "clean"
	if statusErr != nil || finalStatus != "" {
		ev.WorkingTree = "dirty"
	}
	wtStatus := "PASS"
	if snapshotChanged {
		wtStatus = "FAIL"
	}
	ev.Checks["working_tree"] = ValidationResult{
		Name:       "working_tree",
		Status:     wtStatus,
		StartedAt:  time.Now().UTC().Format(time.RFC3339),
		FinishedAt: time.Now().UTC().Format(time.RFC3339),
		ExitCode:   0,
	}

	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return fmt.Errorf("create evidence directory: %w", err)
	}
	cacheKey := fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s|%s", repoID, ev.Revision, repoCfg.ValidationProfile, configDigest))))
	cacheFile := filepath.Join(baseDir, fmt.Sprintf("evidence_%s.json", cacheKey))
	cacheData, err := json.MarshalIndent(ev, "", "  ")
	if err != nil {
		return fmt.Errorf("encode validation evidence: %w", err)
	}
	if err := os.WriteFile(cacheFile, cacheData, 0644); err != nil {
		return fmt.Errorf("write validation evidence: %w", err)
	}
	if snapshotChanged {
		return fmt.Errorf("repository changed during validation; checks cannot be bound to the committed HEAD; restore or commit changes and validate again")
	}
	if repoCfg.ValidationProfile == "python-stdlib" && (ev.Checks["test"].Status != "PASS" || ev.Checks["build"].Status != "PASS") {
		return fmt.Errorf("python-stdlib validation failed: test=%s build=%s; evidence_digest=%s", ev.Checks["test"].Status, ev.Checks["build"].Status, computeEvidenceDigest(ev))
	}
	fmt.Printf("Validation complete. evidence_digest=%s\n", computeEvidenceDigest(ev))
	return nil
}

// Policy travels with the executable, including source builds. Never let the
// caller's working directory select the authority policy.
func resolvePolicyArtifact() (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locate executable: %w", err)
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return "", fmt.Errorf("resolve executable: %w", err)
	}
	directory := filepath.Dir(executable)
	for _, name := range []string{"howlchangeops.hfbc", "changeops.hfbc"} {
		artifact := filepath.Join(directory, name)
		info, err := os.Stat(artifact)
		if err == nil {
			if !info.Mode().IsRegular() {
				return "", fmt.Errorf("policy artifact %q is not a regular file", artifact)
			}
			return artifact, nil
		}
		if !os.IsNotExist(err) {
			return "", fmt.Errorf("inspect policy artifact %q: %w", artifact, err)
		}
	}
	return "", fmt.Errorf("policy artifact missing beside executable in %q: install howlchangeops.hfbc alongside howlchangeops", directory)
}

func invokeHowlFrame(proposalFile string, ev EvidenceEnvelope, rtEv RuntimeEvidence, repoCfg ConfigRepo) (map[string]interface{}, error) {
	if err := checkHowlFrameCompatibility(); err != nil {
		return nil, fmt.Errorf("howlframe runtime compatibility check failed: %w", err)
	}
	policyArtifact, err := resolvePolicyArtifact()
	if err != nil {
		return nil, err
	}
	args := []string{"run", "-allow-caps", "filesystem", policyArtifact, proposalFile}
	args = append(args, fmt.Sprintf("repo=%s", ev.Repo))
	args = append(args, fmt.Sprintf("branch=%s", ev.Branch))
	args = append(args, fmt.Sprintf("revision=%s", ev.Revision))
	args = append(args, fmt.Sprintf("current_revision=%s", rtEv.CurrentRevision))
	args = append(args, fmt.Sprintf("working_tree=%s", rtEv.WorkingTree))

	testStatus := "UNKNOWN"
	if c, ok := ev.Checks["test"]; ok {
		testStatus = c.Status
	}
	buildStatus := "UNKNOWN"
	if c, ok := ev.Checks["build"]; ok {
		buildStatus = c.Status
	}

	args = append(args, fmt.Sprintf("tests=%s", testStatus))
	args = append(args, fmt.Sprintf("build=%s", buildStatus))
	args = append(args, fmt.Sprintf("approved=%s", rtEv.Approved))
	args = append(args, fmt.Sprintf("candidate_exists=%s", rtEv.CandidateExists))
	args = append(args, fmt.Sprintf("allowed_branches=%s", strings.Join(repoCfg.AllowedBranches, ",")))
	args = append(args, fmt.Sprintf("allowed_actions=%s", strings.Join(repoCfg.AllowedActions, ",")))

	// Risk parameters
	args = append(args, fmt.Sprintf("risk_infra=%t", ev.Risk.ContainsInfrastructure))
	args = append(args, fmt.Sprintf("risk_deps=%t", ev.Risk.ContainsDependency))
	args = append(args, fmt.Sprintf("risk_ci=%t", ev.Risk.ContainsCI))

	// Remote parameters
	args = append(args, fmt.Sprintf("remote_head=%s", ev.Remote.RemoteHEAD))
	args = append(args, fmt.Sprintf("current_remote_head=%s", rtEv.RemoteHEAD))
	args = append(args, fmt.Sprintf("local_remote_match=%t", ev.Remote.LocalRemoteMatch))
	args = append(args, fmt.Sprintf("ci_status=%s", ev.Remote.CIStatus))

	cmd := exec.Command(getHowlFrameBin(), args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("howlframe error: %v, out: %s", err, string(out))
	}

	var result map[string]interface{}
	if err := json.Unmarshal(out, &result); err != nil {
		return nil, fmt.Errorf("howlframe output invalid JSON: %v (out: %s)", err, string(out))
	}
	return result, nil
}

func appendAudit(entry map[string]interface{}) {
	entry["timestamp"] = time.Now().UTC().Format(time.RFC3339)
	data, _ := json.Marshal(entry)
	f, _ := os.OpenFile(historyFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	defer f.Close()
	f.Write(data)
	f.WriteString("\n")
}

func main() {
	progName := filepath.Base(os.Args[0])
	if progName != "changeops" && progName != "howlchangeops" {
		progName = "howlchangeops"
	}

	if len(os.Args) < 2 {
		die("failed", "USAGE", "Usage: %s <command> [args...]", progName)
	}

	args, wantJSON := splitJSONFlag(os.Args)
	os.Args = args
	cmd := os.Args[1]
	command = []string{cmd}
	if wantJSON {
		enableJSON()
		if !supportsJSON(cmd) {
			die("failed", "USAGE", "%s", unknownJSONCommand(cmd))
		}
	}

	// interop, version and --version must work with no config or
	// .howlchangeops state directory present -- they are the installer's
	// health and compatibility checks, run against a fresh install before any
	// repo has been configured.
	if cmd == "interop" {
		printInterop()
		return
	}
	if cmd == "version" || cmd == "--version" {
		fmt.Printf("%s %s\n", progName, Version)
		fmt.Printf("compatible HowlFrame: v%s (HFBC format %s)\n", CompatibleHowlFrameVersion, CompatibleHFBCFormat)
		succeed("ok", map[string]any{"version": Version, "compatible_howlframe": CompatibleHowlFrameVersion, "hfbc_format": CompatibleHFBCFormat})
		return
	}
	if cmd == "authority" {
		runAuthority(os.Args[2:])
		return
	}

	initDirs()
	cfg, configDigest, err := loadConfig()
	if err != nil {
		die("unavailable", "CONFIG_UNAVAILABLE", "Error loading config: %v", err)
	}

	// Model B cannot fall back to shared-account terminal/HMAC approval. Until
	// a protected executor, enrollment and replay ledger are deployed, deny both
	// minting approval and executing effects before touching legacy paths.
	if cfg.AuthorizationModel != "" && cfg.AuthorizationModel != "cooperative" && cfg.AuthorizationModel != "model_b" {
		die("blocked", "AUTHORIZATION_MODEL_INVALID", "%s", "Unknown authorization_model; refusing authorization downgrade")
	}
	if cfg.AuthorizationModel == "model_b" {
		if cmd == "approve" {
			die("blocked", "INDEPENDENT_AUTHORIZATION_UNAVAILABLE", "%s", "Model B requires independent owner signing; use 'howlchangeops authority sign' outside the agent session")
		}
		if cmd == "execute" && os.Getenv("HOWLCHANGEOPS_AUTHORITY_LEDGER") == "" {
			die("blocked", "INDEPENDENT_AUTHORIZATION_UNAVAILABLE", "%s", "Model B protected executor is not deployed; terminal confirmation and owner-confirmed flags cannot authorize this operation")
		}
	}

	// Startup pre-flight check for commands that execute or evaluate HowlFrame policy (HOWL-CANON-013)
	switch cmd {
	case "plan", "dogfood", "evaluate", "execute":
		if err := checkHowlFrameCompatibility(); err != nil {
			fmt.Fprintf(os.Stderr, "HOWLFRAME_INCOMPATIBLE: %v\n", err)
			writeResult("unavailable", nil, "HOWLFRAME_INCOMPATIBLE", err.Error())
			os.Exit(1)
		}
	}

	switch cmd {
	case "authority":
		runAuthority(os.Args[2:])
	case "inspect":
		if len(os.Args) < 3 {
			die("failed", "USAGE", "Usage: %s inspect <repo_id>", progName)
		}
		repoID := os.Args[2]
		if err := validateRepoIdentifier(repoID); err != nil {
			die("failed", "UNKNOWN_REPOSITORY", "UNKNOWN_REPOSITORY: %s", repoID)
		}
		repoCfg, ok := cfg.Repos[repoID]
		if !ok {
			die("failed", "UNKNOWN_REPOSITORY", "UNKNOWN_REPOSITORY: %s", repoID)
		}
		ev, rtEv := gatherEvidence(repoID, repoCfg.Path, repoCfg, configDigest)
		fmt.Println("Evidence Envelope:")
		evData, _ := json.MarshalIndent(ev, "", "  ")
		fmt.Println(string(evData))
		fmt.Println("\nRuntime Evidence:")
		rtData, _ := json.MarshalIndent(rtEv, "", "  ")
		fmt.Println(string(rtData))

	case "validate":
		if len(os.Args) < 3 {
			die("failed", "USAGE", "Usage: %s validate <repo_id>", progName)
		}
		repoID := os.Args[2]
		if err := validateRepoIdentifier(repoID); err != nil {
			die("failed", "UNKNOWN_REPOSITORY", "UNKNOWN_REPOSITORY: %s", repoID)
		}
		repoCfg, ok := cfg.Repos[repoID]
		if !ok {
			die("failed", "UNKNOWN_REPOSITORY", "UNKNOWN_REPOSITORY: %s", repoID)
		}
		if err := validate(repoID, repoCfg.Path, repoCfg, configDigest); err != nil {
			fmt.Fprintf(os.Stderr, "VALIDATION_FAILED: %v\n", err)
			os.Exit(1)
		}

	case "plan":
		if len(os.Args) < 3 {
			die("failed", "USAGE", "Usage: %s plan <repo_id>", progName)
		}
		repoID := os.Args[2]
		if err := validateRepoIdentifier(repoID); err != nil {
			die("failed", "UNKNOWN_REPOSITORY", "UNKNOWN_REPOSITORY: %s", repoID)
		}
		repoCfg, ok := cfg.Repos[repoID]
		if !ok {
			die("failed", "UNKNOWN_REPOSITORY", "UNKNOWN_REPOSITORY: %s", repoID)
		}
		ev, rtEv := gatherEvidence(repoID, repoCfg.Path, repoCfg, configDigest)

		actions := []string{
			"create_release_candidate",
			"create_github_draft_release",
			"record_release_ready",
			"rollback_release_candidate",
		}

		tmpProp := filepath.Join(baseDir, "tmp_plan.json")
		defer os.Remove(tmpProp)

		fmt.Printf("Plan for repository: %s (revision: %s)\n", repoID, ev.Revision[:7])
		fmt.Printf("Evidence Identity: %s\n", rtEv.EvidenceDigest[:16])
		if rtEv.EvidenceAge != "" {
			fmt.Printf("Evidence Age: %s\n", rtEv.EvidenceAge)
		}
		fmt.Println()

		for _, act := range actions {
			prop := Proposal{Action: act, Repo: repoID, Reason: "plan simulation"}
			propData, _ := json.Marshal(prop)
			os.WriteFile(tmpProp, propData, 0644)

			res, err := invokeHowlFrame(tmpProp, ev, rtEv, repoCfg)
			if err != nil {
				fmt.Printf("%-30s ERROR — %v\n", act, err)
				continue
			}
			decision := res["decision"].(string)
			reason := res["reason"].(string)
			if decision == "ALLOW" || decision == "REQUIRE_APPROVAL" {
				fmt.Printf("%-30s %s\n", act, decision)
			} else {
				fmt.Printf("%-30s %s — %s\n", act, decision, reason)
			}
		}

	case "dogfood":
		if len(os.Args) < 3 {
			die("failed", "USAGE", "Usage: %s dogfood <repo_id>", progName)
		}
		repoID := os.Args[2]
		if err := validateRepoIdentifier(repoID); err != nil {
			die("failed", "UNKNOWN_REPOSITORY", "UNKNOWN_REPOSITORY: %s", repoID)
		}
		repoCfg, ok := cfg.Repos[repoID]
		if !ok {
			die("failed", "UNKNOWN_REPOSITORY", "UNKNOWN_REPOSITORY: %s", repoID)
		}

		fmt.Println("HowlChangeOps Self-Dogfooding Workflow")
		fmt.Println("--------------------------------------")

		fmt.Printf("1. Identifying trusted repo: %s (%s)\n", repoID, repoCfg.Path)
		fmt.Println("2. Gathering evidence and running validation profile...")
		if err := validate(repoID, repoCfg.Path, repoCfg, configDigest); err != nil {
			fmt.Fprintf(os.Stderr, "VALIDATION_FAILED: %v\n", err)
			os.Exit(1)
		}

		ev, rtEv := gatherEvidence(repoID, repoCfg.Path, repoCfg, configDigest)

		fmt.Printf("3. Proposing release candidate for revision: %s\n", ev.Revision[:7])
		prop := Proposal{
			Action:     "create_release_candidate",
			Repo:       repoID,
			Reason:     "Automated self-dogfooding workflow proposal",
			Confidence: 1.0,
		}

		tmpProp := filepath.Join(baseDir, "tmp_dogfood_proposal.json")
		propData, _ := json.Marshal(prop)
		os.WriteFile(tmpProp, propData, 0644)
		defer os.Remove(tmpProp)

		fmt.Println("4. Evaluating proposal through HowlFrame policy...")
		res, err := invokeHowlFrame(tmpProp, ev, rtEv, repoCfg)
		if err != nil {
			die("failed", "EVALUATION_ERROR", "Evaluation error: %v", err)
		}

		decision := res["decision"].(string)
		reason := res["reason"].(string)

		fmt.Printf("5. Policy Decision: %s\n", decision)
		fmt.Printf("   Reason: %s\n", reason)

		if decision == "REQUIRE_APPROVAL" {
			decisionID := fmt.Sprintf("decision-%x", sha256.Sum256([]byte(fmt.Sprintf("%s-%s-%d", prop.Action, ev.Revision, time.Now().UnixNano()))))[:16]
			fmt.Printf("\nBOUNDARY: Cooperative owner confirmation required; shared-account callers are not independently authenticated.\n")
			fmt.Printf("Use '%s approve %s' to authorize this proposal.\n", progName, decisionID)

			// Save decision
			var gates []Gate
			if g, ok := res["gates"].([]interface{}); ok {
				for _, item := range g {
					if m, ok := item.(map[string]interface{}); ok {
						gates = append(gates, Gate{Name: m["name"].(string), Status: m["status"].(string)})
					}
				}
			}
			dec := Decision{
				ID:              decisionID,
				Proposal:        prop,
				Evidence:        ev,
				RuntimeEvidence: rtEv,
				Gates:           gates,
				Result:          decision,
				Reason:          reason,
			}
			dec.Digest = computeDecisionDigest(dec)
			decData, _ := json.MarshalIndent(dec, "", "  ")
			os.WriteFile(filepath.Join(decisionsDir, dec.ID+".json"), decData, 0644)

			appendAudit(map[string]interface{}{"event": "dogfood", "decision": dec})
		} else {
			fmt.Println("\nBOUNDARY CHECK: Failed to reach REQUIRE_APPROVAL. Is evidence passing?")
		}

	case "evaluate":
		if len(os.Args) < 3 {
			die("failed", "USAGE", "Usage: %s evaluate <proposal.json>", progName)
		}
		proposalFile := os.Args[2]
		propData, err := os.ReadFile(proposalFile)
		if err != nil {
			die("failed", "INVALID_INPUT", "Error reading proposal: %v", err)
		}
		var prop Proposal
		if err := json.Unmarshal(propData, &prop); err != nil {
			die("failed", "INVALID_INPUT", "Error parsing proposal: %v", err)
		}

		if err := validateActionName(prop.Action); err != nil {
			die("denied", "INVALID_ACTION", "%s", "DENY: Invalid proposal action name format")
		}

		if err := validateRepoIdentifier(prop.Repo); err != nil {
			die("failed", "UNKNOWN_REPOSITORY", "UNKNOWN_REPOSITORY: %s", prop.Repo)
		}

		repoCfg, ok := cfg.Repos[prop.Repo]
		if !ok {
			die("failed", "UNKNOWN_REPOSITORY", "UNKNOWN_REPOSITORY: %s", prop.Repo)
		}

		ev, rtEv := gatherEvidence(prop.Repo, repoCfg.Path, repoCfg, configDigest)
		res, err := invokeHowlFrame(proposalFile, ev, rtEv, repoCfg)
		if err != nil {
			die("failed", "EVALUATION_ERROR", "Evaluation error: %v", err)
		}

		decisionID := fmt.Sprintf("decision-%x", sha256.Sum256([]byte(fmt.Sprintf("%s-%s-%d", prop.Action, ev.Revision, time.Now().UnixNano()))))[:16]

		var gates []Gate
		if g, ok := res["gates"].([]interface{}); ok {
			for _, item := range g {
				if m, ok := item.(map[string]interface{}); ok {
					gates = append(gates, Gate{
						Name:   m["name"].(string),
						Status: m["status"].(string),
					})
				}
			}
		}

		dec := Decision{
			ID:              decisionID,
			Proposal:        prop,
			Evidence:        ev,
			RuntimeEvidence: rtEv,
			Gates:           gates,
			Result:          res["decision"].(string),
			Reason:          res["reason"].(string),
		}
		dec.Digest = computeDecisionDigest(dec)

		fmt.Printf("Decision: %s\nReason: %s\n", dec.Result, dec.Reason)

		saved := false
		if dec.Result == "REQUIRE_APPROVAL" {
			decData, _ := json.MarshalIndent(dec, "", "  ")
			os.WriteFile(filepath.Join(decisionsDir, dec.ID+".json"), decData, 0644)
			fmt.Printf("Decision saved as %s. Use '%s approve %s' to approve.\n", dec.ID, progName, dec.ID)
			saved = true
		}

		appendAudit(map[string]interface{}{
			"event":    "evaluate",
			"decision": dec,
		})
		succeed(verdictStatus(dec.Result), map[string]any{
			"decision_id":     dec.ID,
			"decision_saved":  saved,
			"verdict":         dec.Result,
			"reason":          dec.Reason,
			"gates":           gatesData(dec.Gates),
			"action":          prop.Action,
			"repo":            prop.Repo,
			"revision":        ev.Revision,
			"decision_digest": dec.Digest,
			"evidence_digest": rtEv.EvidenceDigest,
		})

	case "approve":
		if len(os.Args) < 3 {
			die("failed", "USAGE", "Usage: %s approve <decision_id>", progName)
		}
		decID := os.Args[2]
		decFile := filepath.Join(decisionsDir, decID+".json")
		decData, err := os.ReadFile(decFile)
		if err != nil {
			die("failed", "DECISION_NOT_FOUND", "Decision not found: %v", err)
		}
		var dec Decision
		json.Unmarshal(decData, &dec)
		if dec.Digest != computeDecisionDigest(dec) {
			die("denied", "DECISION_MODIFIED", "%s", "Decision modified")
		}

		key := getApprovalKey()
		if key == nil {
			die("blocked", "APPROVAL_KEY_MISSING", "%s", "DENIED: HOWLCHANGEOPS_APPROVAL_KEY_FILE / CHANGEOPS_APPROVAL_KEY_FILE not set or invalid")
		}

		// Legacy cooperative confirmation records a caller assertion only.
		// Neither a terminal nor --owner-confirmed authenticates a human against
		// same-account agents. This path is unavailable in model_b mode.
		opts := parseApproveFlags(os.Args[3:])
		confirmation := "owner_relayed"
		if !opts.ownerConfirmed {
			if !stdinIsTerminal() {
				die("blocked", "OWNER_CONFIRMATION_REQUIRED", "DENIED: approving %s is the owner's decision; run `%s approve %s` at a terminal, or pass --owner-confirmed only to relay a decision the owner gave", decID, progName, decID)
			}
			fmt.Fprintf(os.Stderr, "Approve %s on %s at %.12s (decision %s)? [y/N] ", dec.Proposal.Action, dec.Proposal.Repo, dec.Evidence.Revision, decID)
			if !confirmAtTerminal(os.Stdin) {
				die("denied", "NOT_CONFIRMED", "Decision %s was not approved.", decID)
			}
			confirmation = "terminal"
		}

		now := time.Now().UTC()
		app := Approval{
			AuthorizationGuarantee: "cooperative_confirmation_only",
			Schema:                 "howlchangeops.approval/v1",
			ApprovalID:             fmt.Sprintf("app-%x", sha256.Sum256([]byte(fmt.Sprintf("%s-%d", dec.ID, now.UnixNano()))))[:16],
			DecisionID:             dec.ID,
			DecisionDigest:         dec.Digest,
			EvidenceDigest:         dec.RuntimeEvidence.EvidenceDigest,
			Repo:                   dec.Proposal.Repo,
			Action:                 dec.Proposal.Action,
			Revision:               dec.Evidence.Revision,
			Approver:               approverName(opts.approver),
			Confirmation:           confirmation,
			IssuedAt:               now.Format(time.RFC3339),
			ExpiresAt:              now.Add(30 * time.Minute).Format(time.RFC3339),
			Nonce:                  fmt.Sprintf("%d", now.UnixNano()),
		}
		app.Signature = signApproval(app, key)

		appData, _ := json.MarshalIndent(app, "", "  ")
		appFile := filepath.Join(approvalsDir, dec.ID+".json")
		os.WriteFile(appFile, appData, 0644)

		fmt.Printf("Decision %s approved.\n", decID)
		appendAudit(map[string]interface{}{
			"event":                   "approve",
			"authorization_guarantee": "cooperative_confirmation_only",
			"decision_id":             decID,
			"approval_id":             app.ApprovalID,
		})
		succeed("ok", map[string]any{
			"decision_id":             decID,
			"approval_id":             app.ApprovalID,
			"approver":                app.Approver,
			"confirmation":            app.Confirmation,
			"authorization_guarantee": "cooperative_confirmation_only",
			"expires_at":              app.ExpiresAt,
		})

	case "execute":
		if len(os.Args) < 3 {
			die("failed", "USAGE", "Usage: %s execute <decision_id>", progName)
		}
		decID := os.Args[2]
		decFile := filepath.Join(decisionsDir, decID+".json")
		decData, err := os.ReadFile(decFile)
		if err != nil {
			die("failed", "DECISION_NOT_FOUND", "Decision not found: %v", err)
		}
		var dec Decision
		json.Unmarshal(decData, &dec)
		if dec.Digest != computeDecisionDigest(dec) {
			die("denied", "DECISION_MODIFIED", "%s", "DENIED: Decision modified")
		}

		if cfg.AuthorizationModel == "model_b" {
			executeModelB(dec, cfg)
			return
		}

		// Replay protection - check existing receipts
		receiptFile := filepath.Join(receiptsDir, decID+".json")
		if recData, err := os.ReadFile(receiptFile); err == nil {
			var prevRec ExecutionReceipt
			if json.Unmarshal(recData, &prevRec) == nil {
				if prevRec.Verification == "PASS" {
					die("denied", "ALREADY_EXECUTED", "%s", "DENIED: Decision already executed successfully")
				}
				die("denied", "ALREADY_EXECUTED", "DENIED: Decision previously failed execution with verification %s (rollback: %s)", prevRec.Verification, prevRec.RollbackStatus)
			}
			die("denied", "ALREADY_EXECUTED", "%s", "DENIED: Decision already executed")
		}

		repoCfg, ok := cfg.Repos[dec.Proposal.Repo]
		if !ok {
			die("failed", "UNKNOWN_REPOSITORY", "UNKNOWN_REPOSITORY: %s", dec.Proposal.Repo)
		}

		// Gather current evidence to check for staleness
		_, rtEv := gatherEvidence(dec.Proposal.Repo, repoCfg.Path, repoCfg, configDigest)

		key := getApprovalKey()
		if key == nil {
			die("blocked", "APPROVAL_KEY_MISSING", "%s", "DENIED: HOWLCHANGEOPS_APPROVAL_KEY_FILE / CHANGEOPS_APPROVAL_KEY_FILE not set")
		}

		// Check for valid approval
		var app Approval
		appFile := filepath.Join(approvalsDir, decID+".json")
		if appData, err := os.ReadFile(appFile); err == nil {
			json.Unmarshal(appData, &app)
			if app.Signature == signApproval(app, key) && app.DecisionDigest == dec.Digest {
				exp, _ := time.Parse(time.RFC3339, app.ExpiresAt)
				if time.Now().UTC().Before(exp) {
					rtEv.Approved = "true"
				} else {
					die("denied", "APPROVAL_EXPIRED", "%s", "DENIED: Approval expired")
				}
			} else {
				die("denied", "APPROVAL_INVALID", "%s", "DENIED: Approval integrity invalid")
			}
		}

		// Write proposal back to a temp file for HowlFrame
		tmpProp := filepath.Join(baseDir, "tmp_proposal.json")
		propData, _ := json.Marshal(dec.Proposal)
		os.WriteFile(tmpProp, propData, 0644)
		defer os.Remove(tmpProp)

		res, err := invokeHowlFrame(tmpProp, dec.Evidence, rtEv, repoCfg)
		if err != nil {
			die("failed", "EVALUATION_ERROR", "Execution evaluation error: %v", err)
		}

		if res["decision"].(string) != "ALLOW" {
			fmt.Printf("Execution DENIED: %s. Reason: %s\n", res["decision"], res["reason"])
			code := "DENIED"
			if strings.Contains(res["reason"].(string), "STALE_REMOTE_EVIDENCE") {
				fmt.Println("STALE_REMOTE_EVIDENCE")
				code = "STALE_REMOTE_EVIDENCE"
			} else if strings.Contains(res["reason"].(string), "STALE_EVIDENCE") {
				fmt.Println("STALE_EVIDENCE")
				code = "STALE_EVIDENCE"
			}
			status := "denied"
			if res["decision"] == "REQUIRE_APPROVAL" {
				status = "awaiting_human"
			}
			writeResult(status, map[string]any{"decision_id": decID, "verdict": res["decision"]}, code, fmt.Sprint(res["reason"]))
			os.Exit(1)
		}

		// Perform bounded action with post-action verification and rollback recovery
		fmt.Printf("Executing action: %s\n", dec.Proposal.Action)
		success := false
		verificationPassed := false
		rollbackStatus := "NOT_NEEDED"
		var execErr error

		if dec.Proposal.Action == "create_release_candidate" {
			tag := fmt.Sprintf("howlchangeops/rc-%s", rtEv.CurrentRevision[:7])
			out, err := gitCommand(repoCfg.Path, "tag", "-a", tag, "-m", "HowlChangeOps RC", rtEv.CurrentRevision)
			if err != nil {
				execErr = fmt.Errorf("failed to create RC tag: %w (%s)", err, out)
				fmt.Println(execErr)
			} else {
				fmt.Printf("Created tag: %s\n", tag)
				verifyTag, _ := gitCommand(repoCfg.Path, "tag", "-l", tag)
				tagRev, _ := gitCommand(repoCfg.Path, "rev-parse", "-q", "--verify", fmt.Sprintf("refs/tags/%s^{commit}", tag))
				if verifyTag == tag && strings.HasPrefix(tagRev, rtEv.CurrentRevision[:7]) {
					fmt.Println("Verified: tag created successfully.")
					verificationPassed = true
					success = true
				} else {
					execErr = fmt.Errorf("verification failed: tag verification mismatch (expected %s on rev %s, got tag=%q rev=%q)", tag, rtEv.CurrentRevision[:7], verifyTag, tagRev)
					fmt.Println(execErr)
					// Automated rollback
					fmt.Printf("Initiating automated rollback for %s...\n", tag)
					rbOut, rbErr := gitCommand(repoCfg.Path, "tag", "-d", tag)
					if rbErr == nil {
						rbVerify, _ := gitCommand(repoCfg.Path, "tag", "-l", tag)
						if rbVerify == "" {
							fmt.Println("Rollback succeeded: invalid tag removed.")
							rollbackStatus = "EXECUTED"
						} else {
							fmt.Printf("Rollback verification failed: tag %s still present\n", tag)
							rollbackStatus = "FAILED"
						}
					} else {
						fmt.Printf("Rollback failed: %v (%s)\n", rbErr, rbOut)
						rollbackStatus = "FAILED"
					}
				}
			}
		} else if dec.Proposal.Action == "create_github_draft_release" {
			tag := fmt.Sprintf("howlchangeops/rc-%s", rtEv.CurrentRevision[:7])
			out, err := runGH(repoCfg.Path, "release", "create", tag, "--target", rtEv.CurrentRevision, "--draft", "--title", "Release Candidate "+tag, "--notes", "Automated RC via HowlChangeOps")
			if err != nil {
				execErr = fmt.Errorf("failed to create GitHub release: %w (%s)", err, out)
				fmt.Println(execErr)
			} else {
				fmt.Printf("Created GitHub release: %s\n", tag)
				verify, _ := runGH(repoCfg.Path, "release", "view", tag)
				if verify != "" && !strings.Contains(verify, "release not found") {
					fmt.Println("Verified: GitHub release created successfully.")
					verificationPassed = true
					success = true
				} else {
					execErr = fmt.Errorf("verification failed: GitHub release not found")
					fmt.Println(execErr)
					// Automated rollback
					fmt.Printf("Initiating automated rollback for release %s...\n", tag)
					rbOut, rbErr := runGH(repoCfg.Path, "release", "delete", tag, "-y")
					if rbErr == nil {
						fmt.Println("Rollback succeeded: draft release deleted.")
						rollbackStatus = "EXECUTED"
					} else {
						fmt.Printf("Rollback failed: %v (%s)\n", rbErr, rbOut)
						rollbackStatus = "FAILED"
					}
				}
			}
		} else if dec.Proposal.Action == "record_release_ready" {
			fmt.Println("Recorded release ready.")
			verificationPassed = true
			success = true
		} else if dec.Proposal.Action == "rollback_release_candidate" {
			tag := fmt.Sprintf("howlchangeops/rc-%s", rtEv.CurrentRevision[:7])
			tagCheck, _ := gitCommand(repoCfg.Path, "tag", "-l", tag)
			if tagCheck == "" {
				// Fallback to legacy tag format
				tag = fmt.Sprintf("changeops/rc-%s", rtEv.CurrentRevision[:7])
			}
			out, err := gitCommand(repoCfg.Path, "tag", "-d", tag)
			if err != nil {
				execErr = fmt.Errorf("failed to rollback RC tag: %w (%s)", err, out)
				fmt.Println(execErr)
			} else {
				fmt.Printf("Rolled back tag: %s\n", tag)
				tags, _ := gitCommand(repoCfg.Path, "tag", "-l", tag)
				if tags == "" {
					fmt.Println("Verified: tag removed.")
					verificationPassed = true
					success = true
					rollbackStatus = "EXECUTED"
				} else {
					execErr = fmt.Errorf("verification failed: tag still exists after rollback")
					fmt.Println(execErr)
					rollbackStatus = "FAILED"
				}
			}
		} else {
			execErr = fmt.Errorf("action not allowed: %s", dec.Proposal.Action)
			fmt.Printf("ACTION_NOT_ALLOWED: %s\n", dec.Proposal.Action)
		}

		// Always record an immutable ExecutionReceipt to prevent replay and capture audit truth
		verStatus := "FAIL"
		if verificationPassed {
			verStatus = "PASS"
		}
		errMsg := ""
		if execErr != nil {
			errMsg = execErr.Error()
		}

		receipt := ExecutionReceipt{
			AuthorizationGuarantee: "cooperative_confirmation_only",
			Schema:                 "howlchangeops.execution_receipt/v1",
			DecisionID:             decID,
			ApprovalID:             app.ApprovalID,
			Action:                 dec.Proposal.Action,
			Repo:                   dec.Proposal.Repo,
			Revision:               rtEv.CurrentRevision,
			ExecutedAt:             time.Now().UTC().Format(time.RFC3339),
			Verification:           verStatus,
			RollbackStatus:         rollbackStatus,
			ErrorMessage:           errMsg,
		}
		recData, _ := json.MarshalIndent(receipt, "", "  ")
		os.WriteFile(filepath.Join(receiptsDir, decID+".json"), recData, 0644)

		appendAudit(map[string]interface{}{
			"event":                   "execute",
			"authorization_guarantee": "cooperative_confirmation_only",
			"decision_id":             decID,
			"action":                  dec.Proposal.Action,
			"success":                 success,
			"verification":            verStatus,
			"rollback_status":         rollbackStatus,
			"error":                   errMsg,
		})

		execData := map[string]any{
			"authorization_guarantee": "cooperative_confirmation_only",
			"decision_id":             decID,
			"approval_id":             app.ApprovalID,
			"action":                  dec.Proposal.Action,
			"repo":                    dec.Proposal.Repo,
			"revision":                rtEv.CurrentRevision,
			"verification":            verStatus,
			"rollback_status":         rollbackStatus,
			"receipt_schema":          receipt.Schema,
		}
		if !success {
			writeResult("failed", execData, "EXECUTION_FAILED", errMsg)
			os.Exit(1)
		}
		succeed("ok", execData)

	case "rollback":
		if len(os.Args) < 3 {
			die("failed", "USAGE", "Usage: %s rollback <decision_id>", progName)
		}
		decID := os.Args[2]
		decFile := filepath.Join(decisionsDir, decID+".json")
		decData, err := os.ReadFile(decFile)
		if err != nil {
			die("failed", "DECISION_NOT_FOUND", "Decision not found: %v", err)
		}
		var dec Decision
		if err := json.Unmarshal(decData, &dec); err != nil {
			die("failed", "INVALID_INPUT", "Error parsing decision: %v", err)
		}

		// Verify that this decision was previously executed
		receiptFile := filepath.Join(receiptsDir, decID+".json")
		recData, err := os.ReadFile(receiptFile)
		if err != nil {
			die("blocked", "ROLLBACK_NOT_APPLICABLE", "Cannot rollback: decision %s has not been executed.", decID)
		}
		var rec ExecutionReceipt
		json.Unmarshal(recData, &rec)
		if rec.Verification != "PASS" {
			die("blocked", "ROLLBACK_NOT_APPLICABLE", "Cannot rollback: decision %s did not successfully complete execution.", decID)
		}

		if dec.Proposal.Action != "create_release_candidate" {
			die("blocked", "ROLLBACK_NOT_APPLICABLE", "Rollback only applies to create_release_candidate decisions (found: %s).", dec.Proposal.Action)
		}

		repoCfg, ok := cfg.Repos[dec.Proposal.Repo]
		if !ok {
			die("failed", "UNKNOWN_REPOSITORY", "UNKNOWN_REPOSITORY: %s", dec.Proposal.Repo)
		}

		tag := fmt.Sprintf("howlchangeops/rc-%s", dec.Evidence.Revision[:7])
		tagCheck, _ := gitCommand(repoCfg.Path, "tag", "-l", tag)
		if tagCheck == "" {
			tag = fmt.Sprintf("changeops/rc-%s", dec.Evidence.Revision[:7])
			tagCheck, _ = gitCommand(repoCfg.Path, "tag", "-l", tag)
		}
		if tagCheck == "" {
			die("blocked", "ROLLBACK_NOT_APPLICABLE", "Candidate tag %s does not exist; nothing to rollback.", tag)
		}

		rbProp := Proposal{
			Action:     "rollback_release_candidate",
			Repo:       dec.Proposal.Repo,
			Reason:     fmt.Sprintf("Rollback executed decision %s", decID),
			Confidence: 1.0,
		}

		tmpProp := filepath.Join(baseDir, "tmp_rollback_proposal.json")
		propData, _ := json.Marshal(rbProp)
		os.WriteFile(tmpProp, propData, 0644)
		defer os.Remove(tmpProp)

		ev, rtEv := gatherEvidence(dec.Proposal.Repo, repoCfg.Path, repoCfg, configDigest)
		res, err := invokeHowlFrame(tmpProp, ev, rtEv, repoCfg)
		if err != nil {
			die("failed", "EVALUATION_ERROR", "Rollback evaluation error: %v", err)
		}

		rbDecID := fmt.Sprintf("decision-%x", sha256.Sum256([]byte(fmt.Sprintf("%s-%s-%d", rbProp.Action, ev.Revision, time.Now().UnixNano()))))[:16]
		var gates []Gate
		if g, ok := res["gates"].([]interface{}); ok {
			for _, item := range g {
				if m, ok := item.(map[string]interface{}); ok {
					gates = append(gates, Gate{
						Name:   m["name"].(string),
						Status: m["status"].(string),
					})
				}
			}
		}

		rbDec := Decision{
			ID:              rbDecID,
			Proposal:        rbProp,
			Evidence:        ev,
			RuntimeEvidence: rtEv,
			Gates:           gates,
			Result:          res["decision"].(string),
			Reason:          res["reason"].(string),
		}
		rbDec.Digest = computeDecisionDigest(rbDec)

		fmt.Printf("Rollback Decision: %s\nReason: %s\n", rbDec.Result, rbDec.Reason)
		if rbDec.Result == "REQUIRE_APPROVAL" {
			decData, _ := json.MarshalIndent(rbDec, "", "  ")
			os.WriteFile(filepath.Join(decisionsDir, rbDec.ID+".json"), decData, 0644)
			fmt.Printf("Rollback decision saved as %s. Use '%s approve %s' then '%s execute %s' to apply rollback.\n", rbDec.ID, progName, rbDec.ID, progName, rbDec.ID)
		} else if rbDec.Result == "DENY" {
			die("denied", "DENIED", "Rollback denied by policy: %s", rbDec.Reason)
		}

		appendAudit(map[string]interface{}{
			"event":             "rollback_propose",
			"target_decision":   decID,
			"rollback_decision": rbDec,
		})
		succeed(verdictStatus(rbDec.Result), map[string]any{
			"target_decision_id": decID,
			"decision_id":        rbDec.ID,
			"decision_saved":     rbDec.Result == "REQUIRE_APPROVAL",
			"verdict":            rbDec.Result,
			"reason":             rbDec.Reason,
			"gates":              gatesData(rbDec.Gates),
		})

	case "history":
		data, err := os.ReadFile(historyFile)
		if err != nil {
			fmt.Println("No history found.")
			succeed("ok", map[string]any{"entries": []any{}})
			return
		}
		fmt.Println(string(data))
		entries := []any{}
		for _, line := range strings.Split(string(data), "\n") {
			var entry any
			if strings.TrimSpace(line) != "" && json.Unmarshal([]byte(line), &entry) == nil {
				entries = append(entries, entry)
			}
		}
		succeed("ok", map[string]any{"entries": entries})

	case "explain":
		if len(os.Args) < 3 {
			die("failed", "USAGE", "Usage: %s explain <decision_id>", progName)
		}
		decID := os.Args[2]
		decFile := filepath.Join(decisionsDir, decID+".json")
		decData, err := os.ReadFile(decFile)
		if err != nil {
			die("failed", "DECISION_NOT_FOUND", "Decision not found: %v", err)
		}
		var dec Decision
		json.Unmarshal(decData, &dec)

		fmt.Printf("Decision: %s\nAction: %s\nRepo: %s\nRevision: %s\n\nGates:\n", dec.Result, dec.Proposal.Action, dec.Proposal.Repo, dec.Evidence.Revision)
		for _, g := range dec.Gates {
			fmt.Printf("  - %s: %s\n", g.Name, g.Status)
		}
		fmt.Printf("\nReason: %s\n", dec.Reason)

		receiptFile := filepath.Join(receiptsDir, decID+".json")
		var receipt *ExecutionReceipt
		defer func() { succeed("ok", map[string]any{"decision": dec, "receipt": receipt}) }()
		if recData, err := os.ReadFile(receiptFile); err == nil {
			var rec ExecutionReceipt
			if json.Unmarshal(recData, &rec) == nil {
				receipt = &rec
				fmt.Printf("\nExecution Receipt:\n")
				fmt.Printf("  - Executed At: %s\n", rec.ExecutedAt)
				fmt.Printf("  - Verification: %s\n", rec.Verification)
				if rec.RollbackStatus != "" {
					fmt.Printf("  - Rollback Status: %s\n", rec.RollbackStatus)
				}
				if rec.ErrorMessage != "" {
					fmt.Printf("  - Error: %s\n", rec.ErrorMessage)
				}
			}
		}

	default:
		die("failed", "UNKNOWN_COMMAND", "Unknown command: %s", cmd)
	}
}
