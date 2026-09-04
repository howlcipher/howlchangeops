package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Version is HowlChangeOps's own release version. Bumped alongside each
// tagged release; not derived from git state at build time.
const Version = "0.1.0"

// CompatibleHowlFrameVersion is the HowlFrame release this build's
// compiled policy (howlchangeops.hfbc) was built and verified against.
// HowlChangeOps consumes HowlFrame entirely through its public CLI, so
// this is a documented compatibility pin, not an enforced runtime check.
const CompatibleHowlFrameVersion = "0.1.0"

type ConfigRepo struct {
	Path              string   `json:"path"`
	AllowedBranches   []string `json:"allowed_branches"`
	ValidationProfile string   `json:"validation_profile"`
	AllowedActions    []string `json:"allowed_actions"`
}

type Config struct {
	Repos map[string]ConfigRepo `json:"repos"`
}

type Proposal struct {
	Action     string  `json:"action"`
	Repo       string  `json:"repo"`
	Reason     string  `json:"reason"`
	Confidence float64 `json:"confidence"`
}

type ValidationResult struct {
	Name         string `json:"name"`
	Status       string `json:"status"`
	StartedAt    string `json:"started_at"`
	FinishedAt   string `json:"finished_at"`
	ExitCode     int    `json:"exit_code"`
	Profile      string `json:"profile"`
	Revision     string `json:"revision"`
	OutputDigest string `json:"output_digest"`
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
	Schema         string `json:"schema"`
	ApprovalID     string `json:"approval_id"`
	DecisionID     string `json:"decision_id"`
	DecisionDigest string `json:"decision_digest"`
	EvidenceDigest string `json:"evidence_digest"`
	Repo           string `json:"repo"`
	Action         string `json:"action"`
	Revision       string `json:"revision"`
	Approver       string `json:"approver"`
	IssuedAt       string `json:"issued_at"`
	ExpiresAt      string `json:"expires_at"`
	Nonce          string `json:"nonce"`
	Signature      string `json:"signature"`
}

type ExecutionReceipt struct {
	Schema         string `json:"schema"`
	DecisionID     string `json:"decision_id"`
	ApprovalID     string `json:"approval_id"`
	Action         string `json:"action"`
	Repo           string `json:"repo"`
	Revision       string `json:"revision"`
	ExecutedAt     string `json:"executed_at"`
	Verification   string `json:"verification"`
	RollbackStatus string `json:"rollback_status,omitempty"`
	ErrorMessage   string `json:"error_message,omitempty"`
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
	configFile := "config/howlchangeops-config.json"
	data, err := os.ReadFile(configFile)
	if err != nil {
		configFile = "config/changeops-config.json"
		data, err = os.ReadFile(configFile)
		if err != nil {
			return nil, "", err
		}
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
	return fmt.Sprintf("schema:%s|approval_id:%s|decision_id:%s|decision_digest:%s|evidence_digest:%s|repo:%s|action:%s|revision:%s|approver:%s|issued_at:%s|expires_at:%s|nonce:%s",
		a.Schema, a.ApprovalID, a.DecisionID, a.DecisionDigest, a.EvidenceDigest, a.Repo, a.Action, a.Revision, a.Approver, a.IssuedAt, a.ExpiresAt, a.Nonce)
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
			if cachedEv.Revision == rev && cachedEv.ConfigDigest == configDigest && cachedEv.ValidationProfile == repoCfg.ValidationProfile {
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

func validate(repoID string, repoPath string, repoCfg ConfigRepo, configDigest string) {
	ev, _ := gatherEvidence(repoID, repoPath, repoCfg, configDigest)
	ev.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
	ev.Checks = make(map[string]ValidationResult)

	if repoCfg.ValidationProfile == "go" {
		fmt.Println("Running go test ./...")
		ev.Checks["test"] = runValidationCommand("go_test", repoPath, "go", "test", "./...")

		fmt.Println("Running go build ./...")
		ev.Checks["build"] = runValidationCommand("go_build", repoPath, "go", "build", "./...")
	} else {
		fmt.Printf("Unknown profile: %s\n", repoCfg.ValidationProfile)
	}

	wtStatus := "FAIL"
	if ev.WorkingTree == "clean" {
		wtStatus = "PASS"
	}
	ev.Checks["working_tree"] = ValidationResult{
		Name:       "working_tree",
		Status:     wtStatus,
		StartedAt:  time.Now().UTC().Format(time.RFC3339),
		FinishedAt: time.Now().UTC().Format(time.RFC3339),
		ExitCode:   0,
	}

	os.MkdirAll(baseDir, 0755)
	cacheKey := fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s|%s", repoID, ev.Revision, repoCfg.ValidationProfile, configDigest))))
	cacheFile := filepath.Join(baseDir, fmt.Sprintf("evidence_%s.json", cacheKey))
	cacheData, _ := json.MarshalIndent(ev, "", "  ")
	os.WriteFile(cacheFile, cacheData, 0644)
	fmt.Printf("Validation complete. evidence_digest=%s\n", computeEvidenceDigest(ev))
}

func invokeHowlFrame(proposalFile string, ev EvidenceEnvelope, rtEv RuntimeEvidence, repoCfg ConfigRepo) (map[string]interface{}, error) {
	policyArtifact := "howlchangeops.hfbc"
	if _, err := os.Stat(policyArtifact); err != nil {
		policyArtifact = "changeops.hfbc"
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

	cmd := exec.Command("howlframe", args...)
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
		fmt.Printf("Usage: %s <command> [args...]\n", progName)
		os.Exit(1)
	}

	// version/--version must work with no config or .howlchangeops state
	// directory present -- it's the installer's health/version check, run
	// against a fresh install before any repo has been configured.
	if os.Args[1] == "version" || os.Args[1] == "--version" {
		fmt.Printf("%s %s\n", progName, Version)
		fmt.Printf("compatible HowlFrame: v%s\n", CompatibleHowlFrameVersion)
		return
	}

	initDirs()
	cfg, configDigest, err := loadConfig()
	if err != nil {
		fmt.Printf("Error loading config: %v\n", err)
		os.Exit(1)
	}

	cmd := os.Args[1]

	switch cmd {
	case "inspect":
		if len(os.Args) < 3 {
			fmt.Printf("Usage: %s inspect <repo_id>\n", progName)
			os.Exit(1)
		}
		repoID := os.Args[2]
		if err := validateRepoIdentifier(repoID); err != nil {
			fmt.Printf("UNKNOWN_REPOSITORY: %s\n", repoID)
			os.Exit(1)
		}
		repoCfg, ok := cfg.Repos[repoID]
		if !ok {
			fmt.Printf("UNKNOWN_REPOSITORY: %s\n", repoID)
			os.Exit(1)
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
			fmt.Printf("Usage: %s validate <repo_id>\n", progName)
			os.Exit(1)
		}
		repoID := os.Args[2]
		if err := validateRepoIdentifier(repoID); err != nil {
			fmt.Printf("UNKNOWN_REPOSITORY: %s\n", repoID)
			os.Exit(1)
		}
		repoCfg, ok := cfg.Repos[repoID]
		if !ok {
			fmt.Printf("UNKNOWN_REPOSITORY: %s\n", repoID)
			os.Exit(1)
		}
		validate(repoID, repoCfg.Path, repoCfg, configDigest)

	case "plan":
		if len(os.Args) < 3 {
			fmt.Printf("Usage: %s plan <repo_id>\n", progName)
			os.Exit(1)
		}
		repoID := os.Args[2]
		if err := validateRepoIdentifier(repoID); err != nil {
			fmt.Printf("UNKNOWN_REPOSITORY: %s\n", repoID)
			os.Exit(1)
		}
		repoCfg, ok := cfg.Repos[repoID]
		if !ok {
			fmt.Printf("UNKNOWN_REPOSITORY: %s\n", repoID)
			os.Exit(1)
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
			fmt.Printf("Usage: %s dogfood <repo_id>\n", progName)
			os.Exit(1)
		}
		repoID := os.Args[2]
		if err := validateRepoIdentifier(repoID); err != nil {
			fmt.Printf("UNKNOWN_REPOSITORY: %s\n", repoID)
			os.Exit(1)
		}
		repoCfg, ok := cfg.Repos[repoID]
		if !ok {
			fmt.Printf("UNKNOWN_REPOSITORY: %s\n", repoID)
			os.Exit(1)
		}

		fmt.Println("HowlChangeOps Self-Dogfooding Workflow")
		fmt.Println("--------------------------------------")

		fmt.Printf("1. Identifying trusted repo: %s (%s)\n", repoID, repoCfg.Path)
		fmt.Println("2. Gathering evidence and running validation profile...")
		validate(repoID, repoCfg.Path, repoCfg, configDigest)

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
			fmt.Printf("Evaluation error: %v\n", err)
			os.Exit(1)
		}

		decision := res["decision"].(string)
		reason := res["reason"].(string)

		fmt.Printf("5. Policy Decision: %s\n", decision)
		fmt.Printf("   Reason: %s\n", reason)

		if decision == "REQUIRE_APPROVAL" {
			decisionID := fmt.Sprintf("decision-%x", sha256.Sum256([]byte(fmt.Sprintf("%s-%s-%d", prop.Action, ev.Revision, time.Now().UnixNano()))))[:16]
			fmt.Printf("\nBOUNDARY: Human approval required. Cannot silently self-approve.\n")
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
			fmt.Printf("Usage: %s evaluate <proposal.json>\n", progName)
			os.Exit(1)
		}
		proposalFile := os.Args[2]
		propData, err := os.ReadFile(proposalFile)
		if err != nil {
			fmt.Printf("Error reading proposal: %v\n", err)
			os.Exit(1)
		}
		var prop Proposal
		if err := json.Unmarshal(propData, &prop); err != nil {
			fmt.Printf("Error parsing proposal: %v\n", err)
			os.Exit(1)
		}

		if err := validateActionName(prop.Action); err != nil {
			fmt.Println("DENY: Invalid proposal action name format")
			os.Exit(1)
		}

		if err := validateRepoIdentifier(prop.Repo); err != nil {
			fmt.Printf("UNKNOWN_REPOSITORY: %s\n", prop.Repo)
			os.Exit(1)
		}

		repoCfg, ok := cfg.Repos[prop.Repo]
		if !ok {
			fmt.Printf("UNKNOWN_REPOSITORY: %s\n", prop.Repo)
			os.Exit(1)
		}

		ev, rtEv := gatherEvidence(prop.Repo, repoCfg.Path, repoCfg, configDigest)
		res, err := invokeHowlFrame(proposalFile, ev, rtEv, repoCfg)
		if err != nil {
			fmt.Printf("Evaluation error: %v\n", err)
			os.Exit(1)
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

		if dec.Result == "REQUIRE_APPROVAL" {
			decData, _ := json.MarshalIndent(dec, "", "  ")
			os.WriteFile(filepath.Join(decisionsDir, dec.ID+".json"), decData, 0644)
			fmt.Printf("Decision saved as %s. Use '%s approve %s' to approve.\n", dec.ID, progName, dec.ID)
		}

		appendAudit(map[string]interface{}{
			"event":    "evaluate",
			"decision": dec,
		})

	case "approve":
		if len(os.Args) < 3 {
			fmt.Printf("Usage: %s approve <decision_id>\n", progName)
			os.Exit(1)
		}
		decID := os.Args[2]
		decFile := filepath.Join(decisionsDir, decID+".json")
		decData, err := os.ReadFile(decFile)
		if err != nil {
			fmt.Printf("Decision not found: %v\n", err)
			os.Exit(1)
		}
		var dec Decision
		json.Unmarshal(decData, &dec)
		if dec.Digest != computeDecisionDigest(dec) {
			fmt.Println("Decision modified")
			os.Exit(1)
		}

		key := getApprovalKey()
		if key == nil {
			fmt.Println("DENIED: HOWLCHANGEOPS_APPROVAL_KEY_FILE / CHANGEOPS_APPROVAL_KEY_FILE not set or invalid")
			os.Exit(1)
		}

		now := time.Now().UTC()
		app := Approval{
			Schema:         "howlchangeops.approval/v1",
			ApprovalID:     fmt.Sprintf("app-%x", sha256.Sum256([]byte(fmt.Sprintf("%s-%d", dec.ID, now.UnixNano()))))[:16],
			DecisionID:     dec.ID,
			DecisionDigest: dec.Digest,
			EvidenceDigest: dec.RuntimeEvidence.EvidenceDigest,
			Repo:           dec.Proposal.Repo,
			Action:         dec.Proposal.Action,
			Revision:       dec.Evidence.Revision,
			Approver:       "admin", // TODO: read from authenticated context
			IssuedAt:       now.Format(time.RFC3339),
			ExpiresAt:      now.Add(30 * time.Minute).Format(time.RFC3339),
			Nonce:          fmt.Sprintf("%d", now.UnixNano()),
		}
		app.Signature = signApproval(app, key)

		appData, _ := json.MarshalIndent(app, "", "  ")
		appFile := filepath.Join(approvalsDir, dec.ID+".json")
		os.WriteFile(appFile, appData, 0644)

		fmt.Printf("Decision %s approved.\n", decID)
		appendAudit(map[string]interface{}{
			"event":       "approve",
			"decision_id": decID,
			"approval_id": app.ApprovalID,
		})

	case "execute":
		if len(os.Args) < 3 {
			fmt.Printf("Usage: %s execute <decision_id>\n", progName)
			os.Exit(1)
		}
		decID := os.Args[2]
		decFile := filepath.Join(decisionsDir, decID+".json")
		decData, err := os.ReadFile(decFile)
		if err != nil {
			fmt.Printf("Decision not found: %v\n", err)
			os.Exit(1)
		}
		var dec Decision
		json.Unmarshal(decData, &dec)
		if dec.Digest != computeDecisionDigest(dec) {
			fmt.Println("DENIED: Decision modified")
			os.Exit(1)
		}

		// Replay protection - check existing receipts
		receiptFile := filepath.Join(receiptsDir, decID+".json")
		if recData, err := os.ReadFile(receiptFile); err == nil {
			var prevRec ExecutionReceipt
			if json.Unmarshal(recData, &prevRec) == nil {
				if prevRec.Verification == "PASS" {
					fmt.Println("DENIED: Decision already executed successfully")
				} else {
					fmt.Printf("DENIED: Decision previously failed execution with verification %s (rollback: %s)\n", prevRec.Verification, prevRec.RollbackStatus)
				}
			} else {
				fmt.Println("DENIED: Decision already executed")
			}
			os.Exit(1)
		}

		repoCfg, ok := cfg.Repos[dec.Proposal.Repo]
		if !ok {
			fmt.Printf("UNKNOWN_REPOSITORY: %s\n", dec.Proposal.Repo)
			os.Exit(1)
		}

		// Gather current evidence to check for staleness
		_, rtEv := gatherEvidence(dec.Proposal.Repo, repoCfg.Path, repoCfg, configDigest)

		key := getApprovalKey()
		if key == nil {
			fmt.Println("DENIED: HOWLCHANGEOPS_APPROVAL_KEY_FILE / CHANGEOPS_APPROVAL_KEY_FILE not set")
			os.Exit(1)
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
					fmt.Println("DENIED: Approval expired")
					os.Exit(1)
				}
			} else {
				fmt.Println("DENIED: Approval integrity invalid")
				os.Exit(1)
			}
		}

		// Write proposal back to a temp file for HowlFrame
		tmpProp := filepath.Join(baseDir, "tmp_proposal.json")
		propData, _ := json.Marshal(dec.Proposal)
		os.WriteFile(tmpProp, propData, 0644)
		defer os.Remove(tmpProp)

		res, err := invokeHowlFrame(tmpProp, dec.Evidence, rtEv, repoCfg)
		if err != nil {
			fmt.Printf("Execution evaluation error: %v\n", err)
			os.Exit(1)
		}

		if res["decision"].(string) != "ALLOW" {
			fmt.Printf("Execution DENIED: %s. Reason: %s\n", res["decision"], res["reason"])
			if strings.Contains(res["reason"].(string), "STALE_REMOTE_EVIDENCE") {
				fmt.Println("STALE_REMOTE_EVIDENCE")
			} else if strings.Contains(res["reason"].(string), "STALE_EVIDENCE") {
				fmt.Println("STALE_EVIDENCE")
			}
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
			Schema:         "howlchangeops.execution_receipt/v1",
			DecisionID:     decID,
			ApprovalID:     app.ApprovalID,
			Action:         dec.Proposal.Action,
			Repo:           dec.Proposal.Repo,
			Revision:       rtEv.CurrentRevision,
			ExecutedAt:     time.Now().UTC().Format(time.RFC3339),
			Verification:   verStatus,
			RollbackStatus: rollbackStatus,
			ErrorMessage:   errMsg,
		}
		recData, _ := json.MarshalIndent(receipt, "", "  ")
		os.WriteFile(filepath.Join(receiptsDir, decID+".json"), recData, 0644)

		appendAudit(map[string]interface{}{
			"event":           "execute",
			"decision_id":     decID,
			"action":          dec.Proposal.Action,
			"success":         success,
			"verification":    verStatus,
			"rollback_status": rollbackStatus,
			"error":           errMsg,
		})

		if !success {
			os.Exit(1)
		}

	case "rollback":
		if len(os.Args) < 3 {
			fmt.Printf("Usage: %s rollback <decision_id>\n", progName)
			os.Exit(1)
		}
		decID := os.Args[2]
		decFile := filepath.Join(decisionsDir, decID+".json")
		decData, err := os.ReadFile(decFile)
		if err != nil {
			fmt.Printf("Decision not found: %v\n", err)
			os.Exit(1)
		}
		var dec Decision
		if err := json.Unmarshal(decData, &dec); err != nil {
			fmt.Printf("Error parsing decision: %v\n", err)
			os.Exit(1)
		}

		// Verify that this decision was previously executed
		receiptFile := filepath.Join(receiptsDir, decID+".json")
		recData, err := os.ReadFile(receiptFile)
		if err != nil {
			fmt.Printf("Cannot rollback: decision %s has not been executed.\n", decID)
			os.Exit(1)
		}
		var rec ExecutionReceipt
		json.Unmarshal(recData, &rec)
		if rec.Verification != "PASS" {
			fmt.Printf("Cannot rollback: decision %s did not successfully complete execution.\n", decID)
			os.Exit(1)
		}

		if dec.Proposal.Action != "create_release_candidate" {
			fmt.Printf("Rollback only applies to create_release_candidate decisions (found: %s).\n", dec.Proposal.Action)
			os.Exit(1)
		}

		repoCfg, ok := cfg.Repos[dec.Proposal.Repo]
		if !ok {
			fmt.Printf("UNKNOWN_REPOSITORY: %s\n", dec.Proposal.Repo)
			os.Exit(1)
		}

		tag := fmt.Sprintf("howlchangeops/rc-%s", dec.Evidence.Revision[:7])
		tagCheck, _ := gitCommand(repoCfg.Path, "tag", "-l", tag)
		if tagCheck == "" {
			tag = fmt.Sprintf("changeops/rc-%s", dec.Evidence.Revision[:7])
			tagCheck, _ = gitCommand(repoCfg.Path, "tag", "-l", tag)
		}
		if tagCheck == "" {
			fmt.Printf("Candidate tag %s does not exist; nothing to rollback.\n", tag)
			os.Exit(1)
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
			fmt.Printf("Rollback evaluation error: %v\n", err)
			os.Exit(1)
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
			fmt.Printf("Rollback denied by policy: %s\n", rbDec.Reason)
			os.Exit(1)
		}

		appendAudit(map[string]interface{}{
			"event":             "rollback_propose",
			"target_decision":   decID,
			"rollback_decision": rbDec,
		})

	case "history":
		data, err := os.ReadFile(historyFile)
		if err != nil {
			fmt.Println("No history found.")
			return
		}
		fmt.Println(string(data))

	case "explain":
		if len(os.Args) < 3 {
			fmt.Printf("Usage: %s explain <decision_id>\n", progName)
			os.Exit(1)
		}
		decID := os.Args[2]
		decFile := filepath.Join(decisionsDir, decID+".json")
		decData, err := os.ReadFile(decFile)
		if err != nil {
			fmt.Printf("Decision not found: %v\n", err)
			os.Exit(1)
		}
		var dec Decision
		json.Unmarshal(decData, &dec)

		fmt.Printf("Decision: %s\nAction: %s\nRepo: %s\nRevision: %s\n\nGates:\n", dec.Result, dec.Proposal.Action, dec.Proposal.Repo, dec.Evidence.Revision)
		for _, g := range dec.Gates {
			fmt.Printf("  - %s: %s\n", g.Name, g.Status)
		}
		fmt.Printf("\nReason: %s\n", dec.Reason)

		receiptFile := filepath.Join(receiptsDir, decID+".json")
		if recData, err := os.ReadFile(receiptFile); err == nil {
			var rec ExecutionReceipt
			if json.Unmarshal(recData, &rec) == nil {
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
		fmt.Printf("Unknown command: %s\n", cmd)
		os.Exit(1)
	}
}
