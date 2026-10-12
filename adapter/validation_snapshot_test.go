package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestPublicValidationSnapshotIdentity(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("python-stdlib requires POSIX group cancellation")
	}
	install := t.TempDir()
	bin := filepath.Join(install, "howlchangeops")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	source, err := filepath.Abs("../src/howlchangeops.howl")
	if err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(getHowlFrameBin(), "build", source, "-o", filepath.Join(install, "howlchangeops.hfbc")).CombinedOutput(); err != nil {
		t.Fatalf("policy: %v %s", err, out)
	}
	for _, scenario := range []string{"dirty-restored", "test-modifies-source"} {
		t.Run(scenario, func(t *testing.T) {
			testCode := "import unittest\nclass T(unittest.TestCase):\n    def test_value(self):\n        self.assertEqual(1,2)\n"
			if scenario == "test-modifies-source" {
				testCode = "import unittest\nfrom pathlib import Path\nclass T(unittest.TestCase):\n    def test_changes_source(self):\n        Path('app.py').write_text('VALUE=2\\n')\n"
			}
			root := pythonFixture(t, map[string]string{"app.py": "VALUE=1\n", "tests/test_app.py": testCode})
			cwd := t.TempDir()
			state := t.TempDir()
			if err := os.Mkdir(filepath.Join(cwd, "config"), 0755); err != nil {
				t.Fatal(err)
			}
			repoCfg := ConfigRepo{Path: root, ValidationProfile: "python-stdlib", AllowedBranches: []string{"main"}, AllowedActions: []string{"create_release_candidate"}}
			cfg := Config{Repos: map[string]ConfigRepo{"sample": repoCfg}}
			data, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(cwd, "config", "howlchangeops-config.json"), data, 0644); err != nil {
				t.Fatal(err)
			}
			proposal := filepath.Join(cwd, "proposal.json")
			if err := os.WriteFile(proposal, []byte(`{"action":"create_release_candidate","repo":"sample"}`), 0644); err != nil {
				t.Fatal(err)
			}
			run := func(args ...string) ([]byte, error) {
				cmd := exec.Command(bin, args...)
				cmd.Dir = cwd
				cmd.Env = append(os.Environ(), "HOWLCHANGEOPS_BASE="+state)
				return cmd.CombinedOutput()
			}
			if scenario == "dirty-restored" {
				passing := strings.Replace(testCode, "1,2", "1,1", 1)
				if err := os.WriteFile(filepath.Join(root, "tests", "test_app.py"), []byte(passing), 0644); err != nil {
					t.Fatal(err)
				}
			}
			out, err := run("validate", "sample")
			if err == nil || strings.Contains(string(out), "Validation complete") {
				t.Errorf("changed snapshot accepted: %v %s", err, out)
			}
			if scenario == "dirty-restored" {
				// Simulate the previously released dirty cache, which must never regain authority.
				rev, err := gitCommand(root, "rev-parse", "HEAD")
				if err != nil {
					t.Fatal(err)
				}
				digest := fmt.Sprintf("%x", sha256.Sum256(data))
				ev := EvidenceEnvelope{Repo: "sample", Branch: "main", Revision: rev, ValidationProfile: "python-stdlib", ConfigDigest: digest, WorkingTree: "dirty", GeneratedAt: time.Now().UTC().Format(time.RFC3339), Checks: map[string]ValidationResult{"test": {Status: "PASS"}, "build": {Status: "PASS"}, "working_tree": {Status: "FAIL"}}}
				encoded, err := json.Marshal(ev)
				if err != nil {
					t.Fatal(err)
				}
				key := fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s|%s", "sample", rev, "python-stdlib", digest))))
				if err := os.WriteFile(filepath.Join(state, "evidence_"+key+".json"), encoded, 0644); err != nil {
					t.Fatal(err)
				}
			} else {
				paths, err := filepath.Glob(filepath.Join(state, "evidence_*.json"))
				if err != nil || len(paths) != 1 {
					t.Fatalf("expected actual changed-snapshot evidence: %v %v", paths, err)
				}
				recorded, err := os.ReadFile(paths[0])
				if err != nil {
					t.Fatal(err)
				}
				var ev EvidenceEnvelope
				if err := json.Unmarshal(recorded, &ev); err != nil {
					t.Fatal(err)
				}
				if ev.Checks["test"].Status != "PASS" || ev.Checks["build"].Status != "PASS" || ev.Checks["working_tree"].Status != "FAIL" {
					t.Errorf("changed source evidence inaccurate: %+v", ev)
				}
			}
			cmd := exec.Command("git", "restore", ".")
			cmd.Dir = root
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("restore: %v %s", err, out)
			}
			out, err = run("evaluate", proposal)
			if err != nil || !strings.Contains(string(out), "DENY") || strings.Contains(string(out), "REQUIRE_APPROVAL") {
				t.Fatalf("stale validation gained authority after restore: %v %s", err, out)
			}
		})
	}
}
