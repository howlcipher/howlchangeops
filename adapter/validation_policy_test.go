package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnsupportedProfilePublicCommands(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, "howlchangeops")
	build := exec.Command("go", "build", "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v: %s", err, out)
	}
	for _, command := range []string{"validate", "dogfood"} {
		for _, profile := range []string{"python", "", "GO"} {
			t.Run(command+"/"+profile, func(t *testing.T) {
				cwd := t.TempDir()
				if err := os.Mkdir(filepath.Join(cwd, "config"), 0755); err != nil {
					t.Fatal(err)
				}
				cfg := Config{Repos: map[string]ConfigRepo{"sample": {Path: cwd, ValidationProfile: profile}}}
				data, err := json.Marshal(cfg)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(cwd, "config", "howlchangeops-config.json"), data, 0644); err != nil {
					t.Fatal(err)
				}
				state := filepath.Join(cwd, "state")
				if err := os.Mkdir(state, 0755); err != nil {
					t.Fatal(err)
				}
				existing := filepath.Join(state, "evidence_existing.json")
				if err := os.WriteFile(existing, []byte("old evidence"), 0644); err != nil {
					t.Fatal(err)
				}
				cmd := exec.Command(bin, command, "sample")
				cmd.Dir = cwd
				cmd.Env = append(os.Environ(), "HOWLCHANGEOPS_BASE="+state)
				out, err := cmd.CombinedOutput()
				if err == nil {
					t.Errorf("unsupported profile succeeded: %s", out)
				}
				if !strings.Contains(string(out), "unsupported validation profile") || !strings.Contains(string(out), "go") {
					t.Errorf("missing actionable failure: %s", out)
				}
				if strings.Contains(string(out), "Validation complete") || strings.Contains(string(out), "3. Proposing") {
					t.Errorf("workflow continued: %s", out)
				}
				evidence, err := filepath.Glob(filepath.Join(state, "evidence_*.json"))
				if err != nil {
					t.Fatal(err)
				}
				if len(evidence) != 1 || evidence[0] != existing {
					t.Errorf("fresh evidence written: %v", evidence)
				}
				preserved, err := os.ReadFile(existing)
				if err != nil || string(preserved) != "old evidence" {
					t.Errorf("prior evidence changed: %s %v", preserved, err)
				}
			})
		}
	}
}

func TestPolicyBesideResolvedExecutablePublicCommand(t *testing.T) {
	install := t.TempDir()
	bin := filepath.Join(install, "howlchangeops")
	build := exec.Command("go", "build", "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v: %s", err, out)
	}
	source, err := filepath.Abs("../src/howlchangeops.howl")
	if err != nil {
		t.Fatal(err)
	}
	canonical := filepath.Join(install, "howlchangeops.hfbc")
	compile := exec.Command(getHowlFrameBin(), "build", source, "-o", canonical)
	if out, err := compile.CombinedOutput(); err != nil {
		t.Fatalf("compile policy: %v: %s", err, out)
	}
	caller := t.TempDir()
	alias := filepath.Join(caller, "changeops")
	if err := os.Symlink(bin, alias); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(caller, "config"), 0755); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Repos: map[string]ConfigRepo{"sample": {Path: caller, ValidationProfile: "go", AllowedBranches: []string{"main"}, AllowedActions: []string{"create_release_candidate"}}}}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(caller, "config", "howlchangeops-config.json"), data, 0644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"init", "-b", "main"}, {"-c", "user.name=Test User", "-c", "user.email=test@example.com", "commit", "--allow-empty", "-m", "test fixture"}} {
		cmd := exec.Command("git", args...)
		cmd.Dir = caller
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git: %v: %s", err, out)
		}
	}
	proposal := filepath.Join(caller, "proposal.json")
	if err := os.WriteFile(proposal, []byte(`{"action":"create_release_candidate","repo":"sample"}`), 0644); err != nil {
		t.Fatal(err)
	}
	// Invalid caller policies must never shadow the installed authority.
	for _, name := range []string{"howlchangeops.hfbc", "changeops.hfbc"} {
		if err := os.WriteFile(filepath.Join(caller, name), []byte("caller shadow"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	run := func() ([]byte, error) {
		cmd := exec.Command(alias, "evaluate", proposal)
		cmd.Dir = caller
		cmd.Env = append(os.Environ(), "HOWLCHANGEOPS_BASE="+filepath.Join(caller, "state"))
		return cmd.CombinedOutput()
	}
	for _, name := range []string{"canonical", "legacy"} {
		t.Run(name, func(t *testing.T) {
			out, err := run()
			if err != nil || !strings.Contains(string(out), "DENY") {
				t.Fatalf("sidecar evaluation failed: %v: %s", err, out)
			}
		})
		if name == "canonical" {
			if err := os.Rename(canonical, filepath.Join(install, "changeops.hfbc")); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := os.Remove(filepath.Join(install, "changeops.hfbc")); err != nil {
		t.Fatal(err)
	}
	out, err := run()
	if err == nil || !strings.Contains(string(out), "policy artifact missing beside executable") {
		t.Fatalf("missing installed policy must reject cwd fallback: %v: %s", err, out)
	}
}
