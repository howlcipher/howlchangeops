package main

import (
	"bytes"
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

func pythonFixture(t *testing.T, files map[string]string) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "repo; literal")
	if err := os.MkdirAll(root, 0755); err != nil {
		t.Fatal(err)
	}
	for path, content := range files {
		target := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{{"init", "-b", "main"}, {"add", "."}, {"-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "--allow-empty", "-m", "fixture"}} {
		cmd := exec.Command("git", args...)
		cmd.Dir = root
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v: %s", err, out)
		}
	}
	return root
}

func TestPythonProfileRegression(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("python-stdlib requires POSIX group cancellation")
	}
	for _, tc := range []struct {
		name  string
		files map[string]string
		pass  bool
	}{
		{"passing", map[string]string{"app.py": "VALUE = 42\n", "tests/test_app.py": "import unittest\nimport app\nclass TestApp(unittest.TestCase):\n    def test_value(self):\n        self.assertEqual(app.VALUE, 42)\n", "unittest.py": "raise RuntimeError('shadow')\n"}, true},
		{"missing", map[string]string{"app.py": "x=1\n"}, false},
		{"empty", map[string]string{"tests/test_empty.py": "x=1\n"}, false},
		{"failing", map[string]string{"tests/test_bad.py": "import unittest\nclass T(unittest.TestCase):\n    def test_bad(self):\n        self.fail('bad')\n"}, false},
		{"all-skipped", map[string]string{"tests/test_skip.py": "import unittest\nclass T(unittest.TestCase):\n    @unittest.skip('x')\n    def test_s(self):\n        pass\n"}, false},
		{"syntax", map[string]string{"bad.py": "def broken(\n", "tests/test_ok.py": "import unittest\nclass T(unittest.TestCase):\n    def test_ok(self):\n        pass\n"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := pythonFixture(t, tc.files)
			old := baseDir
			baseDir = t.TempDir()
			defer func() { baseDir = old }()
			err := validate("sample", root, ConfigRepo{ValidationProfile: "python-stdlib"}, "digest")
			if (err == nil) != tc.pass {
				t.Fatalf("pass=%v err=%v", tc.pass, err)
			}
			filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
				if filepath.Ext(path) == ".pyc" || filepath.Base(path) == "__pycache__" {
					t.Errorf("bytecode write: %s", path)
				}
				return nil
			})
		})
	}
}

func TestPythonBoundsAndDigest(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("python-stdlib requires POSIX group cancellation")
	}
	root := t.TempDir()
	for _, tc := range []struct {
		name, helper       string
		timeout, truncated bool
	}{
		{"timeout", "import time\ntime.sleep(10)", true, false},
		{"overflow", "print('x' * 10000)", false, true},
		{"inherited-pipes", "import subprocess\nsubprocess.Popen(['python3', '-I', '-B', '-c', 'import time; time.sleep(10)'])", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			got := runPythonCheck(tc.name, root, tc.helper, 150*time.Millisecond, 128)
			if got.Status != "FAIL" || got.TimedOut != tc.timeout || got.OutputTruncated != tc.truncated {
				t.Fatalf("%+v", got)
			}
			if time.Since(start) > 3*time.Second {
				t.Fatal("deadline not bounded")
			}
		})
	}
	got := runPythonCheck("digest", root, "print('hello')", time.Second, 128)
	want := fmt.Sprintf("%x", sha256.Sum256([]byte("hello\n")))
	if got.Status != "PASS" || got.OutputDigest != want {
		t.Fatalf("%+v want %s", got, want)
	}
	got = runPythonCheck("digest", root, "print('x' * 10000)", time.Second, 128)
	want = fmt.Sprintf("%x", sha256.Sum256(bytes.Repeat([]byte("x"), 128)))
	if got.OutputDigest != want {
		t.Fatalf("truncated digest %s want %s", got.OutputDigest, want)
	}
}

func TestPythonTrackedSourceSafety(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX source and symlink fixtures")
	}
	for _, kind := range []string{"absent", "symlink", "missing", "parent-symlink", "directory"} {
		t.Run(kind, func(t *testing.T) {
			files := map[string]string{"readme": "fixture"}
			if kind != "absent" {
				files["src/app.py"] = "x=1\n"
			}
			root := pythonFixture(t, files)
			source := filepath.Join(root, "src", "app.py")
			switch kind {
			case "symlink":
				os.Remove(source)
				if err := os.Symlink("/etc/passwd", source); err != nil {
					t.Fatal(err)
				}
			case "missing":
				os.Remove(source)
			case "parent-symlink":
				os.Rename(filepath.Join(root, "src"), filepath.Join(root, "other"))
				if err := os.Symlink("other", filepath.Join(root, "src")); err != nil {
					t.Fatal(err)
				}
			case "directory":
				os.Remove(source)
				os.Mkdir(source, 0755)
			}
			got := runPythonCheck("build", root, pythonBuildHelper, time.Second, 4096)
			if got.Status != "FAIL" {
				t.Fatalf("%+v", got)
			}
		})
	}
}

func TestPythonPublicFailureEvidence(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("python-stdlib requires POSIX group cancellation")
	}
	bin := filepath.Join(t.TempDir(), "howlchangeops")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	for _, command := range []string{"validate", "dogfood"} {
		root := pythonFixture(t, map[string]string{"tests/test_bad.py": "import unittest\nclass T(unittest.TestCase):\n    def test_bad(self):\n        self.fail()\n"})
		cwd := t.TempDir()
		os.Mkdir(filepath.Join(cwd, "config"), 0755)
		cfg := Config{Repos: map[string]ConfigRepo{"sample": {Path: root, ValidationProfile: "python-stdlib"}}}
		data, _ := json.Marshal(cfg)
		os.WriteFile(filepath.Join(cwd, "config", "howlchangeops-config.json"), data, 0644)
		state := t.TempDir()
		cmd := exec.Command(bin, command, "sample")
		cmd.Dir = cwd
		cmd.Env = append(os.Environ(), "HOWLCHANGEOPS_BASE="+state)
		out, err := cmd.CombinedOutput()
		if err == nil || strings.Contains(string(out), "Validation complete") || strings.Contains(string(out), "3. Proposing") {
			t.Fatalf("%v %s", err, out)
		}
		paths, _ := filepath.Glob(filepath.Join(state, "evidence_*.json"))
		if len(paths) != 1 {
			t.Fatalf("evidence %v", paths)
		}
		data, err = os.ReadFile(paths[0])
		if err != nil {
			t.Fatal(err)
		}
		var ev EvidenceEnvelope
		if err = json.Unmarshal(data, &ev); err != nil {
			t.Fatal(err)
		}
		if ev.Checks["test"].Status != "FAIL" || ev.Checks["build"].Status != "PASS" {
			t.Fatalf("%+v", ev)
		}
	}
}

func TestPythonPublicSuccessAndPolicy(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX only")
	}
	install := t.TempDir()
	bin := filepath.Join(install, "howlchangeops")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	source, _ := filepath.Abs("../src/howlchangeops.howl")
	if out, err := exec.Command(getHowlFrameBin(), "build", source, "-o", filepath.Join(install, "howlchangeops.hfbc")).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	root := pythonFixture(t, map[string]string{"app.py": "VALUE=42\n", "tests/test_app.py": "import unittest, app\nclass T(unittest.TestCase):\n    def test_ok(self):\n        self.assertEqual(app.VALUE,42)\n"})
	cwd := t.TempDir()
	os.Mkdir(filepath.Join(cwd, "config"), 0755)
	cfg := Config{Repos: map[string]ConfigRepo{"sample": {Path: root, ValidationProfile: "python-stdlib", AllowedBranches: []string{"main"}, AllowedActions: []string{"create_release_candidate"}}}}
	data, _ := json.Marshal(cfg)
	os.WriteFile(filepath.Join(cwd, "config", "howlchangeops-config.json"), data, 0644)
	state := t.TempDir()
	run := func(args ...string) ([]byte, error) {
		cmd := exec.Command(bin, args...)
		cmd.Dir = cwd
		cmd.Env = append(os.Environ(), "HOWLCHANGEOPS_BASE="+state)
		return cmd.CombinedOutput()
	}
	out, err := run("validate", "sample")
	if err != nil || !strings.Contains(string(out), "Validation complete") {
		t.Fatalf("%v %s", err, out)
	}
	out, err = run("dogfood", "sample")
	if err != nil || !strings.Contains(string(out), "REQUIRE_APPROVAL") {
		t.Fatalf("%v %s", err, out)
	}
	paths, _ := filepath.Glob(filepath.Join(state, "evidence_*.json"))
	if len(paths) != 1 {
		t.Fatalf("%v", paths)
	}
	data, _ = os.ReadFile(paths[0])
	var ev EvidenceEnvelope
	if err = json.Unmarshal(data, &ev); err != nil {
		t.Fatal(err)
	}
	if ev.Checks["test"].Status != "PASS" || ev.Checks["build"].Status != "PASS" {
		t.Fatalf("%+v", ev)
	}
	// A declaration cannot substitute for a missing build check.
	delete(ev.Checks, "build")
	data, _ = json.Marshal(ev)
	os.WriteFile(paths[0], data, 0644)
	proposal := filepath.Join(cwd, "proposal.json")
	os.WriteFile(proposal, []byte(`{"action":"create_release_candidate","repo":"sample","approved":true,"security_verified":true}`), 0644)
	out, err = run("evaluate", proposal)
	if err != nil || !strings.Contains(string(out), "DENY") {
		t.Fatalf("missing build accepted: %v %s", err, out)
	}
}

func TestValidationPublicMissingRepositoryFailsActionably(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "howlchangeops")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	for _, profile := range []string{"go", "python-stdlib"} {
		t.Run(profile, func(t *testing.T) {
			cwd := t.TempDir()
			if err := os.Mkdir(filepath.Join(cwd, "config"), 0755); err != nil {
				t.Fatal(err)
			}
			cfg := Config{Repos: map[string]ConfigRepo{"sample": {Path: filepath.Join(cwd, "missing"), ValidationProfile: profile}}}
			data, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(cwd, "config", "howlchangeops-config.json"), data, 0644); err != nil {
				t.Fatal(err)
			}
			state := filepath.Join(cwd, "state")
			cmd := exec.Command(bin, "validate", "sample")
			cmd.Dir = cwd
			cmd.Env = append(os.Environ(), "HOWLCHANGEOPS_BASE="+state)
			out, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(out), "committed HEAD") || strings.Contains(string(out), "panic:") || strings.Contains(string(out), "Validation complete") {
				t.Fatalf("expected actionable repository failure: %v %s", err, out)
			}
			paths, err := filepath.Glob(filepath.Join(state, "evidence_*.json"))
			if err != nil || len(paths) != 0 {
				t.Fatalf("invalid repo evidence: %v %v", paths, err)
			}
		})
	}
}
