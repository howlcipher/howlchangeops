package main

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func TestSplitJSONFlagOnlyAfterTheCommand(t *testing.T) {
	args, ok := splitJSONFlag([]string{"howlchangeops", "evaluate", "--json", "p.json"})
	if !ok || strings.Join(args, " ") != "howlchangeops evaluate p.json" {
		t.Fatalf("got %v %v", args, ok)
	}
	if _, ok := splitJSONFlag([]string{"howlchangeops", "history"}); ok {
		t.Fatal("found --json that was not given")
	}
}

func TestConfigCandidatesPreferExplicitThenXDG(t *testing.T) {
	env := map[string]string{}
	getenv := func(k string) string { return env[k] }
	got := configCandidates(getenv, "/home/u")
	want := []string{
		"/home/u/.config/howlchangeops/howlchangeops-config.json",
		filepath.Join("config", "howlchangeops-config.json"),
		filepath.Join("config", "changeops-config.json"),
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("default candidates = %v", got)
	}
	env["XDG_CONFIG_HOME"] = "/xdg"
	if got := configCandidates(getenv, "/home/u"); got[0] != "/xdg/howlchangeops/howlchangeops-config.json" {
		t.Fatalf("XDG candidate = %v", got)
	}
	env["CHANGEOPS_CONFIG"] = "/legacy.json"
	if got := configCandidates(getenv, "/home/u"); len(got) != 1 || got[0] != "/legacy.json" {
		t.Fatalf("CHANGEOPS_CONFIG = %v", got)
	}
	env["HOWLCHANGEOPS_CONFIG"] = "/explicit.json"
	if got := configCandidates(getenv, "/home/u"); len(got) != 1 || got[0] != "/explicit.json" {
		t.Fatalf("HOWLCHANGEOPS_CONFIG = %v", got)
	}
}

func TestHowlFrameVersionRange(t *testing.T) {
	for v, ok := range map[string]bool{"0.1.0": true, "0.1.7": true, "v0.1.2": true, "0.1.3-rc1": true, "0.2.0": false, "1.1.0": false, "0.1": false, "0.1.x": false} {
		if got := sameMinorRelease(v, "0.1.0"); got != ok {
			t.Errorf("sameMinorRelease(%q) = %v, want %v", v, got, ok)
		}
	}
}

func mockHowlFrame(t *testing.T, script string) {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "howlframe")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOWLFRAME_BIN", bin)
}

func TestHowlFrameCompatibility_PatchReleaseAccepted(t *testing.T) {
	mockHowlFrame(t, "echo 'HowlFrame 0.1.4'\necho 'HFBC format: 1'\n")
	if err := checkHowlFrameCompatibility(); err != nil {
		t.Fatalf("patch release rejected: %v", err)
	}
}

func TestHowlFrameCompatibility_BytecodeFormatMismatch(t *testing.T) {
	mockHowlFrame(t, "echo 'HowlFrame 0.1.4'\necho 'HFBC format: 2'\n")
	err := checkHowlFrameCompatibility()
	if err == nil || !strings.Contains(err.Error(), "HFBC format 2") {
		t.Fatalf("expected an HFBC format error, got %v", err)
	}
}

func TestVerdictStatus(t *testing.T) {
	for verdict, status := range map[string]string{"ALLOW": "ok", "REQUIRE_APPROVAL": "awaiting_human", "DENY": "denied", "": "failed"} {
		if got := verdictStatus(verdict); got != status {
			t.Errorf("verdictStatus(%q) = %q, want %q", verdict, got, status)
		}
	}
}

// The descriptor lists exactly the commands main() dispatches.
func TestInteropDescriptorMatchesDispatch(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	dispatched := map[string]bool{"interop": true, "version": true}
	ast.Inspect(file, func(n ast.Node) bool {
		sw, ok := n.(*ast.SwitchStmt)
		if !ok {
			return true
		}
		if id, ok := sw.Tag.(*ast.Ident); !ok || id.Name != "cmd" {
			return true
		}
		for _, stmt := range sw.Body.List {
			cc := stmt.(*ast.CaseClause)
			if len(cc.List) != 1 {
				continue // the HowlFrame pre-flight switch groups several commands
			}
			name, _ := strconv.Unquote(cc.List[0].(*ast.BasicLit).Value)
			dispatched[name] = true
		}
		return true
	})
	var want, got []string
	for name := range dispatched {
		want = append(want, name)
	}
	for _, c := range interopCommands {
		if len(c.Path) == 1 {
			got = append(got, c.Path[0])
		}
	}
	sort.Strings(want)
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("descriptor commands %v, main dispatches %v", got, want)
	}
}

func buildAdapter(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "howlchangeops")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return bin
}

type envelope struct {
	Schema    string         `json:"schema"`
	Component string         `json:"component"`
	Command   []string       `json:"command"`
	Status    string         `json:"status"`
	Data      map[string]any `json:"data"`
	Error     *resultError   `json:"error"`
}

func runJSON(t *testing.T, bin, dir string, env []string, args ...string) (envelope, int) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.Output()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	var e envelope
	if err := json.Unmarshal(out, &e); err != nil {
		t.Fatalf("%v: stdout is not one JSON document: %v\n%s", args, err, out)
	}
	return e, code
}

func TestJSONEnvelopesWithoutConfiguration(t *testing.T) {
	bin := buildAdapter(t)
	dir := t.TempDir()
	env := []string{"XDG_CONFIG_HOME=" + filepath.Join(dir, "xdg"), "HOWLCHANGEOPS_BASE=" + filepath.Join(dir, "state")}

	e, code := runJSON(t, bin, dir, env, "version", "--json")
	if code != 0 || e.Schema != resultSchema || e.Component != "howlchangeops" || e.Status != "ok" || e.Data["version"] != Version {
		t.Fatalf("version --json: %d %+v", code, e)
	}

	e, code = runJSON(t, bin, dir, env, "evaluate", "--json", "proposal.json")
	if code != 1 || e.Status != "unavailable" || e.Error == nil || e.Error.Code != "CONFIG_UNAVAILABLE" {
		t.Fatalf("evaluate without config: %d %+v", code, e)
	}
	if !strings.Contains(e.Error.Message, filepath.Join(dir, "xdg", "howlchangeops")) {
		t.Errorf("error should name the XDG location it looked in: %q", e.Error.Message)
	}

	e, code = runJSON(t, bin, dir, env, "inspect", "--json", "repo")
	if code != 1 || e.Error == nil || e.Error.Code != "USAGE" {
		t.Fatalf("--json on a command without JSON output: %d %+v", code, e)
	}

	// A config in the XDG directory is found from any working directory.
	cfgDir := filepath.Join(dir, "xdg", "howlchangeops")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfgDir, "howlchangeops-config.json"), []byte(`{"repos":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	e, code = runJSON(t, bin, dir, env, "history", "--json")
	if code != 0 || e.Status != "ok" {
		t.Fatalf("history --json with XDG config: %d %+v", code, e)
	}
	if entries, ok := e.Data["entries"].([]any); !ok || len(entries) != 0 {
		t.Fatalf("history entries = %#v", e.Data["entries"])
	}
	if err := os.WriteFile(filepath.Join(dir, "proposal.json"), []byte(`{"action":"create_release_candidate","repo":"nope"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	e, code = runJSON(t, bin, dir, append(env, "HOWLFRAME_BIN=/bin/true"), "evaluate", "--json", "proposal.json")
	if code != 1 || e.Error == nil || (e.Error.Code != "UNKNOWN_REPOSITORY" && e.Error.Code != "HOWLFRAME_INCOMPATIBLE") {
		t.Fatalf("evaluate unknown repo: %d %+v", code, e)
	}
}

func TestInteropCommandPrintsTheDescriptor(t *testing.T) {
	bin := buildAdapter(t)
	out, err := exec.Command(bin, "interop", "--json").Output()
	if err != nil {
		t.Fatal(err)
	}
	var d struct {
		Schema, Component, Version string
		Commands                   []interopCommand
		Consumes                   []interopConsume
		ExitCodes                  map[string]string `json:"exit_codes"`
	}
	if err := json.Unmarshal(out, &d); err != nil {
		t.Fatal(err)
	}
	if d.Schema != "howl.interop/v1" || d.Component != "howlchangeops" || d.Version != Version || len(d.ExitCodes) == 0 {
		t.Fatalf("descriptor header %+v", d)
	}
	if len(d.Consumes) != 2 || d.Consumes[1].Command[0] != "run" {
		t.Fatalf("consumes = %+v", d.Consumes)
	}
}
