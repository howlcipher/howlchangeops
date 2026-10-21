package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Machine-readable output follows the Howl interop contract
// (https://github.com/howlcipher/howl/blob/main/docs/INTEROP.md): with
// --json, a command prints exactly one howl.result/v1 envelope on stdout and
// its human-readable progress goes to stderr. Callers branch on `status`.

const resultSchema = "howl.result/v1"

var (
	jsonOut    bool
	realStdout io.Writer = os.Stdout
	command    []string
)

// splitJSONFlag removes --json from the arguments after the command name and
// reports whether it was present.
func splitJSONFlag(args []string) ([]string, bool) {
	if len(args) < 2 {
		return args, false
	}
	out := []string{args[0], args[1]}
	found := false
	for _, a := range args[2:] {
		if a == "--json" || a == "-json" {
			found = true
			continue
		}
		out = append(out, a)
	}
	return out, found
}

// enableJSON routes everything printed with fmt.Print* to stderr so stdout
// carries only the result envelope.
func enableJSON() {
	jsonOut = true
	realStdout = os.Stdout
	os.Stdout = os.Stderr
}

type resultError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type result struct {
	Schema    string         `json:"schema"`
	Component string         `json:"component"`
	Command   []string       `json:"command"`
	Status    string         `json:"status"`
	Data      map[string]any `json:"data"`
	Error     *resultError   `json:"error"`
}

func writeResult(status string, data map[string]any, errCode, errMsg string) {
	if !jsonOut {
		return
	}
	r := result{Schema: resultSchema, Component: "howlchangeops", Command: command, Status: status, Data: data}
	if errCode != "" {
		r.Error = &resultError{Code: errCode, Message: errMsg}
	}
	enc := json.NewEncoder(realStdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(r)
}

// succeed writes the success envelope (JSON mode only).
func succeed(status string, data map[string]any) {
	writeResult(status, data, "", "")
}

// die prints the human message exactly as before (stdout in text mode) and,
// with --json, the failure envelope; then exits 1. The code is the
// message's own prefix token where it has one (UNKNOWN_REPOSITORY,
// DENIED, ...).
func die(status, code, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	fmt.Println(msg)
	writeResult(status, nil, code, msg)
	os.Exit(1)
}

// verdictStatus maps a HowlFrame policy verdict to a result status.
func verdictStatus(verdict string) string {
	switch verdict {
	case "ALLOW":
		return "ok"
	case "REQUIRE_APPROVAL":
		return "awaiting_human"
	case "DENY":
		return "denied"
	default:
		return "failed"
	}
}

func gatesData(gates []Gate) []map[string]string {
	out := make([]map[string]string, 0, len(gates))
	for _, g := range gates {
		out = append(out, map[string]string{"name": g.Name, "status": g.Status})
	}
	return out
}

// configCandidates lists where the repository configuration may live, in
// order: an explicit HOWLCHANGEOPS_CONFIG (or CHANGEOPS_CONFIG) file, the
// user's XDG config directory, then the legacy paths relative to the working
// directory. The XDG location survives `howl update`, which replaces the
// release directory callers used to run from.
func configCandidates(getenv func(string) string, home string) []string {
	if p := getenv("HOWLCHANGEOPS_CONFIG"); p != "" {
		return []string{p}
	}
	if p := getenv("CHANGEOPS_CONFIG"); p != "" {
		return []string{p}
	}
	xdg := getenv("XDG_CONFIG_HOME")
	if xdg == "" && home != "" {
		xdg = filepath.Join(home, ".config")
	}
	var out []string
	if xdg != "" {
		out = append(out, filepath.Join(xdg, "howlchangeops", "howlchangeops-config.json"))
	}
	return append(out, filepath.Join("config", "howlchangeops-config.json"), filepath.Join("config", "changeops-config.json"))
}

type interopCommand struct {
	Path    []string `json:"path"`
	Flags   []string `json:"flags"`
	JSON    bool     `json:"json"`
	Emits   []string `json:"emits,omitempty"`
	Accepts []string `json:"accepts,omitempty"`
}

type interopConsume struct {
	Component  string   `json:"component"`
	Command    []string `json:"command"`
	Flags      []string `json:"flags,omitempty"`
	MinVersion string   `json:"min_version,omitempty"`
}

// interopCommands mirrors the dispatch in main();
// TestInteropDescriptorMatchesDispatch keeps them in step.
var interopCommands = []interopCommand{
	{Path: []string{}, Flags: []string{"--version"}},
	{Path: []string{"version"}, Flags: []string{"--json"}, JSON: true, Emits: []string{resultSchema}},
	{Path: []string{"interop"}, Flags: []string{"--json"}, JSON: true, Emits: []string{"howl.interop/v1"}},
	{Path: []string{"inspect"}, Flags: []string{}},
	{Path: []string{"validate"}, Flags: []string{}, Emits: []string{"howlchangeops.evidence/v1"}},
	{Path: []string{"plan"}, Flags: []string{}},
	{Path: []string{"dogfood"}, Flags: []string{}},
	{Path: []string{"evaluate"}, Flags: []string{"--json"}, JSON: true, Emits: []string{resultSchema}, Accepts: []string{"howlchangeops.proposal/v1"}},
	{Path: []string{"approve"}, Flags: []string{"--json", "--owner-confirmed", "--approver"}, JSON: true, Emits: []string{resultSchema, "howlchangeops.approval/v1"}},
	{Path: []string{"execute"}, Flags: []string{"--json"}, JSON: true, Emits: []string{resultSchema, "howlchangeops.execution_receipt/v1"}},
	{Path: []string{"rollback"}, Flags: []string{"--json"}, JSON: true, Emits: []string{resultSchema}},
	{Path: []string{"history"}, Flags: []string{"--json"}, JSON: true, Emits: []string{resultSchema}},
	{Path: []string{"explain"}, Flags: []string{"--json"}, JSON: true, Emits: []string{resultSchema}},
}

func interopDescriptor() map[string]any {
	return map[string]any{
		"schema":    "howl.interop/v1",
		"component": "howlchangeops",
		"version":   Version,
		"commands":  interopCommands,
		"exit_codes": map[string]string{
			"0": "ok; with --json read status: evaluate exits 0 for ALLOW, DENY and REQUIRE_APPROVAL alike",
			"1": "error, refusal (DENIED, UNKNOWN_REPOSITORY, STALE_EVIDENCE, HOWLFRAME_INCOMPATIBLE), or failed execution",
		},
		"env": []string{
			"HOWLCHANGEOPS_BASE", "CHANGEOPS_BASE", "HOWLCHANGEOPS_CONFIG", "CHANGEOPS_CONFIG",
			"HOWLCHANGEOPS_APPROVAL_KEY_FILE", "CHANGEOPS_APPROVAL_KEY_FILE", "HOWLFRAME_BIN", "XDG_CONFIG_HOME",
		},
		"consumes": []interopConsume{
			{Component: "howlframe", Command: []string{}, Flags: []string{"--version"}, MinVersion: CompatibleHowlFrameVersion},
			{Component: "howlframe", Command: []string{"run"}, Flags: []string{"-allow-caps"}, MinVersion: CompatibleHowlFrameVersion},
		},
	}
}

func printInterop() {
	enc := json.NewEncoder(realStdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(interopDescriptor())
}

// supportsJSON reports whether --json is implemented for cmd.
func supportsJSON(cmd string) bool {
	for _, c := range interopCommands {
		if len(c.Path) == 1 && c.Path[0] == cmd {
			return c.JSON
		}
	}
	return false
}

func unknownJSONCommand(cmd string) string {
	var with []string
	for _, c := range interopCommands {
		if c.JSON && len(c.Path) == 1 {
			with = append(with, c.Path[0])
		}
	}
	return fmt.Sprintf("--json is not supported for %q (supported: %s)", cmd, strings.Join(with, ", "))
}
