package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Exercise the real public structured CLI without credentials or side effects.
func TestModelBUnavailableFailsClosedBeforeLegacyPaths(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "howlchangeops")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	for _, mode := range []string{"model_b", "unknown"} {
		for _, command := range []string{"approve", "execute"} {
			t.Run(mode+"/"+command, func(t *testing.T) {
				dir := t.TempDir()
				config := `{"authorization_model":"` + mode + `","repos":{}}`
				if err := os.WriteFile(filepath.Join(dir, "howlchangeops.json"), []byte(config), 0600); err != nil {
					t.Fatal(err)
				}
				cmd := exec.Command(bin, command, "synthetic-decision", "--owner-confirmed", "--json")
				cmd.Dir = dir
				cmd.Env = append(os.Environ(), "HOWLCHANGEOPS_CONFIG="+filepath.Join(dir, "howlchangeops.json"), "HOWLCHANGEOPS_BASE="+filepath.Join(dir, "state"))
				out, err := cmd.Output()
				if err == nil {
					t.Fatal("protected command unexpectedly succeeded")
				}
				var result struct {
					Status string `json:"status"`
					Error  struct {
						Code string `json:"code"`
					} `json:"error"`
				}
				if err := json.Unmarshal(out, &result); err != nil {
					t.Fatalf("result: %v %s", err, out)
				}
				want := "INDEPENDENT_AUTHORIZATION_UNAVAILABLE"
				if mode == "unknown" {
					want = "AUTHORIZATION_MODEL_INVALID"
				}
				if result.Error.Code != want || result.Status != "blocked" {
					t.Fatalf("got %+v; want blocked %s", result, want)
				}
			})
		}
	}
}
