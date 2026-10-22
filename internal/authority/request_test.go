package authority

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestCanonicalParametersStrictBoundedObjects(t *testing.T) {
	for _, raw := range [][]byte{[]byte(`{"duplicate":1,"duplicate":2}`), []byte(`[]`), []byte(`null`), []byte(`{"x":1} {}`), []byte(`{"x":NaN}`), bytes.Repeat([]byte("x"), MaxParametersBytes+1), []byte("{\"x\":\"\xff\"}")} {
		if _, err := CanonicalParameters(raw); err == nil {
			t.Fatalf("invalid parameters accepted, len=%d", len(raw))
		}
	}
	deep := []byte(`{"x":`)
	deep = append(deep, bytes.Repeat([]byte("["), 20)...)
	deep = append(deep, bytes.Repeat([]byte("]"), 20)...)
	deep = append(deep, '}')
	if _, err := CanonicalParameters(deep); err == nil {
		t.Fatal("excessively nested input accepted")
	}
	canonical, err := CanonicalParameters([]byte(` {"z": [true, 4], "a": "synthetic"} `))
	if err != nil || string(canonical) != `{"a":"synthetic","z":[true,4]}` {
		t.Fatalf("canonical: %s %v", canonical, err)
	}
}

func privateDir(t *testing.T) string {
	t.Helper()
	// The development container maps /tmp's owner to an unrelated UID. Keep
	// synthetic authority storage under a genuinely protected ancestry rather
	// than weaken the production guard to accommodate a mapped temp owner.
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(home, ".howl-authority-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestCanonicalExpansionCannotExceedStorageBudget(t *testing.T) {
	raw := []byte(`{"value":"` + strings.Repeat("<", MaxParametersBytes/4) + `"}`)
	if len(raw) > MaxParametersBytes {
		t.Fatal("fixture must fit raw input budget")
	}
	if _, err := CanonicalParameters(raw); err == nil {
		t.Fatal("JSON escaping bypassed canonical byte budget")
	}
}
