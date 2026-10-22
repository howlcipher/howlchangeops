//go:build !cgo

package authority

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWithoutCGORefusesAuthorityStorage(t *testing.T) {
	dir := privateDir(t)
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	ledger, err := CreateLedger(filepath.Join(dir, "ledger.sqlite"), "synthetic/generation-1")
	if ledger != nil || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("CGO-disabled storage must fail closed: %v %v", ledger, err)
	}
}
