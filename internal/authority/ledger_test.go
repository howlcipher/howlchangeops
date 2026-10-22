//go:build cgo

package authority

import (
	"path/filepath"
	"testing"
)

func TestPersistentAuthorityLedgerAvailable(t *testing.T) {
	ledger, err := CreateLedger(filepath.Join(privateDir(t), "ledger.sqlite"), "synthetic-executor/generation-1")
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
}
