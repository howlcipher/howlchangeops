//go:build cgo

package authority

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestLedgerRejectsUnsafePathsAndMismatchedGeneration(t *testing.T) {
	dir := privateDir(t)
	for _, path := range []string{":memory:", "file:memory?mode=memory", filepath.Join(dir, "db.sqlite") + "?mode=memory", "relative.sqlite"} {
		if l, err := OpenLedger(path, "synthetic/generation-1"); err == nil {
			l.Close()
			t.Fatalf("unsafe path accepted: %q", path)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "public"), 0755); err != nil {
		t.Fatal(err)
	}
	if l, err := OpenLedger(filepath.Join(dir, "public", "ledger.sqlite"), "synthetic/generation-1"); err == nil {
		l.Close()
		t.Fatal("unprotected directory accepted")
	}
	if err := os.WriteFile(filepath.Join(dir, "actual"), []byte{}, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "actual"), filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if l, err := OpenLedger(filepath.Join(dir, "link"), "synthetic/generation-1"); err == nil {
		l.Close()
		t.Fatal("symlink database accepted")
	}
	path := filepath.Join(dir, "ledger.sqlite")
	l := createFixture(t, path)
	if alternate, err := OpenLedger(path, "synthetic/generation-2"); err == nil {
		alternate.Close()
		t.Fatal("generation mismatch accepted")
	}
	if _, err := l.db.Exec("PRAGMA user_version=999"); err != nil {
		t.Fatal(err)
	}
	if alternate, err := OpenLedger(path, "synthetic/generation-1"); err == nil {
		alternate.Close()
		t.Fatal("unknown migration version accepted")
	}
}

func TestCorruptPersistedBindingOrReceiptFailsClosed(t *testing.T) {
	for _, kind := range []string{"request", "receipt", "receipt-binding", "receipt-owner", "authorization", "oversized-receipt"} {
		t.Run(kind, func(t *testing.T) {
			l := createFixture(t, filepath.Join(privateDir(t), "ledger.sqlite"))
			request := fixtureRequest()
			envelope := fixtureEnvelope(t, request, "approval-1", 1)
			var calls atomic.Int32
			executor := fixtureExecutor(t, l, nil, func(context.Context, Request, string) (json.RawMessage, error) {
				calls.Add(1)
				return json.RawMessage(`{"synthetic":true}`), nil
			})
			if _, err := executor.Execute(context.Background(), envelope, request); err != nil {
				t.Fatal(err)
			}
			var err error
			switch kind {
			case "request":
				_, err = l.db.Exec("UPDATE operations SET request_json=?", []byte(`{"tampered":true}`))
			case "receipt":
				_, err = l.db.Exec("UPDATE operations SET receipt=?", []byte(`{}`))
			case "authorization":
				_, err = l.db.Exec("UPDATE authorizations SET envelope=?", []byte(`{}`))
			case "oversized-receipt":
				data := []byte(strings.Repeat("x", MaxReceiptBytes+1))
				_, err = l.db.Exec("UPDATE operations SET receipt=?,receipt_digest=?", data, hash(data))
			case "receipt-binding", "receipt-owner":
				var raw []byte
				if err := l.db.QueryRow("SELECT receipt FROM operations").Scan(&raw); err != nil {
					t.Fatal(err)
				}
				var receipt Receipt
				if err := json.Unmarshal(raw, &receipt); err != nil {
					t.Fatal(err)
				}
				if kind == "receipt-binding" {
					receipt.RequestDigest = strings.Repeat("e", 64)
				} else {
					receipt.Owner = "other-owner"
				}
				data, err := json.Marshal(receipt)
				if err != nil {
					t.Fatal(err)
				}
				_, err = l.db.Exec("UPDATE operations SET receipt=?,receipt_digest=?", data, hash(data))
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := executor.Execute(context.Background(), envelope, request); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("corrupt persisted record accepted: %v", err)
			}
			if calls.Load() != 1 {
				t.Fatal("corrupt ledger caused effect")
			}
		})
	}
}

func TestUnavailableDatabaseAndBoundedRecordCountRefuseDispatch(t *testing.T) {
	for _, kind := range []string{"closed", "capacity"} {
		t.Run(kind, func(t *testing.T) {
			l := createFixture(t, filepath.Join(privateDir(t), "ledger.sqlite"))
			var calls atomic.Int32
			executor := fixtureExecutor(t, l, nil, func(context.Context, Request, string) (json.RawMessage, error) {
				calls.Add(1)
				return json.RawMessage(`{}`), nil
			})
			if kind == "closed" {
				l.Close()
			} else {
				_, err := l.db.Exec(`WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<?) INSERT INTO operations(operation_id,request_json,request_digest,execution_approval_id,status,created_at) SELECT 'synthetic-filled-'||x,x'', 'unused','unused','RESERVED','synthetic' FROM n`, maxRecords)
				if err != nil {
					t.Fatal(err)
				}
			}
			request := fixtureRequest()
			if _, err := executor.Execute(context.Background(), fixtureEnvelope(t, request, "approval-1", 1), request); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("storage unavailable accepted: %v", err)
			}
			if calls.Load() != 0 {
				t.Fatal("effect occurred without durable reservation")
			}
		})
	}
}

func TestWritableAncestorCannotReplacePrivateLedgerDirectory(t *testing.T) {
	root := privateDir(t)
	intermediate := filepath.Join(root, "untrusted")
	if err := os.Mkdir(intermediate, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(intermediate, 0777); err != nil {
		t.Fatal(err)
	}
	leaf := filepath.Join(intermediate, "private")
	if err := os.Mkdir(leaf, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(leaf, 0700); err != nil {
		t.Fatal(err)
	}
	if ledger, err := CreateLedger(filepath.Join(leaf, "ledger.sqlite"), "synthetic/generation-1"); err == nil {
		ledger.Close()
		t.Fatal("writable ancestor accepted despite private leaf")
	}
	if _, err := os.Lstat(filepath.Join(leaf, "ledger.sqlite")); !os.IsNotExist(err) {
		t.Fatal("unsafe path created a database")
	}
}

func TestMissingReplayTablesCannotBeReinitializedAsFresh(t *testing.T) {
	path := filepath.Join(privateDir(t), "ledger.sqlite")
	ledger := createFixture(t, path)
	if _, err := ledger.db.Exec("DROP TABLE authorizations; DROP TABLE operations"); err != nil {
		t.Fatal(err)
	}
	if reopened, err := OpenLedger(path, "synthetic/generation-1"); err == nil {
		reopened.Close()
		t.Fatal("damaged replay schema was recreated as fresh")
	}
	var count int
	if err := ledger.db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='operations'").Scan(&count); err != nil || count != 0 {
		t.Fatalf("damaged ledger modified: %d %v", count, err)
	}
}

func TestMissingOrEmptyReplayDatabaseNeverReinitializesAtRuntime(t *testing.T) {
	for _, kind := range []string{"missing", "truncated", "empty-schema"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(privateDir(t), "ledger.sqlite")
			ledger := createFixture(t, path)
			request := fixtureRequest()
			envelope := fixtureEnvelope(t, request, "approval-1", 1)
			var calls atomic.Int32
			run := func(context.Context, Request, string) (json.RawMessage, error) {
				calls.Add(1)
				return json.RawMessage(`{"once":true}`), nil
			}
			if _, err := fixtureExecutor(t, ledger, nil, run).Execute(context.Background(), envelope, request); err != nil {
				t.Fatal(err)
			}
			if err := ledger.Close(); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "missing":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "truncated":
				if err := os.Truncate(path, 0); err != nil {
					t.Fatal(err)
				}
			case "empty-schema":
				// Replace lost application state with a valid SQLite file containing no
				// authority schema; runtime must refuse rather than migrate it as fresh.
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				db, err := sql.Open("sqlite3", path)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := db.Exec("PRAGMA user_version=0; VACUUM"); err != nil {
					db.Close()
					t.Fatal(err)
				}
				db.Close()
				if err := os.Chmod(path, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if reopened, err := OpenLedger(path, "synthetic/generation-1"); !errors.Is(err, ErrUnavailable) || reopened != nil {
				if reopened != nil {
					reopened.Close()
				}
				t.Fatalf("lost replay state accepted: %v", err)
			}
			if calls.Load() != 1 {
				t.Fatal("previously valid approval redispatched")
			}
			if kind == "missing" {
				if _, err := os.Lstat(path); !os.IsNotExist(err) {
					t.Fatal("runtime recreated missing ledger")
				}
			}
		})
	}
}

func TestExplicitCreateIsExclusiveAndNeverResetsExistingState(t *testing.T) {
	path := filepath.Join(privateDir(t), "ledger.sqlite")
	ledger := createFixture(t, path)
	request := fixtureRequest()
	envelope := fixtureEnvelope(t, request, "approval-1", 1)
	if _, err := fixtureExecutor(t, ledger, nil, nil).Execute(context.Background(), envelope, request); err != nil {
		t.Fatal(err)
	}
	if second, err := CreateLedger(path, "synthetic/generation-1"); !errors.Is(err, ErrUnavailable) || second != nil {
		if second != nil {
			second.Close()
		}
		t.Fatal("setup reset existing ledger")
	}
	ledger.Close()
	reopened := openFixture(t, path)
	var count int
	if err := reopened.db.QueryRow("SELECT count(*) FROM operations").Scan(&count); err != nil || count != 1 {
		t.Fatalf("existing state changed: %d %v", count, err)
	}
}

func TestOpenHandleCannotDispatchAfterLedgerPathLossOrReplacement(t *testing.T) {
	for _, kind := range []string{"removed-before-call", "replaced-before-call", "removed-before-dispatch"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(privateDir(t), "ledger.sqlite")
			ledger := createFixture(t, path)
			var calls atomic.Int32
			loads := 0
			state := func(context.Context) (Snapshot, error) {
				loads++
				if kind == "removed-before-dispatch" && loads == 2 {
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
				}
				return fixtureSnapshot(), nil
			}
			executor := fixtureExecutor(t, ledger, state, func(context.Context, Request, string) (json.RawMessage, error) {
				calls.Add(1)
				return json.RawMessage(`{}`), nil
			})
			if kind == "removed-before-call" || kind == "replaced-before-call" {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if kind == "replaced-before-call" {
					if err := os.WriteFile(path, []byte("synthetic replacement"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			request := fixtureRequest()
			if _, err := executor.Execute(context.Background(), fixtureEnvelope(t, request, "approval-1", 1), request); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("lost live ledger accepted: %v", err)
			}
			if calls.Load() != 0 {
				t.Fatal("effect occurred with lost/replaced ledger")
			}
		})
	}
}

func TestMalformedVersionOneSchemaRefusesAtOpen(t *testing.T) {
	path := filepath.Join(privateDir(t), "ledger.sqlite")
	ledger := createFixture(t, path)
	if _, err := ledger.db.Exec("DROP TABLE authorizations; CREATE TABLE authorizations(incorrect TEXT)"); err != nil {
		t.Fatal(err)
	}
	if opened, err := OpenLedger(path, "synthetic/generation-1"); err == nil {
		opened.Close()
		t.Fatal("malformed v1 schema accepted")
	}
}
