//go:build cgo

package authority

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"howlchangeops/internal/approval"
)

var fixtureTime = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
var fixtureKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))

func fixtureRequest() Request {
	return Request{Binding: approval.Binding{Audience: "synthetic/generation-1", DecisionID: "operation-1", DecisionDigest: strings.Repeat("a", 64), EvidenceDigest: strings.Repeat("b", 64), Target: "synthetic/repo", Action: "synthetic_action", Revision: strings.Repeat("c", 40), ParametersDigest: hash([]byte(`{"value":"synthetic"}`))}, Parameters: json.RawMessage(`{"value":"synthetic"}`)}
}
func fixtureEnvelope(t *testing.T, request Request, id string, nonce byte) []byte {
	t.Helper()
	claims := approval.Claims{Schema: approval.Schema, KeyID: "synthetic-key", ApprovalID: id, Nonce: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{nonce}, 32)), IssuedAt: fixtureTime.Add(-time.Minute).Format(time.RFC3339), ExpiresAt: fixtureTime.Add(time.Minute).Format(time.RFC3339), Binding: request.Binding}
	envelope := approval.Envelope{Claims: claims, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(fixtureKey, approval.SigningBytes(claims)))}
	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func fixtureSnapshot() Snapshot {
	return Snapshot{Enrolled: map[string]approval.Enrollment{"synthetic-key": {Owner: "synthetic-owner", PublicKey: fixtureKey.Public().(ed25519.PublicKey)}}, Now: fixtureTime, SignerAvailable: true}
}
func fixtureExecutor(t *testing.T, l *Ledger, load StateSource, run func(context.Context, Request, string) (json.RawMessage, error)) *Executor {
	t.Helper()
	if load == nil {
		load = func(context.Context) (Snapshot, error) { return fixtureSnapshot(), nil }
	}
	if run == nil {
		run = func(context.Context, Request, string) (json.RawMessage, error) {
			return json.RawMessage(`{"synthetic":true}`), nil
		}
	}
	executor, err := NewExecutor(l, load, map[string]Adapter{"synthetic_action": {Validate: func(r Request) error {
		if r.Binding.Target != "synthetic/repo" {
			return ErrInvalid
		}
		return nil
	}, Run: run}})
	if err != nil {
		t.Fatal(err)
	}
	return executor
}
func createFixture(t *testing.T, path string) *Ledger {
	t.Helper()
	l, err := CreateLedger(path, "synthetic/generation-1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

func TestPersistentReopenAndResignedSemanticOperationDoNotRepeat(t *testing.T) {
	path := filepath.Join(privateDir(t), "ledger.sqlite")
	l := createFixture(t, path)
	request := fixtureRequest()
	envelope := fixtureEnvelope(t, request, "approval-1", 1)
	var calls atomic.Int32
	run := func(context.Context, Request, string) (json.RawMessage, error) {
		calls.Add(1)
		return json.RawMessage(`{"effect":"once"}`), nil
	}
	first, err := fixtureExecutor(t, l, nil, run).Execute(context.Background(), envelope, request)
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
	l = openFixture(t, path)
	executor := fixtureExecutor(t, l, nil, run)
	for _, data := range [][]byte{envelope, fixtureEnvelope(t, request, "approval-2", 2)} {
		prior, err := executor.Execute(context.Background(), data, request)
		if err != nil || string(prior.Payload) != string(first.Payload) || prior.ApprovalID != "approval-1" {
			t.Fatalf("prior receipt: %+v %v", prior, err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("effects=%d", calls.Load())
	}
	var count int
	if err := l.db.QueryRow("SELECT count(*) FROM authorizations").Scan(&count); err != nil || count != 2 {
		t.Fatalf("new signed identifier not consumed: %d %v", count, err)
	}
}

func TestConcurrentLedgerHandlesDispatchOnce(t *testing.T) {
	path := filepath.Join(privateDir(t), "ledger.sqlite")
	a := createFixture(t, path)
	b := openFixture(t, path)
	var calls atomic.Int32
	run := func(context.Context, Request, string) (json.RawMessage, error) {
		calls.Add(1)
		time.Sleep(30 * time.Millisecond)
		return json.RawMessage(`{"once":true}`), nil
	}
	executors := []*Executor{fixtureExecutor(t, a, nil, run), fixtureExecutor(t, b, nil, run)}
	request := fixtureRequest()
	envelope := fixtureEnvelope(t, request, "approval-1", 1)
	var wg sync.WaitGroup
	errorsOut := make(chan error, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := executors[i%2].Execute(context.Background(), envelope, request)
			errorsOut <- err
		}(i)
	}
	wg.Wait()
	close(errorsOut)
	for err := range errorsOut {
		if err != nil && !errors.Is(err, ErrUncertain) {
			t.Fatal(err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("concurrent effects=%d", calls.Load())
	}
}

func TestApprovalAndNonceAndOperationCollisionsRefused(t *testing.T) {
	for _, kind := range []string{"approval", "nonce", "operation"} {
		t.Run(kind, func(t *testing.T) {
			l := createFixture(t, filepath.Join(privateDir(t), "ledger.sqlite"))
			executor := fixtureExecutor(t, l, nil, nil)
			request := fixtureRequest()
			if _, err := executor.Execute(context.Background(), fixtureEnvelope(t, request, "approval-1", 1), request); err != nil {
				t.Fatal(err)
			}
			id, nonce := "approval-2", byte(2)
			switch kind {
			case "approval":
				id = "approval-1"
				request.Binding.DecisionID = "operation-2"
			case "nonce":
				nonce = 1
				request.Binding.DecisionID = "operation-2"
			case "operation":
				request.Parameters = json.RawMessage(`{"different":true}`)
				request.Binding.ParametersDigest = hash(request.Parameters)
			}
			if _, err := executor.Execute(context.Background(), fixtureEnvelope(t, request, id, nonce), request); !errors.Is(err, ErrConflict) {
				t.Fatalf("collision accepted: %v", err)
			}
		})
	}
}

func TestFailedOrUncertainExecutionAlwaysConsumes(t *testing.T) {
	for _, kind := range []string{"error", "panic", "invalid-json", "oversized", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			l := createFixture(t, filepath.Join(privateDir(t), "ledger.sqlite"))
			var calls atomic.Int32
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			executor := fixtureExecutor(t, l, nil, func(context.Context, Request, string) (json.RawMessage, error) {
				calls.Add(1)
				switch kind {
				case "panic":
					panic("synthetic panic, never diagnostics")
				case "invalid-json":
					return []byte("invalid"), nil
				case "oversized":
					return json.RawMessage(`"` + strings.Repeat("x", MaxReceiptBytes) + `"`), nil
				case "cancel":
					cancel()
					return json.RawMessage(`{}`), nil
				}
				return nil, fmt.Errorf("synthetic sensitive diagnostic never exposed")
			})
			request := fixtureRequest()
			envelope := fixtureEnvelope(t, request, "approval-1", 1)
			if _, err := executor.Execute(ctx, envelope, request); !errors.Is(err, ErrAdapter) {
				t.Fatalf("failed dispatch: %v", err)
			}
			if _, err := executor.Execute(context.Background(), envelope, request); !errors.Is(err, ErrUncertain) {
				t.Fatalf("retry was not refused: %v", err)
			}
			if calls.Load() != 1 {
				t.Fatalf("effects=%d", calls.Load())
			}
		})
	}
}

func TestExpiryRevocationAndSignerUnavailableRecheckedAfterReservation(t *testing.T) {
	for _, kind := range []string{"expiry", "revocation", "unavailable", "identity"} {
		t.Run(kind, func(t *testing.T) {
			l := createFixture(t, filepath.Join(privateDir(t), "ledger.sqlite"))
			loads := 0
			var effects atomic.Int32
			load := func(context.Context) (Snapshot, error) {
				loads++
				state := fixtureSnapshot()
				if loads >= 2 {
					switch kind {
					case "expiry":
						state.Now = fixtureTime.Add(time.Minute)
					case "revocation":
						key := state.Enrolled["synthetic-key"]
						key.Revoked = true
						state.Enrolled["synthetic-key"] = key
					case "unavailable":
						state.SignerAvailable = false
					case "identity":
						key := state.Enrolled["synthetic-key"]
						key.Owner = "other"
						state.Enrolled["synthetic-key"] = key
					}
				}
				return state, nil
			}
			executor := fixtureExecutor(t, l, load, func(context.Context, Request, string) (json.RawMessage, error) {
				effects.Add(1)
				return json.RawMessage(`{}`), nil
			})
			request := fixtureRequest()
			envelope := fixtureEnvelope(t, request, "approval-1", 1)
			if _, err := executor.Execute(context.Background(), envelope, request); err == nil {
				t.Fatal("changed authorization dispatched")
			}
			if effects.Load() != 0 {
				t.Fatal("effect occurred")
			}
			var status string
			if err := l.db.QueryRow("SELECT status FROM operations").Scan(&status); err != nil || status != "UNKNOWN" {
				t.Fatalf("reservation released: %s %v", status, err)
			}
		})
	}
}

func TestRequestMismatchAndBadSignatureFailBeforeReservation(t *testing.T) {
	for _, kind := range []string{"parameters", "target", "audience", "signature", "expired", "missing-signer", "unknown-action"} {
		t.Run(kind, func(t *testing.T) {
			l := createFixture(t, filepath.Join(privateDir(t), "ledger.sqlite"))
			request := fixtureRequest()
			envelope := fixtureEnvelope(t, request, "approval-1", 1)
			state := fixtureSnapshot()
			switch kind {
			case "parameters":
				request.Parameters = []byte(`{"tampered":true}`)
			case "target":
				request.Binding.Target = "other/repo"
			case "audience":
				request.Binding.Audience = "other/generation"
			case "signature":
				envelope = bytes.Replace(envelope, []byte("synthetic-key"), []byte("missing-key"), 1)
			case "expired":
				state.Now = fixtureTime.Add(time.Minute)
			case "missing-signer":
				state.SignerAvailable = false
			case "unknown-action":
				request.Binding.Action = "unconfigured"
			}
			executor := fixtureExecutor(t, l, func(context.Context) (Snapshot, error) { return state, nil }, nil)
			if _, err := executor.Execute(context.Background(), envelope, request); err == nil {
				t.Fatal("invalid request accepted")
			}
			var count int
			if err := l.db.QueryRow("SELECT count(*) FROM operations").Scan(&count); err != nil || count != 0 {
				t.Fatalf("invalid request reserved: %d %v", count, err)
			}
		})
	}
}

// This child process exits after a durable reservation or a synthetic effect,
// deliberately bypassing defers; parent tests reopen actual SQLite storage.
func TestAuthorityCrashFixture(t *testing.T) {
	mode := os.Getenv("HOWL_SYNTHETIC_CRASH_MODE")
	if mode == "" {
		return
	}
	path := os.Getenv("HOWL_SYNTHETIC_LEDGER")
	l, err := OpenLedger(path, "synthetic/generation-1")
	if err != nil {
		t.Fatal(err)
	}
	request := fixtureRequest()
	envelope := fixtureEnvelope(t, request, "approval-1", 1)
	if mode == "reserved" {
		normalized, data, digest, err := normalize(request)
		if err != nil {
			t.Fatal(err)
		}
		verified, err := approval.Verify(envelope, fixtureSnapshot().Enrolled, request.Binding, fixtureTime)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := l.reserve(context.Background(), normalized, data, digest, envelope, verified, fixtureTime); err != nil {
			t.Fatal(err)
		}
		os.Exit(71)
	}
	executor := fixtureExecutor(t, l, nil, func(context.Context, Request, string) (json.RawMessage, error) {
		if err := os.WriteFile(filepath.Join(filepath.Dir(path), "synthetic-effect"), []byte("once"), 0600); err != nil {
			t.Fatal(err)
		}
		os.Exit(72)
		return nil, nil
	})
	executor.Execute(context.Background(), envelope, request)
	t.Fatal("crash fixture returned")
}
func TestProcessCrashBeforeReceiptNeverRedispatches(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"reserved", "effect"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(privateDir(t), "ledger.sqlite")
			provisioned := createFixture(t, path)
			provisioned.Close()
			child := exec.Command(binary, "-test.run=^TestAuthorityCrashFixture$")
			child.Env = append(os.Environ(), "HOWL_SYNTHETIC_CRASH_MODE="+mode, "HOWL_SYNTHETIC_LEDGER="+path)
			output, err := child.CombinedOutput()
			var exit *exec.ExitError
			want := 71
			if mode == "effect" {
				want = 72
			}
			if !errors.As(err, &exit) || exit.ExitCode() != want {
				t.Fatalf("child: %v %s", err, output)
			}
			l := openFixture(t, path)
			var calls atomic.Int32
			executor := fixtureExecutor(t, l, nil, func(context.Context, Request, string) (json.RawMessage, error) {
				calls.Add(1)
				return json.RawMessage(`{}`), nil
			})
			request := fixtureRequest()
			if _, err := executor.Execute(context.Background(), fixtureEnvelope(t, request, "approval-1", 1), request); !errors.Is(err, ErrUncertain) {
				t.Fatalf("crashed operation retried: %v", err)
			}
			if calls.Load() != 0 {
				t.Fatal("crashed operation dispatched")
			}
			if mode == "effect" {
				if data, err := os.ReadFile(filepath.Join(filepath.Dir(path), "synthetic-effect")); err != nil || string(data) != "once" {
					t.Fatalf("effect evidence: %s %v", data, err)
				}
			}
		})
	}
}

func TestAuthorityConcurrentFixture(t *testing.T) {
	path := os.Getenv("HOWL_SYNTHETIC_CONCURRENT_LEDGER")
	if path == "" {
		return
	}
	ledger, err := OpenLedger(path, "synthetic/generation-1")
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	executor := fixtureExecutor(t, ledger, nil, func(context.Context, Request, string) (json.RawMessage, error) {
		file, err := os.OpenFile(filepath.Join(filepath.Dir(path), "concurrent-effect"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal("second synthetic effect attempted")
		}
		if _, err := file.Write([]byte("once")); err != nil {
			t.Fatal(err)
		}
		file.Close()
		time.Sleep(75 * time.Millisecond)
		return json.RawMessage(`{"once":true}`), nil
	})
	request := fixtureRequest()
	_, err = executor.Execute(context.Background(), fixtureEnvelope(t, request, "approval-1", 1), request)
	if errors.Is(err, ErrUncertain) {
		os.Exit(73)
	}
	if err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentProcessesShareOneDurableReservation(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(privateDir(t), "ledger.sqlite")
	provisioned := createFixture(t, path)
	provisioned.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			child := exec.CommandContext(ctx, binary, "-test.run=^TestAuthorityConcurrentFixture$")
			child.Env = append(os.Environ(), "HOWL_SYNTHETIC_CONCURRENT_LEDGER="+path)
			output, err := child.CombinedOutput()
			var exit *exec.ExitError
			if err != nil && (!errors.As(err, &exit) || exit.ExitCode() != 73) {
				results <- fmt.Errorf("synthetic process failed: %w %s", err, output)
			} else {
				results <- nil
			}
		}()
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(path), "concurrent-effect"))
	if err != nil || string(data) != "once" {
		t.Fatalf("effect evidence: %s %v", data, err)
	}
	ledger := openFixture(t, path)
	var calls atomic.Int32
	executor := fixtureExecutor(t, ledger, nil, func(context.Context, Request, string) (json.RawMessage, error) {
		calls.Add(1)
		return json.RawMessage(`{}`), nil
	})
	request := fixtureRequest()
	if _, err := executor.Execute(context.Background(), fixtureEnvelope(t, request, "approval-1", 1), request); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Fatal("process retry duplicated effect")
	}
}

func openFixture(t *testing.T, path string) *Ledger {
	t.Helper()
	ledger, err := OpenLedger(path, "synthetic/generation-1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ledger.Close() })
	return ledger
}
