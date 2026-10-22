package authority

import (
	"bytes"
	"context"
	"encoding/json"
	"time"
	"unicode/utf8"

	"howlchangeops/internal/approval"
)

// Snapshot is loaded from protected enrollment/authenticator-health/clock state,
// twice per new dispatch. It must be an atomic independent copy, not a map being
// concurrently modified. SignerAvailable is an explicit fail-closed prerequisite;
// no local prompt, environment flag or caller key can establish this state.
type Snapshot struct {
	Enrolled        map[string]approval.Enrollment
	Now             time.Time
	SignerAvailable bool
}
type StateSource func(context.Context) (Snapshot, error)

// Adapter is a fixed, reviewed action implementation, never code or shell
// commands from a request/repository. Validate must be pure. Run must honor the
// deadline and enforce bounded subprocesses/output if it uses them. It receives
// the signed semantic operation ID for external idempotency where available.
// An error/panic/cancellation never releases authorization for automatic retry.
type Adapter struct {
	Validate func(Request) error
	Run      func(context.Context, Request, string) (json.RawMessage, error)
}
type Executor struct {
	ledger   *Ledger
	state    StateSource
	adapters map[string]Adapter
}

func NewExecutor(ledger *Ledger, state StateSource, adapters map[string]Adapter) (*Executor, error) {
	if ledger == nil || ledger.db == nil || state == nil || len(adapters) == 0 {
		return nil, ErrInvalid
	}
	copyAdapters := make(map[string]Adapter, len(adapters))
	for action, adapter := range adapters {
		if action == "" || adapter.Validate == nil || adapter.Run == nil {
			return nil, ErrInvalid
		}
		copyAdapters[action] = adapter
	}
	return &Executor{ledger: ledger, state: state, adapters: copyAdapters}, nil
}

// Execute is not connected to any production CLI/API entry point. Deployment
// must route every protected path here under an independently protected executor
// principal and remove alternate credentials/direct action access from agents.
func (e *Executor) Execute(ctx context.Context, envelope []byte, request Request) (Receipt, error) {
	if ctx == nil || len(envelope) > approval.MaxEnvelopeBytes {
		return Receipt{}, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	envelope = bytes.TrimSpace(append([]byte(nil), envelope...))
	request, data, digest, err := normalize(request)
	if err != nil || request.Binding.Audience != e.ledger.audience {
		return Receipt{}, ErrInvalid
	}
	adapter, ok := e.adapters[request.Binding.Action]
	if !ok || validate(adapter, request) != nil {
		return Receipt{}, ErrInvalid
	}
	first, err := e.state(ctx)
	if err != nil || !first.SignerAvailable || ctx.Err() != nil {
		return Receipt{}, ErrUnavailable
	}
	verified, err := approval.Verify(envelope, first.Enrolled, request.Binding, first.Now)
	if err != nil || len(verified.Owner) > 1024 || !utf8.ValidString(verified.Owner) {
		return Receipt{}, ErrInvalid
	}
	reservation, prior, err := e.ledger.reserve(ctx, request, data, digest, envelope, verified, first.Now)
	if err != nil {
		return Receipt{}, err
	}
	if prior != nil {
		return *prior, nil
	}
	// From this point, every error/crash is consumed even if no effect occurred.
	// Keeping RESERVED on storage failure is sufficient to refuse redispatch.
	succeeded := false
	defer func() {
		if !succeeded {
			e.ledger.uncertain(context.Background(), reservation, time.Now())
		}
	}()
	second, err := e.state(ctx)
	if err != nil || !second.SignerAvailable || ctx.Err() != nil || !e.ledger.available() {
		return Receipt{}, ErrUnavailable
	}
	again, err := approval.Verify(envelope, second.Enrolled, request.Binding, second.Now)
	if err != nil || again.Owner != verified.Owner {
		return Receipt{}, ErrInvalid
	}
	_, currentData, currentDigest, err := normalize(request)
	if err != nil || !bytes.Equal(currentData, data) || currentDigest != digest || validate(adapter, request) != nil {
		return Receipt{}, ErrInvalid
	}
	started := time.Now()
	payload, err := runAdapter(ctx, adapter, request)
	if err != nil || ctx.Err() != nil || len(payload) > MaxReceiptBytes/2 || !json.Valid(payload) || !utf8.Valid(payload) {
		return Receipt{}, ErrAdapter
	}
	receipt := Receipt{OperationID: request.Binding.DecisionID, ApprovalID: verified.Claims.ApprovalID, Owner: verified.Owner, RequestDigest: digest, Payload: payload}
	if err = e.ledger.complete(ctx, reservation, receipt, second.Now.Add(time.Since(started))); err != nil {
		return Receipt{}, err
	}
	succeeded = true
	return receipt, nil
}
func runAdapter(ctx context.Context, adapter Adapter, request Request) (payload json.RawMessage, err error) {
	defer func() {
		if recover() != nil {
			payload = nil
			err = ErrAdapter
		}
	}()
	return adapter.Run(ctx, request, request.Binding.DecisionID)
}

func validate(adapter Adapter, request Request) error {
	// Prevent an accidental validator mutation from changing signed parameters
	// after their digest was checked. Implementations still must be pure.
	request.Parameters = append(json.RawMessage(nil), request.Parameters...)
	return adapter.Validate(request)
}
