// Package authority is a protected-executor foundation, not a deployed trust
// boundary. Its storage, code, enrollment, clock and fixed adapters must be
// outside the agent principal's administrative and credential reach.
package authority

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"

	"howlchangeops/internal/approval"
)

const MaxParametersBytes = 16384
const MaxRequestBytes = 32768
const MaxReceiptBytes = 65536

var (
	ErrUnavailable = errors.New("protected authority unavailable")
	ErrInvalid     = errors.New("protected request invalid")
	ErrConflict    = errors.New("protected operation or authorization conflicts")
	ErrUncertain   = errors.New("operation already reserved or uncertain; reconciliation required")
	ErrAdapter     = errors.New("protected adapter failed; authorization remains consumed")
)

// DecisionID is the globally unique semantic operation ID. It is signed as part
// of Binding. Never generate a new ID merely to retry an uncertain operation.
type Request struct {
	Binding    approval.Binding `json:"binding"`
	Parameters json.RawMessage  `json:"parameters"`
}

// Hash returns the lowercase hex sha256 digest of data.
func Hash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func hash(data []byte) string {
	return Hash(data)
}

// CanonicalParameters rejects duplicate keys, excessive nesting, nonobjects and
// ambiguous encodings before hashing. The trusted signer/display must use the
// same representation; no arbitrary request bytes become executable commands.
func CanonicalParameters(raw []byte) ([]byte, error) {
	if len(raw) == 0 || len(raw) > MaxParametersBytes || !utf8.Valid(raw) {
		return nil, ErrInvalid
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	budget := 4096
	value, err := jsonValue(dec, 0, &budget)
	if err != nil {
		return nil, ErrInvalid
	}
	if _, ok := value.(map[string]any); !ok {
		return nil, ErrInvalid
	}
	if _, err = dec.Token(); err != io.EOF {
		return nil, ErrInvalid
	}
	canonical, err := json.Marshal(value)
	if err != nil || len(canonical) > MaxParametersBytes {
		return nil, ErrInvalid
	}
	return canonical, nil
}
func jsonValue(dec *json.Decoder, depth int, budget *int) (any, error) {
	*budget--
	if depth > 16 || *budget < 0 {
		return nil, ErrInvalid
	}
	token, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch token {
	case json.Delim('{'):
		object := map[string]any{}
		for dec.More() {
			key, err := dec.Token()
			if err != nil {
				return nil, err
			}
			name, ok := key.(string)
			if !ok {
				return nil, ErrInvalid
			}
			if _, exists := object[name]; exists {
				return nil, ErrInvalid
			}
			value, err := jsonValue(dec, depth+1, budget)
			if err != nil {
				return nil, err
			}
			object[name] = value
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim('}') {
			return nil, ErrInvalid
		}
		return object, nil
	case json.Delim('['):
		array := []any{}
		for dec.More() {
			value, err := jsonValue(dec, depth+1, budget)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim(']') {
			return nil, ErrInvalid
		}
		return array, nil
	}
	if _, ok := token.(json.Delim); ok {
		return nil, ErrInvalid
	}
	return token, nil
}

func normalize(request Request) (Request, []byte, string, error) {
	for _, value := range []string{request.Binding.Audience, request.Binding.DecisionID, request.Binding.DecisionDigest, request.Binding.EvidenceDigest, request.Binding.Target, request.Binding.Action, request.Binding.Revision, request.Binding.ParametersDigest} {
		if len(value) > 1024 {
			return Request{}, nil, "", ErrInvalid
		}
	}
	params, err := CanonicalParameters(request.Parameters)
	if err != nil || hash(params) != request.Binding.ParametersDigest {
		return Request{}, nil, "", ErrInvalid
	}
	request.Parameters = params
	data, err := json.Marshal(request)
	if err != nil || len(data) > MaxRequestBytes {
		return Request{}, nil, "", ErrInvalid
	}
	return request, data, hash(data), nil
}
