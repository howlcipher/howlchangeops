package authority

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"howlchangeops/internal/approval"
)

var (
	ErrReviewRejected = errors.New("operation review rejected by owner")
	ErrReviewTimeout  = errors.New("operation review timed out")
)

type ReviewSummary struct {
	DecisionID       string          `json:"decision_id"`
	Audience         string          `json:"audience"`
	Target           string          `json:"target"`
	Action           string          `json:"action"`
	Revision         string          `json:"revision"`
	EvidenceDigest   string          `json:"evidence_digest"`
	DecisionDigest   string          `json:"decision_digest"`
	ParametersDigest string          `json:"parameters_digest"`
	Parameters       json.RawMessage `json:"parameters"`
}

// ReviewRequest parses and verifies the proposal parameters and digests, returning an immutable review summary.
func ReviewRequest(req Request) (*ReviewSummary, error) {
	normReq, _, _, err := normalize(req)
	if err != nil {
		return nil, err
	}
	if normReq.Binding.ParametersDigest != hash(normReq.Parameters) {
		return nil, ErrInvalid
	}
	return &ReviewSummary{
		DecisionID:       normReq.Binding.DecisionID,
		Audience:         normReq.Binding.Audience,
		Target:           normReq.Binding.Target,
		Action:           normReq.Binding.Action,
		Revision:         normReq.Binding.Revision,
		EvidenceDigest:   normReq.Binding.EvidenceDigest,
		DecisionDigest:   normReq.Binding.DecisionDigest,
		ParametersDigest: normReq.Binding.ParametersDigest,
		Parameters:       normReq.Parameters,
	}, nil
}

// SignRequest authorizes a reviewed Request by signing an approval.Envelope with an Ed25519 private key.
func SignRequest(req Request, priv ed25519.PrivateKey, keyID string, ttl time.Duration) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize || keyID == "" {
		return nil, ErrInvalid
	}
	normReq, _, _, err := normalize(req)
	if err != nil {
		return nil, err
	}
	if ttl <= 0 || ttl > approval.MaxLifetime {
		ttl = 5 * time.Minute
	}
	now := time.Now().UTC()
	hashInput := fmt.Sprintf("%s-%s-%d", normReq.Binding.DecisionID, keyID, now.UnixNano())
	appHash := sha256.Sum256([]byte(hashInput))
	approvalID := fmt.Sprintf("app-%x", appHash[:8])

	nonceBytes := make([]byte, 32)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, err
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)

	claims := approval.Claims{
		Schema:     approval.Schema,
		KeyID:      keyID,
		ApprovalID: approvalID,
		Nonce:      nonce,
		IssuedAt:   now.Format(time.RFC3339),
		ExpiresAt:  now.Add(ttl).Format(time.RFC3339),
		Binding:    normReq.Binding,
	}

	signingBytes := approval.SigningBytes(claims)
	sig := ed25519.Sign(priv, signingBytes)
	sigStr := base64.RawURLEncoding.EncodeToString(sig)

	envelope := approval.Envelope{
		Claims:    claims,
		Signature: sigStr,
	}
	return json.Marshal(envelope)
}
