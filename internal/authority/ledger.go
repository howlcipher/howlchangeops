package authority

import (
	"bytes"
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"howlchangeops/internal/approval"
)

//go:embed schema.sql
var schema string

const maxRecords = 100000
const databaseTimeout = 3 * time.Second

// Ledger requires a protected, owner-only directory on a reliable local
// filesystem. It cannot defend against its own UID/root replacing the database,
// rolling back backups or modifying this code. Recovery must rotate audience
// generation outside that principal before accepting restored state.
type Ledger struct {
	db       *sql.DB
	audience string
	path     string
	identity os.FileInfo
}

// OpenLedger is runtime-only: missing, empty or uninitialized replay state is
// unavailable, never an invitation to start fresh under still-valid approvals.
func OpenLedger(path, audience string) (*Ledger, error) {
	return openLedger(path, audience, false)
}

// CreateLedger is explicit protected provisioning, not runtime recovery. It
// exclusively creates a new database and refuses every existing path. The owner
// must separately authenticate/authorize provisioning and choose a fresh audience
// generation after loss/restoration; this API does not prove that identity.
// Failed provisioning retains the created artifact for review, never resets it.
func CreateLedger(path, audience string) (*Ledger, error) {
	return openLedger(path, audience, true)
}

func openLedger(path, audience string, create bool) (*Ledger, error) {
	if err := checkCgoSupported(); err != nil {
		return nil, err
	}
	if err := checkPlatformSupported(); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "?#\x00") || audience == "" || len(audience) > 1024 || strings.TrimSpace(audience) != audience || strings.ContainsAny(audience, "\x00\r\n") {
		return nil, ErrInvalid
	}
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 || !owned(info) {
		return nil, ErrUnavailable
	}
	// Enforce protected physical ancestry. These checks cannot replace the
	// independent OS/administrative separation from the agent principal.
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil || resolved != parent {
		return nil, ErrUnavailable
	}
	for ancestor := parent; ; ancestor = filepath.Dir(ancestor) {
		info, err := os.Lstat(ancestor)
		if err != nil || !info.IsDir() || !protectedAncestor(info, ancestor) {
			return nil, ErrUnavailable
		}
		if ancestor == filepath.Dir(ancestor) {
			break
		}
	}
	if create {
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if err != nil {
			return nil, ErrUnavailable
		}
		if file.Close() != nil {
			return nil, ErrUnavailable
		}
	}
	info, err = os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !owned(info) || (!create && info.Size() == 0) {
		return nil, ErrUnavailable
	}
	uri := url.URL{Scheme: "file", Path: path}
	query := url.Values{"mode": {"rw"}, "_busy_timeout": {"1500"}, "_foreign_keys": {"on"}, "_journal_mode": {"WAL"}, "_synchronous": {"FULL"}, "_txlock": {"immediate"}}
	uri.RawQuery = query.Encode()
	db, err := sql.Open("sqlite3", uri.String())
	if err != nil {
		return nil, ErrUnavailable
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	fail := func() (*Ledger, error) { db.Close(); return nil, ErrUnavailable }
	ctx, cancel := context.WithTimeout(context.Background(), databaseTimeout)
	defer cancel()
	// Concurrent first opens can race while SQLite enters WAL mode, before
	// the driver's normal busy handler applies. Retry only BUSY/LOCKED within
	// the same bounded initialization deadline; never retry policy/corruption.
	for {
		err = initialize(ctx, db, audience, create)
		if err == nil {
			break
		}
		if !transientSQLite(err) {
			return fail()
		}
		select {
		case <-ctx.Done():
			return fail()
		case <-time.After(10 * time.Millisecond):
		}
	}
	directory, err := os.Open(parent)
	if err != nil {
		return fail()
	}
	err = directory.Sync()
	closeErr := directory.Close()
	if err != nil || closeErr != nil {
		return fail()
	}
	return &Ledger{db: db, audience: audience, path: path, identity: info}, nil
}
func initialize(ctx context.Context, db *sql.DB, audience string, create bool) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version int
	if err := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version != 0 && version != 1 {
		return ErrUnavailable
	}
	var tableCount int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").Scan(&tableCount); err != nil {
		return err
	}
	if create {
		if version != 0 {
			return ErrUnavailable
		}
		// Never reinterpret a damaged/rolled-back application schema as a new
		// ledger: that would silently re-enable previously consumed operations.
		if tableCount != 0 {
			return ErrUnavailable
		}
		if _, err := tx.ExecContext(ctx, schema); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO authority_metadata(singleton,schema_version,audience) VALUES(1,1,?)", audience); err != nil {
			return err
		}
	} else if version != 1 || tableCount != 3 {
		return ErrUnavailable
	}
	for _, query := range []string{
		"SELECT operation_id,request_json,request_digest,execution_approval_id,status,created_at,finished_at,receipt,receipt_digest,outcome FROM operations LIMIT 0",
		"SELECT approval_id,nonce,operation_id,envelope,envelope_digest,owner,created_at FROM authorizations LIMIT 0",
	} {
		rows, err := tx.QueryContext(ctx, query)
		if err != nil {
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
	}
	var stored string
	if err := tx.QueryRowContext(ctx, "SELECT audience FROM authority_metadata WHERE singleton=1 AND schema_version=1").Scan(&stored); err != nil {
		return err
	}
	if stored != audience {
		return ErrUnavailable
	}
	return tx.Commit()
}

func (l *Ledger) Close() error { return l.db.Close() }

func (l *Ledger) available() bool {
	info, err := os.Lstat(l.path)
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 || info.Mode().Perm() != 0600 || !owned(info) || !os.SameFile(l.identity, info) {
		return false
	}
	parent, err := os.Lstat(filepath.Dir(l.path))
	return err == nil && parent.IsDir() && parent.Mode().Perm() == 0700 && owned(parent)
}

type reservation struct {
	operationID, approvalID, digest string
}
type Receipt struct {
	OperationID   string          `json:"operation_id"`
	ApprovalID    string          `json:"approval_id"`
	Owner         string          `json:"owner"`
	RequestDigest string          `json:"request_digest"`
	Payload       json.RawMessage `json:"payload"`
}

func (l *Ledger) reserve(ctx context.Context, request Request, data []byte, digest string, envelope []byte, verified approval.Verified, now time.Time) (*reservation, *Receipt, error) {
	if !l.available() {
		return nil, nil, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, databaseTimeout)
	defer cancel()
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, ErrUnavailable
	}
	defer tx.Rollback()
	// Enforce UNIQUE approval and nonce identity before looking up the semantic
	// operation. A fresh signature cannot reuse either identifier for other claims.
	rows, err := tx.QueryContext(ctx, "SELECT approval_id,nonce,operation_id,CASE WHEN length(envelope)<=16384 THEN envelope ELSE NULL END,envelope_digest FROM authorizations WHERE approval_id=? OR nonce=?", verified.Claims.ApprovalID, verified.Claims.Nonce)
	if err != nil {
		return nil, nil, ErrUnavailable
	}
	existingAuth := false
	for rows.Next() {
		var id, nonce, op, storedDigest string
		var stored []byte
		if rows.Scan(&id, &nonce, &op, &stored, &storedDigest) != nil {
			rows.Close()
			return nil, nil, ErrUnavailable
		}
		if hash(stored) != storedDigest {
			rows.Close()
			return nil, nil, ErrUnavailable
		}
		if id != verified.Claims.ApprovalID || nonce != verified.Claims.Nonce || op != request.Binding.DecisionID || !bytes.Equal(stored, envelope) {
			rows.Close()
			return nil, nil, ErrConflict
		}
		existingAuth = true
	}
	if rows.Err() != nil {
		rows.Close()
		return nil, nil, ErrUnavailable
	}
	rows.Close()
	var storedData, receiptData []byte
	var storedDigest, status, receiptDigest, executionID string
	err = tx.QueryRowContext(ctx, "SELECT CASE WHEN length(request_json)<=32768 THEN request_json ELSE NULL END,request_digest,status,CASE WHEN length(coalesce(receipt,x''))<=65536 THEN coalesce(receipt,x'') ELSE NULL END,coalesce(receipt_digest,''),execution_approval_id FROM operations WHERE operation_id=?", request.Binding.DecisionID).Scan(&storedData, &storedDigest, &status, &receiptData, &receiptDigest, &executionID)
	exists := err == nil
	if err != nil && err != sql.ErrNoRows {
		return nil, nil, ErrUnavailable
	}
	if exists {
		var storedRequest Request
		if len(storedData) > MaxParametersBytes+16384 || json.Unmarshal(storedData, &storedRequest) != nil || hash(storedData) != storedDigest {
			return nil, nil, ErrUnavailable
		}
		_, canonical, calculated, err := normalize(storedRequest)
		if err != nil || !bytes.Equal(canonical, storedData) || calculated != storedDigest {
			return nil, nil, ErrUnavailable
		}
		if storedDigest != digest || !bytes.Equal(storedData, data) {
			return nil, nil, ErrConflict
		}
	} else {
		if existingAuth {
			return nil, nil, ErrUnavailable
		}
		var count int
		if tx.QueryRowContext(ctx, "SELECT count(*) FROM operations").Scan(&count) != nil || count >= maxRecords {
			return nil, nil, ErrUnavailable
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO operations(operation_id,request_json,request_digest,execution_approval_id,status,created_at) VALUES(?,?,?,?,'RESERVED',?)", request.Binding.DecisionID, data, digest, verified.Claims.ApprovalID, now.UTC().Format(time.RFC3339Nano)); err != nil {
			return nil, nil, ErrUnavailable
		}
	}
	if !existingAuth {
		var count int
		if tx.QueryRowContext(ctx, "SELECT count(*) FROM authorizations").Scan(&count) != nil || count >= maxRecords {
			return nil, nil, ErrUnavailable
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO authorizations(approval_id,nonce,operation_id,envelope,envelope_digest,owner,created_at) VALUES(?,?,?,?,?,?,?)", verified.Claims.ApprovalID, verified.Claims.Nonce, request.Binding.DecisionID, envelope, hash(envelope), verified.Owner, now.UTC().Format(time.RFC3339Nano)); err != nil {
			return nil, nil, ErrUnavailable
		}
	}
	var prior *Receipt
	if exists && status == "DONE" {
		if len(receiptData) > MaxReceiptBytes || hash(receiptData) != receiptDigest {
			return nil, nil, ErrUnavailable
		}
		var receipt Receipt
		if json.Unmarshal(receiptData, &receipt) != nil || receipt.OperationID != request.Binding.DecisionID || receipt.ApprovalID != executionID || receipt.RequestDigest != digest || receipt.Owner == "" || !json.Valid(receipt.Payload) {
			return nil, nil, ErrUnavailable
		}
		canonical, err := json.Marshal(receipt)
		if err != nil || !bytes.Equal(canonical, receiptData) {
			return nil, nil, ErrUnavailable
		}

		var owner, originalDigest, originalNonce string
		var original []byte
		if tx.QueryRowContext(ctx, "SELECT owner,CASE WHEN length(envelope)<=16384 THEN envelope ELSE NULL END,envelope_digest,nonce FROM authorizations WHERE approval_id=? AND operation_id=?", executionID, request.Binding.DecisionID).Scan(&owner, &original, &originalDigest, &originalNonce) != nil || len(original) == 0 || hash(original) != originalDigest || owner != receipt.Owner {
			return nil, nil, ErrUnavailable
		}
		var provenance approval.Envelope
		if json.Unmarshal(original, &provenance) != nil || provenance.Claims.ApprovalID != executionID || provenance.Claims.Nonce != originalNonce || provenance.Claims.Binding != request.Binding {
			return nil, nil, ErrUnavailable
		}
		prior = &receipt
	}
	if tx.Commit() != nil {
		return nil, nil, ErrUnavailable
	}
	if exists {
		if prior != nil {
			return nil, prior, nil
		}
		return nil, nil, ErrUncertain
	}
	return &reservation{request.Binding.DecisionID, verified.Claims.ApprovalID, digest}, nil, nil
}

func (l *Ledger) uncertain(ctx context.Context, r *reservation, now time.Time) {
	ctx, cancel := context.WithTimeout(ctx, databaseTimeout)
	defer cancel()
	// If storage is unavailable, durable RESERVED still refuses redispatch.
	l.db.ExecContext(ctx, "UPDATE operations SET status='UNKNOWN',finished_at=?,outcome='UNCERTAIN' WHERE operation_id=? AND execution_approval_id=? AND request_digest=? AND status='RESERVED'", now.UTC().Format(time.RFC3339Nano), r.operationID, r.approvalID, r.digest)
}
func (l *Ledger) complete(ctx context.Context, r *reservation, receipt Receipt, now time.Time) error {
	if !l.available() {
		return ErrUnavailable
	}
	data, err := json.Marshal(receipt)
	if err != nil || len(data) > MaxReceiptBytes {
		return ErrAdapter
	}
	ctx, cancel := context.WithTimeout(ctx, databaseTimeout)
	defer cancel()
	result, err := l.db.ExecContext(ctx, "UPDATE operations SET status='DONE',finished_at=?,receipt=?,receipt_digest=?,outcome='SUCCESS' WHERE operation_id=? AND execution_approval_id=? AND request_digest=? AND status='RESERVED'", now.UTC().Format(time.RFC3339Nano), data, hash(data), r.operationID, r.approvalID, r.digest)
	if err != nil {
		return ErrUnavailable
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return ErrUnavailable
	}
	return nil
}
