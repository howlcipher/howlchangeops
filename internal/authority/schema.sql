CREATE TABLE IF NOT EXISTS authority_metadata (
 singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
 schema_version INTEGER NOT NULL CHECK(schema_version = 1),
 audience TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS operations (
 operation_id TEXT PRIMARY KEY,
 request_json BLOB NOT NULL,
 request_digest TEXT NOT NULL,
 execution_approval_id TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('RESERVED','UNKNOWN','DONE')),
 created_at TEXT NOT NULL,
 finished_at TEXT,
 receipt BLOB,
 receipt_digest TEXT,
 outcome TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS authorizations (
 approval_id TEXT PRIMARY KEY,
 nonce TEXT NOT NULL UNIQUE,
 operation_id TEXT NOT NULL REFERENCES operations(operation_id),
 envelope BLOB NOT NULL,
 envelope_digest TEXT NOT NULL,
 owner TEXT NOT NULL,
 created_at TEXT NOT NULL
);
PRAGMA user_version = 1;
