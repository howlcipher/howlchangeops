# Protected executor and durable replay ledger foundation

This source package does not deploy independently authenticated owner approval.
The explicit `model_b` approval and execution paths remain blocked regardless of
caller environment variables. `authority execute` permits only the existing pure
`synthetic_action` for deterministic protocol tests, labeled `synthetic_protocol_only`;
it refuses every real action before opening its approval or ledger.

Source CLIs for key generation, enrollment, signing and revocation and Git action
adapters exist, but no independently authenticated owner or protected deployment
is established. `authority sign --yes` is caller confirmation, never authentication.
Do not expose signing keys, enrollment, or real execution to autonomous workers.

## Placement and guarantees

`internal/authority` is intended to run under the protected host authority after
agents have lost host administration, tool/connector control channels and direct
protected-target credentials. SQLite data, executable/configuration, trusted key
enrollment, clock and fixed action adapters must be outside agent control. A
same-UID/root process that can replace these still defeats the boundary; owner
flags, terminal prompts and guest bootstrap SSH keys do not establish identity.

The constructor accepts an existing absolute, physical path in an owner-only
0700 directory and a fixed audience/generation. It rejects memory/URI/query paths,
symlinks, unowned/shared directories, unsafe writable ancestry and nonregular or
non0600 database files. SQLite URI options come solely from fixed code. Root-owned sticky `/tmp` is
accepted for synthetic temporary tests; production must provision a stable,
nonvolatile protected storage path rather than relying on temporary-directory
retention. Windows
ACL custody has not been implemented and storage therefore refuses on Windows.
CGO-disabled builds also refuse authority storage, rather than using an in-memory
or cooperative fallback. These fail-closed cases do not enable execution.

Schema v1 is an embedded, version-controlled transaction used only by explicit
protected `CreateLedger` provisioning. Creation is exclusive and refuses every
existing path; failed provisioning retains its artifact for owner review. This
API is not an owner authenticator. The enrollment CLI is a provisioning utility,
not an independent owner-authentication boundary. Runtime
`OpenLedger` uses SQLite read/write-existing mode and requires an existing,
nonempty v1 database with its replay tables and metadata; missing, truncated,
empty-schema or damaged state refuses, never initializes fresh replay storage.
An already-open handle also verifies the same nonempty regular database path
before reserving and immediately before dispatch; observed path loss/replacement
refuses instead of relying on an unlinked SQLite descriptor. Unknown versions
and mismatched audience generations fail closed. Removing or
rolling back replay state is not a supported migration rollback: recovery must
revoke old enrollment/rotate the audience generation under owner authentication
and reconcile uncertain external operations before using a restored database.

The signed `Binding.DecisionID` is the globally unique semantic operation ID.
Canonical request hashing covers the complete exact binding and strict JSON
parameters, excluding ephemeral approval IDs/nonces/timestamps/signatures. A new
approval for the same operation therefore cannot cause another dispatch. New
approval IDs and nonces are also consumed when returning a prior receipt; both
are globally unique and cannot bind a different operation or envelope. Owner
intentional new operations require new decision IDs; do not create a new ID just
to retry uncertainty.

The executor requires a configured fixed adapter for the exact action. It checks
strict bounded parameters against the signed parameters digest, loads trusted
current enrollment/clock/signer availability, verifies the existing Ed25519
protocol, and commits a SQLite `RESERVED` record before any callback. It then
reloads current enrollment/clock/signer availability and rechecks expiry,
revocation, identity and binding immediately before dispatch. Validators receive
copies and must be pure; adapters must never run submitted repository scripts or
caller commands with protected credentials. Every subprocess/output/deadline used
by a real adapter needs its own reviewed bounded implementation. In-process
callbacks must honor the supplied deadline; this package is not a process sandbox.

SQLite uses WAL, FULL synchronization, foreign keys, an immediate write
transaction and bounded busy/deadline handling. Only SQLite BUSY/LOCKED errors are
retried during concurrent initialization. A uniqueness/capacity/storage error
refuses dispatch. Operations and authorizations are each capped at100000 rows;
parameters16KiB, approval envelopes16KiB, adapter receipt payloads32KiB and full
receipts64KiB. Persisted blobs are read with explicit length limits and validated
against request/receipt/provenance digests before a cached result is returned.
No SQL statements or raw failure diagnostics are returned to clients.

After successful bounded JSON output, `DONE` records the immutable receipt,
enrolled owner and execution approval provenance. Identical authorized retries
return that prior receipt without calling the adapter. A failure, panic,
cancellation or post-reservation authorization failure stays consumed as UNKNOWN;
process death or storage loss can leave RESERVED. Both refuse redispatch on
reopen, even if the effect may not have happened. A crash after an external effect
but before receipt commit remains uncertain; external reconciliation or reviewed
operator recovery is required. Exactly-once external APIs are not claimed.

## SQLite driver choice

| Option reviewed at implementation time | Benefits | Costs |
| --- | --- | --- |
| mattn/go-sqlite3 v1.14.52 | Current driver, bundled SQLite3.53.4, small dependency graph, declares Go1.21 | CGO needed for authority storage; audit C/SQLite separately from Go reachability |
| modernc.org/sqlite v1.61.0 | Pure Go, easier native-free cross builds | Current release requires Go1.26 and a larger runtime dependency graph |
| Current ncruces/go-sqlite3 | WASM-backed SQLite without CGO | Current source requires Go1.26 and a WASM/runtime dependency chain |

The current mattn driver preserves the existing Go1.21 source minimum without
pinning an old driver for compatibility. The protected package is not imported
by the legacy adapter, so legacy standalone CLI cross-build behavior is unchanged.
Production authority builds must use a currently patched supported Go toolchain;
Go1.21 source compatibility does not endorse deploying an end-of-life compiler.
Implementation validation uses a separately downloaded Go1.27.3 toolchain without
replacing the owner's installed Go binary. `govulncheck` finds no advisories for
that tested module/toolchain combination; this is not a complete C-code or future
vulnerability audit. A prior Go1.26.0 scan found unreachable standard-library
package/module advisories; its log is retained and is not described as fully clean.

References: [driver source/module](https://github.com/mattn/go-sqlite3),
[modernc module](https://gitlab.com/cznic/sqlite),
[SQLite transaction durability](https://www.sqlite.org/atomiccommit.html),
[SQLite WAL](https://www.sqlite.org/wal.html). Filesystem/device fsync correctness
and independently protected storage are deployment assumptions.

## Evidence and deployment acceptance

Tests use synthetic Ed25519 keys only. They exercise real persistent SQLite,
multiple handles and actual concurrent OS processes, approval/nonce/operation
collisions, subprocess death after reservation and after a synthetic effect,
reopen/refusal, receipts and corruption, expiry/revocation/unavailable signer,
path restrictions, bounded storage/output, and callback error/panic/cancellation.
CLI tests enforce model_b refusal even with a caller-selected ledger, and
refuse real authority actions through the lower-level CLI. Synthetic-only CLI
tests still exercise actual signature verification and persistent replay state.
Mocked state/authenticator inputs
are not real human authentication or custody evidence.

Before enabling a production entry point, independently review the host
principal/administrative boundary, owner authentication/display/enrollment,
action/target policy, fixed real adapters, remote credential migration, host
filesystem/backup durability and all alternate CLI/API/orchestration paths.
The guest is not an authority principal. A running guest alone does not finish
Model B. Keep protected actions blocked until these acceptance gates pass.
