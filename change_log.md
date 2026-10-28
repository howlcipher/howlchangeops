# Change Log

## Unreleased

* Restore unconditional Model B execution refusal despite caller-selected ledger
  environment variables. Refuse all real lower-level `authority execute` actions
  until independently authenticated protected deployment exists; preserve and
  explicitly label pure synthetic protocol tests. Regressions reproduce the
  former environment bypass and cover all three real adapter actions.
* Correct protected-authority documentation: provisioning/signing CLIs and real
  Git adapters exist in source but do not establish independent identity or
  custody; `--yes` is never authentication.


* Add explicit trusted-repository python-stdlib validation with positive unittest discovery, independent in-memory tracked-source compilation, bounded output and deadlines, POSIX group cancellation, and truthful failed evidence. Windows fails closed; Go evidence fields and authority policy remain compatible.
* Add Python profile regressions for nonpackage imports, stdlib shadowing, empty/missing/failing tests, syntax and unsafe-source failures, deadlines, retained output digests, no bytecode writes, and public failure behavior.

* Reject unsupported and empty validation profiles with an actionable configuration error and nonzero exit in both validate and dogfood. Do not create fresh evidence or continue proposing on that failure.
* Load the authority policy beside the resolved executable, including symlinked installations and source builds. Preserve the legacy sidecar filename without allowing caller working directory policies to shadow an installation.
* Add public command regressions for validation failure, preserved prior evidence, installed sidecar selection, executable symlinks, and missing installed policy.

Validation now rejects invalid repository paths or missing committed HEAD before
gathering evidence, avoiding a panic and preventing invalid fresh evidence.

Reject dirty validation starts and changed HEAD or working tree after checks.
Keep actual results but fail snapshot binding when checks change the repository.
Reject previously dirty cached envelopes so restored trees cannot reuse results
from uncommitted source. Add public dirty-restore and test-mutation regressions.

## Mission007 remediation

F3 preparation: pure Ed25519 exact-binding verifier, strict claims/expiry validation and explicit model_b fail-closed approval/execution mode until protected deployment. Legacy records/results label cooperative guarantee; new guarantee is HMAC-bound. This does not complete Model B authentication or replay enforcement.

* Add a source-only protected-executor interface and durable SQLite replay ledger,
  with exact signed operation binding, reserve-before-effects, current enrollment
  rechecks, bounded receipts and uncertain-crash refusal. Synthetic multi-process
  tests cover persistence and duplicate prevention. Legacy explicit Model B CLI
  remains unavailable; no owner authentication, credentials or real action adapter
  is deployed. Authority storage requires CGO/POSIX protected paths.
