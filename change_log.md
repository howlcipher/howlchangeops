# Change Log

## Unreleased

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
