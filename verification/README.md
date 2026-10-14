# Bounded release-package verification

This temporary branch verifies the exact reviewed HowlChangeOpsv0.1.0 archives
from sourcee039fb4 against the pinned official Framev0.1.0 binaries. It does not
change product sources, the default branch, campaign counters or policy authority.
Do not merge this verification harness as an engineering delivery.

Each job checks OS/CPU and executable headers, archive/file hashes and the regular
alias, then executes packaged binaries. An ephemeral Go fixture exercises actual
passing/failing validation and DENY/REQUIRE_APPROVAL decisions; no approve or
execute action is called. The Go relay records native output and matches its hash
to stored evidence. GOFLAGS=-v is diagnostic instrumentation, not a product change.
The validator records failing check results even when its collection command exits
zero; the test requires the actual FAIL/nonzero check and policy denial.

The workflow runs once for a branch push, with no scheduler or recursive worker.
It uses read-only repository permission and removes download tokens before package
execution. All native results remain required before stable release publication.
The signed source-branch head, raw failed attempts and independent review limits
are retained in the private mission record; localLinux success is not a claim
about the four other platforms until their jobs complete.
