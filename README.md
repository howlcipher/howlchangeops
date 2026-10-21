# HowlChangeOps

A policy-driven release controller and authority execution boundary component of the Howl ecosystem, built on HowlFrame.

Website: https://howlcipher.github.io/howlchangeops/  
Repository: https://github.com/howlcipher/howlchangeops

## What problem does it solve?
HowlChangeOps bridges the gap between AI proposals and production reality using bounded execution. AI agents are excellent at reasoning about when a release candidate should be created, but they cannot be given unconstrained authority to mutate your repository. HowlChangeOps proves that **intent is not authority**. It allows an AI (or a user) to propose actions, strictly validates intent via deterministic `HowlFrame` capability checks, requires trusted approval for state mutations, and executes bounded operations securely.

As part of the broader Howl ecosystem alongside **HowlFrame** (orchestration & VM), **HowlPlane** (control plane), **HowlBoard** (operational visibility & evaluation), **HowlNotes** (knowledge field notebook), and the **Howl Hub** (central discovery), HowlChangeOps serves as the canonical approval, execution-boundary, verification, and rollback component.

## Five-minute demo
1. **Initialize Repositories**: Configure local Git repos securely in `config/howlchangeops-config.json`. Set `HOWLCHANGEOPS_APPROVAL_KEY_FILE` (or `CHANGEOPS_APPROVAL_KEY_FILE` for backward compatibility) to point to a secure key.
2. **Inspect**: `howlchangeops inspect my_repo` retrieves verifiable Git states.
3. **Validate**: `howlchangeops validate my_repo` runs tests and stores status safely in a cryptographically bound Evidence Envelope.
4. **Evaluate**: Submit a JSON intent (e.g. `{"action": "create_release_candidate", "repo": "my_repo"}`). HowlChangeOps evaluates against a compiled `.hfbc` bytecode logic policy via the HowlFrame VM, safely outputting an evaluation decision (e.g. `REQUIRE_APPROVAL`).
5. **Approve**: A human validates and signs off on the exact deterministic decision snapshot via `howlchangeops approve <decision_id>`, which generates an HMAC-SHA256 signature using the trusted key.
6. **Execute**: `howlchangeops execute <decision_id>` performs a bounded action (like creating a local Git tag) *only* if the repo's evidence is not stale (`STALE_EVIDENCE`) and the approval hasn't already been consumed.
7. **Rollback**: `howlchangeops rollback <decision_id>` initiates governed, verified rollback workflows for previously executed actions.

## Architecture
HowlChangeOps uses bounded execution to maintain clear boundaries between AI proposals and production reality.

```text
AI / User (Proposer)
   ↓ proposes intent
HowlChangeOps Host Adapter
   ↓ gathers trusted evidence (Git / GitHub)
HowlFrame Policy Engine (.howl → .hfbc)
   ↓ deterministic evaluation
ALLOW / DENY / REQUIRE_APPROVAL
   ↓
Human Authority Gate (HMAC-SHA256)
   ↓
Evidence Revalidation & TOCTOU Verification
   ↓
Bounded Execution & Automated Verification
   ↓
Immutable Receipts, Rollback Recovery & Audit Trail
```

1. **The Policy Authority (HowlFrame)**: `src/howlchangeops.howl` compiles into `howlchangeops.hfbc`. It parses inputs, consumes local and remote evidence, checks conditions, and enforces transitions resulting in `ALLOW`, `DENY`, or `REQUIRE_APPROVAL`. 
2. **The Host Adapter (Go)**: The Go application handles Git/GitHub inspection, executes bounded commands securely, and invokes the HowlFrame runtime under strict sandbox capabilities. 

## Intent is not authority
Proposals dictating actions, logic overrides, or fake approval metrics (like passing `"approved": true`) within the JSON payload are categorically rejected. AI dictates the proposition; HowlFrame owns the authorization machinery.

## Installation

**Standard install**: download a versioned release archive from
[GitHub Releases](https://github.com/howlcipher/howlchangeops/releases). Each
platform archive contains the `howlchangeops` binary, a `changeops` alias
copy, the compiled `howlchangeops.hfbc` policy, and an example config --
verify it against the published `SHA256SUMS` before use. This is also the
path the Howl installer's standard profile uses.

**Developer/source build**: build the adapter from a local checkout:
```bash
cd adapter
go build -o ../howlchangeops
cd ..
ln -sf howlchangeops changeops # optional compatibility alias
```

Compile the authoritative policy layer beside the built executable:
```bash
howlframe check src/howlchangeops.howl
howlframe build src/howlchangeops.howl
ln -sf howlchangeops.hfbc changeops.hfbc
```

Policy evaluation resolves the executable through symlinks and loads
`howlchangeops.hfbc` beside that executable, with `changeops.hfbc` as a
legacy sidecar fallback. Keep the binary and policy together when installing
or moving a source build. A policy in the caller's working directory cannot
replace the installed sidecar. Missing installed policy fails evaluation.

## HowlFrame dependency
HowlChangeOps consumes **HowlFrame 0.1.x** (any patch release of 0.1 whose `--version` reports `HFBC format: 1`) entirely via its public CLI interface. It is independent of HowlFrame's source code, serving as real-world dogfooding for the platform's release candidates. See the dogfooding report in `docs/howlframe_dogfooding_report.md` for findings.

## Configuration
Configure repositories in a JSON file; see `config/howlchangeops-config.example.json` for mapping logical repo IDs to physical absolute paths and their bounded actions. HowlChangeOps reads the first of:

1. the file named by `HOWLCHANGEOPS_CONFIG` (or `CHANGEOPS_CONFIG`);
2. `$XDG_CONFIG_HOME/howlchangeops/howlchangeops-config.json` (default `~/.config/howlchangeops/`);
3. `config/howlchangeops-config.json`, then `config/changeops-config.json`, relative to the working directory (legacy).

Prefer the XDG location: it works from any directory and survives `howl update`, which replaces the release directory.

## Machine-readable output
Other Howl components call HowlChangeOps through its command line under the
[Howl interop contract](https://github.com/howlcipher/howl/blob/main/docs/INTEROP.md).
`howlchangeops interop --json` prints the `howl.interop/v1` descriptor (commands, flags, exit codes, and the HowlFrame commands it runs).

`version`, `evaluate`, `approve`, `execute`, `rollback`, `history` and `explain` accept `--json`. Stdout then carries exactly one `howl.result/v1` envelope and the human-readable progress goes to stderr:

```json
{
  "schema": "howl.result/v1",
  "component": "howlchangeops",
  "command": ["evaluate"],
  "status": "awaiting_human",
  "data": {"decision_id": "decision-…", "decision_saved": true, "verdict": "REQUIRE_APPROVAL", "reason": "…", "gates": [], "action": "create_release_candidate", "repo": "my_repo", "revision": "…", "decision_digest": "…", "evidence_digest": "…"},
  "error": null
}
```

Branch on `status`: `ok` (ALLOW, or a completed approve/execute), `awaiting_human` (REQUIRE_APPROVAL), `denied` (a DENY verdict or a refused execution; `error.code` is `DENIED`, `STALE_EVIDENCE`, `STALE_REMOTE_EVIDENCE`, `ALREADY_EXECUTED`, `APPROVAL_EXPIRED`, …), `blocked` (for example `APPROVAL_KEY_MISSING`), `unavailable` (`CONFIG_UNAVAILABLE`, `HOWLFRAME_INCOMPATIBLE`), or `failed`. Exit codes are unchanged: `evaluate` exits 0 for every verdict, and refusals and errors exit 1.

## CLI Usage

### Version
```bash
howlchangeops --version
```
Reports HowlChangeOps's own version and the HowlFrame version its compiled
policy was built against. Works with no configuration present -- this is
what the Howl installer uses as the post-install health check.

### Inspect
```bash
howlchangeops inspect <repo_id>
```
Gathers current evidence, git branch, tag state, and working tree clean/dirty status.

### Validate
```bash
howlchangeops validate <repo_id>
```
Supported `validation_profile` values are `go` and explicit `python-stdlib`.
Go retains its existing `go test ./...` and `go build ./...` contract.
Plain `python`, empty, and unknown profiles fail with an actionable configuration
error before creating evidence.

Validation requires a clean configured Git repository with a committed HEAD.
Commit or restore changes before validating. Missing paths, repositories without
a commit, nonrepositories, and dirty working trees fail actionably. Both profiles
recheck HEAD and the working tree after checks. If checks change the repository,
actual results are saved with a failed working-tree check and validation exits
nonzero. Cached results from a dirty or changed validation cannot be reused
after the working tree is restored. These checks bound cache reuse; they do not
make trusted repository code an immutable or isolated snapshot.

`python-stdlib` requires Python 3 and Git on PATH and executes trusted repository
tests; it is not a security sandbox, dependency audit, or approval. Fixed
`python3 -I -B -c` helpers use no shell or configurable commands. The test helper
preimports standard-library unittest, adds the repository import path, discovers
`tests/test*.py` (including a nonpackage tests directory), requires a positive
suite count, and runs the suite; a suite where every test is skipped is rejected.
Only `test*.py` files directly in `tests/` and in importable packages
(directories with `__init__.py`) are discovered. The build helper separately compiles working-tree
bytes for Git-tracked `.py` paths in memory without executing source or writing
bytecode. Missing sources, symlink components, nonregular sources, syntax errors,
missing/empty tests, and failing tests reject validation.

Each Python check has a 120-second deadline and a 1 MiB combined stdout/stderr
capture cap. Timeout or excess output fails the check; evidence adds
`timed_out` and `output_truncated` when true. `output_digest` is SHA-256 of
the captured bytes, including only the retained prefix on overflow; concurrent
stdout/stderr ordering can vary. POSIX cancellation kills the process group,
including children retaining output pipes. Descendants that deliberately escape
the group are outside this boundary. Windows rejects this profile because
equivalent descendant cancellation is not implemented. Both test and build
results are persisted even on failure; failed Python validation exits nonzero
without a completion message or dogfood proposal continuation. The unchanged
policy still requires both checks and independently governs approval.

### Plan
```bash
howlchangeops plan <repo_id>
```
Simulates and evaluates all supported actions against current repository evidence.

### Evaluate
```bash
howlchangeops evaluate proposal.json
```
Evaluates an intent payload. Outputs a decision and binds a `decision_id` for approval gating.

### Approve
```bash
howlchangeops approve <decision_id>
```
Provides trusted authorization context binding directly to a decision state without relying on input intent parameters.

### Execute
```bash
howlchangeops execute <decision_id>
```
Gathers current state evidence, verifies no TOCTOU drift has occurred (safely denying with `STALE_EVIDENCE` or `STALE_REMOTE_EVIDENCE` if so), and executes the strictly bounded physical change (e.g., git tagging) followed by automated post-action verification.

### Rollback
```bash
howlchangeops rollback <decision_id>
```
Proposes governed rollback for a previously executed decision, requiring approval before reverting mutated state.

### Explain
```bash
howlchangeops explain <decision_id>
```
Displays full policy gate breakdown and execution receipt details for an evaluation.

### History
```bash
howlchangeops history
```
Outputs the JSON lines audit trail of evaluation and execution logic.

## Backward Compatibility
To prevent disruption to existing automated workflows, `changeops` is preserved as a supported CLI command alias and environment variable fallback:
- Executable: `howlchangeops` (canonical) and `changeops` (alias)
- Environment: `HOWLCHANGEOPS_BASE` (primary) and `CHANGEOPS_BASE` (fallback)
- Keys: `HOWLCHANGEOPS_APPROVAL_KEY_FILE` (primary) and `CHANGEOPS_APPROVAL_KEY_FILE` (fallback)
- Config: `HOWLCHANGEOPS_CONFIG` (primary) and `CHANGEOPS_CONFIG` (fallback); `config/howlchangeops-config.json` (primary) and `config/changeops-config.json` (fallback) after the XDG location

## Trust boundary
- **AI Proposal:** Can dictate the logical repo ID, action to pursue, and descriptive reasons.
- **HowlChangeOps Adapter:** Maps logical IDs to true absolute paths, handles true process invocations securely.
- **HowlFrame Policy:** Retains exclusive ownership over capabilities, validation requirements, and approvals.

## Security limitations
This V0.2 architecture bounds logical actions within a local operational domain utilizing the Host Go Adapter wrapper and HowlFrame's execution capabilities. It establishes a strong local trusted evidence foundation with HMAC-SHA256 approvals and strict replay prevention. Remote GitHub API ingestion provides TOCTOU protection.

## Business mapping
The local HowlChangeOps implementation mirrors enterprise DevOps CI/CD integration models: AI acts as the proposer, a deterministic authority layer strictly handles permissions, and a trusted executor pushes the physical bounds only within predetermined logic loops.
