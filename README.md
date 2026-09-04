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

Compile the authoritative policy layer:
```bash
howlframe check src/howlchangeops.howl
howlframe build src/howlchangeops.howl
ln -sf howlchangeops.hfbc changeops.hfbc
```

## HowlFrame dependency
HowlChangeOps consumes **HowlFrame v0.1.0** entirely via its public CLI interface. It is independent of HowlFrame's source code, serving as real-world dogfooding for the platform's release candidates. See the dogfooding report in `docs/howlframe_dogfooding_report.md` for findings.

## Configuration
Configure repositories securely via `config/howlchangeops-config.json` (or `config/changeops-config.json`). Refer to the `.example.json` file for mapping logical repo IDs to physical absolute paths and their bounded actions.

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
Executes the predefined validation profile bounded by configuration limits (e.g. `go test ./...` and `go build ./...`) and caches the state.

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
- Config: `config/howlchangeops-config.json` (primary) and `config/changeops-config.json` (fallback)

## Trust boundary
- **AI Proposal:** Can dictate the logical repo ID, action to pursue, and descriptive reasons.
- **HowlChangeOps Adapter:** Maps logical IDs to true absolute paths, handles true process invocations securely.
- **HowlFrame Policy:** Retains exclusive ownership over capabilities, validation requirements, and approvals.

## Security limitations
This V0.2 architecture bounds logical actions within a local operational domain utilizing the Host Go Adapter wrapper and HowlFrame's execution capabilities. It establishes a strong local trusted evidence foundation with HMAC-SHA256 approvals and strict replay prevention. Remote GitHub API ingestion provides TOCTOU protection.

## Business mapping
The local HowlChangeOps implementation mirrors enterprise DevOps CI/CD integration models: AI acts as the proposer, a deterministic authority layer strictly handles permissions, and a trusted executor pushes the physical bounds only within predetermined logic loops.
