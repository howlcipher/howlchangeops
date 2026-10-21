#!/bin/bash
set -e

# Setup temp repo
TEMP_REPO=$(mktemp -d)
cd "$TEMP_REPO"
git init
git config user.name "Test User"
git config user.email "test@example.com"
echo "test" > file.txt
git add file.txt
git commit -m "initial commit"
git branch -m main

# Mock go profile for tests
echo "package main; func main() {}" > main.go
go mod init testrepo
echo "testrepo" > .gitignore
echo ".howlchangeops" >> .gitignore
echo ".changeops" >> .gitignore
git add main.go go.mod .gitignore
git commit -m "add go mock profile"

# Back to project dir
cd - > /dev/null
PROJECT_DIR=$PWD
# Setup mock gh for remote testing
MOCK_BIN=$(mktemp -d)
cat <<'EOF' > "$MOCK_BIN/gh"
#!/bin/bash
if [ "$1" = "api" ]; then
  if echo "$*" | grep -q "status"; then
    echo "success"
  elif echo "$*" | grep -q "commits/"; then
    if [ -f /tmp/mock_remote_head ]; then
      cat /tmp/mock_remote_head
    else
      echo "1111111111111111111111111111111111111111"
    fi
  fi
elif [ "$1" = "release" ]; then
  echo "mock release"
fi
EOF
chmod +x "$MOCK_BIN/gh"
export PATH="$MOCK_BIN:$PROJECT_DIR:$PATH"
export HOWLCHANGEOPS_BASE="$TEMP_REPO/.howlchangeops"

# Generate approval key
TEMP_KEY=$(mktemp)
dd if=/dev/urandom of="$TEMP_KEY" bs=32 count=1 2>/dev/null
chmod 600 "$TEMP_KEY"
export HOWLCHANGEOPS_APPROVAL_KEY_FILE="$TEMP_KEY"

mkdir -p config
cat <<EOF > config/howlchangeops-config.json
{
  "repos": {
    "testrepo": {
      "path": "$TEMP_REPO",
      "allowed_branches": ["main"],
      "validation_profile": "go",
      "allowed_actions": [
        "create_release_candidate",
        "create_github_draft_release",
        "record_release_ready",
        "rollback_release_candidate"
      ]
    }
  }
}
EOF

# Build adapter and policy
cd adapter && go build -o ../howlchangeops
cd ..
ln -sf howlchangeops changeops
~/.local/bin/howlframe build src/howlchangeops.howl
ln -sf howlchangeops.hfbc changeops.hfbc

echo "=== Scenario 1 - Dirty Repo ==="
echo "modify" >> "$TEMP_REPO/file.txt"
cat <<EOF > tests/proposal_1.json
{
  "action": "create_release_candidate",
  "repo": "testrepo",
  "reason": "Test dirty repo",
  "confidence": 0.9
}
EOF
howlchangeops evaluate tests/proposal_1.json | grep -q "DENY" && echo "PASS: Denied due to dirty repo"

echo "=== Scenario 2 - Clean repo but no approval ==="
cd "$TEMP_REPO" && git commit -am "clean" && cd - > /dev/null
howlchangeops validate testrepo
EVAL_OUT=$(howlchangeops evaluate tests/proposal_1.json)
echo "$EVAL_OUT" | grep -q "REQUIRE_APPROVAL" && echo "PASS: Required approval"
DECISION_ID=$(echo "$EVAL_OUT" | grep "Decision saved as" | awk '{print $4}' | tr -d '.')

echo "=== Scenario 3 - AI self approval ==="
cat <<EOF > tests/proposal_3.json
{
  "action": "create_release_candidate",
  "repo": "testrepo",
  "reason": "Test self approval",
  "confidence": 0.9,
  "approved": true,
  "admin": true,
  "override": true
}
EOF
howlchangeops evaluate tests/proposal_3.json | grep -q "REQUIRE_APPROVAL" && echo "PASS: Self approval ignored, still REQUIRE_APPROVAL"

echo "=== Scenario 4 - Trusted approval & execution ==="
howlchangeops approve "$DECISION_ID" --owner-confirmed
EXEC_OUT=$(howlchangeops execute "$DECISION_ID")
echo "$EXEC_OUT" | grep -q "Executing action: create_release_candidate" && echo "PASS: Action executed"
echo "$EXEC_OUT" | grep -q "Verified: tag created successfully" && echo "PASS: Post-action verification passed"
cd "$TEMP_REPO" && git tag -l | grep -q "howlchangeops/rc-" && echo "PASS: Tag created" && cd - > /dev/null
# Check execution receipt
grep -q '"verification": "PASS"' "$HOWLCHANGEOPS_BASE/receipts/${DECISION_ID}.json" && echo "PASS: Execution receipt verified PASS"

echo "=== Scenario 5 - Stale local evidence ==="
cd "$TEMP_REPO" && git commit --allow-empty -m "clean commit" && cd - > /dev/null
howlchangeops validate testrepo
DECISION_ID2=$(howlchangeops evaluate tests/proposal_1.json | grep "Decision saved as" | awk '{print $4}' | tr -d '.')
howlchangeops approve "$DECISION_ID2" --owner-confirmed
# Modify repo before executing
echo "stale" >> "$TEMP_REPO/file.txt"
cd "$TEMP_REPO" && git commit -am "stale commit" && cd - > /dev/null
# Execute should fail
if howlchangeops execute "$DECISION_ID2" 2>&1 | grep -q "STALE_EVIDENCE"; then
  echo "PASS: Stale local evidence detected and blocked"
else
  echo "FAIL: Stale local evidence was allowed!"
  exit 1
fi

echo "=== Scenario 6 - Stale remote evidence (TOCTOU) ==="
cd "$TEMP_REPO"
git commit --allow-empty -m "clean commit for remote TOCTOU"
git remote add origin https://github.com/example/testrepo.git 2>/dev/null || true
CURR_REV=$(git rev-parse HEAD)
echo "$CURR_REV" > /tmp/mock_remote_head
cd - > /dev/null
howlchangeops validate testrepo
DECISION_ID_REMOTE=$(howlchangeops evaluate tests/proposal_1.json | grep "Decision saved as" | awk '{print $4}' | tr -d '.')
howlchangeops approve "$DECISION_ID_REMOTE" --owner-confirmed
# Remote advances before execution
echo "2222222222222222222222222222222222222222" > /tmp/mock_remote_head
if howlchangeops execute "$DECISION_ID_REMOTE" 2>&1 | grep -q "STALE_REMOTE_EVIDENCE"; then
  echo "PASS: Remote TOCTOU drift detected and blocked with STALE_REMOTE_EVIDENCE"
else
  echo "FAIL: Remote TOCTOU drift was not caught!"
  exit 1
fi
rm -f /tmp/mock_remote_head

echo "=== Scenario 7 - HowlFrame failure (Fail-Closed) ==="
cd "$TEMP_REPO" && git commit --allow-empty -m "clean for scenario 7" && cd - > /dev/null
howlchangeops validate testrepo
DECISION_ID3=$(howlchangeops evaluate tests/proposal_1.json | grep "Decision saved as" | awk '{print $4}' | tr -d '.')
howlchangeops approve "$DECISION_ID3" --owner-confirmed

# Break HowlFrame by deleting the policy file temporarily
mv howlchangeops.hfbc howlchangeops.hfbc.bak
if howlchangeops execute "$DECISION_ID3" 2>&1 | grep -q "Execution evaluation error"; then
  echo "PASS: HowlFrame failure blocked execution"
else
  echo "FAIL: HowlFrame failure did not block execution!"
  mv howlchangeops.hfbc.bak howlchangeops.hfbc
  exit 1
fi
mv howlchangeops.hfbc.bak howlchangeops.hfbc

echo "=== Scenario 8 - Governed Rollback Workflow ==="
# Execute a valid release candidate first
cd "$TEMP_REPO" && git commit --allow-empty -m "clean for rollback test" && cd - > /dev/null
howlchangeops validate testrepo
DECISION_ID_RB_TARGET=$(howlchangeops evaluate tests/proposal_1.json | grep "Decision saved as" | awk '{print $4}' | tr -d '.')
howlchangeops approve "$DECISION_ID_RB_TARGET" --owner-confirmed
howlchangeops execute "$DECISION_ID_RB_TARGET"
# Propose rollback via CLI command
RB_OUT=$(howlchangeops rollback "$DECISION_ID_RB_TARGET")
echo "$RB_OUT" | grep -q "REQUIRE_APPROVAL" && echo "PASS: Rollback proposal evaluated and requires approval"
RB_DEC_ID=$(echo "$RB_OUT" | grep "Rollback decision saved as" | awk '{print $5}' | tr -d '.')
howlchangeops approve "$RB_DEC_ID" --owner-confirmed
RB_EXEC_OUT=$(howlchangeops execute "$RB_DEC_ID")
echo "$RB_EXEC_OUT" | grep -q "Rolled back tag" && echo "PASS: Rollback executed and tag removed"
grep -q '"action": "rollback_release_candidate"' "$HOWLCHANGEOPS_BASE/receipts/${RB_DEC_ID}.json" && echo "PASS: Rollback receipt recorded"

echo "=== Scenario 9 - Plan Simulation ==="
PLAN_OUT=$(howlchangeops plan testrepo)
echo "$PLAN_OUT" | grep -q "create_release_candidate" && echo "PASS: Plan simulated create_release_candidate"
echo "$PLAN_OUT" | grep -q "rollback_release_candidate" && echo "PASS: Plan simulated rollback_release_candidate"

echo "=== Scenario 10 - Explain Output with Execution Receipt ==="
EXPLAIN_OUT=$(howlchangeops explain "$DECISION_ID_RB_TARGET")
echo "$EXPLAIN_OUT" | grep -q "Execution Receipt:" && echo "PASS: Explain displays execution receipt"
echo "$EXPLAIN_OUT" | grep -q "Verification: PASS" && echo "PASS: Explain displays verification status"

echo "=== Scenario 11 - Post-Action Failure, Receipt Persistence & Replay Prevention ==="
cd "$TEMP_REPO" && git commit --allow-empty -m "clean for scenario 11" && cd - > /dev/null
howlchangeops validate testrepo
DEC_11_OUT=$(howlchangeops evaluate tests/proposal_1.json)
DEC_11_ID=$(echo "$DEC_11_OUT" | grep "Decision saved as" | awk '{print $4}' | tr -d '.')
howlchangeops approve "$DEC_11_ID" --owner-confirmed
# Pre-create conflicting tag to force tag creation failure
CURR_REV=$(cd "$TEMP_REPO" && git rev-parse HEAD && cd - > /dev/null)
cd "$TEMP_REPO" && git tag "howlchangeops/rc-${CURR_REV:0:7}" && cd - > /dev/null
# Execute will fail
if howlchangeops execute "$DEC_11_ID" 2>&1 | grep -q "failed to create RC tag"; then
  echo "PASS: Action failure detected"
fi
# Verify failure receipt exists with FAIL status
grep -q '"verification": "FAIL"' "$HOWLCHANGEOPS_BASE/receipts/${DEC_11_ID}.json" && echo "PASS: Failure execution receipt persisted"
# Verify replay protection blocks re-execution of failed decision
if howlchangeops execute "$DEC_11_ID" 2>&1 | grep -q "DENIED: Decision previously failed execution"; then
  echo "PASS: Replay protection blocks re-executing failed decision"
else
  echo "FAIL: Replay protection did not block failed decision!"
  exit 1
fi

echo "=== Scenario 12 - Compatibility Alias (changeops CLI command) ==="
ALIAS_OUT=$(changeops plan testrepo)
echo "$ALIAS_OUT" | grep -q "create_release_candidate" && echo "PASS: Compatibility alias changeops executes plan successfully"

echo "=== Scenario 13 - JSON result envelopes (howl.result/v1) ==="
jfield() { python3 -c 'import json,sys; d=json.load(sys.stdin); print(eval("d"+sys.argv[1]))' "$1"; }
expect() { if [ "$1" = "$2" ]; then echo "PASS: $3"; else echo "FAIL: $3 (got '$1', want '$2')"; exit 1; fi; }
cd "$TEMP_REPO" && git commit --allow-empty -m "clean for json scenario" && cd - > /dev/null
howlchangeops validate testrepo
EVAL_JSON=$(howlchangeops evaluate --json tests/proposal_1.json)
expect "$(echo "$EVAL_JSON" | jfield '["status"]')" "awaiting_human" "evaluate --json reports awaiting_human"
JSON_DEC_ID=$(echo "$EVAL_JSON" | jfield '["data"]["decision_id"]')
expect "$(echo "$EVAL_JSON" | jfield '["data"]["verdict"]')" "REQUIRE_APPROVAL" "evaluate --json carries the verdict"
expect "$([ -f "$HOWLCHANGEOPS_BASE/decisions/${JSON_DEC_ID}.json" ] && echo yes)" "yes" "evaluate --json decision_id names the saved decision"
APPROVE_JSON=$(howlchangeops approve "$JSON_DEC_ID" --owner-confirmed --json)
expect "$(echo "$APPROVE_JSON" | jfield '["status"]')" "ok" "approve --json ok"
EXEC_JSON=$(howlchangeops execute --json "$JSON_DEC_ID")
expect "$(echo "$EXEC_JSON" | jfield '["data"]["verification"]')" "PASS" "execute --json reports verification"
REPLAY_JSON=$(howlchangeops execute --json "$JSON_DEC_ID" || true)
expect "$(echo "$REPLAY_JSON" | jfield '["error"]["code"]')" "ALREADY_EXECUTED" "replay is denied with ALREADY_EXECUTED"
echo "dirty" >> "$TEMP_REPO/file.txt"
DENY_JSON=$(howlchangeops evaluate --json tests/proposal_1.json)
expect "$(echo "$DENY_JSON" | jfield '["status"]')" "denied" "evaluate --json reports denied"
cd "$TEMP_REPO" && git checkout -- file.txt && cd - > /dev/null
expect "$(howlchangeops interop --json | jfield '["component"]')" "howlchangeops" "interop descriptor"

echo "=== Scenario 14 - Configuration from XDG_CONFIG_HOME, any working directory ==="
XDG_TMP=$(mktemp -d)
mkdir -p "$XDG_TMP/howlchangeops"
cp config/howlchangeops-config.json "$XDG_TMP/howlchangeops/howlchangeops-config.json"
XDG_OUT=$(cd "$XDG_TMP" && XDG_CONFIG_HOME="$XDG_TMP" howlchangeops plan testrepo)
expect "$(echo "$XDG_OUT" | grep -q "create_release_candidate" && echo yes)" "yes" "plan runs from another directory with the XDG config"
rm -rf "$XDG_TMP"

echo "=== Scenario 15 - Approval is the owner's decision ==="
cd "$TEMP_REPO" && git commit --allow-empty -m "clean for owner approval scenario" && cd - > /dev/null
howlchangeops validate testrepo
OWNER_DEC=$(howlchangeops evaluate --json tests/proposal_1.json | jfield '["data"]["decision_id"]')
REFUSED=$(howlchangeops approve "$OWNER_DEC" --json < /dev/null || true)
expect "$(echo "$REFUSED" | jfield '["error"]["code"]')" "OWNER_CONFIRMATION_REQUIRED" "approve without a terminal or --owner-confirmed is refused"
expect "$([ -f "$HOWLCHANGEOPS_BASE/approvals/${OWNER_DEC}.json" ] && echo yes || echo no)" "no" "a refused approval writes nothing"
RELAYED=$(howlchangeops approve "$OWNER_DEC" --owner-confirmed --approver owner-alice --json < /dev/null)
expect "$(echo "$RELAYED" | jfield '["data"]["approver"]')" "owner-alice" "the named approver is recorded"
expect "$(echo "$RELAYED" | jfield '["data"]["confirmation"]')" "owner_relayed" "a relayed approval says so"
expect "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["approver"])' "$HOWLCHANGEOPS_BASE/approvals/${OWNER_DEC}.json")" "owner-alice" "the signed approval file names the approver"

echo "ALL INTEGRATION TESTS PASSED"
