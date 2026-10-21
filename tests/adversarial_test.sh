#!/bin/bash
set -e

TEMP_REPO=$(mktemp -d)
cd "$TEMP_REPO"
git init
git config user.name "Test User"
git config user.email "test@example.com"
echo "package main; func main() {}" > main.go
go mod init testrepo
echo "testrepo" > .gitignore
echo ".howlchangeops" >> .gitignore
echo ".changeops" >> .gitignore
git add main.go go.mod .gitignore
git commit -m "add go mock profile"
git branch -m main

cd - > /dev/null
PROJECT_DIR=$PWD
export PATH="$PROJECT_DIR:$PATH"
export HOWLCHANGEOPS_BASE="$TEMP_REPO/.howlchangeops"

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
      "allowed_actions": ["create_release_candidate"]
    }
  }
}
EOF

cd adapter && go build -o ../howlchangeops && cd ..
ln -sf howlchangeops changeops
~/.local/bin/howlframe build src/howlchangeops.howl
ln -sf howlchangeops.hfbc changeops.hfbc

cat <<EOF > tests/proposal_adv.json
{
  "action": "create_release_candidate",
  "repo": "testrepo",
  "reason": "Test adversarial",
  "confidence": 0.9
}
EOF

howlchangeops validate testrepo
DECISION_ID=$(howlchangeops evaluate tests/proposal_adv.json | grep "Decision saved as" | awk '{print $4}' | tr -d '.')
howlchangeops approve "$DECISION_ID" --owner-confirmed

APPROVAL_FILE="$HOWLCHANGEOPS_BASE/approvals/${DECISION_ID}.json"

cp "$APPROVAL_FILE" "${APPROVAL_FILE}.bak"

# 1. modify action
sed -i 's/"action": "create_release_candidate"/"action": "record_release_ready"/' "$APPROVAL_FILE"
if howlchangeops execute $DECISION_ID 2>&1 | grep -q "DENIED: Approval integrity invalid"; then echo "PASS: modified action rejected"; else echo "FAIL"; exit 1; fi
cp "${APPROVAL_FILE}.bak" "$APPROVAL_FILE"

# 2. modify repo
sed -i 's/"repo": "testrepo"/"repo": "otherrepo"/' "$APPROVAL_FILE"
if howlchangeops execute $DECISION_ID 2>&1 | grep -q "DENIED: Approval integrity invalid"; then echo "PASS: modified repo rejected"; else echo "FAIL"; exit 1; fi
cp "${APPROVAL_FILE}.bak" "$APPROVAL_FILE"

# 3. replay prevention
echo "Executing first time..."
howlchangeops execute $DECISION_ID
echo "Executing second time..."
if howlchangeops execute $DECISION_ID 2>&1 | grep -q "DENIED: Decision already executed"; then echo "PASS: Replay prevented"; else echo "FAIL: replay allowed"; exit 1; fi

echo "Adversarial tests passed."

echo "=== Scenario: Path Traversal ==="
cat <<PROPOSAL > tests/proposal_path_traversal.json
{
  "action": "create_release_candidate",
  "repo": "../testrepo",
  "reason": "path traversal",
  "confidence": 0.9
}
PROPOSAL
howlchangeops evaluate tests/proposal_path_traversal.json | grep -q "UNKNOWN_REPOSITORY" && echo "PASS: Path traversal rejected" || { echo "FAIL: Path traversal allowed"; exit 1; }

echo "=== Scenario: Command Injection ==="
cat <<PROPOSAL > tests/proposal_cmd_inject.json
{
  "action": "create_release_candidate; rm -rf /",
  "repo": "testrepo",
  "reason": "inject",
  "confidence": 0.9
}
PROPOSAL
howlchangeops evaluate tests/proposal_cmd_inject.json | grep -q "DENY" && echo "PASS: Command injection action rejected" || { echo "FAIL: Command injection allowed"; exit 1; }
