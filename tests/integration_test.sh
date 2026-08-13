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
git add main.go go.mod .gitignore
git commit -m "add go mock profile"

# Back to project dir
cd - > /dev/null
PROJECT_DIR=$PWD
export PATH="$PROJECT_DIR:$PATH"
export CHANGEOPS_BASE="$TEMP_REPO/.changeops"

cat <<EOF > config/changeops-config.json
{
  "repos": {
    "testrepo": {
      "path": "$TEMP_REPO",
      "allowed_branches": ["main"],
      "validation_profile": "go",
      "allowed_actions": [
        "create_release_candidate"
      ]
    }
  }
}
EOF

# Build adapter and policy
cd adapter && go build -o ../changeops
cd ..
~/.local/bin/howlframe build src/changeops.howl

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
changeops evaluate tests/proposal_1.json | grep -q "DENY" && echo "PASS: Denied due to dirty repo"

echo "=== Scenario 2 - Clean repo but no approval ==="
cd "$TEMP_REPO" && git commit -am "clean" && cd - > /dev/null
changeops validate testrepo
changeops evaluate tests/proposal_1.json | grep -q "REQUIRE_APPROVAL" && echo "PASS: Required approval"
DECISION_ID=$(changeops evaluate tests/proposal_1.json | grep "Decision saved as" | awk '{print $4}' | tr -d '.')

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
changeops evaluate tests/proposal_3.json | grep -q "REQUIRE_APPROVAL" && echo "PASS: Self approval ignored, still REQUIRE_APPROVAL"

echo "=== Scenario 4 - Trusted approval ==="
changeops approve $DECISION_ID
changeops execute $DECISION_ID | grep -q "Executing action: create_release_candidate" && echo "PASS: Action executed"
cd "$TEMP_REPO" && git tag -l | grep -q "changeops/rc-" && echo "PASS: Tag created" && cd - > /dev/null

echo "=== Scenario 5 - Stale evidence ==="
DECISION_ID2=$(changeops evaluate tests/proposal_1.json | grep "Decision saved as" | awk '{print $4}' | tr -d '.')
changeops approve $DECISION_ID2
# Modify repo before executing
echo "stale" >> "$TEMP_REPO/file.txt"
cd "$TEMP_REPO" && git commit -am "stale commit" && cd - > /dev/null
# Execute should fail
if changeops execute $DECISION_ID2 2>&1 | grep -q "STALE_EVIDENCE"; then
  echo "PASS: Stale evidence detected and blocked"
else
  echo "FAIL: Stale evidence was allowed!"
  exit 1
fi


echo "=== Scenario 6 - HowlFrame failure ==="
# We have a valid decision, let's create a new one since DECISION_ID2 is stale
cd "$TEMP_REPO" && git commit --allow-empty -m "clean for scenario 6" && cd - > /dev/null
changeops validate testrepo
changeops evaluate tests/proposal_1.json | grep -q "REQUIRE_APPROVAL" && echo "PASS: Required approval for HowlFrame failure test"
DECISION_ID3=$(changeops evaluate tests/proposal_1.json | grep "Decision saved as" | awk '{print $4}' | tr -d '.')
changeops approve $DECISION_ID3

# Break HowlFrame by deleting the policy file temporarily
mv changeops.hfbc changeops.hfbc.bak
if changeops execute $DECISION_ID3 2>&1 | grep -q "Execution evaluation error"; then
  echo "PASS: HowlFrame failure blocked execution"
else
  echo "FAIL: HowlFrame failure did not block execution!"
  mv changeops.hfbc.bak changeops.hfbc
  exit 1
fi
mv changeops.hfbc.bak changeops.hfbc

echo "ALL TESTS PASSED"
