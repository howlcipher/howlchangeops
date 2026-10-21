#!/bin/bash
set -e

# Setup test environment
TEMP_KEY=$(mktemp)
dd if=/dev/urandom of="$TEMP_KEY" bs=32 count=1 2>/dev/null
chmod 600 "$TEMP_KEY"
export HOWLCHANGEOPS_APPROVAL_KEY_FILE="$TEMP_KEY"

mkdir -p config
cat <<EOF > config/howlchangeops-config.json
{
  "repos": {
    "testrepo": {
      "path": "$(pwd)/tests/testrepo",
      "allowed_branches": ["main"],
      "validation_profile": "go",
      "allowed_actions": ["create_release_candidate"]
    }
  }
}
EOF

rm -rf tests/testrepo .howlchangeops .changeops
mkdir -p tests/testrepo
cd tests/testrepo
git init
git checkout -b main
git config user.email "test@example.com"
git config user.name "Test User"
echo "package main; func main() {}" > main.go
go mod init testrepo
echo "testrepo" > .gitignore
git add main.go go.mod .gitignore
git commit -m "initial"
git checkout -b feature-branch
cd ../..

# Build
cd adapter && go build -o ../howlchangeops
cd ..
ln -sf howlchangeops changeops
export PATH="$HOME/.local/bin:$PATH"
~/.local/bin/howlframe build src/howlchangeops.howl
ln -sf howlchangeops.hfbc changeops.hfbc

FAILURES=0
echo "=== Authority Bypass Tests ==="

# Test 1: Branch bypass
echo "Test 1: Branch bypass"
cat <<EOF > tests/prop.json
{"action":"create_release_candidate","repo":"testrepo"}
EOF
# evaluate on feature-branch
./howlchangeops validate testrepo >/dev/null || true
OUT=$(./howlchangeops evaluate tests/prop.json) || true
if echo "$OUT" | grep -q "branch not permitted"; then
  echo "  PASS: Stopped by branch policy"
else
  echo "  FAIL: Allowed branch not enforced. Output: $OUT"
  FAILURES=$((FAILURES+1))
fi

# Test 2: Action bypass
echo "Test 2: Action bypass"
cat <<EOF > config/howlchangeops-config.json
{
  "repos": {
    "testrepo": {
      "path": "$(pwd)/tests/testrepo",
      "allowed_branches": ["main"],
      "validation_profile": "go",
      "allowed_actions": ["record_release_ready"]
    }
  }
}
EOF
cd tests/testrepo && git checkout main && cd ../..
./howlchangeops validate testrepo >/dev/null || true
OUT=$(./howlchangeops evaluate tests/prop.json) || true
if echo "$OUT" | grep -q "action not permitted"; then
  echo "  PASS: Stopped by action policy"
else
  echo "  FAIL: Allowed action not enforced. Output: $OUT"
  FAILURES=$((FAILURES+1))
fi

# Test 3: Decision mutation bypass
echo "Test 3: Decision mutation bypass (repo transfer)"
cat <<EOF > config/howlchangeops-config.json
{
  "repos": {
    "testrepo": {
      "path": "$(pwd)/tests/testrepo",
      "allowed_branches": ["main"],
      "validation_profile": "go",
      "allowed_actions": ["create_release_candidate"]
    },
    "testrepo2": {
      "path": "$(pwd)/tests/testrepo2",
      "allowed_branches": ["main"],
      "validation_profile": "go",
      "allowed_actions": ["create_release_candidate"]
    }
  }
}
EOF
# create testrepo2
rm -rf tests/testrepo2
mkdir -p tests/testrepo2
cd tests/testrepo2
git init
git checkout -b main
git config user.email "test@example.com"
git config user.name "Test User"
echo "package main; func main() {}" > main.go
go mod init testrepo2
echo "testrepo2" > .gitignore
git add main.go go.mod .gitignore
git commit -m "initial"
cd ../..

./howlchangeops validate testrepo >/dev/null || true
./howlchangeops validate testrepo2 >/dev/null || true

OUT=$(./howlchangeops evaluate tests/prop.json) || true
DEC_ID=$(echo "$OUT" | grep "Decision saved as" | awk '{print $4}' | tr -d '.')
./howlchangeops approve "$DEC_ID" --owner-confirmed >/dev/null

# mutate decision to transfer to testrepo2 and bypass stale evidence
REV2=$(cd tests/testrepo2 && git rev-parse HEAD)
sed -i "s/\"repo\": \"testrepo\"/\"repo\": \"testrepo2\"/g" .howlchangeops/decisions/${DEC_ID}.json
sed -i "s/\"revision\": \"[a-f0-9]*\"/\"revision\": \"${REV2}\"/g" .howlchangeops/decisions/${DEC_ID}.json

OUT2=$(./howlchangeops execute "$DEC_ID" 2>&1) || true
if echo "$OUT2" | grep -q "Created tag"; then
  echo "  FAIL: Decision mutation bypassed! Tag created on testrepo2"
  FAILURES=$((FAILURES+1))
else
  echo "  PASS: Decision mutation caught. Output: $OUT2"
fi

# Cleanup test repos
rm -rf tests/testrepo tests/testrepo2 tests/prop.json config/howlchangeops-config.json

if [ $FAILURES -eq 0 ]; then
  echo "ALL PASSED"
else
  echo "FAILURES: $FAILURES"
  exit 1
fi
