#!/bin/bash
set -e

# Build
cd adapter && go build -o ../changeops
cd ..

echo "=== Adversarial Tests ==="
FAILURES=0

run_adv() {
  local name=$1
  local proposal=$2
  local expected=$3
  echo "Testing: $name"
  echo "$proposal" > tests/adv_prop.json
  if ./changeops evaluate tests/adv_prop.json 2>&1 | grep -q "$expected"; then
    echo "  PASS: Stopped by '$expected'"
  else
    echo "  FAIL: Did not see '$expected'"
    FAILURES=$((FAILURES+1))
  fi
}

run_adv "Unknown repo" '{"action":"create_release_candidate","repo":"unknown","reason":"..."}' "UNKNOWN_REPOSITORY"

run_adv "Path traversal repo" '{"action":"create_release_candidate","repo":"../../etc/shadow","reason":"..."}' "UNKNOWN_REPOSITORY"

run_adv "Absolute path repo" '{"action":"create_release_candidate","repo":"/etc/passwd","reason":"..."}' "UNKNOWN_REPOSITORY"

run_adv "Unknown action" '{"action":"delete_database","repo":"testrepo","reason":"..."}' "DENY"

run_adv "Command injection reason" '{"action":"create_release_candidate","repo":"testrepo","reason":"\"; rm -rf /;\""}' "DENY"

run_adv "Missing fields" '{"confidence":0.9}' "UNKNOWN_REPOSITORY"

rm tests/adv_prop.json

if [ $FAILURES -eq 0 ]; then
  echo "ALL ADVERSARIAL TESTS PASSED"
else
  echo "$FAILURES ADVERSARIAL TESTS FAILED"
  exit 1
fi
