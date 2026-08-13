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
  local expected_outcome=$3
  echo "Testing: $name"
  echo "$proposal" > tests/adv_prop.json
  local out=$(./changeops evaluate tests/adv_prop.json 2>&1)
  
  if [ "$expected_outcome" == "UNKNOWN_REPOSITORY" ]; then
    if echo "$out" | grep -q "UNKNOWN_REPOSITORY"; then
      echo "  PASS: Stopped securely (Unknown repo)"
      return
    fi
  elif [ "$expected_outcome" == "DENY" ]; then
    if echo "$out" | grep -q "Decision: DENY"; then
      echo "  PASS: Stopped securely (Decision: DENY)"
      return
    fi
  elif [ "$expected_outcome" == "REQUIRE_APPROVAL" ]; then
    if echo "$out" | grep -q "Decision: REQUIRE_APPROVAL"; then
      echo "  PASS: Stopped securely (Decision: REQUIRE_APPROVAL)"
      return
    fi
  fi
  
  echo "  FAIL: Did not see expected secure outcome '$expected_outcome'. Output was:"
  echo "$out"
  FAILURES=$((FAILURES+1))
}

run_adv "Unknown repo" '{"action":"create_release_candidate","repo":"unknown","reason":"..."}' "UNKNOWN_REPOSITORY"

run_adv "Path traversal repo" '{"action":"create_release_candidate","repo":"../../etc/shadow","reason":"..."}' "UNKNOWN_REPOSITORY"

run_adv "Absolute path repo" '{"action":"create_release_candidate","repo":"/etc/passwd","reason":"..."}' "UNKNOWN_REPOSITORY"

run_adv "Unknown action" '{"action":"delete_database","repo":"testrepo","reason":"..."}' "DENY"

run_adv "Command injection reason" '{"action":"create_release_candidate","repo":"testrepo","reason":"\"; rm -rf /;\""}' "REQUIRE_APPROVAL"

run_adv "Missing fields" '{"confidence":0.9}' "UNKNOWN_REPOSITORY"

rm tests/adv_prop.json

if [ $FAILURES -eq 0 ]; then
  echo "ALL ADVERSARIAL TESTS PASSED"
else
  echo "$FAILURES ADVERSARIAL TESTS FAILED"
  exit 1
fi
