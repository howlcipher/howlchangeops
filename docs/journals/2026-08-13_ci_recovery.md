# CI Recovery - 2026-08-13

## Issue
The adversarial test suite failed during CI on the main branch for the `howlcipher/changeops` repository. The failure occurred specifically in the "Unknown action" scenario, which expected the string "unknown action" to be present in the output.

## Root Cause
Recent hardening of the policy authority within `src/changeops.howl` caused the evaluation of unauthorized or unknown actions (such as `delete_database`) to correctly yield a strict `DENY` decision. Consequently, the literal string "unknown action" was no longer emitted, causing the brittle prose check in `tests/adversarial_test.sh` to fail.

## Fix
Updated `tests/adversarial_test.sh` to accurately reflect the hardened security posture. The test now asserts that unknown actions result in a `DENY` decision rather than expecting arbitrary prose. This validates our security invariants (i.e. that unknown actions cannot bypass the policy engine, resulting in a strict denial without taking any mutating effect).

## Validation
- Rebuilt the adapter logic and the policy using `howlframe build`.
- Ran integration and adversarial test suites successfully locally.
- Verified that the `DENY` condition successfully stops unauthorized actions without creating actionable decision outputs.
