#!/usr/bin/env bash
#
# Listing-service fuzzing — full Jest run with reproducible results.
#
# Outputs:
#   backend/src/fuzz/results/fuzz-results.json     ← BEFORE fix (from fuzzer)
#   backend/src/fuzz/results/fuzz-results-after.json ← AFTER fix (from Jest)
#
# Diff command:
#   diff -u src/fuzz/results/fuzz-results.json \
#        src/fuzz/results/fuzz-results-after.json | less
#
# Usage:
#   ./run_listing.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$(cd "$SCRIPT_DIR/../../backend" && pwd)"
RESULTS_DIR="$BACKEND_DIR/src/fuzz/results"
mkdir -p "$RESULTS_DIR"

cd "$BACKEND_DIR"

echo "=========================================================="
echo " LISTING-SERVICE FUZZING — Jest run"
echo " Backend:  $BACKEND_DIR"
echo " Spec:     src/modules/listing/__tests__/listing.fuzz.spec.ts"
echo "=========================================================="

# Run Jest; capture both human output and machine JSON.
# --testPathPattern scopes to the fuzz spec file only.
# --json produces a structured report consumable in CI.
TMP_JSON="$(mktemp -t listing-jest-XXXX.json)"
trap 'rm -f "$TMP_JSON"' EXIT

# Default: 60s timeout. Increase if you run --maxWorkers=1.
# Prefer gtimeout (Homebrew coreutils) on macOS; fall back to no timeout.
TIMEOUT_CMD=""
if command -v timeout >/dev/null 2>&1; then
  TIMEOUT_CMD="timeout 120"
elif command -v gtimeout >/dev/null 2>&1; then
  TIMEOUT_CMD="gtimeout 120"
fi

$TIMEOUT_CMD npx jest \
  --testPathPattern="listing.fuzz" \
  --json \
  --outputFile="$TMP_JSON" \
  --testTimeout=30000 2>&1 | tail -25

# Re-format the raw Jest JSON into the same shape as the fuzzer's
# fuzz-results.json (numFailingTests, numPassingTests, testResults…),
# so a "before vs after" diff is straightforward.
DEST="$RESULTS_DIR/fuzz-results-after.json"
python3 - "$TMP_JSON" >"$DEST" <<'PY'
import json
import sys
import time

raw = json.load(open(sys.argv[1]))
agg = raw.get("testResults", [])
rows = []
for suite in agg:
    # Jest 29+ renames the inner key to `assertionResults`.
    # Fall back to the older name for backward compatibility.
    inner = suite.get("assertionResults") or suite.get("testResults") or []
    for t in inner:
        rows.append({
            "id": (t.get("name") or "?").split()[-1] if t.get("name") else "?",
            "title": t.get("title") or t.get("name"),
            "fullName": t.get("fullName"),
            "status": t.get("status"),         # passed | failed | skipped | pending
            "duration_ms": t.get("duration", 0),
            "failureMessages": t.get("failureMessages", []),
        })

passed = sum(1 for r in rows if r["status"] == "passed")
failed = sum(1 for r in rows if r["status"] == "failed")
skipped = sum(1 for r in rows if r["status"] in {"skipped", "pending", "todo"})

# Also pick up the top-level counters Jest already aggregates.
# Useful for a quick eyeball check.
num_total = raw.get("numTotalTests", len(rows))
num_passed = raw.get("numPassedTests", passed)
num_failed = raw.get("numFailedTests", failed)
num_skipped = raw.get("numPendingTests", skipped)

out = {
    "target": {
        "file": "backend/src/modules/listing/services/listing.service.ts",
        "class": "ListingService",
        "method": "findAll",
    },
    "phase": "after",
    "finished_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "total": num_total,
    "passed": num_passed,
    "failed": num_failed,
    "skipped": num_skipped,
    # align with before-format (exceptions = failed Jest tests)
    "exceptions": num_failed,
    "jest_counters": {
        "numTotalTests": num_total,
        "numPassedTests": num_passed,
        "numFailedTests": num_failed,
        "numPendingTests": num_skipped,
        "numTotalTestSuites": raw.get("numTotalTestSuites"),
        "success": raw.get("success"),
    },
    "test_results": rows,
}
json.dump(out, sys.stdout, indent=2, ensure_ascii=False)
sys.stdout.write("\n")
PY

echo
echo "[*] After-results written to: $DEST"
echo "    Compare with before-fix:  $RESULTS_DIR/fuzz-results.json"
