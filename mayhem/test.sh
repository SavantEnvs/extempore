#!/usr/bin/env bash
#
# mayhem/test.sh -- run upstream's gtest cases for the OSC wire/text helpers (osc_test.cpp) and the
# zone allocator (zones_test.cpp), built by mayhem/build.sh. They assert known inputs against known
# outputs (escaped Scheme literals, packet encodings, zone footprints and layout).
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=/mayhem}"
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

RUNNER=build/mayhem/tests/extempore_cpp_unit
if [ ! -x "$RUNNER" ]; then
  echo "missing $RUNNER: mayhem/build.sh did not build the test runner" >&2
  exit 1
fi

OUT=$(mktemp)
"$RUNNER" > "$OUT" 2>&1
RC=$?
cat "$OUT"

passed=$(sed -n 's/^\[  PASSED  \] \([0-9][0-9]*\) tests\?\..*/\1/p' "$OUT" | tail -1)
failed=$(grep -c '^\[  FAILED  \] .*\.' "$OUT" || true)
skipped=$(sed -n 's/^\[  SKIPPED \] \([0-9][0-9]*\) tests\?, listed below.*/\1/p' "$OUT" | tail -1)
passed=${passed:-0}; skipped=${skipped:-0}
rm -f "$OUT"

# upstream's 7 cpp-unit files hold 50 cases; fewer than 45 passing means the runner did not really run
if [ "$RC" -ne 0 ] && [ "$failed" -eq 0 ]; then failed=1; fi
if [ "$passed" -lt 45 ]; then failed=$(( failed + 1 )); fi
emit_ctrf "gtest" "$passed" "$failed" "$skipped"
