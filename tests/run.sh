#!/usr/bin/env bash
# Run every test file. They are plain unittest scripts with no dependencies, so
# `bash tests/run.sh` works on a bare box with nothing installed.
set -uo pipefail
cd "$(dirname "$0")"
fail=0
for t in test_*.py; do
  echo "=== $t"
  python3 "$t" -q || fail=1
done
if [ "$fail" -eq 0 ]; then
  echo "ALL TESTS PASSED"
else
  echo "TESTS FAILED"
fi
exit "$fail"
