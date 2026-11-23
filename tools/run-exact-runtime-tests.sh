#!/bin/bash
# Run named libtest cases in one target and fail if a case was removed or ignored.
set -euo pipefail
if [[ $# -lt 2 ]]; then
  echo 'Usage: bash tools/run-exact-runtime-tests.sh <test-target|--lib> <test-name>...' >&2
  exit 2
fi
target=(--test "$1")
if [[ "$1" == --lib ]]; then target=(--lib); fi
shift

if output=$(cargo test --locked -p claude-watch-runtime "${target[@]}" -- --exact --format pretty --color never "$@"); then
  printf '%s\n' "$output"
else
  status=$?
  printf '%s\n' "$output"
  exit "$status"
fi
if ! grep -q "^test result: ok\. $# passed; 0 failed;" <<<"$output"; then
  printf 'Expected %d passing exact tests in %s: %s\n' "$#" "${target[*]}" "$*" >&2
  exit 1
fi
