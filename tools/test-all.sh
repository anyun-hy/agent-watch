#!/bin/bash
# Default pure contracts; --level 2 selects native fixtures. Never installs a service.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd -P)
command -v python3 >/dev/null || { echo 'python3 is required to collect test results.' >&2; exit 2; }
exec python3 "$ROOT/tools/run_all_tests.py" "$@"
