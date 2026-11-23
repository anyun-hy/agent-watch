#!/bin/bash
# Narrow, no-signal regression selection for policy faults and warning recovery.
# These tests use temporary state and mocks. Never run the whole controlled
# suite here: some unrelated legacy tests deliberately signal owned children.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd -P)
cd "$ROOT"
if [[ $# -ne 0 ]]; then
  echo 'Usage: bash tools/test-warning-regressions.sh' >&2
  exit 2
fi
command -v cargo >/dev/null || { echo 'cargo is required; no tests have run.' >&2; exit 1; }
cargo check --locked -p claude-watch-runtime -p claude-watch-engine
cargo test --locked -p claude-watch-core --test probe_independence_regressions -- --nocapture
cargo test --locked -p claude-watch-core --test probe_drift_contracts -- --nocapture
bash tools/run-exact-runtime-tests.sh controlled_contracts \
  invalid_config_guard_reports_unknown_and_preserves_session
bash tools/run-exact-runtime-tests.sh channel_pipeline_contracts \
  independent_current_risks_keep_their_configured_action_and_warn_recovers_without_rebasing \
  managed_multi_main_membership_preserves_continuity_and_fast_risk_across_join_exit_and_pid_reuse
