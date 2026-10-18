#!/usr/bin/env bash
#
# V2 — Image-upload fuzzing — full pipeline in one command.
#
# Usage:
#   ./run_all.sh                    # full 6-phase (spec → verify)
#   ./run_all.sh --skip-verify      # stop at Phase 3 (no fix needed)
#   SEED=42 ./run_all.sh            # override default seed
#
# Outputs (all paths are relative to v2/):
#   logs/reports/req_extraction.json
#   logs/raw/module_trace.json
#   logs/raw/audit_log_sample.jsonl
#   logs/reports/module_analysis.md
#   logs/decisions/wb_models.jsonl
#   logs/decisions/kill_events.jsonl
#   logs/decisions/trials_summary.json
#   logs/decisions/trials_summary.csv

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PYTHON="${PYTHON:-python3}"

# Reuse any extra args, so callers can still pass --seed, --runs, etc.
EXTRA_ARGS=("$@")

if [ ! -d "logs" ] || [ ! -d "logs/raw" ] || [ ! -d "logs/reports" ] || [ ! -d "logs/decisions" ]; then
  mkdir -p logs/raw logs/reports logs/decisions
fi

echo "=========================================================="
echo " V2 IMAGE-UPLOAD FUZZING — full pipeline"
echo " Python: $($PYTHON --version 2>&1)"
echo " Args:   ${EXTRA_ARGS[*]:-}"
echo "=========================================================="

# Phase 0 — module + log analysis
echo
echo "── Phase 0: module + log analyzer ──"
$PYTHON module_log_analyzer.py

# Phase 3 — show spec
echo
echo "── Phase 3: show_specs (spec only) ──"
$PYTHON show_specs.py spec

# Phase 4 — Z3 solvers
echo
echo "── Phase 4: Z3 solvers ──"
if [ ${#EXTRA_ARGS[@]} -gt 0 ]; then
  $PYTHON z3_modeler.py "${EXTRA_ARGS[@]}"
else
  $PYTHON z3_modeler.py
fi

# Phase 6 — campaign (bb + wb + hybrid)
echo
echo "── Phase 6: campaign (bb + wb + hybrid) ──"
if [ ${#EXTRA_ARGS[@]} -gt 0 ]; then
  $PYTHON fuzz_campaign.py all "${EXTRA_ARGS[@]}"
else
  $PYTHON fuzz_campaign.py all
fi

# Phase 7 — convert JSONL → CSV
echo
echo "── Phase 7: to_csv (JSONL → CSV) ──"
$PYTHON to_csv.py --all

echo
echo "=========================================================="
echo " V2 pipeline done."
echo " Summary CSV: logs/decisions/trials_summary.csv"
echo " Live CSVs:   logs/live/static.csv  logs/live/dynamic.csv"
echo "=========================================================="
