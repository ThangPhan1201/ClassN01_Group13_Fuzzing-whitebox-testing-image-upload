#!/usr/bin/env bash
#
# Image-upload fuzzing — full pipeline in one command.
#
# Usage:
#   ./run_all.sh                    # full 6-phase (spec → verify)
#   ./run_all.sh --skip-verify      # stop at Phase 3 (no fix needed)
#   SEED=42 ./run_all.sh            # override default seed
#
# Outputs (all paths are absolute relative to this script):
#   logs/specs.json
#   logs/bb_magic_trials.json
#   logs/wb_z3_model.json
#   logs/compare.json
#   logs/fuzz_results.json     ← before fix (PASS/FAIL on original parser)
#   logs/verify.json           ← after fix  (PASS/FAIL on fixed parser)
#   crashes/IMG-01_*.bin ...   ← one crash file per IMG spec; replayable
#   crashes/IMG-MAGIC_elf_magic.bin

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Always use the same Python and Z3 found in requirements.txt
PYTHON="${PYTHON:-python3}"

# Reuse any extra args, so callers can still pass --seed, --runs, etc.
EXTRA_ARGS=("$@")

if [ ! -d "logs" ] || [ ! -d "crashes" ]; then
  mkdir -p logs crashes
fi

echo "=========================================================="
echo " IMAGE-UPLOAD FUZZING — full pipeline"
echo " Python: $($PYTHON --version 2>&1)"
echo " Args:   ${EXTRA_ARGS[*]:-}"
echo "=========================================================="

# Use "+ expansion" trick to avoid "unbound variable" under set -u when no args
if [ ${#EXTRA_ARGS[@]} -gt 0 ]; then
  $PYTHON fuzz_image_upload.py all "${EXTRA_ARGS[@]}"
else
  $PYTHON fuzz_image_upload.py all
fi

echo
echo "[*] Replay any crash file (example):"
echo "    xxd crashes/IMG-MAGIC_elf_magic.bin"
echo "    $PYTHON -c \""
echo "      from parser import UploadFile, validate_file, Outcome;"
echo "      buf = open('crashes/IMG-MAGIC_elf_magic.bin','rb').read();"
echo "      print(validate_file(UploadFile('photo.jpg','image/jpeg',len(buf),buf), mode='fixed'))"
echo "    \""
