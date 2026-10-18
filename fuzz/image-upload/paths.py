from pathlib import Path

ROOT = Path(__file__).resolve().parent
LOGS = ROOT / "logs"
CRASHES = ROOT / "crashes"

SPECS_JSON = LOGS / "specs.json"
BB_JSON = LOGS / "bb_magic_trials.json"
WB_JSON = LOGS / "wb_z3_model.json"
COMPARE_JSON = LOGS / "compare.json"
RESULTS_JSON = LOGS / "fuzz_results.json"
ELF_BIN = CRASHES / "elf_magic.bin"


def ensure_dirs() -> None:
    LOGS.mkdir(parents=True, exist_ok=True)
    CRASHES.mkdir(parents=True, exist_ok=True)
