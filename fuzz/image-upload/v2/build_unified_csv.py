#!/usr/bin/env python3
"""
Build a unified fuzzing results CSV from 3 sources:

  1. Static (property-based, fast-check)  -> backend/src/fuzz/results/fuzz-results.json
  2. Dynamic (HTTP black-box)             -> fuzz/image-upload/v2/logs/live/dynamic.jsonl
  3. Mutation (Z3 white-box)              -> fuzz/image-upload/v2/logs/decisions/wb_models.jsonl

Output schema (per spec):
  layer,mutant,method,group,total_trials,kill_count,kill_rate,
  first_kill_trial,mean_elapsed_ms,mean_z3_ms,cwe_id,cwe_name,cve_example

- layer     : static_property | dynamic_http | mutation
- mutant    : filled only when source is Stryker/PIT, else blank
- kill_rate : (static) exceptions/total_trials, (dynamic) crashes/attempts,
              (mutation) sat/14 if all 14 mutants were solved
- cve_example: '-' for custom app, only filled for OSS libs
"""
from __future__ import annotations

import csv
import json
import statistics
from collections import Counter, defaultdict
from pathlib import Path

# ------------------------------------------------------------------
# Paths
# ------------------------------------------------------------------
ROOT = Path("/Users/admin/Downloads/fuzzing-white-box")

STATIC_JSON = ROOT / "backend/src/fuzz/results/fuzz-results.json"
DYNAMIC_JSONL = ROOT / "fuzz/image-upload/v2/logs/live/dynamic.jsonl"
MUTATION_JSONL = ROOT / "fuzz/image-upload/v2/logs/decisions/wb_models.jsonl"
OUT_CSV = ROOT / "fuzz/image-upload/v2/logs/reports/unified_fuzzing.csv"

# ------------------------------------------------------------------
# CWE mapping (filled from observed error types)
# ------------------------------------------------------------------
CWE_MAP = {
    "CWE-20": "Improper Input Validation",
    "CWE-89": "Improper Neutralization of Special Elements used in an SQL Command",
    "CWE-1284": "Improper Validation of Specified Quantity in Input",
    "CWE-176": "Improper Handling of Unicode Encoding",
    "CWE-22": "Improper Limitation of a Pathname to a Restricted Directory",
    "CWE-79": "Improper Neutralization of Input During Web Page Generation (XSS)",
    "CWE-307": "Improper Restriction of Excess Authentication Attempts",
    "CWE-770": "Allocation of Resources Without Limits or Throttling",
    "CWE-863": "Incorrect Authorization",
    "CWE-200": "Information Exposure",
}

# Category -> CWE mapping (based on generator labels)
CATEGORY_CWE = {
    "type_confusion": "CWE-20",
    "boundary": "CWE-1284",
    "unicode": "CWE-176",
    "sql_injection": "CWE-89",
    "xss": "CWE-79",
    "path_traversal": "CWE-22",
    "empty": "CWE-20",
    "very_long": "CWE-20",
    "special_chars": "CWE-20",
    "normal": "CWE-20",
    # dynamic kinds
    "polyglot_jpeg_zip": "CWE-20",
    "name_with_path": "CWE-22",
    "wrong_magic": "CWE-20",
    "all_0xff": "CWE-20",
    "empty": "CWE-20",
    "extension_mismatch": "CWE-20",
    "valid": "CWE-20",
    "null_bytes": "CWE-20",
    "truncated": "CWE-20",
    "all_zeros": "CWE-20",
    "huge_magic": "CWE-20",
    "oversize": "CWE-770",
    "exe_in_disguise": "CWE-20",
}


def cwe_for(category: str) -> str:
    cid = CATEGORY_CWE.get(category, "CWE-20")
    return f"{cid},{CWE_MAP[cid]}"


# ------------------------------------------------------------------
# 1. STATIC: backend/src/fuzz/results/fuzz-results.json
# ------------------------------------------------------------------
def load_static() -> list[dict]:
    """One row per category in categoryStats."""
    data = json.loads(STATIC_JSON.read_text(encoding="utf-8"))
    method = (
        f"{data['target']['class']}."
        f"{data['target']['method'].split('(')[0]}"
    )

    cat_stats: dict[str, dict] = data.get("categoryStats", {})
    failures: list[dict] = data.get("failures", [])

    # Track first failure trial per category (approx: 1-based ordinal among failures)
    first_failure_per_cat: dict[str, int] = {}
    for idx, f in enumerate(failures, start=1):
        cat = f.get("category", "unknown")
        if cat not in first_failure_per_cat:
            first_failure_per_cat[cat] = idx

    rows = []
    for category, s in cat_stats.items():
        total = s.get("total", 0)
        exceptions = s.get("exceptions", 0)
        # kill_rate = exceptions / total (per spec)
        kill_rate = round(exceptions / total, 6) if total else 0.0
        # mean elapsed from individual failures in this category
        times = [
            f.get("executionTime", 0)
            for f in failures
            if f.get("category") == category
        ]
        mean_elapsed = round(statistics.mean(times), 3) if times else 0.0
        rows.append({
            "layer": "static_property",
            "mutant": "",  # no Stryker/PIT
            "method": method,
            "group": category,
            "total_trials": total,
            "kill_count": exceptions,
            "kill_rate": kill_rate,
            "first_kill_trial": first_failure_per_cat.get(category, 0),
            "mean_elapsed_ms": mean_elapsed,
            "mean_z3_ms": 0.0,  # fast-check uses shrinking, not Z3
            "cwe_id,cwe_name": cwe_for(category),
            "cve_example": "-",
        })
    return rows


# ------------------------------------------------------------------
# 2. DYNAMIC: fuzz/image-upload/v2/logs/live/dynamic.jsonl
# ------------------------------------------------------------------
def load_dynamic() -> list[dict]:
    """One row per (kind, outcome) group, with crashes counted as kills."""
    trials: list[dict] = []
    with DYNAMIC_JSONL.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            trials.append(json.loads(line))

    # group by kind
    by_kind: dict[str, list[dict]] = defaultdict(list)
    for t in trials:
        by_kind[t["kind"]].append(t)

    rows = []
    for kind, items in by_kind.items():
        total = len(items)
        crashes = sum(1 for t in items if t["outcome"] == "CRASH")
        kill_rate = round(crashes / total, 6) if total else 0.0
        # first crash ordinal
        first_crash_trial = 0
        for idx, t in enumerate(items, start=1):
            if t["outcome"] == "CRASH":
                first_crash_trial = idx
                break
        mean_elapsed = round(
            statistics.mean(t["elapsed_ms"] for t in items), 3
        ) if items else 0.0
        rows.append({
            "layer": "dynamic_http",
            "mutant": "",  # no Stryker/PIT
            "method": "POST /api/upload (image-upload endpoint)",
            "group": kind,
            "total_trials": total,
            "kill_count": crashes,
            "kill_rate": kill_rate,
            "first_kill_trial": first_crash_trial,
            "mean_elapsed_ms": mean_elapsed,
            "mean_z3_ms": 0.0,  # black-box doesn't use Z3
            "cwe_id,cwe_name": cwe_for(kind),
            "cve_example": "-",
        })
    return rows


# ------------------------------------------------------------------
# 3. MUTATION (Z3): fuzz/image-upload/v2/logs/decisions/wb_models.jsonl
# ------------------------------------------------------------------
def load_mutation() -> list[dict]:
    """
    One row per mutant solved. kill_count = 1 if sat, 0 if unsat.
    kill_rate = 1/1 for sat, 0/1 for unsat.
    """
    rows = []
    with MUTATION_JSONL.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            status = r["status"]
            kill = 1 if status == "sat" else 0
            rows.append({
                "layer": "mutation",
                "mutant": r["mutant"],  # filled: this IS mutation testing
                "method": f"image-upload validateFile / REQ {r['model_id']}",
                "group": r["model_id"],
                "total_trials": 1,  # one Z3 solve per mutant
                "kill_count": kill,
                "kill_rate": float(kill),
                "first_kill_trial": 1 if kill else 0,
                "mean_elapsed_ms": 0.0,  # not a runtime measurement
                "mean_z3_ms": round(r.get("z3_solve_ms", 0.0), 3),
                "cwe_id,cwe_name": cwe_for("type_confusion"),  # upload validation
                "cve_example": "-",  # custom app, no CVE
            })
    return rows


# ------------------------------------------------------------------
# Main
# ------------------------------------------------------------------
def main() -> None:
    static_rows = load_static()
    dynamic_rows = load_dynamic()
    mutation_rows = load_mutation()

    all_rows = static_rows + dynamic_rows + mutation_rows

    OUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    with OUT_CSV.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(all_rows[0].keys()))
        writer.writeheader()
        writer.writerows(all_rows)

    # Print summary
    print(f"[*] Wrote {len(all_rows)} rows to {OUT_CSV}")
    print(f"    static_property : {len(static_rows)}")
    print(f"    dynamic_http    : {len(dynamic_rows)}")
    print(f"    mutation        : {len(mutation_rows)}")

    # Top killers per layer
    print("\n=== Top kill_rate per layer ===")
    by_layer = defaultdict(list)
    for r in all_rows:
        by_layer[r["layer"]].append(r)
    for layer, rows in by_layer.items():
        top = sorted(rows, key=lambda r: r["kill_rate"], reverse=True)[:3]
        for r in top:
            print(
                f"  [{layer:<18}] group={r['group']:<22} "
                f"kills={r['kill_count']:>4}/{r['total_trials']:<5} "
                f"rate={r['kill_rate']:.4f} "
                f"cwe={r['cwe_id,cwe_name']}"
            )


if __name__ == "__main__":
    main()
