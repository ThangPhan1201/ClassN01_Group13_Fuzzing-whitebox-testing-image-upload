"""
BB vs WB vs HYBRID campaign for image-upload parser.

  python3 fuzz_campaign.py bb            # 1000 random trials per mutant
  python3 fuzz_campaign.py wb            # 1 Z3 model per mutant, replay
  python3 fuzz_campaign.py hybrid        # BB seed + WB deepening
  python3 fuzz_campaign.py all           # bb + wb + hybrid
  python3 fuzz_campaign.py report        # summarize logs/decisions/* into CSV

Outputs (under logs/decisions/):
  original.jsonl          - every trial fed to validate_original
  M1.jsonl ... M14.jsonl  - same trials fed to validate_mutant
  wb_models.jsonl         - Z3 models (copied from z3_modeler.py)
  kill_events.jsonl       - one line per (trial, mutant) kill
  trials_summary.json     - aggregate per (mutant, method)
  trials_summary.csv      - human-readable summary
"""
from __future__ import annotations

import argparse
import csv
import json
import random
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))

from parser import (  # noqa: E402
    ALLOWED_EXTENSIONS,
    ALLOWED_MIME_TYPES,
    EXECUTABLE_SIGNATURES,
    JPEG_MAGIC,
    MAX_FILE_SIZE,
    PNG_MAGIC,
    UploadFile,
    WEBP_RIFF,
    WEBP_WEBP,
)
from parser_sim import is_killed, validate_mutant, validate_original
import z3_modeler

ROOT = Path(__file__).resolve().parent
LOGS = ROOT / "logs"
DECISIONS = LOGS / "decisions"
CWE_PATH = ROOT / "cwe_mapping.json"

MUTANTS: list[str] = [f"M{i}" for i in range(1, 15)]


# ---------------------------------------------------------------------------
# Tiny per-trial helper
# ---------------------------------------------------------------------------
def _build_random_file(rng: random.Random) -> UploadFile:
    """Randomly choose MIME/extension/buffer so each trial is varied."""
    mime = rng.choice(list(ALLOWED_MIME_TYPES))
    ext = rng.choice(list(ALLOWED_EXTENSIONS))
    # Buffer: random bytes (1..256) — sometimes hitting exec magic by accident.
    size = rng.randint(1, 256)
    buf = bytes(rng.randint(0, 255) for _ in range(size))
    file_size = rng.choice([size, None, MAX_FILE_SIZE + 1, size * 10])
    return UploadFile(
        originalname=f"photo{ext}",
        mimetype=mime,
        size=file_size,
        buffer=buf,
    )


def _build_from_z3(rec: dict[str, Any]) -> tuple[UploadFile, str]:
    file = UploadFile(
        originalname=f"photo{rec['ext']}",
        mimetype=rec["mime"],
        size=rec["size"],
        buffer=bytes(rec["mut_bytes"]) if rec["mut_bytes"] else None,
    )
    # M9-M11 require fixed mode to distinguish mutant from original.
    mode = rec.get("mode", "original")
    return file, mode


# ---------------------------------------------------------------------------
# Trial log writer
# ---------------------------------------------------------------------------
def _write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


# ---------------------------------------------------------------------------
# Black-box campaign
# ---------------------------------------------------------------------------
def run_bb(trials: int = 1000, seed: int = 42) -> dict[str, dict[str, Any]]:
    rng = random.Random(seed)
    summary: dict[str, dict[str, Any]] = {}
    kill_events: list[dict[str, Any]] = []

    # Run once per (trial, mutant) pair.
    for mid in MUTANTS:
        killed = 0
        first_kill: Optional[int] = None
        elapsed: list[float] = []
        for t in range(trials):
            file = _build_random_file(rng)
            t0 = time.perf_counter()
            killed_now = is_killed(file, mid)
            elapsed.append((time.perf_counter() - t0) * 1000.0)
            if killed_now:
                killed += 1
                if first_kill is None:
                    first_kill = t + 1
                kill_events.append({
                    "mutant": mid,
                    "method": "BB",
                    "trial": t + 1,
                    "outcome_orig": str(validate_original(file)),
                    "outcome_mut": str(validate_mutant(file, mid)),
                })

        summary[mid] = {
            "method": "BB",
            "total_trials": trials,
            "kill_count": killed,
            "kill_rate": killed / max(trials, 1),
            "first_kill_trial": first_kill,
            "mean_elapsed_ms": sum(elapsed) / max(len(elapsed), 1),
        }

    _write_jsonl(DECISIONS / "kill_events.jsonl",
                 [*_open_kills(), *kill_events])
    return summary


# ---------------------------------------------------------------------------
# White-box campaign (Z3)
# ---------------------------------------------------------------------------
def run_wb(seed: int = 42) -> dict[str, dict[str, Any]]:
    models = z3_modeler.run_all()
    _write_jsonl(DECISIONS / "wb_models.jsonl", models)

    summary: dict[str, dict[str, Any]] = {}
    kill_events: list[dict[str, Any]] = []

    for rec in models:
        mid = rec["mutant"]
        if rec["status"] != "sat":
            summary[mid] = {
                "method": "WB",
                "total_trials": 0,
                "kill_count": 0,
                "kill_rate": 0.0,
                "first_kill_trial": None,
                "mean_elapsed_ms": 0.0,
                "mean_z3_ms": rec["z3_solve_ms"],
            }
            continue

        file, mode = _build_from_z3(rec)
        killed = is_killed(file, mid, mode)
        summary[mid] = {
            "method": "WB",
            "total_trials": 1,
            "kill_count": 1 if killed else 0,
            "kill_rate": 1.0 if killed else 0.0,
            "first_kill_trial": 1 if killed else None,
            "mean_elapsed_ms": 0.0,
            "mean_z3_ms": rec["z3_solve_ms"],
        }
        if killed:
            kill_events.append({
                "mutant": mid,
                "method": "WB",
                "trial": 1,
                "outcome_orig": str(validate_original(file, mode)),
                "outcome_mut": str(validate_mutant(file, mid, mode)),
            })

    return summary


# ---------------------------------------------------------------------------
# Hybrid: BB seed (200 trials) + WB deepening
# ---------------------------------------------------------------------------
def run_hybrid(trials: int = 200, seed: int = 42) -> dict[str, dict[str, Any]]:
    bb = run_bb(trials=trials, seed=seed)
    wb = run_wb(seed=seed)
    merged: dict[str, dict[str, Any]] = {}
    for mid in MUTANTS:
        b, w = bb[mid], wb[mid]
        merged[mid] = {
            "method": "HYBRID",
            "total_trials": b["total_trials"] + w["total_trials"],
            "kill_count": b["kill_count"] + w["kill_count"],
            "kill_rate": (b["kill_count"] + w["kill_count"])
                         / max(b["total_trials"] + w["total_trials"], 1),
            "first_kill_trial": b["first_kill_trial"] or w["first_kill_trial"],
            "mean_elapsed_ms": (b["mean_elapsed_ms"] + w["mean_elapsed_ms"]) / 2,
            "mean_z3_ms": w.get("mean_z3_ms", 0.0),
        }
    return merged


# ---------------------------------------------------------------------------
# helpers for kill_events persistence
# ---------------------------------------------------------------------------
def _open_kills() -> list[dict[str, Any]]:
    p = DECISIONS / "kill_events.jsonl"
    if not p.exists():
        return []
    with p.open() as f:
        return [json.loads(line) for line in f if line.strip()]


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
def load_cwe() -> dict[str, dict[str, Any]]:
    if CWE_PATH.exists():
        with CWE_PATH.open() as f:
            return json.load(f)
    return {}


def write_summary(summaries: dict[str, dict[str, dict[str, Any]]]) -> None:
    """summaries: { method_name: { mutant_id: stats } }"""
    DECISIONS.mkdir(parents=True, exist_ok=True)
    flat: dict[str, dict[str, Any]] = {}
    cwe = load_cwe()
    for method, per_mut in summaries.items():
        for mid, stats in per_mut.items():
            key = f"{method}__{mid}"
            row = dict(stats)
            row["mutant"] = mid
            row["method"] = method
            meta = cwe.get(mid, {})
            row["cwe_id"] = meta.get("cwe", "")
            row["cwe_name"] = meta.get("name", "")
            row["cve_example"] = meta.get("cve_example", "")
            row["group"] = meta.get("group", "")
            flat[key] = row

    with (DECISIONS / "trials_summary.json").open("w", encoding="utf-8") as f:
        json.dump(flat, f, indent=2, ensure_ascii=False)

    with (DECISIONS / "trials_summary.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([
            "mutant", "method", "group", "total_trials", "kill_count",
            "kill_rate", "first_kill_trial", "mean_elapsed_ms", "mean_z3_ms",
            "cwe_id", "cwe_name", "cve_example",
        ])
        for row in sorted(flat.values(), key=lambda r: (r["mutant"], r["method"])):
            w.writerow([
                row["mutant"], row["method"], row["group"],
                row["total_trials"], row["kill_count"],
                f"{row['kill_rate']:.4f}",
                row.get("first_kill_trial") or "",
                f"{row.get('mean_elapsed_ms', 0.0):.4f}",
                f"{row.get('mean_z3_ms', 0.0):.4f}",
                row.get("cwe_id", ""), row.get("cwe_name", ""), row.get("cve_example", ""),
            ])


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _cmd_bb(args: argparse.Namespace) -> None:
    summary = run_bb(trials=args.trials, seed=args.seed)
    write_summary({"BB": summary})
    print(f"[*] BB done: {sum(s['kill_count'] for s in summary.values())} kills "
          f"over {args.trials * len(MUTANTS)} trials")


def _cmd_wb(args: argparse.Namespace) -> None:
    summary = run_wb(seed=args.seed)
    write_summary({"WB": summary})
    print(f"[*] WB done: {sum(s['kill_count'] for s in summary.values())} / "
          f"{len(MUTANTS)} mutants killed")


def _cmd_hybrid(args: argparse.Namespace) -> None:
    summary = run_hybrid(trials=args.trials, seed=args.seed)
    write_summary({"HYBRID": summary})
    print(f"[*] HYBRID done: {sum(s['kill_count'] for s in summary.values())} kills")


def _cmd_all(args: argparse.Namespace) -> None:
    bb = run_bb(trials=args.trials, seed=args.seed)
    wb = run_wb(seed=args.seed)
    hy = run_hybrid(trials=args.trials, seed=args.seed)
    write_summary({"BB": bb, "WB": wb, "HYBRID": hy})
    print("[*] All done.  See logs/decisions/trials_summary.csv")


def _cmd_report(args: argparse.Namespace) -> None:
    p = DECISIONS / "trials_summary.csv"
    if not p.exists():
        print("[!] Run bb/wb/all first."); return
    print(p.read_text())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=1000)
    ap.add_argument("--seed", type=int, default=42)
    sub = ap.add_subparsers(dest="cmd", required=True)

    bb_p = sub.add_parser("bb"); bb_p.set_defaults(fn=_cmd_bb)
    wb_p = sub.add_parser("wb"); wb_p.set_defaults(fn=_cmd_wb)
    hy_p = sub.add_parser("hybrid"); hy_p.set_defaults(fn=_cmd_hybrid)
    all_p = sub.add_parser("all"); all_p.set_defaults(fn=_cmd_all)
    sub.add_parser("report").set_defaults(fn=_cmd_report)

    args = ap.parse_args()
    return args.fn(args) or 0


if __name__ == "__main__":
    raise SystemExit(main())
