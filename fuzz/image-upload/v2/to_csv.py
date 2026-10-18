#!/usr/bin/env python3
"""
V2 — to_csv.py: JSONL → CSV (one-way only).

Chỉ làm JSONL → CSV. Không làm ngược lại, không merge 2 file, không analyze.

Usage:
    python3 to_csv.py                          # mặc định: static.jsonl → static.csv
    python3 to_csv.py dynamic                  # dynamic.jsonl → dynamic.csv
    python3 to_csv.py logs/live/static.jsonl   # file tùy ý → file.csv cùng thư mục
    python3 to_csv.py in.jsonl out.csv         # chỉ định input + output rõ ràng
    python3 to_csv.py --all                    # convert cả static.jsonl + dynamic.jsonl

Schema cố định (12 cột):
    ts, mode, trial, kind, size, mime, name, outcome, reason,
    elapsed_ms, returncode, stderr
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

# Schema cố định — record nào thiếu trường sẽ để trống
RECORD_FIELDS = [
    "ts",
    "mode",
    "trial",
    "kind",
    "size",
    "mime",
    "name",
    "outcome",
    "reason",
    "elapsed_ms",
    "returncode",
    "stderr",
]


def jsonl_to_csv(jsonl_path: Path, csv_path: Path) -> int:
    """Convert 1 file JSONL → 1 file CSV. Trả về số dòng đã ghi."""
    if not jsonl_path.exists():
        print(f"[!] Not found: {jsonl_path}", file=sys.stderr)
        return 0
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with jsonl_path.open("r", encoding="utf-8") as fin, \
         csv_path.open("w", newline="", encoding="utf-8") as fout:
        w = csv.DictWriter(fout, fieldnames=RECORD_FIELDS, extrasaction="ignore")
        w.writeheader()
        for line in fin:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError as e:
                print(f"[!] bad json line {n + 1}: {e}", file=sys.stderr)
                continue
            w.writerow({k: rec.get(k, "") for k in RECORD_FIELDS})
            n += 1
    return n


def main() -> int:
    ap = argparse.ArgumentParser(
        description="V2 to_csv.py: JSONL → CSV (one-way only)."
    )
    ap.add_argument(
        "input", nargs="?",
        help="Input JSONL file (e.g. logs/live/static.jsonl)"
    )
    ap.add_argument(
        "output", nargs="?",
        help="Output CSV file. Nếu trống: tự đặt cùng tên .csv cạnh input."
    )
    ap.add_argument(
        "--all", action="store_true",
        help="Convert cả logs/live/static.jsonl + logs/live/dynamic.jsonl"
    )
    args = ap.parse_args()

    here = Path(__file__).resolve().parent
    live_dir = here / "logs" / "live"

    # Mặc định nếu không truyền gì: convert static.jsonl → static.csv
    if not args.input and not args.all:
        args.input = str(live_dir / "static.jsonl")
        args.all = False

    converted: list[tuple[Path, Path, int]] = []

    if args.all:
        for name in ("static", "dynamic"):
            in_p = live_dir / f"{name}.jsonl"
            out_p = live_dir / f"{name}.csv"
            n = jsonl_to_csv(in_p, out_p)
            converted.append((in_p, out_p, n))
    else:
        in_p = Path(args.input)
        if args.output:
            out_p = Path(args.output)
        else:
            out_p = in_p.with_suffix(".csv")
        n = jsonl_to_csv(in_p, out_p)
        converted.append((in_p, out_p, n))

    print("[*] to_csv.py done (JSONL → CSV, one-way only)")
    for in_p, out_p, n in converted:
        print(f"    {n:>5} rows  {in_p}  →  {out_p}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
