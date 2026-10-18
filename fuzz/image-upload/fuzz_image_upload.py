#!/usr/bin/env python3
"""
Image-upload white-box / black-box fuzzing (Ch.4 / ch4_dynafuzz style).

Run phases in order — one command each:

  python fuzz_image_upload.py spec
  python fuzz_image_upload.py fuzz-bb
  python fuzz_image_upload.py fuzz-wb
  python fuzz_image_upload.py compare
  python fuzz_image_upload.py log
  python fuzz_image_upload.py verify    # after the manual IMG-03 patch
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List

from parser import (
    ELF_MAGIC,
    MZ_MAGIC,
    Outcome,
    UploadFile,
    validate_file,
)
from paths import (
    BB_JSON,
    COMPARE_JSON,
    CRASHES,
    ELF_BIN,
    RESULTS_JSON,
    SPECS_JSON,
    WB_JSON,
    ensure_dirs,
)
from specs import SPECS

LINE = "=" * 56


def banner(title: str) -> None:
    print(LINE)
    print(f" {title}")
    print(LINE)


def die(msg: str, code: int = 1) -> None:
    print(f"[!] {msg}", file=sys.stderr)
    sys.exit(code)


def load_json(path) -> Dict[str, Any]:
    if not path.exists():
        die(f"Missing {path}. Run the previous phase first.")
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def save_json(path, data: Dict[str, Any]) -> None:
    ensure_dirs()
    with path.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
        fh.write("\n")


def require_specs() -> None:
    if not SPECS_JSON.exists():
        die("Run spec first: python fuzz_image_upload.py spec")


# ---------------------------------------------------------------------------
# Phase 1
# ---------------------------------------------------------------------------

def cmd_spec(_args: argparse.Namespace) -> None:
    banner("IMAGE UPLOAD FUZZING - ERROR SPECIFICATION")
    print(" Target: backend/src/common/services/image-upload.service.ts")
    print("         ImageUploadService.validateFile / containsExecutableContent")
    print(" Oracle: SPEC loaded BEFORE any fuzzing. Severity = predicted, not confirmed.")
    print()
    for spec in SPECS:
        print(f"[{spec['id']}] {spec['title']}")
        print(f"  Input:       {spec['input']}")
        print(f"  Expected:    {spec['expected']}")
        print(f"  Severity:    {spec['severity']}")
        if spec.get("note"):
            print(f"  Note:        {spec['note']}")
        print()
    banner("STATUS")
    print(f" Total specifications: {len(SPECS)}")
    print(" Status: SPECIFICATIONS LOADED")
    print(LINE)
    payload = {
        "target": "ImageUploadService.validateFile",
        "loaded_at": datetime.now(timezone.utc).isoformat(),
        "specs": SPECS,
        "status": "SPECIFICATIONS LOADED",
    }
    save_json(SPECS_JSON, payload)
    print(f"[*] Saved: {SPECS_JSON}")


# ---------------------------------------------------------------------------
# Phase 2a — black-box
# ---------------------------------------------------------------------------

def random_buffer(rng: random.Random, length: int) -> bytes:
    return bytes(rng.randrange(256) for _ in range(length))


def blackbox_search(
    magic: bytes,
    seed: int,
    runs: int,
    max_trials: int,
    length: int,
) -> Dict[str, Any]:
    """Random bytes until prefix == magic. No constraints, no Z3."""
    run_rows: List[Dict[str, Any]] = []
    successes: List[int] = []
    times: List[float] = []

    for run in range(1, runs + 1):
        rng = random.Random(seed + run * 10007)
        found = False
        trials = 0
        t0 = time.perf_counter()
        hit_hex = None
        while trials < max_trials:
            trials += 1
            buf = random_buffer(rng, length)
            if buf[: len(magic)] == magic:
                found = True
                hit_hex = buf[: len(magic)].hex()
                break
        elapsed = time.perf_counter() - t0
        times.append(elapsed)
        if found:
            successes.append(trials)
            status = f"FOUND     trials={trials:<10} time={elapsed:.3f}s  hex={hit_hex}"
        else:
            status = f"NOT FOUND trials={trials:<10} time={elapsed:.3f}s"
        print(f"  run {run:2d}: {status}")
        run_rows.append(
            {
                "run": run,
                "found": found,
                "trials": trials,
                "time_s": round(elapsed, 6),
                "hit_hex": hit_hex,
            }
        )

    hits = len(successes)
    mean_trials = sum(successes) / hits if hits else None
    return {
        "magic_hex": magic.hex(),
        "search_space": 256 ** len(magic),
        "seed": seed,
        "runs": runs,
        "max_trials": max_trials,
        "hits": hits,
        "mean_trials": mean_trials,
        "mean_time_s": sum(times) / len(times) if times else None,
        "runs_detail": run_rows,
    }


def cmd_fuzz_bb(args: argparse.Namespace) -> None:
    require_specs()
    ensure_dirs()
    banner("BLACK-BOX FUZZING")
    print(" Goal: mean #trials to hit IMG-MAGIC (ELF 4-byte)")
    print(" Mode: random; no constraints, no Z3")
    print()
    print(f"[*] Magic target: {ELF_MAGIC.hex(' ').upper()}")
    print(f"[*] Search space: 256^4 = {256 ** 4:,}")
    print(f"[*] Runs: {args.runs}  |  max_trials/run: {args.max_trials}  |  seed: {args.seed}")
    print()

    elf = blackbox_search(ELF_MAGIC, args.seed, args.runs, args.max_trials, length=8)
    print()
    if elf["mean_trials"] is None:
        print("[*] Mean trials to success:  INF (0 hits — expected for 4-byte magic)")
    else:
        print(f"[*] Mean trials to success:  {elf['mean_trials']:.1f}")
    print(f"[*] Mean time:               {elf['mean_time_s']:.3f}s / run")
    print(f"[*] Hits:                    {elf['hits']}/{elf['runs']}")

    print()
    print(" Optional 2-byte MZ (4D 5A) for contrast:")
    mz_trials = min(args.mz_max_trials, max(args.max_trials, 300_000))
    print(f"[*] Runs: {args.mz_runs}  |  max_trials/run: {mz_trials}")
    mz = blackbox_search(MZ_MAGIC, args.seed + 99, args.mz_runs, mz_trials, length=4)
    if mz["mean_trials"] is None:
        print("[*] MZ mean trials: INF")
    else:
        print(f"[*] MZ mean trials: {mz['mean_trials']:.1f}  |  mean time: {mz['mean_time_s']:.3f}s  |  hits: {mz['hits']}/{mz['runs']}")

    payload = {
        "phase": "fuzz-bb",
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "elf": elf,
        "mz_contrast": mz,
    }
    save_json(BB_JSON, payload)
    print()
    print(f"[*] Saved: {BB_JSON}")


# ---------------------------------------------------------------------------
# Phase 2b — white-box (Z3, ch4_dynafuzz style)
# ---------------------------------------------------------------------------

def solve_magic_z3(magic: bytes) -> Dict[str, Any]:
    try:
        from z3 import BitVec, Solver, sat
    except ImportError:
        die("z3-solver is not installed. pip install -r fuzz/image-upload/requirements.txt")

    t0 = time.perf_counter()
    solver = Solver()
    byte_vars = [BitVec(f"b{i}", 8) for i in range(len(magic))]
    constraints = []
    for i, expected in enumerate(magic):
        pred = byte_vars[i] == expected
        solver.add(pred)
        constraints.append(f"b{i} == 0x{expected:02x}")
    result = solver.check()
    elapsed = time.perf_counter() - t0

    model_hex = None
    model_bytes = None
    if result == sat:
        model = solver.model()
        solved = bytes(model[v].as_long() & 0xFF for v in byte_vars)
        model_hex = solved.hex()
        model_bytes = list(solved)

    return {
        "magic_hex": magic.hex(),
        "constraints": constraints,
        "result": str(result),
        "sat": result == sat,
        "model_hex": model_hex,
        "model_bytes": model_bytes,
        "solver_time_s": round(elapsed, 6),
    }


def cmd_fuzz_wb(_args: argparse.Namespace) -> None:
    require_specs()
    ensure_dirs()
    banner("WHITE-BOX FUZZING (ch4_dynafuzz + Z3)")
    print(" Goal: solve the SAME ELF magic; measure solver time")
    print("[*] Instrumenting buffer_starts_with() / contains_executable_content()")
    print("[*] Path constraint for IMG-MAGIC:")

    elf = solve_magic_z3(ELF_MAGIC)
    for c in elf["constraints"]:
        print(f"      {c}")
    print(f"[*] Z3: {elf['result']}")
    if elf["sat"]:
        print(f"[*] Model:  {' '.join(f'b{i}={b:02X}' for i, b in enumerate(elf['model_bytes']))}")
        print(f"[*] Solved input (hex): {elf['model_hex']}")
    print(f"[*] Solver time: {elf['solver_time_s']:.6f}s")

    payload_bytes = ELF_MAGIC + b"\x00" * 12
    ELF_BIN.write_bytes(payload_bytes)
    replay = validate_file(
        UploadFile(
            originalname="photo.jpg",
            mimetype="image/jpeg",
            size=len(payload_bytes),
            buffer=payload_bytes,
        ),
        mode="original",
    )
    print(f"[*] Replay on original parser: {replay.value}  |  IMG-MAGIC HIT={replay == Outcome.REJECT_EXE}")

    mz = solve_magic_z3(MZ_MAGIC)
    print()
    print(f"[*] Contrast MZ 2-byte Z3 time: {mz['solver_time_s']:.6f}s  model={mz['model_hex']}")

    payload = {
        "phase": "fuzz-wb",
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "elf": elf,
        "mz_contrast": mz,
        "replay_outcome": replay.value,
        "replay_hit": replay == Outcome.REJECT_EXE,
        "saved_input": str(ELF_BIN),
    }
    save_json(WB_JSON, payload)
    print()
    print(f"[*] Saved: {WB_JSON}")
    print(f"[*] WB input: {ELF_BIN}")


# ---------------------------------------------------------------------------
# Phase 2c — compare
# ---------------------------------------------------------------------------

def cmd_compare(_args: argparse.Namespace) -> None:
    bb = load_json(BB_JSON)
    wb = load_json(WB_JSON)
    elf_bb = bb["elf"]
    elf_wb = wb["elf"]

    bb_trials = elf_bb["mean_trials"]
    bb_trials_s = "INF (no hit)" if bb_trials is None else f"{bb_trials:.1f}"
    bb_hit = elf_bb["hits"] > 0
    wb_hit = bool(elf_wb.get("sat") and wb.get("replay_hit"))

    banner("COMPARE (same branch IMG-MAGIC)")
    print(" Black-box: mean trials to guess 7F 45 4C 46")
    print(" White-box: Z3 solves path predicate, measure solver time")
    print()
    print(f"  {'Metric':<22} {'Black-box':<22} {'White-box (Z3)':<20}")
    print(f"  {'-'*22} {'-'*22} {'-'*20}")
    print(f"  {'Hit ELF magic':<22} {str(bb_hit):<22} {str(wb_hit):<20}")
    print(f"  {'Trials':<22} {bb_trials_s:<22} {'1 model':<20}")
    bb_time = f"{elf_bb['mean_time_s']:.3f}s/run"
    print(f"  {'Time':<22} {bb_time:<22} {elf_wb['solver_time_s']:.6f}s")
    print()
    print(" Ch.4.6: 4-byte equality is a narrow condition. Random sampling is")
    print(" exponential in magic length (256^k). SMT solves the path predicate")
    print(" directly; cost does not grow as 256^k.")
    print()
    if bb.get("mz_contrast") and bb["mz_contrast"].get("mean_trials"):
        print(
            f" Contrast MZ (2 byte): BB mean trials={bb['mz_contrast']['mean_trials']:.1f}  "
            f"WB Z3={wb['mz_contrast']['solver_time_s']:.6f}s"
        )
        print(" Shorter magic: black-box can still hit; 4-byte ELF does not.")
    print(LINE)

    payload = {
        "phase": "compare",
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "same_branch": "IMG-MAGIC ELF 7F454C46",
        "black_box": {
            "hit": bb_hit,
            "mean_trials": bb_trials,
            "mean_time_s": elf_bb["mean_time_s"],
        },
        "white_box": {
            "hit": wb_hit,
            "trials": 1,
            "solver_time_s": elf_wb["solver_time_s"],
            "model_hex": elf_wb.get("model_hex"),
        },
        "theory": "Ch.4.6 narrow conditions / magic bytes",
    }
    save_json(COMPARE_JSON, payload)
    print(f"[*] Saved: {COMPARE_JSON}")


# ---------------------------------------------------------------------------
# Phase 3 — oracle log (original parser)
# ---------------------------------------------------------------------------

def oracle_cases() -> List[Dict[str, Any]]:
    """Concrete cases mapped to IMG-01..05 and IMG-MAGIC. Expected = spec, not current code."""
    fake_image = b"NOTANIMAGEFILE!!"  # not JPEG/PNG/WebP, not MZ/ELF/ZIP/CAFEBABE
    # Canonical crash inputs — written to crashes/ so anyone can replay.
    # Naming: IMG-<ID>_<short_description>.bin  (hex preview in companion .txt)
    return [
        {
            "id": "CASE-001",
            "spec_id": "IMG-01",
            "file": None,
            "crash_name": "IMG-01_missing_file.bin",
            "crash_hex": None,
            "expected_reject": True,
            "expected_outcome": Outcome.REJECT_MISSING,
            "note": "empty file rejected",
        },
        {
            "id": "CASE-002",
            "spec_id": "IMG-02",
            "file": UploadFile("photo.bin", "application/octet-stream", 16, b"x" * 16),
            "crash_name": "IMG-02_unsupported_mime.bin",
            "crash_hex": "78" * 16,
            "expected_reject": True,
            "expected_outcome": Outcome.REJECT_MIME,
            "note": "unsupported MIME rejected",
        },
        {
            "id": "CASE-003",
            "spec_id": "IMG-03",
            "file": UploadFile("photo.jpg", "image/jpeg", len(fake_image), fake_image),
            "crash_name": "IMG-03_fake_jpeg_mime.bin",
            "crash_hex": fake_image.hex(),
            "expected_reject": True,
            "expected_outcome": Outcome.REJECT_NOT_IMAGE,
            "note": "JPEG MIME but non-image bytes → original parser ACCEPTs (BUG)",
        },
        {
            "id": "CASE-004",
            "spec_id": "IMG-04",
            "file": UploadFile("photo.jpg", "image/jpeg", MAX_OVERSIZE, JPEG_MINIMAL),
            "crash_name": "IMG-04_oversized.bin",
            "crash_hex": JPEG_MINIMAL.hex(),
            "expected_reject": True,
            "expected_outcome": Outcome.REJECT_SIZE,
            "note": "size > 5MB rejected",
        },
        {
            "id": "CASE-005",
            "spec_id": "IMG-05",
            "file": UploadFile("photo.jpg", "image/jpeg", 1, b"\xff"),
            "crash_name": "IMG-05_truncated.bin",
            "crash_hex": "ff",
            "expected_reject": True,
            "expected_outcome": Outcome.REJECT_NOT_IMAGE,
            "note": "truncated — buffer too short for any magic",
        },
        {
            "id": "CASE-006",
            "spec_id": "IMG-MAGIC",
            "file": UploadFile("photo.jpg", "image/jpeg", 16, ELF_MAGIC + b"\x00" * 12),
            "crash_name": "IMG-MAGIC_elf_magic.bin",
            "crash_hex": (ELF_MAGIC + b"\x00" * 12).hex(),
            "expected_reject": True,
            "expected_outcome": Outcome.REJECT_EXE,
            "note": "ELF magic 7F454C46 → REJECT_EXE",
        },
    ]


# imported after parser constants — avoid circular; define oversize here
MAX_OVERSIZE = 5 * 1024 * 1024 + 1
JPEG_MINIMAL = bytes([0xFF, 0xD8, 0xFF, 0xD9])


def run_oracle(mode: str) -> List[Dict[str, Any]]:
    rows = []
    for case in oracle_cases():
        actual = validate_file(case["file"], mode=mode)
        expected = case["expected_outcome"]
        # PASS = actual matches the specification oracle
        passed = actual == expected
        if passed:
            detail = {
                Outcome.REJECT_MISSING: "Input rejected safely",
                Outcome.REJECT_MIME: "Unsupported MIME rejected",
                Outcome.REJECT_SIZE: "Oversized file rejected",
                Outcome.REJECT_EXE: "ELF magic rejected as executable",
                Outcome.REJECT_NOT_IMAGE: "Invalid image content rejected",
            }.get(actual, actual.value)
            status = "PASS"
        else:
            status = "FAIL"
            if actual == Outcome.ACCEPT and expected != Outcome.ACCEPT:
                detail = "Invalid image content accepted"
            else:
                detail = f"got {actual.value}, expected {expected.value}"

        # ── Save crash input to crashes/ ──────────────────────────────────────
        # Write raw bytes so anyone can `xxd crashes/IMG-03_fake_jpeg_mime.bin`
        # and replay: python3 -c "from parser import ...; validate_file(...)"
        crash_name: str | None = case.get("crash_name")
        crash_hex: str | None = case.get("crash_hex")
        saved_path: str | None = None
        if crash_name and crash_hex:
            crash_path = CRASHES / crash_name
            try:
                crash_path.write_bytes(
                    bytes.fromhex(crash_hex)
                    if crash_hex
                    else b""
                )
                saved_path = str(crash_path)
            except Exception:
                saved_path = f"<write failed: {crash_path}>"

        rows.append(
            {
                "id": case["id"],
                "spec_id": case["spec_id"],
                "status": status,
                "actual": actual.value,
                "expected": expected.value,
                "detail": detail,
                "mode": mode,
                # reproducibility fields
                "crash_file": crash_name,
                "crash_hex": crash_hex,
                "saved_to": saved_path,
                "note": case.get("note"),
            }
        )
    return rows


def cmd_log(_args: argparse.Namespace) -> None:
    require_specs()
    if not BB_JSON.exists() or not WB_JSON.exists():
        die("Run fuzz-bb and fuzz-wb first.")
    banner("FUZZING LOG")
    print(" Parser mode: original (pre-fix snapshot of ImageUploadService)")
    print(" FAIL = program does not meet the spec oracle; not necessarily a crash.")
    print()
    rows = run_oracle("original")
    for row in rows:
        print(f"[{row['id']}] {row['spec_id']:<10} | {row['status']:<4} | {row['detail']}")
        if row.get("saved_to"):
            print(f"       crash → {row['saved_to']}  ({row['crash_hex'] or 'n/a'})")

    payload = {
        "phase": "log",
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "mode": "original",
        "cases": rows,
        "fail_count": sum(1 for r in rows if r["status"] == "FAIL"),
        "pass_count": sum(1 for r in rows if r["status"] == "PASS"),
    }
    save_json(RESULTS_JSON, payload)
    print()
    print(f"[*] Log saved to: {RESULTS_JSON}")
    if ELF_BIN.exists():
        print(f"[*] Reproducible input saved to: {ELF_BIN}")
    else:
        print(f"[*] Reproducible input saved to: {CRASHES}/")


# ---------------------------------------------------------------------------
# Phase 4 — verify after MANUAL fix
# ---------------------------------------------------------------------------

def cmd_verify(_args: argparse.Namespace) -> None:
    results = load_json(RESULTS_JSON)
    before = results.get("cases") or []
    fail_ids = [c["spec_id"] for c in before if c["status"] == "FAIL"]
    if not fail_ids:
        die("No confirmed FAIL in fuzz_results.json. Run log first.")

    banner("BUG ANALYSIS & FIX VERIFICATION")
    print(f"Confirmed FAIL: {', '.join(fail_ids)}")
    print("Issue:     MIME/extension trusted; JPEG/PNG/WebP magic not checked")
    print("Root cause: validateFile() never compared FF D8 / 89 PNG / RIFF..WEBP")
    print("            (executable magic only; image-upload.service.ts)")
    print("Fix:        MANUAL — require buffer; add matchesImageMagic();")
    print("            reject MIME/magic mismatch")
    print("Status:     verifying parser mode=fixed (does not auto-patch source)")
    print()

    after = run_oracle("fixed")
    print("[*] Re-run failing tests after fix")
    for old, new in zip(before, after):
        if old["status"] == "FAIL":
            print(f"    {old['id']} {old['spec_id']}: {old['status']} → {new['status']}")
            if new.get("saved_to"):
                print(f"        crash file: {new['saved_to']}")
    print("[*] Regression")
    all_pass = True
    for new in after:
        mark = "PASS" if new["status"] == "PASS" else "FAIL"
        if new["status"] != "PASS":
            all_pass = False
        print(f"    {new['id']} {new['spec_id']}: {mark}")

    print()
    print("[*] Compare before/after")
    print(f"    before FAIL: {results.get('fail_count')}")
    print(f"    after  FAIL: {sum(1 for r in after if r['status'] == 'FAIL')}")
    print()
    if all_pass:
        print("[*] All oracle cases PASS on fixed parser.")
    else:
        print("[!] Fixed parser still has FAIL cases.")
    print(" Note: BB vs WB magic numbers are unchanged; that experiment")
    print(" finds the ELF branch, it does not apply this patch.")
    print(LINE)

    payload = {
        "phase": "verify",
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "fail_before": fail_ids,
        "after": after,
        "all_pass": all_pass,
        "fix": "manual",
    }
    verify_path = RESULTS_JSON.parent / "verify.json"
    save_json(verify_path, payload)
    print(f"[*] Saved: {verify_path}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Image upload fuzzing — run phases one command at a time.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("spec", help="Phase 1: print error specifications")

    bb = sub.add_parser("fuzz-bb", help="Phase 2a: black-box mean trials for ELF magic")
    bb.add_argument("--seed", type=int, default=12345)
    bb.add_argument("--runs", type=int, default=5)
    bb.add_argument("--max-trials", type=int, default=200_000)
    bb.add_argument("--mz-runs", type=int, default=5)
    bb.add_argument("--mz-max-trials", type=int, default=300_000)

    sub.add_parser("fuzz-wb", help="Phase 2b: Z3 solves ELF magic, measure time")
    sub.add_parser("compare", help="Phase 2c: quantitative BB vs WB table")
    sub.add_parser("log", help="Phase 3: oracle PASS/FAIL log on original parser")
    sub.add_parser("verify", help="Phase 4: re-run oracle on fixed parser")

    all_p = sub.add_parser(
        "all",
        help="Run the entire 6-phase pipeline end-to-end (spec → verify)",
    )
    all_p.add_argument("--seed", type=int, default=12345)
    all_p.add_argument("--runs", type=int, default=5)
    all_p.add_argument("--max-trials", type=int, default=200_000)
    all_p.add_argument("--mz-runs", type=int, default=5)
    all_p.add_argument("--mz-max-trials", type=int, default=300_000)
    all_p.add_argument(
        "--skip-verify",
        action="store_true",
        help="Stop after Phase 3 (log); useful when the manual fix is not yet applied",
    )
    return p


def main() -> None:
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    args = build_parser().parse_args()
    dispatch: Dict[str, Any] = {
        "spec": cmd_spec,
        "fuzz-bb": cmd_fuzz_bb,
        "fuzz-wb": cmd_fuzz_wb,
        "compare": cmd_compare,
        "log": cmd_log,
        "verify": cmd_verify,
    }
    if args.cmd == "all":
        # Run phases in order. Each phase may die() if its
        # predecessor is missing; that's the intended contract.
        start = time.perf_counter()
        cmd_spec(args)
        cmd_fuzz_bb(args)
        cmd_fuzz_wb(args)
        cmd_compare(args)
        cmd_log(args)
        if not args.skip_verify:
            cmd_verify(args)
        elapsed = time.perf_counter() - start
        print(LINE)
        print(f" ALL PHASES DONE in {elapsed:.2f}s")
        print(f" Logs:    {RESULTS_JSON.parent.resolve()}")
        print(f" Crashes: {CRASHES.resolve()}")
        print(LINE)
        return
    dispatch[args.cmd](args)


if __name__ == "__main__":
    main()
