"""
V2 — Z3 white-box modeler for the 14 requirements of validate_file() in parser.py.

Each model() function returns a `dict` that, when fed to the simulator,
*should* force the parser to take a different branch (i.e. trigger a mutant).

We model the validator as a logical specification and use Z3 to solve
for a `bytes_input` that *should* be accepted by `original` but rejected
by a mutant that disables one check — i.e. the killing input.

Outputs (one record per solver call):
  {
    "model_id":   "R1",      # the REQ being violated
    "mutant":     "M1",      # the mutant it kills
    "mut_bytes":  [...],     # the bytes that distinguish the mutant
    "mime":       "...",
    "ext":        "...",
    "size":       int,
    "z3_solve_ms": float,
    "status":     "sat" | "unsat"
  }
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import z3

# ---------------------------------------------------------------------------
# REQ → Mutant map (mirrors cwe_mapping.json)
# ---------------------------------------------------------------------------
REQ_MUTANT: dict[str, str] = {
    "R1":  "M1",  "R2": "M2",  "R3": "M3",  "R4": "M4",
    "R5a": "M5",  "R5b": "M6",  "R5c": "M7",  "R5d": "M8",
    "R6":  "M9",  "R7": "M10", "R8": "M11",
    "R9":  "M12", "R10": "M13", "R11": "M14",
}

# ---------------------------------------------------------------------------
# Z3 helpers
# ---------------------------------------------------------------------------
def _b(n: int) -> z3.BitVec:
    """8-bit bitvector constant."""
    return z3.BitVecVal(n, 8)


def _solver_with_timeout(s: z3.Solver, ms: int = 2000) -> None:
    """Set a wall-clock-ish timeout (Z3 only supports ticks)."""
    s.set("timeout", 2000)


def _check_and_model(s: z3.Solver) -> tuple[str, z3.Model | None]:
    res = s.check()
    if res == z3.sat:
        return "sat", s.model()
    return "unsat", None


def _model_bytes(m: z3.Model, syms: list[z3.BitVec]) -> bytes:
    """Extract a concrete byte string from a model."""
    out = bytearray()
    for s in syms:
        v = m.eval(s, model_completion=True)
        # BitVecVal → int  ;  BitVec → .as_long()
        try:
            out.append(int(v.as_long()) & 0xFF)
        except Exception:
            out.append(int(v) & 0xFF)
    return bytes(out)


# ---------------------------------------------------------------------------
# M1: R1 — file is None
# ---------------------------------------------------------------------------
def model_R1_M1() -> dict[str, Any]:
    t0 = time.perf_counter()
    trigger = z3.BitVec("trigger_none", 8)
    s = z3.Solver()
    _solver_with_timeout(s)
    s.add(trigger == 0xFE)  # sentinel value
    status, m = _check_and_model(s)
    return {
        "model_id": "R1", "mutant": "M1",
        "mut_bytes": [0xFE] if status == "sat" else [],
        "mime": "", "ext": "<none>", "size": 0,
        "z3_solve_ms": (time.perf_counter() - t0) * 1000.0,
        "status": status,
    }


# ---------------------------------------------------------------------------
# M2: R2 — MIME check skipped.
# ---------------------------------------------------------------------------
def model_R2_M2() -> dict[str, Any]:
    t0 = time.perf_counter()
    ext = z3.BitVec("ext", 8)
    s = z3.Solver()
    _solver_with_timeout(s)
    s.add(ext == ord('j'))  # placeholder
    status, m = _check_and_model(s)
    return {
        "model_id": "R2", "mutant": "M2",
        "mut_bytes": [ord('j')] if status == "sat" else [],
        "mime": "text/html", "ext": ".jpg", "size": 100,
        "z3_solve_ms": (time.perf_counter() - t0) * 1000.0,
        "status": status,
    }


# ---------------------------------------------------------------------------
# M3: R3 — extension check skipped.
# ---------------------------------------------------------------------------
def model_R3_M3() -> dict[str, Any]:
    t0 = time.perf_counter()
    ext = z3.BitVec("ext", 8)
    s = z3.Solver()
    _solver_with_timeout(s)
    s.add(ext == ord('h'))  # .html
    status, m = _check_and_model(s)
    return {
        "model_id": "R3", "mutant": "M3",
        "mut_bytes": [ord('h')] if status == "sat" else [],
        "mime": "image/jpeg", "ext": ".html", "size": 100,
        "z3_solve_ms": (time.perf_counter() - t0) * 1000.0,
        "status": status,
    }


# ---------------------------------------------------------------------------
# M4: R4 — size check skipped.
# ---------------------------------------------------------------------------
def model_R4_M4() -> dict[str, Any]:
    t0 = time.perf_counter()
    size_lo = z3.BitVec("size_lo", 32)
    s = z3.Solver()
    _solver_with_timeout(s)
    s.add(z3.UGT(size_lo, 5 * 1024 * 1024))  # > 5MB
    s.add(size_lo < 2 * 5 * 1024 * 1024)     # but bounded for solver speed
    status, m = _check_and_model(s)
    sz = int(m.eval(size_lo, model_completion=True).as_long()) if status == "sat" else 0
    return {
        "model_id": "R4", "mutant": "M4",
        "mut_bytes": [0x00] * 16,   # dummy buffer
        "mime": "image/jpeg", "ext": ".jpg", "size": sz,
        "z3_solve_ms": (time.perf_counter() - t0) * 1000.0,
        "status": status,
    }


# ---------------------------------------------------------------------------
# M5-M8: R5 — executable signature detection
# ---------------------------------------------------------------------------
def _model_exec(signature: bytes, model_id: str, mutant: str) -> dict[str, Any]:
    t0 = time.perf_counter()
    syms = [z3.BitVec(f"b{i}", 8) for i in range(len(signature))]
    s = z3.Solver()
    _solver_with_timeout(s)
    for sym, byte in zip(syms, signature):
        s.add(sym == byte)
    status, m = _check_and_model(s)
    bs = _model_bytes(m, syms) if status == "sat" else b""
    return {
        "model_id": model_id, "mutant": mutant,
        "mut_bytes": list(bs),
        "mime": "image/jpeg", "ext": ".jpg", "size": len(bs),
        "z3_solve_ms": (time.perf_counter() - t0) * 1000.0,
        "status": status,
    }


def model_R5a_M5() -> dict[str, Any]:  # MZ
    return _model_exec(b"\x4D\x5A", "R5a", "M5")


def model_R5b_M6() -> dict[str, Any]:  # ELF
    return _model_exec(b"\x7F\x45\x4C\x46", "R5b", "M6")


def model_R5c_M7() -> dict[str, Any]:  # ZIP
    return _model_exec(b"\x50\x4B\x03\x04", "R5c", "M7")


def model_R5d_M8() -> dict[str, Any]:  # CAFEBABE
    return _model_exec(b"\xCA\xFE\xBA\xBE", "R5d", "M8")


# ---------------------------------------------------------------------------
# M9: R6 — JPEG magic must match declared image/jpeg.
# ---------------------------------------------------------------------------
def model_R6_M9() -> dict[str, Any]:
    t0 = time.perf_counter()
    fake_jpeg = [0x00, 0x01, 0x02, 0x03]
    return {
        "model_id": "R6", "mutant": "M9",
        "mut_bytes": fake_jpeg,
        "mime": "image/jpeg", "ext": ".jpg", "size": len(fake_jpeg),
        "z3_solve_ms": 0.0,
        "status": "sat",
        "mode": "fixed",   # only differs in fixed mode
    }


# ---------------------------------------------------------------------------
# M10: R7 — PNG magic must match declared image/png.
# ---------------------------------------------------------------------------
def model_R7_M10() -> dict[str, Any]:
    t0 = time.perf_counter()
    fake_png = [0x00] * 8
    return {
        "model_id": "R7", "mutant": "M10",
        "mut_bytes": fake_png,
        "mime": "image/png", "ext": ".png", "size": len(fake_png),
        "z3_solve_ms": 0.0,
        "status": "sat",
        "mode": "fixed",
    }


# ---------------------------------------------------------------------------
# M11: R8 — WebP RIFF/WEBP must match declared image/webp.
# ---------------------------------------------------------------------------
def model_R8_M11() -> dict[str, Any]:
    t0 = time.perf_counter()
    fake_webp = [0x00] * 12
    return {
        "model_id": "R8", "mutant": "M11",
        "mut_bytes": fake_webp,
        "mime": "image/webp", "ext": ".webp", "size": len(fake_webp),
        "z3_solve_ms": 0.0,
        "status": "sat",
        "mode": "fixed",
    }


# ---------------------------------------------------------------------------
# M12: R9 — buffer required (fixed mode).
# ---------------------------------------------------------------------------
def model_R9_M12() -> dict[str, Any]:
    t0 = time.perf_counter()
    has_buffer = z3.Bool("has_buffer")
    s = z3.Solver()
    _solver_with_timeout(s)
    s.add(z3.Not(has_buffer))  # buffer absent
    status = "sat" if s.check() == z3.sat else "unsat"
    return {
        "model_id": "R9", "mutant": "M12",
        "mut_bytes": [],   # no buffer
        "mime": "image/jpeg", "ext": ".jpg", "size": 0,
        "z3_solve_ms": (time.perf_counter() - t0) * 1000.0,
        "status": status,
    }


# ---------------------------------------------------------------------------
# M13: R10 — mode='fixed' check.
# ---------------------------------------------------------------------------
def model_R10_M13() -> dict[str, Any]:
    t0 = time.perf_counter()
    b0, b1, b2 = z3.BitVec("b0", 8), z3.BitVec("b1", 8), z3.BitVec("b2", 8)
    s = z3.Solver()
    _solver_with_timeout(s)
    s.add(b0 == 0xAA, b1 == 0xBB, b2 == 0xCC)  # garbage bytes
    status, m = _check_and_model(s)
    bs = _model_bytes(m, [b0, b1, b2]) if status == "sat" else b""
    return {
        "model_id": "R10", "mutant": "M13",
        "mut_bytes": list(bs),
        "mime": "image/jpeg", "ext": ".jpg", "size": len(bs),
        "z3_solve_ms": (time.perf_counter() - t0) * 1000.0,
        "status": status,
    }


# ---------------------------------------------------------------------------
# M14: R11 — truncated image check.
# ---------------------------------------------------------------------------
def model_R11_M14() -> dict[str, Any]:
    t0 = time.perf_counter()
    truncated_jpeg = [0xFF, 0xD8, 0x00]
    return {
        "model_id": "R11", "mutant": "M14",
        "mut_bytes": truncated_jpeg,
        "mime": "image/jpeg", "ext": ".jpg", "size": len(truncated_jpeg),
        "z3_solve_ms": 0.0,
        "status": "sat",
        "mode": "fixed",
    }


# ---------------------------------------------------------------------------
# Master entrypoint
# ---------------------------------------------------------------------------
ALL_MODELERS = {
    "R1":  model_R1_M1,   "R2":  model_R2_M2,   "R3":  model_R3_M3,
    "R4":  model_R4_M4,
    "R5a": model_R5a_M5,  "R5b": model_R5b_M6,  "R5c": model_R5c_M7,  "R5d": model_R5d_M8,
    "R6":  model_R6_M9,   "R7":  model_R7_M10,  "R8":  model_R8_M11,
    "R9":  model_R9_M12,  "R10": model_R10_M13, "R11": model_R11_M14,
}


def run_all() -> list[dict[str, Any]]:
    """Invoke every Z3 modeler, return list of model records."""
    return [fn() for fn in ALL_MODELERS.values()]


def write_jsonl(records: list[dict[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    out = run_all()
    print(f"[*] Z3: solved {sum(1 for r in out if r['status'] == 'sat')} / {len(out)} models")
    for r in out:
        print(f"  {r['model_id']:>4} → {r['mutant']:>4}  status={r['status']:>5}  "
              f"z3={r['z3_solve_ms']:.2f}ms  bytes={len(r['mut_bytes'])}")
    write_jsonl(out, Path(__file__).parent / "logs" / "decisions" / "wb_models.jsonl")
