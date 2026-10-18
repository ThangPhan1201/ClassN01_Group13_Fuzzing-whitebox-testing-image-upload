"""
V2 — Simulator layer for the image-upload parser.

Mirrors `parser.py` (read-only) but exposes two entry points:

  validate_original(file)        — full original behavior
  validate_mutant(file, mutant)  — exactly one check disabled

A mutant is *killed* when the outcome of `validate_mutant`
differs from `validate_original` for the same input.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass
from enum import Enum
from os.path import splitext
from pathlib import Path
from typing import Optional

# Reuse the read-only module so the implementation is single-sourced.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from parser import (  # noqa: E402
    ALLOWED_EXTENSIONS,
    ALLOWED_MIME_TYPES,
    EXECUTABLE_SIGNATURES,
    JPEG_EOI,
    JPEG_MAGIC,
    MAX_FILE_SIZE,
    Outcome,
    PNG_IEND,
    PNG_MAGIC,
    UploadFile,
    WEBP_RIFF,
    WEBP_WEBP,
    buffer_starts_with,
)


# ---------------------------------------------------------------------------
# Helpers (mirroring parser.py)
# ---------------------------------------------------------------------------
def _contains_executable(buffer: bytes) -> Optional[str]:
    for name, sig in EXECUTABLE_SIGNATURES.items():
        if buffer_starts_with(buffer, sig):
            return name
    return None


def _matches_image_magic(buffer: bytes, mimetype: str) -> bool:
    mime = (mimetype or "").lower()
    if mime in {"image/jpeg", "image/jpg"}:
        return buffer_starts_with(buffer, JPEG_MAGIC)
    if mime == "image/png":
        return buffer_starts_with(buffer, PNG_MAGIC)
    if mime == "image/webp":
        return (
            len(buffer) >= 12
            and buffer[0:4] == WEBP_RIFF
            and buffer[8:12] == WEBP_WEBP
        )
    return False


def _is_truncated_image(buffer: bytes, mimetype: str) -> bool:
    """Port of parser.is_truncated_image() for M14."""
    mime = (mimetype or "").lower()
    if mime in {"image/jpeg", "image/jpg"}:
        if len(buffer) < 2:
            return True
        return not buffer_starts_with(buffer[-2:], JPEG_EOI)
    if mime == "image/png":
        if len(buffer) < 12:
            return True
        tail = buffer[-12:]
        for i in range(len(tail) - 4):
            if tail[i : i + 4] == PNG_IEND:
                return False
        return True
    if mime == "image/webp":
        return len(buffer) < 12
    return False


# ---------------------------------------------------------------------------
# Original (full behavior)
# ---------------------------------------------------------------------------
def validate_original(
    file: Optional[UploadFile],
    mode: str = "original",
) -> Outcome:
    if file is None:
        return Outcome.REJECT_MISSING

    if (file.mimetype or "") not in ALLOWED_MIME_TYPES:
        return Outcome.REJECT_MIME

    ext = splitext(file.originalname or "")[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        return Outcome.REJECT_EXT

    size = (
        file.size
        if file.size is not None
        else (len(file.buffer) if file.buffer is not None else 0)
    )
    if size and size > MAX_FILE_SIZE:
        return Outcome.REJECT_SIZE

    if file.buffer:
        if _contains_executable(file.buffer):
            return Outcome.REJECT_EXE
        if mode == "fixed" and not _matches_image_magic(
            file.buffer, file.mimetype or ""
        ):
            return Outcome.REJECT_NOT_IMAGE
    elif mode == "fixed":
        return Outcome.REJECT_NO_BUFFER

    return Outcome.ACCEPT


# ---------------------------------------------------------------------------
# Mutant — exactly one check is disabled
# ---------------------------------------------------------------------------
def validate_mutant(
    file: Optional[UploadFile],
    mutant: str,
    mode: str = "original",
) -> Outcome:
    if mutant == "M1":
        # R1 disabled — never return REJECT_MISSING.
        if file is None:
            # Pretend an empty file was given; fall through to MIME check.
            file = UploadFile(
                originalname="x.jpg", mimetype="image/jpeg", size=0, buffer=b""
            )

    if mutant != "M2":
        if (file.mimetype or "") not in ALLOWED_MIME_TYPES:
            return Outcome.REJECT_MIME

    if mutant != "M3":
        ext = splitext(file.originalname or "")[1].lower()
        if ext not in ALLOWED_EXTENSIONS:
            return Outcome.REJECT_EXT

    if mutant != "M4":
        size = (
            file.size
            if file.size is not None
            else (len(file.buffer) if file.buffer is not None else 0)
        )
        if size and size > MAX_FILE_SIZE:
            return Outcome.REJECT_SIZE

    if file.buffer:
        if mutant not in {"M5", "M6", "M7", "M8"}:
            if _contains_executable(file.buffer):
                return Outcome.REJECT_EXE
        else:
            # The mutant disables one executable-signature check.
            sigs_to_check = dict(EXECUTABLE_SIGNATURES)
            which = {
                "M5": "MZ",
                "M6": "ELF",
                "M7": "ZIP",
                "M8": "CAFEBABE",
            }[mutant]
            sigs_to_check.pop(which, None)
            hit = next(
                (n for n, sig in sigs_to_check.items()
                 if buffer_starts_with(file.buffer, sig)),
                None,
            )
            if hit:
                return Outcome.REJECT_EXE

        if mutant not in {"M9", "M10", "M11"}:
            if mode == "fixed" and not _matches_image_magic(
                file.buffer, file.mimetype or ""
            ):
                return Outcome.REJECT_NOT_IMAGE
        else:
            # Disable the magic check for one specific MIME.
            which = {"M9": "image/jpeg", "M10": "image/png", "M11": "image/webp"}[mutant]
            if mode == "fixed" and (file.mimetype or "").lower() == which:
                # skip the magic check for this MIME
                pass
            elif mode == "fixed" and not _matches_image_magic(
                file.buffer, file.mimetype or ""
            ):
                return Outcome.REJECT_NOT_IMAGE

        # M14: skip truncated image check
        if mutant != "M14":
            if mode == "fixed" and _is_truncated_image(file.buffer, file.mimetype or ""):
                return Outcome.REJECT_TRUNCATED

    elif mutant == "M12":
        # Buffer required (R9) disabled: do nothing — fall through to ACCEPT.
        pass
    elif mode == "fixed":
        return Outcome.REJECT_NO_BUFFER

    if mutant == "M13":
        # R10 disabled: behave as mode='original' regardless of input mode.
        pass

    return Outcome.ACCEPT


# ---------------------------------------------------------------------------
# Convenience: kill-test
# ---------------------------------------------------------------------------
def is_killed(file: Optional[UploadFile], mutant: str, mode: str = "original") -> bool:
    """Return True iff the mutant's outcome differs from the original's."""
    orig = validate_original(file, mode)
    mut = validate_mutant(file, mutant, mode)
    if orig != mut:
        return True
    # Some mutants (M9-M11) only differ in fixed mode — try the other.
    other = "fixed" if mode == "original" else "original"
    if other != mode:
        orig2 = validate_original(file, other)
        mut2 = validate_mutant(file, mutant, other)
        return orig2 != mut2
    return False


if __name__ == "__main__":
    # Quick smoke test
    from parser import UploadFile

    cases = [
        ("empty file",        UploadFile("a.jpg", "image/jpeg", 0, b"")),
        ("JPEG header",       UploadFile("a.jpg", "image/jpeg", 3, JPEG_MAGIC)),
        ("ELF in image slot", UploadFile("a.jpg", "image/jpeg", 4, b"\x7FELF")),
    ]
    for label, f in cases:
        print(f"{label:>20}  orig={validate_original(f)}  M6={validate_mutant(f, 'M6')}")
