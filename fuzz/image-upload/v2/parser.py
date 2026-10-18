"""
V2 — Faithful port of ImageUploadService.validateFile / containsExecutableContent.

Source: backend/src/common/services/image-upload.service.ts

Two modes:
  original — snapshot of the project code BEFORE the IMG-03 patch
  fixed    — after requiring a buffer and checking JPEG/PNG/WebP magic
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from os.path import splitext
from typing import Optional

ALLOWED_MIME_TYPES = {
    "image/jpeg",
    "image/jpg",
    "image/png",
    "image/webp",
}

ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp"}
MAX_FILE_SIZE = 5 * 1024 * 1024

# Same signatures as containsExecutableContent()
EXECUTABLE_SIGNATURES = {
    "MZ": bytes([0x4D, 0x5A]),
    "ELF": bytes([0x7F, 0x45, 0x4C, 0x46]),
    "ZIP": bytes([0x50, 0x4B, 0x03, 0x04]),
    "CAFEBABE": bytes([0xCA, 0xFE, 0xBA, 0xBE]),
}

ELF_MAGIC = EXECUTABLE_SIGNATURES["ELF"]
MZ_MAGIC = EXECUTABLE_SIGNATURES["MZ"]

JPEG_MAGIC = bytes([0xFF, 0xD8, 0xFF])
JPEG_EOI   = bytes([0xFF, 0xD9])
PNG_MAGIC  = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
PNG_IEND   = bytes([0x49, 0x45, 0x4E, 0x44])
WEBP_RIFF  = b"RIFF"
WEBP_WEBP  = b"WEBP"


class Outcome(str, Enum):
    ACCEPT = "ACCEPT"
    REJECT_MISSING = "REJECT_MISSING"
    REJECT_MIME = "REJECT_MIME"
    REJECT_EXT = "REJECT_EXT"
    REJECT_SIZE = "REJECT_SIZE"
    REJECT_EXE = "REJECT_EXE"
    REJECT_NO_BUFFER = "REJECT_NO_BUFFER"
    REJECT_NOT_IMAGE = "REJECT_NOT_IMAGE"
    REJECT_TRUNCATED = "REJECT_TRUNCATED"


@dataclass
class UploadFile:
    originalname: Optional[str] = "photo.jpg"
    mimetype: Optional[str] = "image/jpeg"
    size: Optional[int] = None
    buffer: Optional[bytes] = None


def buffer_starts_with(buffer: bytes, signature: bytes) -> bool:
    """Port of bufferStartsWith()."""
    if len(buffer) < len(signature):
        return False
    for i, byte in enumerate(signature):
        if buffer[i] != byte:
            return False
    return True


def contains_executable_content(buffer: bytes) -> Optional[str]:
    """Port of containsExecutableContent(). Returns signature name or None."""
    for name, sig in EXECUTABLE_SIGNATURES.items():
        if buffer_starts_with(buffer, sig):
            return name
    return None


def matches_image_magic(buffer: bytes, mimetype: str) -> bool:
    """JPEG / PNG / WebP magic must match the declared MIME (the IMG-03 fix)."""
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


def is_truncated_image(buffer: bytes, mimetype: str) -> bool:
    """
    Detect truncated/corrupt images: JPEG missing EOI, PNG missing IEND,
    or WebP shorter than its header requires.

    Port of TypeScript check for R11_truncated_image (M14).
    """
    mime = (mimetype or "").lower()
    if mime in {"image/jpeg", "image/jpg"}:
        # JPEG must end with EOI marker FF D9
        if len(buffer) < 2:
            return True
        return not buffer_starts_with(buffer[-2:], JPEG_EOI)
    if mime == "image/png":
        # PNG must end with IEND chunk (49 45 4E 44)
        if len(buffer) < 12:
            return True
        # Scan last 12 bytes for IEND signature
        tail = buffer[-12:]
        for i in range(len(tail) - 4):
            if tail[i : i + 4] == PNG_IEND:
                return False
        return True
    if mime == "image/webp":
        # WebP requires at least 12 bytes (RIFF header + WEBP)
        if len(buffer) < 12:
            return True
        # A well-formed WebP file must have RIFF...WEBP header
        # Short but valid header passes; truly truncated = less than 12 bytes
        return False  # header check already done in matches_image_magic
    return False


def validate_file(file: Optional[UploadFile], mode: str = "original") -> Outcome:
    """
    Port of validateFile().
    mode='original' matches the unpatched TypeScript service.
    mode='fixed' matches the patched service (buffer required + image magic).
    """
    if file is None:
        return Outcome.REJECT_MISSING

    if (file.mimetype or "") not in ALLOWED_MIME_TYPES:
        return Outcome.REJECT_MIME

    ext = splitext(file.originalname or "")[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        return Outcome.REJECT_EXT

    size = file.size if file.size is not None else (len(file.buffer) if file.buffer is not None else 0)
    if size and size > MAX_FILE_SIZE:
        return Outcome.REJECT_SIZE

    if file.buffer:
        if contains_executable_content(file.buffer):
            return Outcome.REJECT_EXE
        if mode == "fixed" and not matches_image_magic(file.buffer, file.mimetype or ""):
            return Outcome.REJECT_NOT_IMAGE
        if mode == "fixed" and is_truncated_image(file.buffer, file.mimetype or ""):
            return Outcome.REJECT_TRUNCATED
    elif mode == "fixed":
        return Outcome.REJECT_NO_BUFFER

    return Outcome.ACCEPT


def is_reject(outcome: Outcome) -> bool:
    return outcome != Outcome.ACCEPT
