"""V2 — Phase 1 error specifications (oracle). Severity is predicted, not confirmed.

This file mirrors the static ``specs.py`` 1:1 so the V2 show_specs.py
and fuzz_campaign.py can reuse the same 6 oracle cases.
"""

from __future__ import annotations

SPECS = [
    {
        "id": "IMG-01",
        "title": "Missing file",
        "input": "No file provided",
        "expected": "Reject input safely",
        "severity": "Medium",
        "oracle": "REJECT_MISSING",
    },
    {
        "id": "IMG-02",
        "title": "Invalid MIME type",
        "input": "application/octet-stream",
        "expected": "Reject unsupported file type",
        "severity": "Medium",
        "oracle": "REJECT_MIME",
    },
    {
        "id": "IMG-03",
        "title": "Fake image signature",
        "input": "Image MIME with invalid file bytes (non-JPEG/PNG/WebP, non-executable)",
        "expected": "Reject invalid image content",
        "severity": "High",
        "oracle": "REJECT_NOT_IMAGE",
    },
    {
        "id": "IMG-04",
        "title": "Oversized file",
        "input": "File exceeds configured size limit (5MB)",
        "expected": "Reject file",
        "severity": "Medium",
        "oracle": "REJECT_SIZE",
    },
    {
        "id": "IMG-05",
        "title": "Truncated image",
        "input": "Incomplete image data (buffer shorter than magic)",
        "expected": "Reject invalid image content",
        "severity": "Medium",
        "oracle": "REJECT_NOT_IMAGE",
    },
    {
        "id": "IMG-MAGIC",
        "title": "ELF magic-byte target branch (assignment)",
        "input": "First 4 bytes == 7F 45 4C 46",
        "expected": "containsExecutableContent == true → REJECT_EXE",
        "severity": "High",
        "oracle": "REJECT_EXE",
        "note": "Narrow condition for Ch.4.6 black-box vs Z3 comparison",
    },
]
