"""
GĐ 0 — Module + Log analyzer (runs silently, then emits a report).

Scans the backend services that the parser.py mirrors:

  - backend/src/common/services/image-upload.service.ts   (target)
  - backend/src/common/services/audit-log.service.ts     (telemetry)
  - backend/src/modules/listing/services/listing.service.ts (reference)

The analyzer extracts:
  * Module metadata (file size, function list, exported symbols)
  * A list of 13 REQ → TS-line mapping
  * Synthetic log entries (since the runtime Prisma log is unavailable here)
  * A CWE-class hint for each REQ

Outputs (under logs/raw/ and logs/reports/):
  logs/raw/module_trace.jsonl
  logs/raw/audit_log_sample.jsonl
  logs/reports/module_analysis.md
  logs/reports/req_extraction.json
  logs/reports/code_references.json
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parent
BACKEND = ROOT.parent.parent / "backend"
TARGET = BACKEND / "src" / "common" / "services" / "image-upload.service.ts"
AUDIT = BACKEND / "src" / "common" / "services" / "audit-log.service.ts"
LISTING = BACKEND / "src" / "modules" / "listing" / "services" / "listing.service.ts"

LOGS = ROOT / "logs"
RAW = LOGS / "raw"
REPORTS = LOGS / "reports"


# ---------------------------------------------------------------------------
# Requirement table — order matters: matches parser.py branches.
# ---------------------------------------------------------------------------
REQ_TABLE: list[dict[str, Any]] = [
    {"req": "R1",  "branch": "REJECT_MISSING",          "src_keyword": "if (!file)"},
    {"req": "R2",  "branch": "REJECT_MIME",             "src_keyword": "allowedMimeTypes.includes"},
    {"req": "R3",  "branch": "REJECT_EXT",              "src_keyword": "allowedExtensions.includes"},
    {"req": "R4",  "branch": "REJECT_SIZE",             "src_keyword": "maxFileSize"},
    {"req": "R5",  "branch": "REJECT_EXE",              "src_keyword": "containsExecutableContent"},
    {"req": "R6",  "branch": "REJECT_NOT_IMAGE (jpeg)", "src_keyword": "jpegMagic"},
    {"req": "R7",  "branch": "REJECT_NOT_IMAGE (png)",  "src_keyword": "pngMagic"},
    {"req": "R8",  "branch": "REJECT_NOT_IMAGE (webp)", "src_keyword": "webpMagic"},
    {"req": "R9",  "branch": "REJECT_NO_BUFFER (fix)",  "src_keyword": "buffer required"},
    {"req": "R10", "branch": "mode='fixed' (patch)",    "src_keyword": "matchesImageMagic"},
]


# ---------------------------------------------------------------------------
# Trace helpers
# ---------------------------------------------------------------------------
def _read_lines(p: Path) -> list[str]:
    if not p.exists():
        return []
    return p.read_text(encoding="utf-8", errors="replace").splitlines()


def _trace_module(p: Path) -> dict[str, Any]:
    lines = _read_lines(p)
    if not lines:
        return {"path": str(p), "exists": False}
    funcs = re.findall(r"^\s*(?:export\s+)?(?:async\s+)?function\s+(\w+)", "\n".join(lines))
    classes = re.findall(r"^\s*(?:export\s+)?class\s+(\w+)", "\n".join(lines))
    return {
        "path": str(p.relative_to(ROOT.parent.parent)),
        "exists": True,
        "line_count": len(lines),
        "classes": classes,
        "functions": funcs,
    }


def _locate_requirements(p: Path) -> list[dict[str, Any]]:
    """Find the 1-based line number of each REQ's keyword in the TS file."""
    if not p.exists():
        return []
    lines = _read_lines(p)
    out: list[dict[str, Any]] = []
    for entry in REQ_TABLE:
        kw = entry["src_keyword"].lower()
        for idx, line in enumerate(lines, start=1):
            if kw in line.lower():
                out.append({
                    **entry,
                    "line": idx,
                    "snippet": line.strip()[:120],
                })
                break
        else:
            out.append({**entry, "line": None, "snippet": None})
    return out


# ---------------------------------------------------------------------------
# Synthetic audit log (Prisma is offline)
# Each entry now captures: magic bytes, size, allocation, error type
# ---------------------------------------------------------------------------
SAMPLE_LOGS: list[dict[str, Any]] = [
    # ── Normal upload flow ──────────────────────────────────────────
    {
        "action": "UPLOAD_VALIDATE_START",
        "userId": 1,
        "entityType": "UploadFile",
        "metadata": {
            "filename": "product_photo.jpg",
            "mimetype": "image/jpeg",
            "size": 245760,
            "size_human": "240 KB",
            "buffer_length": 245760,
        },
        "audit": {
            "magic_bytes_hex": "ffd8ffe000104a464946",
            "magic_checked": "jpeg",
            "allocation_bytes": 245760,
            "allocation_pool": "node_buffer",
        },
        "result": "PASS",
    },
    # ── MIME check fail ─────────────────────────────────────────────
    {
        "action": "UPLOAD_VALIDATE_REJECT",
        "userId": 2,
        "entityType": "UploadFile",
        "metadata": {
            "filename": "document.pdf",
            "mimetype": "application/pdf",
            "size": 102400,
            "size_human": "100 KB",
        },
        "audit": {
            "failed_check": "REJECT_MIME",
            "allowed_types": ["image/jpeg", "image/jpg", "image/png", "image/webp"],
            "rejected_reason": "Invalid MIME type: application/pdf",
            "cwe_hint": "CWE-20",
        },
        "result": "REJECT",
    },
    # ── Size limit exceeded ─────────────────────────────────────────
    {
        "action": "UPLOAD_VALIDATE_REJECT",
        "userId": 3,
        "entityType": "UploadFile",
        "metadata": {
            "filename": "banner.png",
            "mimetype": "image/png",
            "size": 8388608,
            "size_human": "8 MB",
        },
        "audit": {
            "failed_check": "REJECT_SIZE",
            "limit_bytes": 5242880,
            "limit_human": "5 MB",
            "over_by_bytes": 3145728,
            "over_by_human": "3 MB",
            "cwe_hint": "CWE-770",
        },
        "result": "REJECT",
    },
    # ── Executable content detected (MZ / PE) ─────────────────────
    {
        "action": "UPLOAD_VALIDATE_REJECT",
        "userId": 4,
        "entityType": "UploadFile",
        "metadata": {
            "filename": "photo.jpg",
            "mimetype": "image/jpeg",
            "size": 65536,
            "size_human": "64 KB",
            "buffer_length": 65536,
        },
        "audit": {
            "failed_check": "REJECT_EXE",
            "magic_bytes_hex": "4d5a9000",
            "magic_type": "MZ (Windows PE executable)",
            "signature_match": "MZ",
            "allocation_bytes": 65536,
            "allocation_pool": "node_buffer",
            "cwe_hint": "CWE-693",
            "cve_example": "CVE-2017-3736",
        },
        "result": "REJECT",
    },
    # ── Executable content detected (ELF) ───────────────────────────
    {
        "action": "UPLOAD_VALIDATE_REJECT",
        "userId": 5,
        "entityType": "UploadFile",
        "metadata": {
            "filename": "image.png",
            "mimetype": "image/png",
            "size": 81920,
            "size_human": "80 KB",
        },
        "audit": {
            "failed_check": "REJECT_EXE",
            "magic_bytes_hex": "7f454c46",
            "magic_type": "ELF (Linux executable)",
            "signature_match": "ELF",
            "allocation_bytes": 81920,
            "allocation_pool": "node_buffer",
            "cwe_hint": "CWE-693",
            "cve_example": "CVE-2018-12714",
        },
        "result": "REJECT",
    },
    # ── Image magic mismatch (fake JPEG) ────────────────────────────
    {
        "action": "UPLOAD_VALIDATE_REJECT",
        "userId": 6,
        "entityType": "UploadFile",
        "metadata": {
            "filename": "receipt.jpg",
            "mimetype": "image/jpeg",
            "size": 204800,
            "size_human": "200 KB",
            "buffer_length": 204800,
        },
        "audit": {
            "failed_check": "REJECT_NOT_IMAGE",
            "expected_magic": ["0xff", "0xd8", "0xff"],
            "actual_magic_hex": "89504e470d0a1a0a",
            "actual_magic_type": "PNG (magic does not match declared MIME)",
            "allocation_bytes": 204800,
            "allocation_pool": "node_buffer",
            "cwe_hint": "CWE-345",
            "cve_example": "CVE-2021-44228",
        },
        "result": "REJECT",
    },
    # ── ZIP disguised as WebP ───────────────────────────────────────
    {
        "action": "UPLOAD_VALIDATE_REJECT",
        "userId": 7,
        "entityType": "UploadFile",
        "metadata": {
            "filename": "photo.webp",
            "mimetype": "image/webp",
            "size": 153600,
            "size_human": "150 KB",
        },
        "audit": {
            "failed_check": "REJECT_EXE",
            "magic_bytes_hex": "504b0304",
            "magic_type": "ZIP (archive containing potential payloads)",
            "signature_match": "ZIP",
            "cwe_hint": "CWE-345",
            "cve_example": "CVE-2018-6789",
        },
        "result": "REJECT",
    },
    # ── No buffer provided ─────────────────────────────────────────
    {
        "action": "UPLOAD_VALIDATE_REJECT",
        "userId": 8,
        "entityType": "UploadFile",
        "metadata": {
            "filename": "photo.jpg",
            "mimetype": "image/jpeg",
            "size": 0,
        },
        "audit": {
            "failed_check": "REJECT_NO_BUFFER",
            "buffer_present": False,
            "buffer_length": None,
            "allocation_bytes": 0,
            "cwe_hint": "CWE-20",
        },
        "result": "REJECT",
    },
    # ── Truncated image (incomplete JPEG) ───────────────────────────
    {
        "action": "UPLOAD_VALIDATE_REJECT",
        "userId": 9,
        "entityType": "UploadFile",
        "metadata": {
            "filename": "scan.jpg",
            "mimetype": "image/jpeg",
            "size": 51200,
            "size_human": "50 KB",
            "buffer_length": 51200,
        },
        "audit": {
            "failed_check": "REJECT_TRUNCATED",
            "expected_eoi_hex": "ffd9",
            "eoi_present": False,
            "buffer_content_end_hex": "ffd8ffdb",
            "allocation_bytes": 51200,
            "allocation_pool": "node_buffer",
            "cwe_hint": "CWE-345",
        },
        "result": "REJECT",
    },
    # ── BMP header sent where JPEG expected (suspicious) ────────────
    {
        "action": "SUSPICIOUS_INPUT",
        "userId": None,
        "entityType": "UploadFile",
        "oldData": {
            "hint": "BMP header (424d) sent where image/jpeg expected",
        },
        "audit": {
            "failed_check": "REJECT_NOT_IMAGE",
            "magic_bytes_hex": "424d38b7",
            "magic_type": "BMP (bitmap, not a valid image/* for this endpoint)",
            "cwe_hint": "CWE-20",
        },
        "result": "REJECT",
    },
]


# ---------------------------------------------------------------------------
# Public entrypoint
# ---------------------------------------------------------------------------
def run_full_analysis() -> dict[str, Any]:
    RAW.mkdir(parents=True, exist_ok=True)
    REPORTS.mkdir(parents=True, exist_ok=True)

    target_trace = _trace_module(TARGET)
    audit_trace = _trace_module(AUDIT)
    listing_trace = _trace_module(LISTING)
    req_locs = _locate_requirements(TARGET)

    # ---- raw traces ----
    raw = {
        "target": target_trace,
        "audit": audit_trace,
        "listing": listing_trace,
        "requirements": req_locs,
    }
    (RAW / "module_trace.json").write_text(
        json.dumps(raw, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    with (RAW / "audit_log_sample.jsonl").open("w", encoding="utf-8") as f:
        for entry in SAMPLE_LOGS:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    # ---- reports ----
    (REPORTS / "req_extraction.json").write_text(
        json.dumps(req_locs, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    code_refs = {
        "target_file": target_trace.get("path"),
        "ref_per_req": {r["req"]: r for r in req_locs},
    }
    (REPORTS / "code_references.json").write_text(
        json.dumps(code_refs, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    md = _build_markdown(target_trace, audit_trace, listing_trace, req_locs)
    (REPORTS / "module_analysis.md").write_text(md, encoding="utf-8")

    return raw


def _build_markdown(
    target: dict[str, Any],
    audit: dict[str, Any],
    listing: dict[str, Any],
    reqs: list[dict[str, Any]],
) -> str:
    lines: list[str] = []
    lines.append("# GĐ 0 — Module + Log analysis (image-upload parser)\n")

    # ── Sơ đồ luồng upload ────────────────────────────────────────────
    lines.append("## 1. Luồng xử lý upload (Upload Flow)\n")
    lines.append("> **Lưu ý quan trọng:** Module `image-upload.service.ts` chỉ thực hiện **validation metadata và magic bytes**. "
                 "Nó **KHÔNG phân tích/cấp phát/đọc pixel thực tế** — pixel parsing được xử lý bởi CDN/Image Processing Layer phía sau.")
    lines.append("""
```mermaid
flowchart TD
    A([HTTP POST /upload]) --> B{file param exists?}

    B -->|No| R1[❌ REJECT_MISSING<br/>BadRequestException]
    B -->|Yes| C{MIME type in<br/>allowedMimeTypes?}

    C -->|No| R2[❌ REJECT_MIME<br/>BadRequestException]
    C -->|Yes| D{Extension in<br/>allowedExtensions?}

    D -->|No| R3[❌ REJECT_EXT<br/>BadRequestException]
    D -->|Yes| E{file.size <= 5MB?}

    E -->|No| R4[❌ REJECT_SIZE<br/>BadRequestException]
    E -->|Yes| F{buffer exists<br/>&amp; non-empty?}

    F -->|No| R9[❌ REJECT_NO_BUFFER<br/>BadRequestException]
    F -->|Yes| G{containsExecutable<br/>Content(buffer)?}

    G -->|Yes| R5[❌ REJECT_EXE<br/>BadRequestException]
    G -->|No| H{matchesImageMagic<br/>(buffer, mimetype)?}

    H -->|No| R6_R8[❌ REJECT_NOT_IMAGE<br/>BadRequestException]
    H -->|Yes| I{mode == 'fixed'?}

    I -->|Yes| J{R10: matchesImage<br/>Magic check}
    I -->|No| K[✅ ACCEPT<br/>Proceed to save]

    J -->|Fail| R10[❌ REJECT_NOT_IMAGE<br/>BadRequestException]
    J -->|Pass| K

    style R1 fill:#ffcccc
    style R2 fill:#ffcccc
    style R3 fill:#ffcccc
    style R4 fill:#ffcccc
    style R5 fill:#ffcccc
    style R6_R8 fill:#ffcccc
    style R9 fill:#ffcccc
    style R10 fill:#ffcccc
    style K fill:#ccffcc
```
""")

    # ── Memory allocation ──────────────────────────────────────────────
    lines.append("## 2. Cấp phát bộ nhớ & Vùng đệm (Memory / Buffer)\n")
    lines.append("""
### 2.1 Vùng đệm (`buffer`)

Module sử dụng **Node.js `Buffer`** — vùng nhớ raw binary được Node.js quản lý qua V8 heap:

| Trường | Mô tả |
|--------|--------|
| `file.buffer` | `Buffer` chứa **toàn bộ file binary** (không phải chỉ pixel) |
| Kích thước tối đa | **5 MB** (`maxFileSize = 5 * 1024 * 1024`) |
| Giới hạn số file/request | **10 files** (`maxImages = 10`) |
| Pool quản lý | `node_buffer` (V8 ArrayBuffer / Uint8Array backed) |

### 2.2 Quy trình cấp phát (không qua module này)

```
HTTP multipart/form-data
        │
        ▼
Multer (middleware) ──reads──► Buffer[file.size]
        │
        ▼
ImageUploadService.validateFile(file)
        │
        ├─► Kiểm tra độ dài buffer (không cấp phát thêm)
        ├─► bufferStartsWith() ──reads──► buffer[i] (truy cập O(1))
        └─► containsExecutableContent() ──reads──► toàn bộ buffer

✅ Pass ──► saveFile() ──► fs.writeFile() ──► disk
```

### 2.3 Tại sao KHÔNG có pixel reading trong module này?

Module này là **validator** (gatekeeper), không phải **processor**:
- **Validation layer**: Kiểm tra magic bytes (file signature) → chỉ đọc **2-12 bytes đầu**
- **Processing layer**: CDN / Sharp / ImageMagick phía sau mới đọc pixel, decode, resize, thumbnail

→ Log mẫu ghi `allocation_bytes = buffer_length` nhưng **không có pixel-level access log** vì module không đọc pixel.
""")

    # ── Modules scanned ───────────────────────────────────────────────
    lines.append("## 3. Modules đã quét\n")
    for label, t in [("image-upload.service.ts", target),
                     ("audit-log.service.ts", audit),
                     ("listing.service.ts (ref)", listing)]:
        if not t.get("exists"):
            lines.append(f"- **{label}** — NOT FOUND")
            continue
        lines.append(
            f"- **{label}** — {t['line_count']} lines, "
            f"classes: {t['classes'] or '—'}, funcs: {t['functions'] or '—'}"
        )

    lines.append("\n## 4. Requirements (10) → TS line mapping\n")
    lines.append("| REQ | Branch | TS line | Snippet |")
    lines.append("|-----|--------|---------|---------|")
    for r in reqs:
        snip = (r.get("snippet") or "—").replace("|", "\\|")
        lines.append(f"| {r['req']} | `{r['branch']}` | {r.get('line') or '—'} | {snip} |")

    lines.append("\n## 5. Synthetic audit log (Prisma offline)\n")
    lines.append(f"Captured {len(SAMPLE_LOGS)} sample actions "
                 f"(Prisma is offline in the sandbox). "
                 f"Log fields now include: magic_bytes_hex, allocation_bytes, allocation_pool, cwe_hint.")
    lines.append("Saved to `logs/raw/audit_log_sample.jsonl`.")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    info = run_full_analysis()
    print(f"[*] GĐ 0 done — modules: {sum(1 for v in info.values() if isinstance(v, dict) and v.get('exists'))}, "
          f"requirements mapped: {len(info['requirements'])}")
    print(f"    report → {REPORTS / 'module_analysis.md'}")
