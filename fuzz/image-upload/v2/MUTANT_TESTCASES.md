# Mutant Test Cases — V2 (Dynamic, HTTP-based)

> Mapping từ 14 mutants + 6 oracle specs → HTTP trials trong `http_fuzz.py`.
> Mỗi mutant = 1 attack class × HTTP variant. Mỗi trial = 1 request thật tới backend đang chạy.

**Stack mục tiêu:**
- Backend: `http://localhost:3000/api`
- Auth: `POST /auth/login` → `Bearer <accessToken>`
- Endpoints chính: `PATCH /admin/listings/:id`, `POST /listings`, `POST /auth/login`, `GET /health`

**Công cụ:**
- `http_fuzz.py` — runner HTTP (mutation-based, watchdog dừng khi 5xx liên tiếp)
- `to_csv.py` — convert `*.jsonl` → `*.csv` (12 cột cố định)
- `show_specs.py` — in spec từ `specs.py` + `cwe_mapping.json`

---

## Nhóm 1 — Input Validation (R1–R4)

| ID    | CWE     | Tên                       | Target HTTP                       | Payload ví dụ                                | Expected (spec) | Severity |
|-------|---------|---------------------------|-----------------------------------|----------------------------------------------|-----------------|----------|
| M1    | CWE-20  | Improper Input Validation | `POST /listings`                  | body = `{}` (no field nào)                   | REJECT_MISSING  | Medium   |
| M2    | CWE-20  | Improper Input Validation | `POST /listings`                  | `Content-Type: application/octet-stream`     | REJECT_MIME     | Medium   |
| M3    | CWE-20  | Improper Input Validation | `POST /listings`                  | filename = `evil.html`                       | REJECT_MIME     | Medium   |
| M4    | CWE-770 | Allocation w/o Limits     | `POST /upload/image`              | body = `os.urandom(10_000_000)` (10MB > 5MB) | REJECT_SIZE     | Medium   |

**Generator trong `http_fuzz.py`:** `gen_listing_create()` (M1–M3), size random (M4).

---

## Nhóm 2 — Magic-Byte / Executable Detection (R5–R8, R11)

| ID    | CWE     | Tên                       | Target HTTP          | Payload bytes                               | Expected        | Severity |
|-------|---------|---------------------------|----------------------|---------------------------------------------|-----------------|----------|
| M5    | CWE-693 | MZ (PE) executable        | `POST /upload/image` | `\x4D\x5A\x90\x00` (Windows PE header)     | REJECT_EXE      | High     |
| M6    | CWE-693 | ELF executable            | `POST /upload/image` | `\x7F\x45\x4C\x46` (Linux ELF)              | REJECT_EXE      | High     |
| M7    | CWE-693 | ZIP/JAR executable        | `POST /upload/image` | `\x50\x4B\x03\x04` (JAR/ZIP)                | REJECT_EXE      | High     |
| M8    | CWE-693 | Java class                | `POST /upload/image` | `\xCA\xFE\xBA\xBE` (Java class)            | REJECT_EXE      | High     |
| M14   | CWE-20  | Truncated image           | `POST /upload/image` | JPEG header only, no EOI                    | REJECT_NOT_IMAGE| Medium   |

**Generator trong `http_fuzz.py`:** `gen_listing_patch()` (unicode/null/RCE), upload binary (M5–M8, M14).

---

## Nhóm 3 — Image Authenticity (R6–R8)

| ID    | CWE     | Tên                                  | Target HTTP          | Payload                          | Expected        | Severity |
|-------|---------|--------------------------------------|----------------------|----------------------------------|-----------------|----------|
| M9    | CWE-345 | Polyglot JPEG (image/jpeg + script)  | `POST /upload/image` | `\xFF\xD8\xFF\xE0` + JS payload  | REJECT_NOT_IMAGE| High     |
| M10   | CWE-345 | Fake PNG (image/png + random bytes)  | `POST /upload/image` | `\x89PNG\r\n` + garbage          | REJECT_NOT_IMAGE| High     |
| M11   | CWE-345 | Fake WebP (image/webp + not RIFF)    | `POST /upload/image` | `image/webp` MIME, no RIFF header| REJECT_NOT_IMAGE| High     |

**Generator trong `http_fuzz.py`:** `rand_bytes()` + MIME spoofing.

---

## Nhóm 4 — Mode / Buffer (R9, R10)

| ID    | CWE     | Tên                            | Target HTTP          | Payload                                | Expected | Severity |
|-------|---------|--------------------------------|----------------------|----------------------------------------|----------|----------|
| M12   | CWE-20  | No buffer provided             | `POST /upload/image` | no file in multipart                   | REJECT   | Medium   |
| M13   | CWE-840 | Mode='fixed' check removed     | `POST /upload/image` | valid JPEG + `mode: "original"`        | REJECT   | High     |

**Generator trong `http_fuzz.py`:** empty body, mode override trong JSON wrapper.

---

## Spec Map (6 cases từ `specs.py`)

| Spec ID   | Title                  | HTTP variant chính                          | Trial count target |
|-----------|------------------------|---------------------------------------------|--------------------|
| IMG-01    | Missing file           | M1, M12 — empty body / no field             | ≥ 3 trials        |
| IMG-02    | Invalid MIME type      | M2, M3 — wrong Content-Type                 | ≥ 3 trials        |
| IMG-03    | Fake image signature   | M9, M10, M11, M14 — magic mismatch          | ≥ 4 trials        |
| IMG-04    | Oversized file         | M4 — random 5–10MB                          | ≥ 2 trials        |
| IMG-05    | Truncated image        | M14 — JPEG no EOI, PNG no IEND              | ≥ 2 trials        |
| IMG-MAGIC | ELF magic target       | M6 — pure `\x7F ELF`                        | ≥ 1 trial         |

---

## Trial Output Schema (CSV, 12 cột từ `to_csv.py`)

```
ts, mode, trial, kind, size, mime, name, outcome, reason, elapsed_ms, returncode, stderr
```

- `ts`        — Unix timestamp (float, seconds)
- `mode`      — `original` | `fixed` (từ backend env)
- `trial`     — số thứ tự trial trong session
- `kind`      — label loại payload (vd `M6_elf`)
- `size`      — kích thước body (bytes)
- `mime`      — Content-Type gửi đi
- `name`      — filename trong multipart
- `outcome`   — `PASS` | `REJECT` | `CRASH` | `EXC`
- `reason`    — mã lý do (`HTTP_200`, `HTTP_400`, `HTTP_500`, `EXC_Timeout`, …)
- `elapsed_ms`— thời gian round-trip
- `returncode`— HTTP status code
- `stderr`    — backend error log nếu có

---

## Cách chạy 1 lệnh tương tự "tĩnh"

```bash
# 1. Show spec (giống `python3 show_specs.py`)
cd /Users/admin/Downloads/fuzzing-white-box/fuzz/image-upload/v2
python3 show_specs.py

# 2. Chạy fuzzer 60s
python3 http_fuzz.py --target admin-listing-patch --duration 60

# 3. Convert JSONL → CSV (đúng schema 12 cột)
python3 to_csv.py logs/live/http_admin-listing-patch.jsonl logs/decisions/trials_summary.csv

# 4. Mở CSV
open -e logs/decisions/trials_summary.csv

# 5. Mở mutant testcases (file này)
open -a TextEdit MUTANT_TESTCASES.md
```

---

## Notes

- File này là **tài liệu cố định** (write-once), không generate runtime.
- Runtime output: xem `logs/decisions/trials_summary.csv` (rebuild mỗi lần chạy `to_csv.py`).
- Crashes (5xx) được lưu riêng trong `logs/live/crashes/*.json` (giữ nguyên, không convert sang CSV).
