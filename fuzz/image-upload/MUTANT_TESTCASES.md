# Bảng Đặc Tả 14 Mutant — Image Upload Parser

> File này là phiên bản **dễ đọc** của `cwe_mapping.json` (đầy đủ 14 mutant, bao gồm M14: Truncated Image).
> Mỗi mutant vô hiệu hóa đúng **1 check** trong `validate_file()` của `parser.py`.
>
> Nguồn code: `backend/src/common/services/image-upload.service.ts` (chế độ `original` vs `fixed`).

## Tổng quan 3 nhóm lỗi

| Nhóm | Phạm vi | Mutant | Đặc điểm |
|------|---------|--------|----------|
| **N1_Input** | Kiểm tra đầu vào (null, mime, ext, size) | M1–M4 | Bỏ qua validation input cơ bản |
| **N2_Magic** | Kiểm tra magic bytes (chống polyglot / file thực thi / truncated) | M5–M11, M14 | Bỏ qua check chữ ký nhị phân và tính toàn vẹn ảnh |
| **N3_Fixed** | Bypass chế độ đã vá (IMG-03) | M12–M13 | Vô hiệu hóa bản vá |

## Bảng chi tiết 13 Mutant

| # | Mutant | Test case (đặc tả) | Đầu vào cụ thể | Outcome kỳ vọng (fixed) | REQ vi phạm | CWE | CVE minh họa | Nhóm |
|---|--------|--------------------|----------------|------------------------|-------------|-----|--------------|------|
| 1 | **M1** | Truyền `file = null` → phải reject | `validate_file(None)` | `REJECT_MISSING` | R1_file_not_none | CWE-20 (Improper Input Validation) | CVE-2017-3735 | N1_Input |
| 2 | **M2** | Mimetype không nằm trong allowlist → phải reject | `mimetype="text/html"` | `REJECT_MIME` | R2_mime_in_allowlist | CWE-20 | CVE-2018-12714 | N1_Input |
| 3 | **M3** | Extension không nằm trong allowlist → phải reject | `originalname="shell.html"` | `REJECT_EXT` | R3_ext_in_allowlist | CWE-20 | CVE-2019-0708 | N1_Input |
| 4 | **M4** | File vượt quá 5MB → phải reject (DoS) | `size=104857600` (100MB) | `REJECT_SIZE` | R4_size_le_5mb | CWE-770 (Allocation of Resources Without Limits) | CVE-2018-6789 | N1_Input |
| 5 | **M5** | Magic bytes bắt đầu bằng `MZ` (Windows PE) → phải reject | `buffer=b"\x4D\x5A..."` | `REJECT_EXE` | R5_detect_MZ_exec | CWE-693 (Protection Mechanism Failure) | CVE-2017-3736 | N2_Magic |
| 6 | **M6** | Magic bytes bắt đầu bằng `\x7FELF` (Linux) → phải reject | `buffer=b"\x7FELF..."` | `REJECT_EXE` | R5_detect_ELF_exec | CWE-693 | CVE-2018-12714 | N2_Magic |
| 7 | **M7** | Magic bytes bắt đầu bằng `PK\x03\x04` (ZIP/JAR) → phải reject | `buffer=b"PK\x03\x04..."` | `REJECT_EXE` | R5_detect_ZIP_exec | CWE-693 | CVE-2019-0708 | N2_Magic |
| 8 | **M8** | Magic bytes bắt đầu bằng `\xCA\xFE\xBA\xBE` (Java class) → phải reject | `buffer=b"\xCA\xFE\xBA\xBE..."` | `REJECT_EXE` | R5_detect_CAFEBABE_exec | CWE-693 | CVE-2018-12714 | N2_Magic |
| 9 | **M9** | Khai báo `image/jpeg` nhưng byte đầu không phải JPEG (polyglot) → phải reject | `mimetype="image/jpeg"`, `buffer=b"AAAA..."` | `REJECT_NOT_IMAGE` | R6_jpeg_magic_match | CWE-345 (Insufficient Verification of Data Authenticity) | CVE-2021-44228 | N2_Magic |
| 10 | **M10** | Khai báo `image/png` nhưng byte đầu không phải PNG → phải reject | `mimetype="image/png"`, `buffer=b"BBBB..."` | `REJECT_NOT_IMAGE` | R7_png_magic_match | CWE-345 | CVE-2017-3735 | N2_Magic |
| 11 | **M11** | Khai báo `image/webp` nhưng header không phải `RIFF...WEBP` → phải reject | `mimetype="image/webp"`, `buffer=b"XXXX..."` | `REJECT_NOT_IMAGE` | R8_webp_riff_match | CWE-345 | CVE-2018-12714 | N2_Magic |
| 12 | **M12** | `mode="fixed"` nhưng request không có `buffer` → phải reject | `mode="fixed"`, `file=UploadFile(buffer=None)` | `REJECT_NO_BUFFER` | R9_buffer_required | CWE-20 | CVE-2017-3735 | N3_Fixed |
| 13 | **M13** | Bỏ qua điều kiện `mode="fixed"` (bypass toàn bộ IMG-03) → phải reject file polyglot | `mode="fixed"`, `mimetype="image/jpeg"`, `buffer=b"NOT_JPEG..."` | `REJECT_NOT_IMAGE` | R10_mode_fixed | CWE-840 (Business Logic Errors) | CVE-2018-12714 | N3_Fixed |
| 14 | **M14** | Ảnh bị cắt ngắn (JPEG thiếu EOI `FF D9`, PNG thiếu IEND chunk, WebP quá ngắn) → phải reject | `mimetype="image/jpeg"`, `buffer=b"\xFF\xD8\xFF\xE0...\xFF\xD8"` (thiếu EOI) | `REJECT_TRUNCATED` | R11_truncated_image | CWE-20 | CVE-2017-3735 | N2_Magic |

## Chỉ số CWE tổng hợp

| CWE | Tên | Số mutant | Danh sách |
|-----|-----|-----------|-----------|
| CWE-20 | Improper Input Validation | 5 | M1, M2, M3, M12, M14 |
| CWE-693 | Protection Mechanism Failure | 4 | M5, M6, M7, M8 |
| CWE-345 | Insufficient Verification of Data Authenticity | 3 | M9, M10, M11 |
| CWE-770 | Allocation of Resources Without Limits | 1 | M4 |
| CWE-840 | Business Logic Errors | 1 | M13 |

## Cách đọc bảng để chạy thử

Ví dụ muốn test thủ công **M5** (MZ bị nhận là ảnh):

```python
from parser import validate_file, UploadFile, Outcome

f = UploadFile(
    originalname="photo.jpg",
    mimetype="image/jpeg",
    size=100,
    buffer=b"\x4D\x5A\x90\x00",   # "MZ" + PE header
)
print(validate_file(f, mode="original"))  # ACCEPT (vì M5 tắt check MZ)
print(validate_file(f, mode="fixed"))     # REJECT_EXE (check MZ vẫn chạy)
```

M5 = mutant: **bỏ check MZ** → `mode="original"` chấp nhận, `mode="fixed"` vẫn reject.
Nếu fuzzer kill được M5 nghĩa là nó tìm ra input này và quan sát thấy `original` != `fixed`.

## Liên kết

- Code parser gốc: `parser.py` (hàm `validate_file()`, dòng 99–126)
- Mapping JSON (ground truth): `cwe_mapping.json`
- Code service TypeScript: `backend/src/common/services/image-upload.service.ts`
- Log chạy campaign: `logs/decisions/trials_summary.csv`, `logs/decisions/kill_events.jsonl`
