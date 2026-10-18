# GĐ 0 — Module + Log analysis (image-upload parser)

## 1. Luồng xử lý upload (Upload Flow)

> **Lưu ý quan trọng:** Module `image-upload.service.ts` chỉ thực hiện **validation metadata và magic bytes**. Nó **KHÔNG phân tích/cấp phát/đọc pixel thực tế** — pixel parsing được xử lý bởi CDN/Image Processing Layer phía sau.

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

## 2. Cấp phát bộ nhớ & Vùng đệm (Memory / Buffer)


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

## 3. Modules đã quét

- **image-upload.service.ts** — 165 lines, classes: —, funcs: —
- **audit-log.service.ts** — 81 lines, classes: —, funcs: —
- **listing.service.ts (ref)** — 654 lines, classes: —, funcs: —

## 4. Requirements (10) → TS line mapping

| REQ | Branch | TS line | Snippet |
|-----|--------|---------|---------|
| R1 | `REJECT_MISSING` | 39 | if (!file) { |
| R2 | `REJECT_MIME` | 44 | if (!this.allowedMimeTypes.includes(file.mimetype \|\| '')) { |
| R3 | `REJECT_EXT` | 52 | if (!this.allowedExtensions.includes(ext)) { |
| R4 | `REJECT_SIZE` | 25 | private readonly maxFileSize = 5 * 1024 * 1024; // 5MB |
| R5 | `REJECT_EXE` | 70 | if (this.containsExecutableContent(file.buffer)) { |
| R6 | `REJECT_NOT_IMAGE (jpeg)` | — | — |
| R7 | `REJECT_NOT_IMAGE (png)` | — | — |
| R8 | `REJECT_NOT_IMAGE (webp)` | — | — |
| R9 | `REJECT_NO_BUFFER (fix)` | — | — |
| R10 | `mode='fixed' (patch)` | 74 | if (!this.matchesImageMagic(file.buffer, file.mimetype \|\| '')) { |

## 5. Synthetic audit log (Prisma offline)

Captured 10 sample actions (Prisma is offline in the sandbox). Log fields now include: magic_bytes_hex, allocation_bytes, allocation_pool, cwe_hint.
Saved to `logs/raw/audit_log_sample.jsonl`.
