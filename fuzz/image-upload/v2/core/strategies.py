#!/usr/bin/env python3
"""Sinh payload ngẫu nhiên cho fuzzer image-upload.

Các "kind" đa dạng, không lặp lại giữa 2 trial (dùng random.choice).
Mỗi payload trả về: (kind, body: bytes, mime: str, originalname: str)
"""
import os
import random
import string

# Pool magic bytes thật - lấy từ nhiều định dạng
MAGIC_POOL = {
    "jpeg":   b"\xff\xd8\xff\xe0",
    "jpeg2":  b"\xff\xd8\xff\xe1",
    "png":    b"\x89PNG\r\n\x1a\n",
    "webp":   b"RIFF" + b"\x00\x00\x0a\x00" + b"WEBP",
    "gif":    b"GIF89a",
    "bmp":    b"BM",
    "tiff_l": b"II*\x00",
    "tiff_b": b"MM\x00*",
    "elf":    b"\x7fELF",
    "pdf":    b"%PDF-1.4",
    "zip":    b"PK\x03\x04",
    "exe":    b"MZ\x90\x00",
    "rar":    b"Rar!\x1a\x07",
    "7z":     b"7z\xbc\xaf",
    "java":   b"\xca\xfe\xba\xbe",
    "script": b"#!/bin/sh",
    "html":   b"<!DOCTYPE",
    "xml":    b"<?xml",
}

MIME_POOL = [
    "image/jpeg", "image/jpg", "image/png", "image/webp",
    "image/gif", "image/bmp", "image/tiff",
    "application/octet-stream", "application/x-msdownload",
    "application/pdf", "application/zip", "application/x-rar-compressed",
    "text/plain", "text/html", "text/xml",
    "application/x-executable",
]

KIND_POOL = [
    "valid", "wrong_magic", "wrong_mime", "exe_in_disguise",
    "truncated", "oversize", "empty", "polyglot_jpeg_zip",
    "mime_spoof", "random_garbage", "huge_magic",
    "null_bytes", "single_byte", "all_0xff", "all_zeros",
    "extension_mismatch", "name_with_path",
    # --- New: focus on bugs fixed in v2 ---
    "polyglot_elf_middle",   # JPEG magic ở đầu + ELF ở giữa
    "polyglot_zip_middle",   # JPEG magic ở đầu + ZIP ở giữa
    "polyglot_mz_middle",    # JPEG magic ở đầu + MZ ở giữa
    "case_upper_mime",       # MIME viết hoa: image/JPEG
    "case_upper_ext",        # Extension viết hoa: .JPG
    "size_mismatch_attack",  # size=0 nhưng buffer 12MB
    "mime_vs_ext_mismatch",  # MIME=jpeg, ext=.png
    "name_with_null_byte",   # Tên file có \x00
]

VALID_MAGIC = {
    "image/jpeg": b"\xff\xd8\xff\xe0",
    "image/jpg":  b"\xff\xd8\xff\xe0",
    "image/png":  b"\x89PNG\r\n\x1a\n",
    "image/webp": b"RIFF" + b"\x00\x00\x0a\x00" + b"WEBP",
}

MAX_SIZE = 5 * 1024 * 1024  # 5MB (giống service)


def random_name(ext=None):
    base = "fuzz_" + "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    if ext is None:
        ext = random.choice([".jpg", ".jpeg", ".png", ".webp", ".bin", ".exe", ".txt"])
    return base + ext


def gen_random_payload(max_size=MAX_SIZE):
    kind = random.choice(KIND_POOL)
    target_mime = random.choice(list(VALID_MAGIC.keys()))
    target_magic = VALID_MAGIC[target_mime]

    if kind == "valid":
        size = random.randint(1024, min(max_size, 256 * 1024))
        body = target_magic + os.urandom(size)
        return kind, body, target_mime, random_name(_ext_for_mime(target_mime))

    if kind == "wrong_magic":
        # MIME bảo jpeg nhưng nội dung là ELF
        wrong = random.choice([b"\x7fELF", b"MZ\x90\x00", b"PK\x03\x04", b"%PDF"])
        body = wrong + os.urandom(random.randint(64, 4096))
        return kind, body, "image/jpeg", random_name(".jpg")

    if kind == "wrong_mime":
        # Nội dung jpeg nhưng MIME bảo octet-stream
        body = target_magic + os.urandom(1024)
        return kind, body, "application/octet-stream", random_name(".bin")

    if kind == "exe_in_disguise":
        body = b"MZ\x90\x00" + os.urandom(8192)
        return kind, body, "image/jpeg", random_name(".jpg")

    if kind == "truncated":
        # Chỉ 2 byte đầu của magic
        body = target_magic[:2]
        return kind, body, target_mime, random_name(_ext_for_mime(target_mime))

    if kind == "oversize":
        body = target_magic + os.urandom(12 * 1024 * 1024)  # 12MB > 5MB
        return kind, body, target_mime, random_name(_ext_for_mime(target_mime))

    if kind == "empty":
        return kind, b"", target_mime, random_name(_ext_for_mime(target_mime))

    if kind == "polyglot_jpeg_zip":
        body = b"\xff\xd8\xff\xe0" + os.urandom(512) + b"PK\x03\x04" + os.urandom(1024)
        return kind, body, "image/jpeg", random_name(".jpg")

    if kind == "mime_spoof":
        magic = random.choice([b"MZ\x90\x00", b"\x7fELF", b"%PDF", b"PK\x03\x04"])
        body = magic + os.urandom(4096)
        return kind, body, random.choice(["image/jpeg", "image/png"]), random_name(".jpg")

    if kind == "random_garbage":
        size = random.randint(0, min(max_size, 64 * 1024))
        return kind, os.urandom(size), random.choice(MIME_POOL), random_name(".bin")

    if kind == "huge_magic":
        body = target_magic * 1000 + os.urandom(512)
        return kind, body, target_mime, random_name(_ext_for_mime(target_mime))

    if kind == "null_bytes":
        body = b"\x00" * random.randint(0, 4096)
        return kind, body, target_mime, random_name(_ext_for_mime(target_mime))

    if kind == "single_byte":
        body = bytes([random.randint(0, 255)])
        return kind, body, target_mime, random_name(_ext_for_mime(target_mime))

    if kind == "all_0xff":
        body = b"\xff" * random.randint(1, 1024)
        return kind, body, "image/jpeg", random_name(".jpg")

    if kind == "all_zeros":
        body = b"\x00" * random.randint(1, 1024)
        return kind, body, "image/jpeg", random_name(".jpg")

    if kind == "extension_mismatch":
        body = target_magic + os.urandom(1024)
        return kind, body, target_mime, random_name(".exe")

    if kind == "name_with_path":
        body = target_magic + os.urandom(1024)
        return kind, body, target_mime, "../../../etc/passwd" + _ext_for_mime(target_mime)

    # ============================================================
    # Targeted strategies for bugs fixed in v2
    # ============================================================
    if kind == "polyglot_elf_middle":
        # JPEG ở đầu (pass matchesImageMagic), ELF ở giữa (cũ pass containsExec)
        body = b"\xff\xd8\xff\xe0" + os.urandom(2048) + b"\x7fELF" + os.urandom(1024)
        return kind, body, "image/jpeg", random_name(".jpg")

    if kind == "polyglot_zip_middle":
        body = b"\xff\xd8\xff\xe0" + os.urandom(2048) + b"PK\x03\x04" + os.urandom(1024)
        return kind, body, "image/jpeg", random_name(".jpg")

    if kind == "polyglot_mz_middle":
        body = b"\xff\xd8\xff\xe0" + os.urandom(2048) + b"MZ\x90\x00" + os.urandom(1024)
        return kind, body, "image/jpeg", random_name(".jpg")

    if kind == "case_upper_mime":
        # MIME viết hoa - trước fix bị REJECT oan
        body = target_magic + os.urandom(1024)
        return kind, body, target_mime.upper(), random_name(_ext_for_mime(target_mime))

    if kind == "case_upper_ext":
        body = target_magic + os.urandom(1024)
        return kind, body, target_mime, random_name(_ext_for_mime(target_mime).upper())

    if kind == "size_mismatch_attack":
        # size=0 nhưng buffer 12MB - trước fix bypass size check
        body = target_magic + os.urandom(12 * 1024 * 1024)
        return kind, body, target_mime, random_name(_ext_for_mime(target_mime))

    if kind == "mime_vs_ext_mismatch":
        # MIME=jpeg nhưng ext=.png
        body = target_magic + os.urandom(1024)
        return kind, body, target_mime, random_name(".png" if ".jpg" in target_mime else ".jpg")

    if kind == "name_with_null_byte":
        body = target_magic + os.urandom(1024)
        return kind, body, target_mime, "fuzz\x00.jpg"

    # fallback
    return "random_garbage", os.urandom(1024), "image/jpeg", random_name(".jpg")


def _ext_for_mime(mime):
    return {
        "image/jpeg": ".jpg",
        "image/jpg":  ".jpg",
        "image/png":  ".png",
        "image/webp": ".webp",
    }.get(mime, ".bin")
