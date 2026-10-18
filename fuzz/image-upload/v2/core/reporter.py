"""
V2 — Reporter helpers shared by StaticRunner / DynamicRunner.

Provides:
  - RECORD_FIELDS: schema cố định 12 cột, khớp v2/to_csv.py
  - build_record(): chuẩn hóa 1 record (mode + trial + payload + result)
  - save_crash(): dump payload + meta khi có CRASH
"""
import json
import os
import time
from typing import Any

# Schema cố định — to_csv.py đọc từ đây.
RECORD_FIELDS = [
    "ts",
    "mode",
    "trial",
    "kind",
    "size",
    "mime",
    "name",
    "outcome",
    "reason",
    "elapsed_ms",
    "returncode",
    "stderr",
]


def build_record(mode: str, trial: int, payload: tuple, result: dict) -> dict:
    """Build 1 record chuẩn hóa từ (mode, trial, payload, result).

    payload = (kind, body: bytes, mime, originalname)
    result  = dict trả về từ _one_trial() của runner
    """
    kind, body, mime, name = payload
    rec = {f: "" for f in RECORD_FIELDS}  # mặc định trống
    rec["ts"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    rec["mode"] = mode
    rec["trial"] = trial
    rec["kind"] = kind
    rec["size"] = len(body) if body is not None else 0
    rec["mime"] = mime
    rec["name"] = name
    rec["outcome"] = result.get("outcome", "")
    rec["reason"] = result.get("reason", "")
    rec["elapsed_ms"] = result.get("elapsed_ms", 0.0)
    rec["returncode"] = result.get("returncode", 0)
    rec["stderr"] = result.get("stderr", "")
    return rec


def save_crash(crash_dir, rec, payload, result, prefix='crash'):
    os.makedirs(crash_dir, exist_ok=True)
    ts = time.strftime('%Y%m%d_%H%M%S')
    name = '%s_%s_t%d_%s.bin' % (
        prefix, ts, rec['trial'], rec.get('reason', 'unknown')
    )
    bin_path = os.path.join(crash_dir, name)
    with open(bin_path, 'wb') as f:
        f.write(payload[1])  # body
    meta_path = bin_path + '.json'
    with open(meta_path, 'w') as f:
        json.dump({
            'record': rec,
            'payload_kind': payload[0],
            'payload_mime': payload[2],
            'payload_name': payload[3],
            'payload_size': len(payload[1]),
            'result': result,
            'saved_at': ts,
        }, f, indent=2, default=str)
    return bin_path, meta_path
