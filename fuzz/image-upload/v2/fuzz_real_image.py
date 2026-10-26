import json
import os
import random
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CORPUS = ROOT / "corpus"
RESULTS = ROOT / "results"
BRIDGE = ROOT / "bridge" / "run_validate.js"
OUTPUT = RESULTS / "real_fuzz_results.jsonl"

MAX_SIZE = 5 * 1024 * 1024
RNG = random.Random(42)

SIGNATURES = {
    "MZ": bytes.fromhex("4D 5A"),
    "ELF": bytes.fromhex("7F 45 4C 46"),
    "ZIP": bytes.fromhex("50 4B 03 04"),
    "JAVA": bytes.fromhex("CA FE BA BE"),
}


def call_bridge(data, mime, filename):
    start = time.perf_counter()

    try:
        env = os.environ.copy()
        env["FUZZ_MIME"] = mime
        env["FUZZ_NAME"] = filename

        proc = subprocess.run(
            ["node", str(BRIDGE)],
            input=data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            timeout=10,
        )

        elapsed = (time.perf_counter() - start) * 1000
        stdout = proc.stdout.decode("utf-8", errors="replace").strip()
        stderr = proc.stderr.decode("utf-8", errors="replace").strip()

        try:
            result = json.loads(stdout)
        except json.JSONDecodeError:
            result = {
                "outcome": "HARNESS_ERROR",
                "reason": "Bridge did not return valid JSON",
                "stdout": stdout[:500],
                "stderr": stderr[:500],
                "returncode": proc.returncode,
            }

        result["elapsed_ms_measured"] = round(elapsed, 3)
        return result

    except subprocess.TimeoutExpired:
        return {
            "outcome": "TIMEOUT",
            "reason": "Bridge exceeded 10-second timeout",
        }
    except Exception as exc:
        return {
            "outcome": "HARNESS_ERROR",
            "reason": repr(exc),
        }


def main():
    RESULTS.mkdir(parents=True, exist_ok=True)

    if not BRIDGE.is_file():
        raise SystemExit(f"Không tìm thấy bridge: {BRIDGE}")

    seeds = [
        p for p in sorted(CORPUS.iterdir())
        if p.is_file()
        and p.suffix.lower() in {".jpg", ".jpeg", ".png", ".webp"}
    ]

    if not seeds:
        raise SystemExit("Không tìm thấy ảnh trong thư mục corpus/.")

    cases = []

    for seed in seeds:
        original = seed.read_bytes()
        suffix = seed.suffix.lower()
        prefix = seed.stem

        if suffix in {".jpg", ".jpeg"}:
            correct_mime = "image/jpeg"
            correct_name = "photo.jpg"
        elif suffix == ".png":
            correct_mime = "image/png"
            correct_name = "photo.png"
        else:
            correct_mime = "image/webp"
            correct_name = "photo.webp"

        # 1. Ảnh gốc
        cases.append((
            f"{prefix}_original",
            original,
            correct_mime,
            correct_name,
        ))

        # 2. Các biến thể cắt ngắn
        for fraction in (0.0, 0.25, 0.5, 0.9):
            cut = int(len(original) * fraction)
            cases.append((
                f"{prefix}_truncated_{int(fraction * 100)}pct",
                original[:cut],
                correct_mime,
                correct_name,
            ))

        # 3. Đảo bit tại một số vị trí
        if original:
            offsets = sorted(set((
                0,
                min(1, len(original) - 1),
                len(original) // 2,
                len(original) - 1,
            )))

            for offset in offsets:
                mutated = bytearray(original)
                mutated[offset] ^= 0xFF
                cases.append((
                    f"{prefix}_flip_byte_{offset}",
                    bytes(mutated),
                    correct_mime,
                    correct_name,
                ))

        # 4. Chèn các chữ ký byte thử nghiệm
        for sig_name, signature in SIGNATURES.items():
            pos = len(original) // 2
            mutated = original[:pos] + signature + original[pos:]
            cases.append((
                f"{prefix}_insert_{sig_name}",
                mutated,
                correct_mime,
                correct_name,
            ))

        # 5. Thêm 32 byte ngẫu nhiên ở cuối
        noise = bytes(RNG.randrange(256) for _ in range(32))
        cases.append((
            f"{prefix}_append_random",
            original + noise,
            correct_mime,
            correct_name,
        ))

        # 6. Khai báo MIME không khớp
        wrong_mime = (
            "image/png"
            if correct_mime == "image/jpeg"
            else "image/jpeg"
        )
        wrong_name = (
            "photo.png"
            if wrong_mime == "image/png"
            else "photo.jpg"
        )
        cases.append((
            f"{prefix}_wrong_mime",
            original,
            wrong_mime,
            wrong_name,
        ))

    # 7. Kiểm tra giới hạn kích thước
    oversized = b"\x00" * (MAX_SIZE + 1)
    cases.append((
        "oversized_5MiB_plus_1",
        oversized,
        "image/png",
        "large.png",
    ))

    if OUTPUT.exists():
        OUTPUT.unlink()

    counts = {}

    print(f"Seeds: {len(seeds)}")
    print(f"Test cases: {len(cases)}")
    print(f"Output: {OUTPUT}")
    print("Bat dau fuzzing...")

    with OUTPUT.open("w", encoding="utf-8") as out:
        for index, (name, data, mime, filename) in enumerate(
            cases, start=1
        ):
            result = call_bridge(data, mime, filename)

            record = {
                "case_id": index,
                "case": name,
                "input_size": len(data),
                "mime": mime,
                "filename": filename,
                **result,
            }

            out.write(json.dumps(record, ensure_ascii=False) + "\n")
            out.flush()

            outcome = record.get("outcome", "UNKNOWN")
            counts[outcome] = counts.get(outcome, 0) + 1

            reason = record.get("reason", "")
            message = f"[{index:03d}/{len(cases):03d}] {name}: {outcome}"

            if reason:
                message += f" - {reason}"

            print(message)

    print("\n=== SUMMARY ===")
    for outcome, count in sorted(counts.items()):
        print(f"{outcome}: {count}")

    print(f"JSONL saved to: {OUTPUT}")


if __name__ == "__main__":
    main()
