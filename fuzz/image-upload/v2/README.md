# Image Upload Fuzzer v2 - Cách B (Process-level Dynamic)

Bộ fuzzer mới dùng cùng file `.ts` thật (`ImageUploadService.validateFile()`)
qua 1 Node bridge, sinh payload ngẫu nhiên, có watchdog + auto-restart có giới hạn.

## Cài đặt

```bash
cd /Users/admin/Downloads/fuzzing-white-box
python3 -m pip install psutil
```

## Compile service .ts 1 lần

```bash
cd backend
npx tsc src/common/services/image-upload.service.ts \
        --outDir ../fuzz/image-upload/v2/compiled \
        --target ES2020 --module commonjs --esModuleInterop true \
        --skipLibCheck
```

## Chạy

```bash
cd fuzz/image-upload/v2

# Chỉ tĩnh
python3 run_fuzzer.py --mode static --duration 30

# Chỉ động (mỗi trial = 1 process node, có watchdog)
python3 run_fuzzer.py --mode dynamic --duration 60 --watchdog

# Cả hai
python3 run_fuzzer.py --mode both --duration 60 --watchdog
```

## Output

- `logs/live/static.jsonl`   — mỗi dòng 1 trial tĩnh
- `logs/live/dynamic.jsonl`  — mỗi dòng 1 trial động
- `logs/live/crashes/`       — payload gây crash + meta
- `logs/live/summary.txt`    — tổng kết cuối run
