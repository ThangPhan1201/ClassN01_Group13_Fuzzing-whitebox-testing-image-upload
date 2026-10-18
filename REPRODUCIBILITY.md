# Reproducibility — image-upload & listing-service fuzzing

This document is the single source of truth for replaying every fuzzing
experiment in this repository. Each step lists the **exact command**,
**inputs**, **expected output**, and **where results land on disk**.

If you only have 5 minutes, run the two one-liners at the bottom.

---

## 0. Environment

| Tool  | Version    | Install                                         |
|-------|------------|-------------------------------------------------|
| Node  | 20+        | already required by the NestJS backend          |
| npm   | 10+        | ships with Node                                 |
| Python| 3.10+      | `brew install python@3.11`  (or any 3.10+)     |
| Z3    | latest     | `pip install z3-solver` (auto-installed below)  |

```bash
# One-time setup for the Python pipeline
pip install -r fuzz/image-upload/requirements.txt

# One-time setup for the TS pipeline
cd backend && npm ci && cd ..
```

---

## 1. Image-upload pipeline (Python / Z3)

### Single command — full 6-phase run

```bash
cd fuzz/image-upload
./run_all.sh
# or with custom seed:
SEED=42 ./run_all.sh
# or stop before "verify" (useful when the manual fix is not yet applied):
./run_all.sh --skip-verify
```

### Step-by-step (same as the script, exposed for transparency)

```bash
cd fuzz/image-upload

python3 fuzz_image_upload.py spec       # Phase 1: print 6 error specs
python3 fuzz_image_upload.py fuzz-bb --seed 12345 --runs 5 --max-trials 200000
python3 fuzz_image_upload.py fuzz-wb    # Phase 2b: Z3 solves the ELF path predicate
python3 fuzz_image_upload.py compare    # Phase 2c: BB-vs-WB table
python3 fuzz_image_upload.py log        # Phase 3: oracle PASS/FAIL on ORIGINAL parser
python3 fuzz_image_upload.py verify     # Phase 4: re-run on FIXED parser
```

### What gets produced

```
fuzz/image-upload/
├── logs/
│   ├── specs.json                  ← 6 error specs (IMG-01..05 + IMG-MAGIC)
│   ├── bb_magic_trials.json        ← black-box mean trials to hit ELF magic
│   ├── wb_z3_model.json            ← Z3 model, constraints, solver time
│   ├── compare.json                ← BB-vs-WB table
│   ├── fuzz_results.json           ← Phase 3 oracle log (BEFORE fix)
│   └── verify.json                 ← Phase 4 oracle log (AFTER fix)
└── crashes/
    ├── IMG-01_missing_file.bin            (no bytes — null case)
    ├── IMG-02_unsupported_mime.bin        16 bytes: 78 78 78…
    ├── IMG-03_fake_jpeg_mime.bin          16 bytes: 4e 4f 54 41 4e 49 4d 41 47 45 46 49 4c 45 21 21
    ├── IMG-04_oversized.bin               4  bytes: ff d8 ff d9   (size tag in companion .txt)
    ├── IMG-05_truncated.bin               1  byte:  ff
    └── IMG-MAGIC_elf_magic.bin            16 bytes: 7f 45 4c 46 00 00 00 00 00 00 00 00 00 00 00 00
```

### Replaying a crash input

```bash
cd fuzz/image-upload
python3 - <<'PY'
from parser import UploadFile, validate_file, Outcome

# Replay IMG-MAGIC (ELF) on the FIXED parser
buf = open("crashes/IMG-MAGIC_elf_magic.bin", "rb").read()
print("file size:", len(buf), "bytes")
print("hex      :", buf.hex())
out = validate_file(
    UploadFile("photo.jpg", "image/jpeg", len(buf), buf),
    mode="fixed",
)
print("outcome  :", out.value)        # expect: REJECT_NOT_IMAGE (because
                                      # ELF bytes don't match JPEG magic)
print("oracle OK:", out == Outcome.REJECT_NOT_IMAGE)
PY
```

The 1-byte `IMG-05_truncated.bin` should also be replayed to confirm
the buffer-length check fires.

---

## 2. Listing-service pipeline (TypeScript / Jest)

### Single command

```bash
cd fuzz/listing
./run_listing.sh
```

### What gets produced

```
backend/src/fuzz/results/
├── fuzz-results.json          ← BEFORE fix (9 exceptions from the random fuzzer)
└── fuzz-results-after.json    ← AFTER fix  (Jest run on the same spec)
```

`fuzz-results-after.json` has the same overall shape as the
before-file (total / passed / failed / exceptions / test_results), so
the two are directly diffable:

```bash
# Side-by-side comparison
jq '{passed, failed, exceptions}' \
   backend/src/fuzz/results/fuzz-results.json \
   backend/src/fuzz/results/fuzz-results-after.json

# Detailed diff (first 30 lines)
diff -u backend/src/fuzz/results/fuzz-results.json \
        backend/src/fuzz/results/fuzz-results-after.json | head -30
```

### Direct Jest invocation (same as the script)

```bash
cd backend
npx jest --testPathPattern="listing.fuzz" 2>&1 | tail -20
```

Expected (post-fix): **50 passed, 0 failed**.

### Spec file with the 12 vector-based tests

```
backend/src/modules/listing/__tests__/listing.fuzz.spec.ts
```

This file contains:

* 8 tests for `q` type-confusion (string / true / false / NaN / Infinity / object / array)
* 6 tests for `page` (0, -1, -999, NaN, Infinity, large valid)
* 5 tests for `limit` (0, 1, -1, 1000, NaN)
* 2 tests for `minPrice` (NaN, 999999999999999)
* 1 test for `q` length (10K chars → truncated to 500)
* SQL-injection, XSS, path-traversal, Unicode normalization, and very-long-string vectors
* boundary sanity (0, -1 clamped consistently with DTO contract)

---

## 3. Two-liner — replicate everything

```bash
# Image-upload (Python)
( cd fuzz/image-upload && ./run_all.sh )

# Listing-service (TypeScript)
( cd fuzz/listing && ./run_listing.sh )
```

Both scripts are deterministic given the same seed; rerunning should
produce **byte-identical** results files.

---

## 4. Versioning & seed tracking

| Artifact                                | Field        | Where                              |
|-----------------------------------------|--------------|------------------------------------|
| Listing before-fuzz                     | `seed`       | `fuzz-results.json` → root `.seed` |
| Listing after-fuzz (Jest)               | n/a          | Jest RNG is per-worker, not seeded |
| Python pipeline                         | `--seed`     | `bb_magic_trials.json` → `.seed`   |
| Phase timestamps                        | `finished_at`| every log file under `logs/`       |

If you bump the seed, only the random-fuzz counts in
`bb_magic_trials.json` change. Everything else (Z3, oracle, Jest) is
deterministic.

---

## 5. What "reproducible" means here

* **Same seed → same fuzz counts.**  Run `python3 fuzz_image_upload.py fuzz-bb --seed 12345`
  twice on the same machine and the `runs_detail` array is byte-identical.
* **Same source code → same Jest outcome.**  Run `npx jest` twice on
  the same commit and the 50 spec tests pass/fail the same way.
* **Same crash files → same oracle outcome.**  The bytes in
  `crashes/IMG-*.bin` are written by the fuzzer itself; replaying them
  with `validate_file(..., mode="fixed")` returns the expected
  `REJECT_*` outcome.

Anything that is NOT reproducible across machines (e.g. absolute
execution time) is recorded as a duration field, not a pass/fail gate.
