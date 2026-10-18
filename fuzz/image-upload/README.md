# Image upload fuzzing (Ch.4 / ch4_dynafuzz)

Parser target: `backend/src/common/services/image-upload.service.ts`  
(`validateFile` / `containsExecutableContent` / magic bytes ELF `7F 45 4C 46`).

Python `parser.py` keeps two modes:

- `original` — snapshot **before** the IMG-03 patch (used by `fuzz-*` and `log`)
- `fixed` — buffer required + JPEG/PNG/WebP magic (used by `verify`)

The fuzzer **does not** patch TypeScript. The NestJS service was patched by hand; `verify` only re-runs the oracle.

## Setup

```bash
cd fuzz/image-upload
python3 -m pip install -r requirements.txt
```

## Run phases in order (one command each)

```bash
python3 fuzz_image_upload.py spec
python3 fuzz_image_upload.py fuzz-bb
python3 fuzz_image_upload.py fuzz-wb
python3 fuzz_image_upload.py compare
python3 fuzz_image_upload.py log
python3 fuzz_image_upload.py verify
```

| Command | Phase | What it measures |
|---------|--------|------------------|
| `spec` | 1 | Error specifications (oracle). Severity is predicted, not confirmed. |
| `fuzz-bb` | 2a | Black-box: mean trials to hit ELF magic (plus MZ 2-byte contrast). |
| `fuzz-wb` | 2b | White-box: Z3 solves the same magic; solver time. |
| `compare` | 2c | Same branch IMG-MAGIC: trials vs Z3 time (Ch.4.6). |
| `log` | 3 | Oracle PASS/FAIL on **original** parser. FAIL ≠ crash. |
| `verify` | 4 | Re-run oracle on **fixed** parser after the manual patch. |

Skip a step and the next command exits with `Run … first`.

Black-box ELF 4-byte space is \(256^4\). Default `--max-trials 200000` is expected to report **INF (0 hits)**. Use `--max-trials` / `--runs` if you need a longer campaign. MZ 2-byte is the contrast where random search can still succeed.

## Artifacts

- `logs/specs.json`
- `logs/bb_magic_trials.json`
- `logs/wb_z3_model.json`
- `logs/compare.json`
- `logs/fuzz_results.json`
- `logs/verify.json`
- `crashes/elf_magic.bin`
