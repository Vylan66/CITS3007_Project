# BUN parser

This project implements a small C parser for the `.bun` container format. The focus is on **robust validation** (reject malformed inputs, flag unsupported features) and on tests that cover headers, assets, compression, and large-file behavior.

## What it does

Given a `.bun` file, the parser validates the internal layout and returns:
- `BUN_OK` for valid inputs
- `BUN_MALFORMED` for corrupted / inconsistent files
- `BUN_UNSUPPORTED` for features that are intentionally not implemented (e.g. zlib compression)

The asset payload is validated using **streaming reads**, so large inputs don’t need to be loaded into memory all at once.

## Requirements (Linux/WSL)

Dependencies:
- `gcc`, `make`
- `pkg-config`
- `check`
- `python3` (to generate fixtures; tests also have a fallback path if Python is missing)
- `valgrind` (optional, for tooling evidence)

Example install on Ubuntu/WSL:

```bash
sudo apt update
sudo apt install build-essential pkg-config check python3 valgrind
```

## Build and test

Build:

```bash
make clean
make all
```

Run tests:

```bash
make clean
make test
```

Run tests with sanitizers (ASan + UBSan):

```bash
make clean
make SAN=1 test
```

Run tests under Valgrind:

```bash
make clean
make valgrind
```

## Fixture generation

Generate the full fixture set:

```bash
python3 bunfile_generator.py --fixtures tests/fixtures
```

Generate header-only fixtures:

```bash
python3 bunfile_generator.py --header-fixtures tests/fixtures
```

## Running the parser

Example:

```bash
./bun_parser tests/fixtures/valid/10-valid-asset.bun
```

Expected output:

```text
Magic: 0x304e5542
Version: 1.0
Asset count: 1
Asset table offset: 60
String table offset: 108
Data section offset: 120
Parsed assets: 1
```

For malformed/unsupported inputs, the parser prints violations to `stderr` and exits with the corresponding error code.

## Task checklist (T1–T7)

### T1 — Extend header tests
- The existing header tests are kept and extended with additional invalid-header cases.

### T2 — Add asset tests
- `tests/test_bun.c` includes an `asset-tests` TCase covering name bounds, printable ASCII, data bounds, flags, and checksums.

### T3 — Add compression tests
- `tests/test_bun.c` includes a `compression-tests` TCase covering “none”, valid RLE, malformed RLE, and unsupported zlib.

### T4 — Use `bunfile_generator.py` for fixtures
- Tests try to generate fixtures via `bunfile_generator.py`; if Python isn’t available, they fall back to writing minimal fixtures directly in C.

### T5 — Large-file / memory-efficiency testing
- A large-file fixture (64 MiB payload) is parsed successfully **and tests assert that peak RSS does not grow by anything close to the payload size**, supporting the claim that payload validation is done via streaming reads (not “slurp into RAM”).

### T6 — Sanitizers and warnings
- The build uses stricter warning flags, and `make SAN=1 test` / `make valgrind` are supported.
