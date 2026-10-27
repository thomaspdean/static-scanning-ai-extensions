# static-scanning-ai-extensions

Static scanner for GenAI browser extensions
Input is a folder of Chrome extension downloads; output is one record per extension.

## Status

Built in stages. Only Stage 1 is implemented.

| Stage | What | State |
|---|---|---|
| 1 | Setup and input handling (`ingest`) | done |
| 2 | Manifest analysis (`analyze`) | stub |
| 3 | JS/HTML scanning (`scan`) | stub |
| 4 | Endpoint classification (`classify`) | stub |
| 5 | Chrome Web Store scraping (`scrape`) | stub |
| 6 | Scoring, outputs, console report (`score`, `report`) | stub |

## What Stage 1 does

`extscan ingest`:

1. Reads every `<input_dir>/*/meta.json`. Rows whose `status` is not `ok` are skipped and recorded with the reason.
2. Computes the SHA-256 of the `.zip` and compares it to `zip_sha256`. A mismatch is recorded and the zip is not extracted.
3. Extracts into `work/unpacked/<ext_id>/` with guards: zip-slip and absolute paths, symlinks, entry count, per-file and total size (measured on bytes written), and compression ratio. Limits are in `config/settings.yaml`. A rejected archive leaves nothing behind.
4. Reads `manifest.json` (utf-8-sig) and resolves `__MSG_*__` name and description from `_locales/`.
5. Writes `out/records.jsonl` (one record per extension) and `out/schema.json`. Later-stage fields (`manifest`, `scan`, `endpoints`, `store`, `score`) are present but empty.

Each record has an `ingest_status` of `ok`, `skipped`, `hash_mismatch` or `failed`, plus `ingest_reason`.

Last full run: 64 loaded, 0 skipped, 0 hash-mismatched, 0 failed.

## Run it

```sh
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'

.venv/bin/extscan ingest                       # all extensions in extension-targets/
.venv/bin/extscan ingest --only grammarly monica   # folder-name substring filter
.venv/bin/extscan --help                       # other subcommands are stubs (exit code 2)

.venv/bin/pytest -q                            # 11 tests
```

Prints `loaded=N total=N` and one line per non-ok extension.

## Layout

```
extscan/    cli.py  config.py  record.py  ingest.py  manifest.py
config/     settings.yaml        paths and extraction limits
tests/      test_ingest.py
extension-targets/               input (gitignored): <folder>/{meta.json,*.crx,*.zip}
work/unpacked/<ext_id>/          extracted extensions (gitignored)
out/                             records.jsonl, schema.json (gitignored)
```
