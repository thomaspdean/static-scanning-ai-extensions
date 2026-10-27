# static-scanning-ai-extensions

Static scanner for GenAI browser extensions
Input is a folder of Chrome extension downloads; output is one record per extension.

## Status

Built in stages. Stages 1 and 2 are implemented.

| Stage | What | State |
|---|---|---|
| 1 | Setup and input handling (`ingest`) | done |
| 2 | Manifest analysis (`analyze`) | done |
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

## What Stage 2 does

`extscan analyze` reads each unpacked `manifest.json` and fills `Record.manifest`. It runs no code and makes no network calls, so it shows what an extension is *allowed* to do, not what it does.

- **Fields:** permissions (required and optional), host permissions, content scripts (`run_at`, `all_frames`, `world`, matches), background, side panel, `externally_connectable`, web-accessible resources, CSP, OAuth scopes, `update_url`. MV2 manifests are handled.
- **Derived flags** (under `manifest.flags`): `broad_host`, `host_scope` (all / wide / narrow / none), `cs_document_start`, `cs_all_frames`, `cs_main_world`, the same three restricted to scripts that run on every site (`broad_cs_*`), `high_risk_permissions`, `can_inject_anywhere`, `externally_connectable_broad`, `war_exposed_to_all_sites`, CSP and `update_url` checks.
- **Permission tiers** (high / medium / low) live in `config/permissions.yaml` and can be edited.
- **Reading the flags:** broad host access is the norm for this category (45 of 64 extensions), so `broad_host`, `can_inject_anywhere` and `war_exposed_to_all_sites` are weak signals. High-risk permissions and `broad_cs_*` combinations are the more selective ones.

Pilot set used at each checkpoint: AI Job Assistant Pro (tiny), AskSia (1K-10K, early/deep injection), Monica (1M+).

## Run it

```sh
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'

.venv/bin/extscan ingest                       # all extensions in extension-targets/
.venv/bin/extscan analyze                      # Stage 2, needs ingest first
.venv/bin/extscan ingest --only grammarly monica   # folder-name substring filter
.venv/bin/extscan --help                       # other subcommands are stubs (exit code 2)

.venv/bin/pytest -q                            # 26 tests
```

Prints `loaded=N total=N` and one line per non-ok extension.

## Layout

```
extscan/    cli.py  config.py  record.py  ingest.py  manifest.py  analyze_manifest.py
config/     settings.yaml        paths and extraction limits
            permissions.yaml     permission risk tiers
tests/      test_ingest.py  test_analyze_manifest.py
extension-targets/               input (gitignored): <folder>/{meta.json,*.crx,*.zip}
work/unpacked/<ext_id>/          extracted extensions (gitignored)
out/                             records.jsonl, schema.json (gitignored)
```
