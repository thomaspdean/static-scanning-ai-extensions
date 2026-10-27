# extscan

Static scanner for GenAI browser extensions. It unpacks Chrome extension downloads, reads each manifest, scans the code for data-collection and data-exfiltration signals, and writes one structured record per extension.

Part of a CS 6262 measurement study of what AI assistant extensions send off-device and whether that matches what they disclose. The static pass is the wide, cheap half of the funnel: it ranks extensions so a smaller sample can be tested dynamically. Everything it reports is a **lead, not proof**. Runtime-built URLs and obfuscated code evade a static scan, so absence of a hit does not mean an extension is clean.

## Install

```sh
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
```

Input is a directory of extension folders (default `extension-targets/`), each containing `meta.json` and the downloaded `.zip`/`.crx`.

## Usage

Commands run in order and share one set of per-extension records in `out/records/`. Each accepts `--only <substring>...` to restrict to matching folder names.

```sh
extscan ingest
extscan analyze
extscan scan
extscan classify
```

### `extscan ingest`
Verifies and unpacks extensions into `work/unpacked/<ext_id>/`.

- Loads every `meta.json`; rows whose status is not `ok` are skipped and the reason recorded.
- Checks the zip's SHA-256 against `meta.json`; a mismatch is recorded and nothing is extracted.
- Extracts with guards against zip-slip, absolute paths, symlinks, excessive entry counts, oversized files and zip bombs (limits in `config/settings.yaml`).
- Reads `manifest.json` (UTF-8 with BOM) and resolves `__MSG_*__` names and descriptions from `_locales/`.
- Writes one `out/records/<ext_id>.json` per extension, plus `out/index.json` and `out/schema.json`. Each record carries an `ingest_status` of `ok`, `skipped`, `hash_mismatch` or `failed`.
- A full `ingest` replaces the record set; `ingest --only` updates just the matching records and leaves the rest alone.

### `extscan analyze`
Reads each manifest and records what the extension is *allowed* to do. Runs no code and makes no network calls.

- **Fields:** permissions (required and optional), host permissions, content scripts (`run_at`, `all_frames`, `world`, matches), background, side panel, `externally_connectable`, web-accessible resources, CSP, OAuth scopes, `update_url`. MV2 manifests are handled.
- **Derived flags** (`manifest.flags`): broad host access and `host_scope` (all / wide / narrow / none); `document_start`, `all_frames` and `MAIN`-world content scripts, both overall and restricted to scripts that run on every site (`broad_cs_*`); high- and medium-risk permissions; `can_inject_anywhere`; exposure of web-accessible resources and `externally_connectable`; CSP and `update_url` checks.
- Permission tiers are defined in `config/permissions.yaml`.
- Broad host access is the norm for this category, so `broad_host`, `can_inject_anywhere` and `war_exposed_to_all_sites` are weak signals. High-risk permissions and `broad_cs_*` combinations discriminate better.

### `extscan scan`
Reads the extension's code and records what it *appears to do*. Covers `.js`, `.mjs`, `.cjs` and `.html` for all signals, and `.json` for endpoint URLs only (the root `manifest.json` is skipped; `analyze` covers it). Minified files are beautified first (5 MB cap, 10 s timeout, otherwise scanned raw); files over 40 MB are skipped and recorded in `scan.coverage`.

1. **Endpoints.** URL literals (`http(s)://`, `ws(s)://`) and their hosts. Filtered out: XML and schema namespaces, `localhost`, documentation links, and URLs inside comments or license banners. Each host carries a `near_sink` hint, set when a network call appears within 200 characters.
2. **Network sinks.** Calls that can send data out: `fetch`, `XMLHttpRequest`, `sendBeacon`, `WebSocket`, `EventSource`, image-pixel beacons, HTTP client libraries, native messaging, `webRequest` listeners.
3. **DOM harvesting.** Reading page content (`innerText`, `textContent`, `innerHTML`/`outerHTML`, `getSelection`, `document.cookie`, `document.title`/URL), form and password fields, hidden inputs, `shadowRoot`, iframe `contentDocument`, `MutationObserver`, screenshots and clipboard reads. These correspond to the honeytoken contexts in the study: visible text, hidden node, password, iframe, shadow DOM.
4. **Sensitive data.** Password, SSN and card-field cues (`cc-number`, `ssn`, `cvv`); use of `chrome.cookies`, `history`, `identity`, `bookmarks`, `downloads` and `management`; hard-coded credential shapes (`sk-…`, `AIza…`, `AKIA…`, bearer tokens). Matches are redacted in the output and obvious placeholders (`YOUR_API_KEY_HERE`) are ignored.
5. **Remote code and obfuscation.** `eval`, `new Function`, string-argument timers, `executeScript` and `userScripts`, `MAIN`-world injection, remote `<script src>`, and remote `importScripts`/`import()`. Obfuscation indicators: packers, `_0x…` identifiers, long `fromCharCode` runs, long base64 and escape-sequence blobs, summarised as an obfuscation level of `none`, `minified` or `suspected_obfuscated`.

**Output** (`scan` in each record): per signal, a total, first-party and vendor counts, and up to 20 deduplicated evidence items (`file`, `line`, `snippet`); candidate endpoint hosts; file coverage; and the obfuscation level. Library files are tagged as vendor by path, filename or banner; a library bundled inside a first-party bundle is not separated. Signals common in ordinary UI code (`computed_style`, `attach_shadow`, `mutation_observer`, `extension_storage_read`, `tabs_query`, `wasm`, `atob`, escape-sequence and base64 runs) are marked `low_value` and excluded from group totals.

Limits, ignored hosts and vendor rules are in `config/scan.yaml`; the regexes are in `extscan/signals.py`.

### `extscan classify`
Labels every candidate endpoint host and writes `out/shared_endpoints.csv`. Uses the hosts found by `scan` plus the hosts the manifest declares, so run `scan` (and ideally `analyze`) first.

Each endpoint in `record.endpoints` gets a `party` (`1p`, `3p`, or `n/a` for templated and local hosts) and a `category`, applied in this order:

1. `tracker`: analytics, advertising, session replay, error monitoring, attribution (`config/trackers.yaml`).
2. `llm_provider`: OpenAI, Anthropic, Gemini and others (`config/llm_providers.yaml`).
3. `first_party`: the host's registrable domain belongs to the extension. Evidence, in order of confidence: `homepage` (manifest `homepage_url`), `store_website`, `externally_connectable` (the manifest's declared web origins), then `name_match` (the domain label appears in the extension's name; generic words and known platforms never match). The evidence is stored in `basis`.
4. `cdn_static` and `known_service`: recognised CDNs and large platforms (`config/known_hosts.yaml`). Still `3p`.
5. `unknown`: third-party and unlabeled. These need human review.

Also recorded per endpoint: the registrable domain (public-suffix aware), whether it was seen in `code`, the `manifest`, or both, whether it appears in first-party code, and the `near_sink` hint.

`out/shared_endpoints.csv` lists third-party hosts referenced by two or more extensions, with category, extension count, how many reference it in first-party code or near a network call, and the extension names. This is the "shared third-party endpoints" measurement.

`unknown` is large for extensions that embed lists of supported websites (shopping, news and so on), because those are page-awareness lists rather than destinations. Prefer `near_sink`, `llm_provider` and `tracker` over the raw `unknown` count when judging where data goes.

### Planned
`scrape` (Chrome Web Store user counts and privacy practices), `score` and `report` (ranking and outputs). These subcommands exist as stubs and exit with code 2.

## Output

| Path | Contents |
|---|---|
| `out/records/<ext_id>.json` | One record per extension; each command fills its own section |
| `out/shared_endpoints.csv` | Third-party hosts shared by two or more extensions |
| `out/index.json` | Lightweight listing: id, name, tier, ingest status, which stages are filled |
| `out/schema.json` | Field names, types and the stage that populates each |
| `work/unpacked/<ext_id>/` | Extracted extension files |

All of these are git-ignored. `scan` writes each record as soon as it finishes, so an interrupted run keeps its progress.

## Layout

```
extscan/    cli.py  config.py  record.py  ingest.py  manifest.py
            analyze_manifest.py  signals.py  js_scan.py  classify.py
config/     settings.yaml     paths and extraction limits
            permissions.yaml  permission risk tiers
            scan.yaml         scan limits, ignored hosts, vendor rules
            trackers.yaml  llm_providers.yaml  known_hosts.yaml   endpoint lists
tests/      test_ingest.py  test_analyze_manifest.py  test_js_scan.py  test_record_io.py  test_classify.py
```

```sh
.venv/bin/pytest -q
```
