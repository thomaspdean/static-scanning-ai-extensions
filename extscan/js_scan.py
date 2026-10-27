"""Stage 3: scan unpacked JS/HTML for endpoint, sink, DOM-harvest, sensitive and remote-code signals."""
from __future__ import annotations

import bisect
import re
import signal
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from . import signals as S
from .config import PROJECT_ROOT, Settings
from .record import STATUS_OK, Record

SCAN_VERSION = 1
NEAR_SINK_CHARS = 200
_COMMENT_PREFIX = re.compile(r"\s*(?://|/\*|\*)")


class ScanTimeout(Exception):
    pass


def load_scan_config(path: Path | None = None) -> dict[str, Any]:
    path = path or PROJECT_ROOT / "config" / "scan.yaml"
    return yaml.safe_load(path.read_text(encoding="utf-8"))


# ---------- helpers ----------

def beautify(text: str, timeout_s: float) -> str:
    """Beautify JS; raises ScanTimeout past the deadline (best effort, main thread only)."""
    import jsbeautifier

    def _handler(signum, frame):
        raise ScanTimeout()

    try:
        old = signal.signal(signal.SIGALRM, _handler)
        signal.setitimer(signal.ITIMER_REAL, timeout_s)
    except ValueError:                      # not in the main thread: no timeout available
        return jsbeautifier.beautify(text)
    try:
        return jsbeautifier.beautify(text)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)


def is_minified(text: str) -> bool:
    if not text:
        return False
    lines = text.split("\n")
    return max(map(len, lines)) > 1000 or len(text) / len(lines) > 200


def vendor_reason(rel: str, head: str, cfg: dict[str, Any]) -> str:
    v = cfg["vendor"]
    p = Path(rel)
    dirs = {d.lower() for d in p.parts[:-1]}
    for d in v["path_dirs"]:
        if d.lower() in dirs:
            return f"dir:{d}"
    if re.search(v["filename_regex"], p.name):
        return "filename"
    if re.search(v["banner_regex"], head[:3000]):
        return "banner"
    return ""


def _snippet(text: str, start: int, end: int, n: int, redact: bool) -> str:
    if redact:
        shown = text[start:start + 6] + "…[redacted]"
        return re.sub(r"\s+", " ", text[max(0, start - 40):start] + shown)[-n:]
    s = text[max(0, start - 60):min(len(text), end + 100)]
    s = re.sub(r"\s+", " ", s).strip()
    return s[:n]


def _host_of(url: str) -> tuple[str, bool]:
    """Return (host, dynamic). Dynamic hosts contain template placeholders."""
    url = url.rstrip(".,;:!?'\"`)")
    try:
        netloc = urlsplit(url).netloc
    except ValueError:
        return "", False
    host = netloc.rsplit("@", 1)[-1]
    if re.search(r"[^A-Za-z0-9.\-:\[\]]", host):
        return "(dynamic)", True
    host = host.lower().split(":")[0] if not host.startswith("[") else host.lower()
    return host, False


def _ignored(host: str, ignore: list[str]) -> bool:
    return any(host == h or host.endswith("." + h) for h in ignore)


_PLACEHOLDER_WORDS = re.compile(
    r"(?i)your|here|placeholder|replace|insert|enter|example|changeme|change_me|dummy|sample|todo|xxxx|apni|yahan")
_QUOTED = re.compile(r"""["']([^"']+)["']""")


def is_placeholder_secret(match_text: str) -> bool:
    """True when a secret-shaped match is obviously a template value, not a credential."""
    quoted = _QUOTED.findall(match_text)
    value = quoted[-1] if quoted else match_text
    if _PLACEHOLDER_WORDS.search(value):
        return True
    return bool(re.fullmatch(r"[A-Z_\-\s]+", value))   # SCREAMING_SNAKE_CASE, no digits


# ---------- per-file scan ----------

def scan_text(text: str, rel: str, is_code: bool, vendor: bool, cfg: dict[str, Any]) -> dict[str, Any]:
    """Run all signals over one file's text. Returns counts, capped evidence, and URLs."""
    lim = cfg["limits"]
    cap, snip_n = lim["evidence_per_signal"], lim["snippet_chars"]
    nl: list[int] | None = None

    def line_of(pos: int) -> int:
        nonlocal nl
        if nl is None:
            nl = [m.start() for m in re.finditer("\n", text)]
        return bisect.bisect_right(nl, pos - 1) + 1

    out: dict[str, Any] = {"signals": {}, "urls": [], "ignored_urls": 0, "comment_urls": 0}
    sink_pos: list[int] = []
    groups = S.GROUPS if is_code else {}
    for group, table in groups.items():
        for name, rx in table.items():
            count, ev = 0, []
            for m in rx.finditer(text):
                if name == "long_base64" and S.BASE64_BENIGN_PREFIX.search(text[max(0, m.start() - 20):m.start()]):
                    continue
                if name in S.REDACT and is_placeholder_secret(m.group(0)):
                    continue
                count += 1
                if group == "network_sinks":
                    sink_pos.append(m.start())
                if len(ev) < cap:
                    ev.append({"file": rel, "line": line_of(m.start()),
                               "snippet": _snippet(text, m.start(), m.end(), snip_n, name in S.REDACT),
                               "vendor": vendor})
            if count:
                out["signals"][(group, name)] = {"count": count, "evidence": ev}

    sink_pos.sort()
    ignore = cfg["ignore_hosts"]
    seen = {}
    for m in S.URL_RE.finditer(text):
        url = m.group(0).rstrip(".,;:!?'\"`)")
        host, dynamic = _host_of(url)
        if not host or (not dynamic and ("." not in host and not host.startswith("["))):
            continue
        if not dynamic and _ignored(host, ignore):
            out["ignored_urls"] += 1
            continue
        ls = text.rfind("\n", 0, m.start()) + 1
        prefix = text[ls:m.start()]
        if len(prefix) < 400 and _COMMENT_PREFIX.match(prefix):   # URL inside a comment / license banner
            out["comment_urls"] += 1
            continue
        i = bisect.bisect_left(sink_pos, m.start() - NEAR_SINK_CHARS)
        near = i < len(sink_pos) and sink_pos[i] <= m.start() + NEAR_SINK_CHARS
        key = (host, url)
        prev = seen.get(key)
        seen[key] = (prev[0] + 1 if prev else 1, (prev[1] if prev else False) or near)
    out["urls"] = [{"host": h, "url": u, "count": c, "near_sink": n} for (h, u), (c, n) in seen.items()]
    return out


# ---------- per-extension scan ----------

def scan_extension(ext_dir: Path, cfg: dict[str, Any]) -> dict[str, Any]:
    lim = cfg["limits"]
    code_sfx, json_sfx = set(cfg["code_suffixes"]), set(cfg["json_suffixes"])
    cov = {"files_total": 0, "files_scanned": 0, "files_beautified": 0, "files_minified": 0,
           "beautify_timeouts": 0, "files_too_large_to_beautify": 0, "files_vendor": 0,
           "bytes_scanned": 0, "bytes_skipped": 0, "skipped_files": []}
    sig: dict[tuple[str, str], dict[str, Any]] = {}
    hosts: dict[str, dict[str, Any]] = {}
    ignored = comment_urls = 0
    obf_files: list[dict[str, Any]] = []
    minified_first_party = False

    for path in sorted(p for p in ext_dir.rglob("*") if p.is_file() and not p.is_symlink()):
        sfx = path.suffix.lower()
        if sfx not in code_sfx and sfx not in json_sfx:
            continue
        rel = path.relative_to(ext_dir).as_posix()
        size = path.stat().st_size
        cov["files_total"] += 1

        def skip(reason: str) -> None:
            cov["bytes_skipped"] += size
            if len(cov["skipped_files"]) < 20:
                cov["skipped_files"].append({"file": rel, "reason": reason, "bytes": size})

        if size > lim["scan_max_bytes"]:
            skip("too_large")
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            skip(f"unreadable: {e}")
            continue
        is_code = sfx in code_sfx
        reason = vendor_reason(rel, text, cfg) if is_code else ""
        vendor = bool(reason)
        cov["files_vendor"] += vendor
        if is_code and sfx != ".html" and sfx != ".htm" and is_minified(text):
            cov["files_minified"] += 1
            minified_first_party |= not vendor
            if size > lim["beautify_max_bytes"]:
                cov["files_too_large_to_beautify"] += 1
            else:
                try:
                    text = beautify(text, lim["beautify_timeout_s"])
                    cov["files_beautified"] += 1
                except ScanTimeout:
                    cov["beautify_timeouts"] += 1
                except Exception:
                    cov["beautify_timeouts"] += 1
        res = scan_text(text, rel, is_code, vendor, cfg)
        cov["files_scanned"] += 1
        cov["bytes_scanned"] += size
        ignored += res["ignored_urls"]
        comment_urls += res["comment_urls"]
        file_obf = 0
        for key, d in res["signals"].items():
            agg = sig.setdefault(key, {"total": 0, "first_party": 0, "vendor": 0, "files": 0, "fp_ev": [], "v_ev": []})
            agg["total"] += d["count"]
            agg["vendor" if vendor else "first_party"] += d["count"]
            agg["files"] += 1
            bucket = agg["v_ev"] if vendor else agg["fp_ev"]
            bucket.extend(d["evidence"])
            if not vendor and key[1] in S.OBFUSCATION_SIGNALS:
                if key[1] == "packer" or d["count"] >= (50 if key[1] == "hex_identifiers" else 5):
                    file_obf += 1
        if file_obf and len(obf_files) < 10:
            obf_files.append({"file": rel, "indicators": file_obf})
        for u in res["urls"]:
            h = hosts.setdefault(u["host"], {"host": u["host"], "dynamic": u["host"] == "(dynamic)", "urls": [],
                                             "url_count": 0, "files": [], "first_party": False,
                                             "near_sink": False, "schemes": set()})
            h["url_count"] += u["count"]
            if len(h["urls"]) < 3 and u["url"] not in h["urls"]:
                h["urls"].append(u["url"][:200])
            if rel not in h["files"] and len(h["files"]) < 5:
                h["files"].append(rel)
            h["first_party"] |= not vendor
            h["near_sink"] |= u["near_sink"]
            h["schemes"].add(u["url"].split(":", 1)[0].lower())

    signals_out: dict[str, dict[str, Any]] = {g: {} for g in S.GROUPS}
    group_totals = {g: {"first_party": 0, "vendor": 0} for g in S.GROUPS}
    for (group, name), a in sorted(sig.items()):
        seen, ev = set(), []
        for e in a["fp_ev"] + a["v_ev"]:        # first-party evidence first
            k = re.sub(r"\d+", "#", e["snippet"])
            if k in seen:
                continue
            seen.add(k)
            ev.append(e)
            if len(ev) >= lim["evidence_per_signal"]:
                break
        low = name in S.LOW_VALUE
        signals_out[group][name] = {"total": a["total"], "first_party": a["first_party"],
                                    "vendor": a["vendor"], "files": a["files"], "low_value": low, "evidence": ev}
        if not low:
            group_totals[group]["first_party"] += a["first_party"]
            group_totals[group]["vendor"] += a["vendor"]

    ep = sorted(hosts.values(), key=lambda h: (not h["first_party"], not h["near_sink"], -h["url_count"], h["host"]))
    for h in ep:
        h["schemes"] = sorted(h["schemes"])
    level = "suspected_obfuscated" if obf_files else ("minified" if minified_first_party else "none")
    return {
        "version": SCAN_VERSION,
        "coverage": cov,
        "obfuscation": {"level": level, "suspect_files": obf_files},
        "group_totals": group_totals,
        "signals": signals_out,
        "endpoint_hosts_total": len(ep),
        "endpoint_urls_ignored": ignored,
        "endpoint_urls_in_comments": comment_urls,
        "endpoints": ep[:lim["max_endpoint_hosts"]],
    }


def _worker(args: tuple[str, dict]) -> dict[str, Any]:
    return scan_extension(Path(args[0]), args[1])


def scan_records(recs: list[Record], st: Settings, cfg: dict[str, Any], progress=None) -> None:
    todo = [r for r in recs if r.ingest_status == STATUS_OK and r.unpacked_path]
    jobs = [(str(st.root / r.unpacked_path), cfg) for r in todo]
    workers = max(1, int(cfg["limits"].get("workers", 1)))
    if workers == 1 or len(jobs) == 1:
        results = map(_worker, jobs)
    else:
        pool = ProcessPoolExecutor(max_workers=workers)
        results = pool.map(_worker, jobs)
    for r, res in zip(todo, results):
        r.scan = res
        if progress:
            progress(r)
