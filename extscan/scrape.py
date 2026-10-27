"""Stage 5: fetch Chrome Web Store pages (cached) and parse popularity, developer links and the
privacy-practices label into Record.store.

The parser works on visible text and anchors, not on CSS classes, so it tolerates markup changes
better, but it can still fail. Every field is optional and failures are recorded in
`parse_issues`; raw HTML is cached so the parser can be fixed and re-run with --no-fetch.
"""
from __future__ import annotations

import json
import random
import re
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Callable

import yaml

from .config import PROJECT_ROOT, Settings
from .record import STATUS_OK, Record

SCRAPE_VERSION = 1
Fetcher = Callable[[str], "tuple[int, str, str]"]      # url -> (http_status, final_url, html)


class Blocked(Exception):
    pass


def load_scrape_config(path: Path | None = None) -> dict[str, Any]:
    path = path or PROJECT_ROOT / "config" / "scrape.yaml"
    return yaml.safe_load(path.read_text(encoding="utf-8"))


# ---------- HTML -> text + anchors ----------

class _Text(HTMLParser):
    _SKIP = {"script", "style", "noscript", "template", "svg"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.lines: list[str] = []
        self.links: list[tuple[str, str]] = []     # (visible text, href)
        self.meta: dict[str, str] = {}
        self._skip = 0
        self._a: list[str] | None = None
        self._href = ""

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in self._SKIP:
            self._skip += 1
        elif tag == "meta" and (a.get("property") or a.get("name")) and a.get("content"):
            self.meta[(a.get("property") or a["name"]).lower()] = a["content"]
        elif tag == "a" and a.get("href"):
            self._a, self._href = [], a["href"]

    def handle_endtag(self, tag):
        if tag in self._SKIP and self._skip:
            self._skip -= 1
        elif tag == "a" and self._a is not None:
            self.links.append((re.sub(r"\s+", " ", "".join(self._a)).strip(), self._href))
            self._a = None

    def handle_data(self, data):
        if self._skip:
            return
        t = re.sub(r"\s+", " ", data).strip()
        if t:
            self.lines.append(t)
            if self._a is not None:
                self._a.append(t + " ")


def extract_text(html: str) -> _Text:
    p = _Text()
    p.feed(html)
    p.close()
    return p


# ---------- parsing ----------

_COUNT = re.compile(r"([\d][\d,.]*)\s*([KkMm])?\s*\+?\s*users?\b")
_NOT_FOUND = re.compile(r"(?i)item not found|isn.t available|no longer available|couldn.t find")
_SECTION_STOP = {"support", "related", "related extensions", "additional information", "more from this developer",
                 "you might also like…", "you might also like..."}
_OUT_OF_5 = re.compile(r"^(\d(?:\.\d+)?) out of 5$")
_NON_NAME = {"website", "email", "phone", "trader", "non-trader"}


def _normalize_href(href: str) -> str:
    """Developers sometimes enter a bare domain; give it a scheme."""
    if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", href) or href.startswith(("/", "#")):
        return href
    return "https://" + href


def parse_count(text: str) -> int | None:
    m = _COUNT.search(text)
    if not m:
        return None
    n = float(m.group(1).replace(",", ""))
    return int(n * {"k": 1_000, "m": 1_000_000}.get((m.group(2) or "").lower(), 1))


def tier_for(count: int, tiers: dict[str, int]) -> str:
    return max((t for t, lo in tiers.items() if count >= lo), key=lambda t: tiers[t])


def _after(lines: list[str], label: str) -> str:
    for i, ln in enumerate(lines[:-1]):
        if ln.lower() == label.lower():
            return lines[i + 1]
    return ""


def parse_privacy(lines: list[str], data_types: list[str]) -> dict[str, Any]:
    """Parse the privacy-practices block.

    Observed layout (Oct 2026): `Privacy`, a Chrome Enterprise banner, "<name> has disclosed the
    following information regarding the collection and usage of your data...", "<name> handles the
    following:", one line per data type, `See details`, "This developer declares that your data is",
    then the three certifications, then `Support`.
    """
    out: dict[str, Any] = {"status": "no_section", "data_types_collected": [],
                           "certifications": {"not_sold": None, "not_unrelated_use": None, "not_lending": None},
                           "raw_text": ""}
    start = next((i for i, ln in enumerate(lines) if ln.lower() in ("privacy", "privacy practices")), None)
    if start is None:
        return out
    section: list[str] = []
    for ln in lines[start + 1:start + 60]:
        if ln.lower() in _SECTION_STOP:
            break
        section.append(ln)
    out["raw_text"] = " | ".join(section)[:2000]
    low = out["raw_text"].lower()
    handles = next((i for i, ln in enumerate(section) if re.search(r"(?:handles|collects) the following", ln, re.I)), None)
    known = {t.lower(): t for t in data_types}
    if handles is not None:
        end = next((i for i in range(handles + 1, len(section))
                    if section[i].lower() in ("see details",) or section[i].lower().startswith("this developer declares")),
                   len(section))
        out["data_types_collected"] = [known[ln.lower()] for ln in section[handles + 1:end] if ln.lower() in known]
        out["status"] = "declared_collection" if out["data_types_collected"] else "unparsed"
    elif re.search(r"(?:does|will) not collect|not collect or use", low):
        out["status"] = "declares_no_collection"
    elif re.search(r"has not (?:provided|disclosed)|no information", low):
        out["status"] = "no_disclosure"
    elif "regarding the collection and usage of your data" in low:
        out["status"] = "no_types_listed"          # disclosure sentence present, but no data-type list
    else:
        out["status"] = "unparsed"
    out["certifications"] = {
        "not_sold": True if "not being sold to third parties" in low else None,
        "not_unrelated_use": True if "unrelated to the item" in low else None,
        "not_lending": True if "creditworthiness" in low else None,
    }
    return out


def parse_store_page(html: str, cfg: dict[str, Any]) -> dict[str, Any]:
    """Parse one store page. Never raises; problems are listed in `parse_issues`."""
    t = extract_text(html)
    lines, issues = t.lines, []
    res: dict[str, Any] = {"name": "", "user_count": None, "user_count_text": "", "rating": None,
                           "rating_count": "", "version": "", "updated": "", "size": "", "languages": "",
                           "category": "", "developer_name": "", "website": "", "support_url": "", "privacy_policy_url": "",
                           "privacy_practices": {}}
    if _NOT_FOUND.search(" ".join(lines[:80])) and not any(_COUNT.search(x) for x in lines):
        return {**res, "parse_status": "not_found", "parse_issues": ["page says the item is not available"]}
    title = next((ln for ln in lines[:3] if ln.endswith(" - Chrome Web Store")), "")      # real page has no og:title
    res["name"] = (t.meta.get("og:title") or title).replace(" - Chrome Web Store", "").strip()
    if not res["name"]:
        issues.append("name: no og:title or page title")
    for ln in lines:
        c = parse_count(ln)
        if c is not None and re.search(r"users?\s*$", ln):
            res["user_count"], res["user_count_text"] = c, ln
            break
    if res["user_count"] is None:
        issues.append("user_count: no 'N users' text found")
    for i, ln in enumerate(lines):
        m = _OUT_OF_5.match(ln)
        if m:
            res["rating"] = float(m.group(1))
            nxt = lines[i + 1] if i + 1 < len(lines) else ""
            rc = re.match(r"^([\d][\d,.]*\s*[KkMm]?)\s+ratings?$", nxt)
            res["rating_count"] = rc.group(1).strip() if rc else ("0" if nxt.lower() == "no ratings" else "")
            break
    u = next((i for i, ln in enumerate(lines) if ln == res["user_count_text"]), None)
    if u and u >= 2 and lines[u - 2].lower() in ("extension", "theme"):
        res["category"] = lines[u - 1]
    for key, label in (("version", "Version"), ("updated", "Updated"), ("size", "Size"), ("languages", "Languages")):
        res[key] = _after(lines, label)
    dev = _after(lines, "Offered by") or _after(lines, "Developer")
    res["developer_name"] = "" if dev.lower() in _NON_NAME else dev
    for text, href in t.links:
        k = text.lower()
        href = _normalize_href(href)
        if re.search(r"(^|\.)google\.com(/|$)", re.sub(r"^https?://", "", href)):
            continue                                   # the store's own links, not the developer's
        if k in ("website", "developer website") and not res["website"]:
            res["website"] = href
        elif "support" in k and "privacy" not in k and not res["support_url"]:
            res["support_url"] = href
        elif k == "privacy policy" and not res["privacy_policy_url"]:
            res["privacy_policy_url"] = href
    res["privacy_practices"] = parse_privacy(lines, cfg["data_types"])
    pp = res["privacy_practices"]["status"]
    if pp in ("no_section", "unparsed", "no_types_listed"):
        issues.append(f"privacy_practices: {pp}")
    if not res["privacy_policy_url"]:
        issues.append("privacy_policy_url: no 'Privacy policy' link")
    core = [res["name"], res["user_count"], pp not in ("no_section", "unparsed", "no_types_listed")]
    status = "ok" if all(core) else ("failed" if not any(core) else "partial")
    return {**res, "parse_status": status, "parse_issues": issues}


# ---------- fetching and caching ----------

def default_fetcher(cfg: dict[str, Any]) -> Fetcher:
    s = cfg["store"]

    def fetch(url: str) -> tuple[int, str, str]:
        req = urllib.request.Request(url, headers={"User-Agent": s["user_agent"], "Accept-Language": "en-US,en;q=0.9"})
        try:
            with urllib.request.urlopen(req, timeout=s["timeout_s"]) as r:
                return r.status, r.geturl(), r.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, url, e.read().decode("utf-8", errors="replace") if e.fp else ""
    return fetch


def fetch_with_retry(url: str, fetch: Fetcher, cfg: dict[str, Any], sleep=time.sleep) -> tuple[int, str, str]:
    s, wait = cfg["store"], cfg["store"]["backoff_s"]
    for attempt in range(s["retries"] + 1):
        try:
            code, final, html = fetch(url)
        except (urllib.error.URLError, TimeoutError, OSError):
            code, final, html = 0, url, ""
        if code and code < 500 and code != 429:
            return code, final, html
        if attempt < s["retries"]:
            sleep(wait)
            wait *= 2
    return code, final, html


def _cache_paths(st: Settings, cfg: dict[str, Any], ext_id: str) -> tuple[Path, Path]:
    d = st.root / cfg["store"]["cache_dir"]
    return d / f"{ext_id}.html", d / f"{ext_id}.json"


def load_page(rec: Record, st: Settings, cfg: dict[str, Any], fetch: Fetcher | None, refresh: bool,
              sleep=time.sleep, state: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return {'meta': {...}, 'html': str} from cache or a live fetch (if `fetch` is given)."""
    html_p, meta_p = _cache_paths(st, cfg, rec.ext_id)
    if not refresh and html_p.is_file() and meta_p.is_file():
        meta = json.loads(meta_p.read_text(encoding="utf-8"))
        if meta.get("fetch_status") in ("ok", "not_found"):
            return {"meta": {**meta, "from_cache": True}, "html": html_p.read_text(encoding="utf-8")}
    url = cfg["store"]["url_template"].format(ext_id=rec.ext_id)
    if fetch is None:
        return {"meta": {"url": url, "fetch_status": "not_fetched", "http_status": None, "final_url": "",
                         "fetched_at": "", "from_cache": False}, "html": ""}
    state = state if state is not None else {}
    if state.get("last_fetch"):
        sleep(max(0.0, cfg["store"]["delay_s"] + random.uniform(0, cfg["store"]["jitter_s"])
                  - (time.monotonic() - state["last_fetch"])))
    code, final, html = fetch_with_retry(url, fetch, cfg, sleep)
    state["last_fetch"] = time.monotonic()
    status = "ok" if code == 200 else "not_found" if code == 404 else "blocked" if code in (403, 429) else "error"
    state["blocked"] = state.get("blocked", 0) + 1 if status == "blocked" else 0
    meta = {"url": url, "final_url": final, "http_status": code, "fetch_status": status,
            "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "from_cache": False}
    if status in ("ok", "not_found"):
        html_p.parent.mkdir(parents=True, exist_ok=True)
        html_p.write_text(html, encoding="utf-8")
        meta_p.write_text(json.dumps(meta, indent=1) + "\n", encoding="utf-8")
    if state["blocked"] >= cfg["store"]["stop_after_blocked"]:
        raise Blocked(f"{state['blocked']} consecutive 403/429 responses; stopping to avoid hammering the store")
    return {"meta": meta, "html": html}


def scrape_record(rec: Record, st: Settings, cfg: dict[str, Any], fetch: Fetcher | None, refresh: bool = False,
                  sleep=time.sleep, state: dict[str, Any] | None = None) -> Record:
    page = load_page(rec, st, cfg, fetch, refresh, sleep, state)
    meta = page["meta"]
    store: dict[str, Any] = {"version": SCRAPE_VERSION, "url": meta["url"], "final_url": meta.get("final_url", ""),
                             "fetched_at": meta.get("fetched_at", ""), "http_status": meta.get("http_status"),
                             "fetch_status": meta["fetch_status"], "from_cache": meta.get("from_cache", False)}
    if page["html"]:
        store.update(parse_store_page(page["html"], cfg))
        c = store["user_count"]
        if c is not None:
            observed = tier_for(c, cfg["tiers"])
            store["tier_check"] = {"meta_tier": rec.tier, "store_tier": observed, "consistent": observed == rec.tier}
    else:
        store.update({"parse_status": "not_parsed", "parse_issues": [f"fetch_status={meta['fetch_status']}"]})
    rec.store = store
    return rec


def scrape_all(recs: list[Record], st: Settings, cfg: dict[str, Any], fetch: Fetcher | None, refresh: bool = False,
               sleep=time.sleep, progress=None) -> None:
    state: dict[str, Any] = {}
    for r in recs:
        if r.ingest_status != STATUS_OK:
            continue
        try:
            scrape_record(r, st, cfg, fetch, refresh, sleep, state)
        finally:
            if progress and r.store:
                progress(r)
