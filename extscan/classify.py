"""Stage 4: label endpoint hosts by party and category, and build the shared-endpoint table.

Party follows the study schema: `1p` (the extension's own infrastructure), `3p`, or `n/a` for
hosts that cannot be resolved (templated) or are local. Category says what kind of host it is.
Precedence: tracker > llm_provider > first_party > cdn_static > known_service > unknown.
"""
from __future__ import annotations

import csv
import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import tldextract
import yaml

from .config import PROJECT_ROOT
from .record import STATUS_OK, Record

CLASSIFY_VERSION = 1
_TLD = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)
_SKIP_NAME_LABELS = 4        # a domain label must be at least this long to be matched by name
_DYNAMIC = "(dynamic)"
_MIN_TOKEN = 5               # leading name word must be at least this long to match inside a domain label
_GENERIC_TOKENS = {"smart", "simple", "floating", "copilot", "assistant", "chatgpt", "gemini", "claude", "openai",
                   "google", "write", "writing", "grammar", "translate", "summarize", "sidebar", "browser"}


@dataclass(frozen=True)
class Lists:
    trackers: list[tuple[str, str, str]]       # (domain, name, kind)
    llm: list[tuple[str, str]]                 # (domain, name)
    cdn: list[str]
    known: list[str]


def load_lists(config_dir: Path | None = None) -> Lists:
    d = config_dir or PROJECT_ROOT / "config"

    def y(name):
        return yaml.safe_load((d / name).read_text(encoding="utf-8"))

    trackers = [(dom.lower(), t["name"], t["kind"]) for t in y("trackers.yaml")["trackers"] for dom in t["domains"]]
    llm = [(dom.lower(), p["name"]) for p in y("llm_providers.yaml")["providers"] for dom in p["domains"]]
    kh = y("known_hosts.yaml")
    return Lists(trackers, llm, [x.lower() for x in kh["cdn_static"]], [x.lower() for x in kh["known_service"]])


def host_matches(host: str, entry: str) -> bool:
    return host == entry or host.endswith("." + entry)


def registrable(host: str) -> str:
    return _TLD(host).top_domain_under_public_suffix or host


def _is_ip(host: str) -> ipaddress._BaseAddress | None:
    try:
        return ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return None


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


def own_domains(rec: Record) -> dict[str, str]:
    """Registrable domains that belong to the extension, with the evidence for each.

    Basis `homepage` / `store_website` / `externally_connectable` comes from the extension's own
    declarations. Name-matching is applied per host in `classify_host`.
    """
    out: dict[str, str] = {}

    def add(host: str, basis: str) -> None:
        host = host.lower().lstrip("*.").split(":")[0]
        if host and "." in host and not _is_ip(host):
            out.setdefault(registrable(host), basis)

    for key, basis in (("homepage_url", "homepage"),):
        url = (rec.manifest or {}).get(key) or ""
        if url:
            add(urlsplit(url).netloc, basis)
    site = (rec.store or {}).get("website") or ""
    if site:
        add(urlsplit(site).netloc, "store_website")
    for pat in ((rec.manifest or {}).get("externally_connectable") or {}).get("matches", []):
        m = re.match(r"^[\w*]+://([^/]*)", pat)
        if m and m.group(1) != "*":
            add(m.group(1), "externally_connectable")
    return out


def classify_host(host: str, rec: Record, lists: Lists, own: dict[str, str]) -> dict[str, Any]:
    """Return {party, category, label, basis, registrable_domain} for one host."""
    if host == _DYNAMIC:
        return {"party": "n/a", "category": "dynamic", "label": "", "basis": "templated host", "registrable_domain": ""}
    ip = _is_ip(host)
    if ip is not None:
        local = ip.is_private or ip.is_loopback or ip.is_link_local
        return {"party": "n/a" if local else "3p", "category": "local_network" if local else "unknown", "label": "",
                "basis": "private IP" if local else "public IP literal", "registrable_domain": host}
    reg = registrable(host)
    base = {"registrable_domain": reg}
    for dom, name, kind in lists.trackers:
        if host_matches(host, dom):
            return {**base, "party": "3p", "category": "tracker", "label": f"{name} ({kind})", "basis": dom}
    for dom, name in lists.llm:
        if host_matches(host, dom):
            return {**base, "party": "3p", "category": "llm_provider", "label": name, "basis": dom}
    if reg in own:
        return {**base, "party": "1p", "category": "first_party", "label": "", "basis": own[reg]}
    known = any(host_matches(host, d) for d in lists.cdn + lists.known)
    label = _norm(_TLD(host).domain)
    if not known and len(label) >= _SKIP_NAME_LABELS:
        slug = rec.folder.split("__")[1] if "__" in rec.folder else ""
        names = [n for n in (_norm(rec.name), _norm(slug)) if n]
        first_words = {_norm(re.split(r"[^A-Za-z0-9]+", w)[0]) for w in (rec.name, slug.replace("-", " ")) if w}
        tokens = {t for t in first_words if len(t) >= _MIN_TOKEN and t not in _GENERIC_TOKENS}
        if any(label in n for n in names) or any(t in label for t in tokens):
            return {**base, "party": "1p", "category": "first_party", "label": "", "basis": "name_match"}
    for dom in lists.cdn:
        if host_matches(host, dom):
            return {**base, "party": "3p", "category": "cdn_static", "label": "", "basis": dom}
    for dom in lists.known:
        if host_matches(host, dom):
            return {**base, "party": "3p", "category": "known_service", "label": "", "basis": dom}
    return {**base, "party": "3p", "category": "unknown", "label": "", "basis": ""}


def classify_record(rec: Record, lists: Lists) -> Record:
    """Fill rec.endpoints from scan endpoints plus manifest-declared hosts."""
    hosts: dict[str, dict[str, Any]] = {}
    for e in (rec.scan or {}).get("endpoints", []):
        hosts[e["host"]] = {"host": e["host"], "sources": ["code"], "in_first_party_code": e["first_party"],
                            "near_sink": e["near_sink"], "url_count": e["url_count"],
                            "sample_url": (e["urls"] or [""])[0], "schemes": e["schemes"]}
    for h in (rec.manifest or {}).get("distinct_hosts", []):
        if h in hosts:
            hosts[h]["sources"].append("manifest")
        else:
            hosts[h] = {"host": h, "sources": ["manifest"], "in_first_party_code": False, "near_sink": False,
                        "url_count": 0, "sample_url": "", "schemes": []}
    own = own_domains(rec)
    out = []
    for h, e in hosts.items():
        out.append({**e, **classify_host(h, rec, lists, own)})
    order = {"tracker": 0, "llm_provider": 1, "unknown": 2, "first_party": 3, "dynamic": 4, "local_network": 5,
             "known_service": 6, "cdn_static": 7}
    out.sort(key=lambda x: (order.get(x["category"], 9), not x["in_first_party_code"], -x["url_count"], x["host"]))
    rec.endpoints = out
    return rec


def build_shared(recs: list[Record], min_extensions: int = 2) -> list[dict[str, Any]]:
    """Third-party hosts that at least `min_extensions` extensions reference."""
    by_host: dict[str, dict[str, Any]] = {}
    for r in recs:
        if r.ingest_status != STATUS_OK:
            continue
        for e in r.endpoints:
            if e["party"] != "3p":
                continue
            d = by_host.setdefault(e["host"], {"host": e["host"], "registrable_domain": e["registrable_domain"],
                                               "category": e["category"], "label": e["label"], "exts": {}})
            x = d["exts"].setdefault(r.ext_id, {"name": r.name, "tier": r.tier, "code": False, "sink": False})
            x["code"] |= "code" in e["sources"] and e["in_first_party_code"]
            x["sink"] |= e["near_sink"]
    rows = []
    for d in by_host.values():
        ex = d["exts"]
        if len(ex) < min_extensions:
            continue
        rows.append({"host": d["host"], "registrable_domain": d["registrable_domain"], "category": d["category"],
                     "label": d["label"], "n_extensions": len(ex),
                     "n_in_first_party_code": sum(x["code"] for x in ex.values()),
                     "n_near_network_call": sum(x["sink"] for x in ex.values()),
                     "tiers": ";".join(sorted({x["tier"] for x in ex.values()})),
                     "extensions": "; ".join(sorted(x["name"] for x in ex.values()))})
    rows.sort(key=lambda r: (-r["n_extensions"], r["host"]))
    return rows


SHARED_COLUMNS = ["host", "registrable_domain", "category", "label", "n_extensions", "n_in_first_party_code",
                  "n_near_network_call", "tiers", "extensions"]


def write_shared_csv(rows: list[dict[str, Any]], out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    p = out_dir / "shared_endpoints.csv"
    with p.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=SHARED_COLUMNS)
        w.writeheader()
        w.writerows(rows)
    return p
