"""Stage 6 outputs: summary.csv (one row per extension) and endpoints.csv (one row per extension x host)."""
from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from .record import STATUS_OK, Record
from .scoring import COMPONENTS

SUMMARY_COLUMNS = [
    "ext_id", "name", "store", "tier", "user_count", "version",
    "score", "suspicion_rank", "rank_in_tier", "tier_size", "top_reasons",
    *[f"pts_{c}" for c in COMPONENTS],
    "host_access", "broad_host", "broad_cs_document_start", "broad_cs_all_frames", "broad_cs_main_world",
    "permissions", "high_risk_permissions",
    "static_endpoints", "n_endpoints", "tracker_hosts", "llm_providers", "obfuscation_level",
    "data_safety", "privacy_status", "declared_data_types", "privacy_policy_url", "website",
    "ingest_status", "notes",
]
ENDPOINT_COLUMNS = ["ext_id", "name", "tier", "host", "registrable_domain", "party", "category", "label", "basis",
                    "sources", "in_first_party_code", "near_sink", "url_count", "sample_url"]
_LISTED_CATEGORIES = ("tracker", "llm_provider", "unknown", "first_party", "local_network", "dynamic")


def _join(items) -> str:
    return ";".join(str(i) for i in items)


def summary_row(r: Record) -> dict[str, Any]:
    m, s, sc, st = r.manifest or {}, r.scan or {}, r.score or {}, r.store or {}
    flags = m.get("flags", {})
    pp = st.get("privacy_practices") or {}
    ep = r.endpoints or []
    static_eps = [e["host"] for e in ep if e["category"] in _LISTED_CATEGORIES and e["host"] != "(dynamic)"]
    scraped = bool(pp)
    return {
        "ext_id": r.ext_id, "name": r.name, "store": "chrome", "tier": r.tier,
        "user_count": st.get("user_count", ""), "version": r.version,
        "score": sc.get("total", ""), "suspicion_rank": sc.get("rank_overall", ""),
        "rank_in_tier": sc.get("rank_in_tier", ""), "tier_size": sc.get("tier_size", ""),
        "top_reasons": " | ".join(sc.get("top_reasons", [])),
        **{f"pts_{c}": sc.get("components", {}).get(c, {}).get("points", "") for c in COMPONENTS},
        "host_access": flags.get("host_scope", ""), "broad_host": flags.get("broad_host", ""),
        "broad_cs_document_start": flags.get("broad_cs_document_start", ""),
        "broad_cs_all_frames": flags.get("broad_cs_all_frames", ""),
        "broad_cs_main_world": flags.get("broad_cs_main_world", ""),
        "permissions": _join(m.get("permissions", [])),
        "high_risk_permissions": _join(flags.get("high_risk_permissions", [])),
        "static_endpoints": _join(static_eps[:15]), "n_endpoints": len(ep),
        "tracker_hosts": _join(e["host"] for e in ep if e["category"] == "tracker"),
        "llm_providers": _join(sorted({e["label"] for e in ep if e["category"] == "llm_provider"})),
        "obfuscation_level": s.get("obfuscation", {}).get("level", ""),
        "data_safety": _join(pp.get("data_types_collected", [])) if scraped else "not_scraped",
        "privacy_status": pp.get("status", "not_scraped") if scraped else "not_scraped",
        "declared_data_types": _join(pp.get("data_types_collected", [])),
        "privacy_policy_url": st.get("privacy_policy_url", ""), "website": st.get("website", ""),
        "ingest_status": r.ingest_status, "notes": " | ".join(sc.get("notes", [])),
    }


def write_summary(recs: list[Record], out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    rows = [summary_row(r) for r in recs]
    rows.sort(key=lambda x: (x["suspicion_rank"] == "", x["suspicion_rank"] or 0, x["name"].lower()))
    p = out_dir / "summary.csv"
    with p.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=SUMMARY_COLUMNS)
        w.writeheader()
        w.writerows(rows)
    return p


def write_endpoints(recs: list[Record], out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    p = out_dir / "endpoints.csv"
    with p.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=ENDPOINT_COLUMNS)
        w.writeheader()
        for r in recs:
            if r.ingest_status != STATUS_OK:
                continue
            for e in r.endpoints:
                w.writerow({"ext_id": r.ext_id, "name": r.name, "tier": r.tier, "host": e["host"],
                            "registrable_domain": e["registrable_domain"], "party": e["party"],
                            "category": e["category"], "label": e["label"], "basis": e["basis"],
                            "sources": _join(e["sources"]), "in_first_party_code": e["in_first_party_code"],
                            "near_sink": e["near_sink"], "url_count": e["url_count"], "sample_url": e["sample_url"]})
    return p
