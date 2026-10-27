"""Stage 6: suspicion score with component breakdown, reasons and ranks.

Inputs are the manifest flags, scan signals and classified endpoints already in the record. Chrome
Web Store data is deliberately not used.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .config import PROJECT_ROOT
from .record import STATUS_OK, Record

SCORE_VERSION = 1
TOP_REASONS = 4
COMPONENTS = ("permissions", "injection_reach", "page_harvesting", "exfil_path", "third_party", "code_risk")

# Human wording for reasons.
HARVEST_TEXT = {
    "page_text": "reads page text (innerText/textContent)", "page_html": "reads page HTML (innerHTML/outerHTML)",
    "form_inputs": "queries form inputs", "password_field": "touches password fields",
    "hidden_input": "touches hidden inputs", "selection": "reads the text selection",
    "iframe_access": "reaches into iframes", "shadow_root_access": "reads shadow roots",
    "document_cookie": "reads document.cookie", "screenshot": "captures screenshots",
    "clipboard_read": "reads the clipboard", "content_extractor": "runs a content extractor (Readability/Turndown)",
    "page_url_title": "reads page URL/title", "cookies_api": "uses chrome.cookies", "history_api": "uses chrome.history",
}
CREDENTIAL_SIGNALS = ("key_openai", "key_google", "key_aws", "key_github", "key_slack", "hardcoded_secret_assign",
                      "bearer_literal")


def load_scoring_config(path: Path | None = None) -> dict[str, Any]:
    path = path or PROJECT_ROOT / "config" / "scoring.yaml"
    return yaml.safe_load(path.read_text(encoding="utf-8"))["components"]


def _fp_signals(rec: Record) -> dict[str, int]:
    """Signal name -> first-party hit count."""
    out: dict[str, int] = {}
    for group in (rec.scan or {}).get("signals", {}).values():
        for name, a in group.items():
            out[name] = a["first_party"]
    return out


def _result(weight: float, parts: list[tuple[float, str]], cap: float = 1.0) -> dict[str, Any]:
    """parts: (share of the component, reason). Share is capped at `cap` overall."""
    raw = sum(p for p, _ in parts)
    sub = min(cap, raw)
    scale = sub / raw if raw else 0.0
    return {"weight": weight, "sub": round(sub, 3), "points": round(weight * sub, 2),
            "details": [{"points": round(weight * p * scale, 2), "reason": r} for p, r in parts if p > 0]}


def _permissions(rec: Record, c: dict[str, Any]) -> dict[str, Any]:
    f = rec.manifest["flags"]
    cap = c["high_risk_cap"]
    parts = []
    if f["high_risk_permissions"]:
        parts.append((min(len(f["high_risk_permissions"]), cap) / cap,
                      "high-risk permissions: " + ", ".join(f["high_risk_permissions"])))
    if f["high_risk_optional_permissions"]:
        parts.append((c["optional_factor"] * min(len(f["high_risk_optional_permissions"]), cap) / cap,
                      "optional high-risk permissions: " + ", ".join(f["high_risk_optional_permissions"])))
    return _result(c["weight"], parts)


def _injection(rec: Record, c: dict[str, Any]) -> dict[str, Any]:
    f = rec.manifest["flags"]
    if not f["broad_content_script"]:
        return _result(c["weight"], [])
    parts = [(c["broad_content_script"], "content script runs on every site")]
    for flag, key, text in (("broad_cs_document_start", "document_start", "before the page loads (document_start)"),
                            ("broad_cs_all_frames", "all_frames", "inside all frames"),
                            ("broad_cs_main_world", "main_world", "in the page's own JS world (MAIN)")):
        if f[flag]:
            parts.append((c[key], "content script on every site " + text))
    return _result(c["weight"], parts)


def _harvesting(rec: Record, c: dict[str, Any], fp: dict[str, int]) -> dict[str, Any]:
    parts = [(w, HARVEST_TEXT[n]) for n, w in c["signals"].items() if fp.get(n, 0) > 0]
    return _result(c["weight"], parts)


def _exfil(rec: Record, c: dict[str, Any], fp: dict[str, int]) -> dict[str, Any]:
    has_sink = any(fp.get(n, 0) > 0 for n in c["sink_signals"])
    has_beacon = any(fp.get(n, 0) > 0 for n in c["beacon_signals"])
    harvest = [n for n in c["harvest_signals"] if fp.get(n, 0) > 0]
    llm = sorted({e["label"] for e in rec.endpoints if e["category"] == "llm_provider"
                  and (e["in_first_party_code"] or "manifest" in e["sources"])})
    parts = []
    if has_sink:
        parts.append((c["sink"], "network calls in first-party code"))
    if has_beacon:
        parts.append((c["beacon"], "beacon-style sends (sendBeacon / pixel / EventSource)"))
    if has_sink and harvest:
        parts.append((c["harvest_and_sink"], "reads page content AND makes network calls (" + ", ".join(harvest) + ")"))
    if llm:
        parts.append((c["llm_endpoint"], "talks to LLM provider: " + ", ".join(llm)))
    return _result(c["weight"], parts)


def _third_party(rec: Record, c: dict[str, Any]) -> dict[str, Any]:
    trackers = sorted({e["label"] for e in rec.endpoints if e["category"] == "tracker"})
    unknown = sorted({e["host"] for e in rec.endpoints
                      if e["category"] == "unknown" and e["near_sink"] and e["in_first_party_code"]})
    parts = []
    if trackers:
        parts.append((c["tracker"] * min(len(trackers), c["tracker_cap"]) / c["tracker_cap"],
                      "tracker endpoints: " + ", ".join(trackers[:4])))
    if unknown:
        parts.append((c["unknown_near_sink"] * min(len(unknown), c["unknown_cap"]) / c["unknown_cap"],
                      "unlabeled third-party hosts next to network calls: " + ", ".join(unknown[:3])))
    return _result(c["weight"], parts)


def _code_risk(rec: Record, c: dict[str, Any], fp: dict[str, int]) -> dict[str, Any]:
    f = rec.manifest["flags"]
    obf = (rec.scan or {}).get("obfuscation", {}).get("level", "none")
    cred = [n for n in CREDENTIAL_SIGNALS if fp.get(n, 0) > 0]
    checks = [
        (c["eval_or_new_function"], fp.get("eval", 0) > 0 or fp.get("new_function", 0) > 0, "uses eval / new Function"),
        (c["string_timer"], fp.get("string_timer", 0) > 0, "string-argument timers"),
        (c["remote_code_load"], fp.get("script_src_remote", 0) > 0 or fp.get("import_scripts_remote", 0) > 0
         or f["csp_remote_script"], "loads remote code"),
        (c["execute_script"], fp.get("execute_script", 0) > 0, "injects scripts (executeScript/userScripts)"),
        (c["main_world_injection"], fp.get("main_world_injection", 0) > 0, "injects into the MAIN world"),
        (c["obfuscated"], obf == "suspected_obfuscated", "suspected obfuscation (static scan may miss behavior)"),
        (c["minified"], obf == "minified", "minified code"),
        (c["hardcoded_credential"], bool(cred), "hard-coded credential shapes: " + ", ".join(cred)),
        (c["non_store_update_url"], f["non_store_update_url"], "update_url is not the Web Store"),
    ]
    return _result(c["weight"], [(w, t) for w, ok, t in checks if ok])


def _notes(rec: Record) -> list[str]:
    notes, cov = [], (rec.scan or {}).get("coverage", {})
    if cov.get("files_too_large_to_beautify"):
        notes.append(f"{cov['files_too_large_to_beautify']} large file(s) scanned without beautifying")
    if cov.get("bytes_skipped"):
        notes.append(f"{cov['bytes_skipped']} bytes of code not scanned (too large)")
    if cov.get("beautify_timeouts"):
        notes.append(f"{cov['beautify_timeouts']} beautify timeout(s)")
    if (rec.scan or {}).get("obfuscation", {}).get("level") == "suspected_obfuscated":
        notes.append("suspected obfuscation: static results may under-report")
    if not rec.endpoints:
        notes.append("endpoints not classified (run `extscan classify`)")
    return notes


def score_record(rec: Record, cfg: dict[str, Any]) -> dict[str, Any] | None:
    """Return the score dict, or None when the record lacks manifest or scan data."""
    if rec.ingest_status != STATUS_OK or not rec.manifest or not rec.scan:
        return None
    fp = _fp_signals(rec)
    comps = {
        "permissions": _permissions(rec, cfg["permissions"]),
        "injection_reach": _injection(rec, cfg["injection_reach"]),
        "page_harvesting": _harvesting(rec, cfg["page_harvesting"], fp),
        "exfil_path": _exfil(rec, cfg["exfil_path"], fp),
        "third_party": _third_party(rec, cfg["third_party"]),
        "code_risk": _code_risk(rec, cfg["code_risk"], fp),
    }
    reasons = sorted(((d["points"], comp, d["reason"]) for comp, v in comps.items() for d in v["details"]),
                     key=lambda x: -x[0])
    return {"version": SCORE_VERSION, "total": round(sum(v["points"] for v in comps.values()), 1),
            "components": comps,
            "top_reasons": [f"{r} ({p:+.1f})" for p, _, r in reasons[:TOP_REASONS]],
            "notes": _notes(rec)}


def _rank(items: list[tuple[str, float, str]]) -> dict[str, int]:
    """Competition ranking (1,2,2,4) by score desc; ties ordered by name for stable output."""
    out, prev, pos = {}, None, 0
    for i, (key, total, _name) in enumerate(sorted(items, key=lambda x: (-x[1], x[2].lower())), 1):
        if total != prev:
            pos, prev = i, total
        out[key] = pos
    return out


def score_all(recs: list[Record], cfg: dict[str, Any]) -> int:
    """Score every eligible record in place and assign overall and per-tier ranks. Returns the count scored."""
    scored = []
    for r in recs:
        r.score = score_record(r, cfg) or {}
        if r.score:
            scored.append(r)
    overall = _rank([(r.ext_id, r.score["total"], r.name) for r in scored])
    tiers: dict[str, list[Record]] = {}
    for r in scored:
        tiers.setdefault(r.tier, []).append(r)
    for tier, members in tiers.items():
        in_tier = _rank([(r.ext_id, r.score["total"], r.name) for r in members])
        for r in members:
            r.score.update(rank_overall=overall[r.ext_id], rank_in_tier=in_tier[r.ext_id], tier_size=len(members),
                           scored_total=len(scored))
    return len(scored)
