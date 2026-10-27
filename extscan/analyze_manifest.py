"""Stage 2: manifest fields and derived flags, written into Record.manifest."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml

from .config import PROJECT_ROOT, Settings
from .record import STATUS_OK, Record

_URL_PATTERN = re.compile(r"^(\*|https?|ftp|file|wss?|chrome-extension|\*?)://|^<all_urls>$")
_CS_WORLDS = ("MAIN", "ISOLATED")


def load_permission_tiers(path: Path | None = None) -> dict[str, Any]:
    path = path or PROJECT_ROOT / "config" / "permissions.yaml"
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    return {"high": set(raw["high"]), "medium": set(raw["medium"]), "low": set(raw.get("low", [])),
            "wide_threshold": int(raw.get("wide_host_threshold", 10))}


def _strs(v: Any) -> list[str]:
    return [x for x in v if isinstance(x, str)] if isinstance(v, list) else []


def _dicts(v: Any) -> list[dict]:
    return [x for x in v if isinstance(x, dict)] if isinstance(v, list) else []


def parse_host(pattern: str) -> tuple[str, str] | None:
    """Return (scheme, host) for a match pattern; ('*','*') for <all_urls>; None if not a URL pattern."""
    if pattern == "<all_urls>":
        return "*", "*"
    m = re.match(r"^([A-Za-z*][A-Za-z0-9+.*-]*)://([^/]*)", pattern)
    if not m:
        return None
    return m.group(1).lower(), m.group(2).lower()


def is_broad(pattern: str) -> bool:
    """True when the pattern matches (web) hosts at large: <all_urls> or a '*' host on http(s)/*."""
    p = parse_host(pattern)
    return bool(p) and p[1] == "*" and p[0] in ("*", "http", "https")


def _hosts(patterns: list[str]) -> list[str]:
    out = []
    for pat in patterns:
        p = parse_host(pat)
        if p and p[1] != "*" and p[0] != "file":
            h = p[1].lstrip("*.").split(":")[0]
            if h:
                out.append(h)
    return sorted(set(out))


def _csp_flags(csp: str) -> dict[str, Any]:
    scripts = re.search(r"script-src([^;]*)", csp)
    s = scripts.group(1) if scripts else ""
    return {"unsafe_eval": "'unsafe-eval'" in csp, "unsafe_inline": "'unsafe-inline'" in csp,
            "wasm_unsafe_eval": "'wasm-unsafe-eval'" in csp,
            "remote_script_src": sorted(set(re.findall(r"https?://[^\s;']+", s)))}


def analyze_manifest(mf: dict[str, Any], tiers: dict[str, Any]) -> dict[str, Any]:
    mv = mf.get("manifest_version")
    perms_all = _strs(mf.get("permissions"))
    # MV2 mixes host patterns into `permissions`; split them out.
    host_in_perms = [p for p in perms_all if _URL_PATTERN.match(p)]
    perms = [p for p in perms_all if p not in host_in_perms]
    opt_all = _strs(mf.get("optional_permissions"))
    opt_hosts_mv2 = [p for p in opt_all if _URL_PATTERN.match(p)]
    opt_perms = [p for p in opt_all if p not in opt_hosts_mv2]
    host_perms = _strs(mf.get("host_permissions")) + host_in_perms
    opt_host_perms = _strs(mf.get("optional_host_permissions")) + opt_hosts_mv2

    css = _dicts(mf.get("content_scripts"))
    cs_matches = sorted({m for c in css for m in _strs(c.get("matches"))})
    cs_excludes = sorted({m for c in css for m in _strs(c.get("exclude_matches"))})
    cs_out = []
    for c in css:
        ms = _strs(c.get("matches"))
        cs_out.append({
            "matches": ms, "exclude_matches": _strs(c.get("exclude_matches")),
            "run_at": c.get("run_at") or "document_idle",   # Chrome default
            "all_frames": bool(c.get("all_frames", False)),
            "match_about_blank": bool(c.get("match_about_blank", False)),
            "world": c.get("world") or "ISOLATED",
            "js": _strs(c.get("js")), "css": _strs(c.get("css")),
            "broad": any(is_broad(m) for m in ms),
        })
    broad_cs = [c for c in cs_out if c["broad"]]

    high = sorted(p for p in perms if p in tiers["high"])
    med = sorted(p for p in perms if p in tiers["medium"])
    high_opt = sorted(p for p in opt_perms if p in tiers["high"])
    unknown = sorted(p for p in perms if p not in tiers["high"] | tiers["medium"] | tiers["low"])

    broad_host = any(is_broad(p) for p in host_perms)
    distinct = _hosts(host_perms + cs_matches)
    if broad_host or broad_cs:
        scope = "all"
    elif len(distinct) > tiers["wide_threshold"]:
        scope = "wide"
    elif distinct:
        scope = "narrow"
    else:
        scope = "none"

    ec = mf.get("externally_connectable") if isinstance(mf.get("externally_connectable"), dict) else {}
    ec_matches = _strs(ec.get("matches"))
    ec_ids = _strs(ec.get("ids"))

    war_raw = mf.get("web_accessible_resources")
    war = []
    for w in (war_raw if isinstance(war_raw, list) else []):
        if isinstance(w, dict):
            war.append({"resources": _strs(w.get("resources")), "matches": _strs(w.get("matches")),
                        "extension_ids": _strs(w.get("extension_ids")),
                        "use_dynamic_url": bool(w.get("use_dynamic_url", False))})
        elif isinstance(w, str):   # MV2 form
            war.append({"resources": [w], "matches": ["<all_urls>"], "extension_ids": [], "use_dynamic_url": False})

    csp = mf.get("content_security_policy")
    csp_pages = csp.get("extension_pages", "") if isinstance(csp, dict) else (csp if isinstance(csp, str) else "")
    csp_sandbox = csp.get("sandbox", "") if isinstance(csp, dict) else ""

    bg = mf.get("background") if isinstance(mf.get("background"), dict) else {}
    action = mf.get("action") or mf.get("browser_action") or mf.get("page_action")
    action = action if isinstance(action, dict) else {}
    oauth = mf.get("oauth2") if isinstance(mf.get("oauth2"), dict) else {}
    dnr = mf.get("declarative_net_request") if isinstance(mf.get("declarative_net_request"), dict) else {}
    options_ui = mf.get("options_ui") if isinstance(mf.get("options_ui"), dict) else {}
    update_url = mf.get("update_url") or ""
    flags = {
        "broad_host": broad_host,
        "broad_content_script": bool(broad_cs),
        "host_scope": scope,
        "optional_broad_host": any(is_broad(p) for p in opt_host_perms),
        "file_url_access": any((parse_host(p) or ("", ""))[0] == "file" for p in host_perms + cs_matches),
        "cs_document_start": any(c["run_at"] == "document_start" for c in cs_out),
        "cs_all_frames": any(c["all_frames"] for c in cs_out),
        "cs_main_world": any(c["world"] == "MAIN" for c in cs_out),
        "cs_match_about_blank": any(c["match_about_blank"] for c in cs_out),
        # same, restricted to content scripts that run on any site
        "broad_cs_document_start": any(c["run_at"] == "document_start" for c in broad_cs),
        "broad_cs_all_frames": any(c["all_frames"] for c in broad_cs),
        "broad_cs_main_world": any(c["world"] == "MAIN" for c in broad_cs),
        "high_risk_permissions": high,
        "high_risk_optional_permissions": high_opt,
        "medium_risk_permissions": med,
        "has_high_risk_permission": bool(high),
        "can_inject_anywhere": "scripting" in perms and (broad_host or any(is_broad(p) for p in opt_host_perms)),
        "can_read_tab_urls": "tabs" in perms or broad_host,
        "externally_connectable_web": bool(ec_matches),
        "externally_connectable_broad": any(is_broad(m) for m in ec_matches) or "*" in ec_ids,
        "war_exposed_to_all_sites": any(is_broad(m) for w in war for m in w["matches"]),
        "csp_unsafe_eval": _csp_flags(csp_pages)["unsafe_eval"],
        "csp_remote_script": bool(_csp_flags(csp_pages)["remote_script_src"]),
        "mv2": mv == 2,
        "non_store_update_url": bool(update_url) and not re.match(
            r"^https://(clients2\.google\.com|edge\.microsoft\.com)/", update_url),
        "overrides_new_tab": isinstance(mf.get("chrome_url_overrides"), dict) and "newtab" in mf["chrome_url_overrides"],
        "uses_oauth": bool(oauth),
    }
    return {
        "manifest_version": mv,
        "permissions": perms, "optional_permissions": opt_perms, "unclassified_permissions": unknown,
        "host_permissions": host_perms, "optional_host_permissions": opt_host_perms,
        "distinct_hosts": distinct,
        "content_scripts": cs_out,
        "content_script_matches": cs_matches, "content_script_exclude_matches": cs_excludes,
        "background": {"service_worker": bg.get("service_worker"), "scripts": _strs(bg.get("scripts")),
                       "page": bg.get("page"), "type": bg.get("type"), "persistent": bg.get("persistent")},
        "action_popup": action.get("default_popup"),
        "side_panel": (mf.get("side_panel") or {}).get("default_path") if isinstance(mf.get("side_panel"), dict) else None,
        "options_page": mf.get("options_page") or options_ui.get("page"),
        "devtools_page": mf.get("devtools_page"),
        "commands": sorted(mf["commands"]) if isinstance(mf.get("commands"), dict) else [],
        "externally_connectable": {"matches": ec_matches, "ids": ec_ids,
                                   "accepts_tls_channel_id": bool(ec.get("accepts_tls_channel_id", False))},
        "web_accessible_resources": war,
        "csp_extension_pages": csp_pages, "csp_sandbox": csp_sandbox, "csp_flags": _csp_flags(csp_pages),
        "oauth2_scopes": _strs(oauth.get("scopes")),
        "declarative_net_request_rulesets": [r.get("path") for r in _dicts(dnr.get("rule_resources"))],
        "update_url": update_url, "homepage_url": mf.get("homepage_url") or "",
        "author": mf.get("author") if isinstance(mf.get("author"), str) else "",
        "minimum_chrome_version": mf.get("minimum_chrome_version") or "",
        "has_key": "key" in mf, "incognito": mf.get("incognito") or "",
        "flags": flags,
    }


def analyze_record(rec: Record, st: Settings, tiers: dict[str, Any]) -> Record:
    if rec.ingest_status != STATUS_OK:
        return rec
    path = st.root / rec.unpacked_path / "manifest.json"
    mf = json.loads(path.read_text(encoding="utf-8-sig"))
    rec.manifest = analyze_manifest(mf, tiers)
    return rec
