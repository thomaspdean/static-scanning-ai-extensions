import pytest

from extscan.analyze_manifest import analyze_manifest, is_broad, load_permission_tiers, parse_host

TIERS = load_permission_tiers()


@pytest.mark.parametrize("pat,broad", [
    ("<all_urls>", True), ("*://*/*", True), ("https://*/*", True), ("http://*/*", True),
    ("https://*.example.com/*", False), ("https://example.com/*", False),
    ("file:///*", False), ("chrome://favicon/*", False), ("garbage", False),
])
def test_is_broad(pat, broad):
    assert is_broad(pat) is broad


def test_parse_host():
    assert parse_host("https://*.a.com/x") == ("https", "*.a.com")
    assert parse_host("nope") is None


def test_broad_and_content_script_flags():
    r = analyze_manifest({
        "manifest_version": 3,
        "permissions": ["storage", "scripting", "cookies", "tabs", "weirdperm"],
        "optional_permissions": ["history"],
        "host_permissions": ["<all_urls>"],
        "content_scripts": [
            {"matches": ["<all_urls>"], "js": ["a.js"], "run_at": "document_start", "all_frames": True, "world": "MAIN"},
            {"matches": ["https://a.com/*"], "js": ["b.js"]},
        ],
    }, TIERS)
    f = r["flags"]
    assert f["broad_host"] and f["broad_content_script"] and f["host_scope"] == "all"
    assert f["cs_document_start"] and f["cs_all_frames"] and f["cs_main_world"]
    assert f["broad_cs_document_start"] and f["broad_cs_all_frames"] and f["broad_cs_main_world"]
    assert f["high_risk_permissions"] == ["cookies"] and f["high_risk_optional_permissions"] == ["history"]
    assert f["can_inject_anywhere"] and f["can_read_tab_urls"]
    assert r["unclassified_permissions"] == ["weirdperm"] or "weirdperm" in r["unclassified_permissions"]
    # defaults applied: second script is idle / isolated / not all_frames
    assert r["content_scripts"][1]["run_at"] == "document_idle"
    assert r["content_scripts"][1]["world"] == "ISOLATED" and not r["content_scripts"][1]["all_frames"]


def test_flags_not_attributed_to_narrow_scripts():
    r = analyze_manifest({"manifest_version": 3, "host_permissions": ["https://a.com/*"],
        "content_scripts": [{"matches": ["https://a.com/*"], "run_at": "document_start", "all_frames": True, "world": "MAIN"}]}, TIERS)
    f = r["flags"]
    assert f["cs_document_start"] and not f["broad_cs_document_start"]
    assert f["host_scope"] == "narrow" and not f["broad_host"] and not f["can_inject_anywhere"]


def test_scope_wide_and_none():
    hosts = [f"https://h{i}.com/*" for i in range(11)]
    assert analyze_manifest({"manifest_version": 3, "host_permissions": hosts}, TIERS)["flags"]["host_scope"] == "wide"
    assert analyze_manifest({"manifest_version": 3}, TIERS)["flags"]["host_scope"] == "none"


def test_mv2_hosts_in_permissions_and_war_strings():
    r = analyze_manifest({"manifest_version": 2, "permissions": ["tabs", "*://*/*", "storage"],
                          "web_accessible_resources": ["x.png"],
                          "content_security_policy": "script-src 'self' 'unsafe-eval' https://cdn.x.com; object-src 'self'"}, TIERS)
    f = r["flags"]
    assert r["permissions"] == ["tabs", "storage"] and r["host_permissions"] == ["*://*/*"]
    assert f["mv2"] and f["broad_host"] and f["war_exposed_to_all_sites"]
    assert f["csp_unsafe_eval"] and f["csp_remote_script"]


def test_externally_connectable_update_url_and_defensive_types():
    r = analyze_manifest({"manifest_version": 3, "update_url": "https://evil.example/u",
        "externally_connectable": {"matches": ["*://*/*"]}, "permissions": "notalist",
        "content_scripts": ["junk", {"matches": None}], "background": "x", "commands": []}, TIERS)
    f = r["flags"]
    assert f["externally_connectable_web"] and f["externally_connectable_broad"] and f["non_store_update_url"]
    assert r["permissions"] == [] and len(r["content_scripts"]) == 1
