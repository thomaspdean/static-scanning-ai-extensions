import time

from extscan.js_scan import is_placeholder_secret, load_scan_config, scan_extension, scan_text, vendor_reason

CFG = load_scan_config()


def sig(text, group, name, is_code=True):
    r = scan_text(text, "a.js", is_code, False, CFG)
    return r["signals"].get((group, name), {"count": 0})["count"]


def test_network_sinks():
    t = "fetch('https://a.io/x'); navigator.sendBeacon(u,d); new WebSocket('wss://b.io'); var x=new XMLHttpRequest();"
    for n in ("fetch", "send_beacon", "websocket", "xhr"):
        assert sig(t, "network_sinks", n) == 1
    assert sig("prefetch(1)", "network_sinks", "fetch") == 0


def test_dom_harvest_contexts():
    t = ("var a=document.body.innerText;var b=document.documentElement.outerHTML;"
         "document.querySelectorAll('input[type=password]');el.shadowRoot;f.contentDocument;window.getSelection()")
    assert sig(t, "dom_harvest", "page_text") == 1
    assert sig(t, "dom_harvest", "page_html") == 1
    assert sig(t, "dom_harvest", "password_field") == 1
    assert sig(t, "dom_harvest", "shadow_root_access") == 1
    assert sig(t, "dom_harvest", "iframe_access") == 1
    assert sig(t, "dom_harvest", "selection") == 1


def test_eval_false_positives_excluded():
    assert sig("eval(code)", "remote_code", "eval") == 1
    assert sig("x.eval(code)", "remote_code", "eval") == 0
    assert sig("/(?:eval(?:cmd)?|exec)/", "remote_code", "eval") == 0
    assert sig("Function('return this')()", "remote_code", "new_function") == 0
    assert sig("new Function('a','return a')", "remote_code", "new_function") == 1


def test_sensitive_field_names_ignore_marketing_copy():
    assert sig("No credit card required!", "sensitive", "sensitive_field_names") == 0
    assert sig("input.name='credit_card'; autocomplete='cc-number'", "sensitive", "sensitive_field_names") == 2
    assert sig("var sSn=1; new i0r(cvc); Geen creditcard vereist", "sensitive", "sensitive_field_names") == 1  # only cvc


def test_secrets_redacted():
    key = "AIza" + "A" * 35
    r = scan_text(f"var k='{key}'; const API_KEY = 'abcdefghijklmnopqrstuvwxyz123456';", "a.js", True, False, CFG)
    for name in ("key_google", "hardcoded_secret_assign"):
        ev = r["signals"][("sensitive", name)]["evidence"][0]["snippet"]
        assert "redacted" in ev and key not in ev and "abcdefghijklmnopqrstuvwxyz" not in ev


def test_base64_data_uri_not_counted():
    b = "A" * 400
    assert sig(f"x='data:image/png;base64,{b}'", "obfuscation", "long_base64") == 0
    assert sig(f"x='{b}'", "obfuscation", "long_base64") == 1


def test_endpoints_filtering_and_comments():
    t = ("// see https://github.com/foo\n/* https://lodash.com/ */\n"
         "var a='https://api.vendor.io/v1/chat';var b='http://www.w3.org/2000/svg';var c=`https://${host}/x`;"
         "fetch('https://api.vendor.io/v1/chat');")
    r = scan_text(t, "a.js", True, False, CFG)
    hosts = {u["host"] for u in r["urls"]}
    assert hosts == {"api.vendor.io", "(dynamic)"}
    assert r["ignored_urls"] == 1 and r["comment_urls"] == 2
    assert any(u["near_sink"] for u in r["urls"] if u["host"] == "api.vendor.io")


def test_json_only_endpoints():
    r = scan_text('{"u":"https://api.vendor.io/x","f":"fetch(1)"}', "c.json", False, False, CFG)
    assert r["signals"] == {} and r["urls"][0]["host"] == "api.vendor.io"


def test_evidence_has_line_numbers():
    r = scan_text("a\nb\nfetch(1)\n", "a.js", True, False, CFG)
    assert r["signals"][("network_sinks", "fetch")]["evidence"][0]["line"] == 3


def test_vendor_reason():
    assert vendor_reason("node_modules/x/a.js", "", CFG).startswith("dir:")
    assert vendor_reason("js/jquery.min.js", "", CFG) == "filename"
    assert vendor_reason("a.js", "/*! jQuery JavaScript Library v3 */", CFG) == "banner"
    assert vendor_reason("content.js", "console.log(1)", CFG) == ""


def _ext(tmp_path, files):
    for rel, content in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return tmp_path


def _cfg(**limits):
    cfg = dict(CFG)
    cfg["limits"] = {**CFG["limits"], **limits}
    return cfg


def test_scan_extension_counts_vendor_split_and_skips(tmp_path):
    ext = _ext(tmp_path, {
        "content.js": "fetch('https://api.x.io/a');",
        "lib/jquery.js": "fetch('https://api.y.io/a');",
        "big.js": "a" * 3000,
        "icon.png": "x",
    })
    r = scan_extension(ext, _cfg(scan_max_bytes=2000))
    f = r["signals"]["network_sinks"]["fetch"]
    assert (f["first_party"], f["vendor"], f["total"]) == (1, 1, 2)
    assert r["coverage"]["files_total"] == 3 and r["coverage"]["files_scanned"] == 2
    assert r["coverage"]["skipped_files"][0]["reason"] == "too_large"
    fp = [e for e in r["endpoints"] if e["first_party"]]
    assert [e["host"] for e in fp] == ["api.x.io"]


def test_minified_beautified_and_obfuscation_level(tmp_path):
    ext = _ext(tmp_path, {"a.js": "var a=1;" * 400 + "fetch('https://api.x.io');"})
    r = scan_extension(ext, CFG)
    assert r["coverage"]["files_beautified"] == 1 and r["obfuscation"]["level"] == "minified"
    ext2 = _ext(tmp_path / "b", {"a.js": "eval(function(p,a,c,k,e,d){});"})
    assert scan_extension(ext2, CFG)["obfuscation"]["level"] == "suspected_obfuscated"
    ext3 = _ext(tmp_path / "c", {"a.js": "var a = 1;\n"})
    assert scan_extension(ext3, CFG)["obfuscation"]["level"] == "none"


def test_beautify_cap_and_timeout(tmp_path, monkeypatch):
    ext = _ext(tmp_path, {"a.js": "var a=1;" * 400})
    r = scan_extension(ext, _cfg(beautify_max_bytes=100))
    assert r["coverage"]["files_too_large_to_beautify"] == 1 and r["coverage"]["files_beautified"] == 0

    import jsbeautifier
    monkeypatch.setattr(jsbeautifier, "beautify", lambda *_a, **_k: time.sleep(5))
    t0 = time.time()
    r = scan_extension(ext, _cfg(beautify_timeout_s=0.3))
    assert time.time() - t0 < 3
    assert r["coverage"]["beautify_timeouts"] == 1 and r["coverage"]["files_scanned"] == 1


def test_evidence_cap_and_dedupe(tmp_path):
    ext = _ext(tmp_path, {"a.js": "\n".join(f"fetch('/p{i}');" for i in range(100)) + "\n" + "fetch('/same');\n" * 5})
    r = scan_extension(ext, _cfg(evidence_per_signal=10))
    f = r["signals"]["network_sinks"]["fetch"]
    assert f["total"] == 105 and len(f["evidence"]) <= 10


def test_placeholder_secrets_not_flagged():
    for v in ("APNI_GEMINI_KEY_YAHAN_DALEN", "YOUR_API_KEY_HERE", "sk-your-key-goes-here-1234567890"):
        assert is_placeholder_secret(f"const API_KEY = '{v}'")
        assert sig(f"const API_KEY = '{v}'", "sensitive", "hardcoded_secret_assign") == 0
    assert not is_placeholder_secret("const API_KEY = 'a9Xk2LmQ7rT4vB8nZ3pW'")
    assert sig("const API_KEY = 'a9Xk2LmQ7rT4vB8nZ3pW'", "sensitive", "hardcoded_secret_assign") == 1


def test_manifest_json_not_scanned_for_endpoints(tmp_path):
    ext = _ext(tmp_path, {"manifest.json": '{"update_url": "https://clients2.google.com/service/update2/crx"}',
                          "sub/manifest.json": '{"x": "https://other.example.io/a"}'})
    r = scan_extension(ext, CFG)
    assert [e["host"] for e in r["endpoints"]] == ["other.example.io"]
