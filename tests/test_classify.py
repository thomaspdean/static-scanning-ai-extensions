import csv

import pytest

from extscan.classify import (build_shared, classify_host, classify_record, host_matches, load_lists,
                              own_domains, registrable, write_shared_csv)
from extscan.record import Record

LISTS = load_lists()


def rec(name="Acme AI Helper", folder="1M-plus__acme-ai-helper__abc", **kw):
    return Record(ext_id=kw.pop("ext_id", "abc"), name=name, folder=folder, tier=kw.pop("tier", "1M+"),
                  ingest_status="ok", **kw)


def cls(host, r=None):
    r = r or rec()
    return classify_host(host, r, LISTS, own_domains(r))


def test_registrable_and_matching():
    assert registrable("api.asksia.ai") == "asksia.ai"
    assert registrable("a.b.co.uk") == "b.co.uk"
    assert registrable("foo.github.io") == "foo.github.io"          # private suffixes kept apart
    assert host_matches("api.openai.com", "openai.com") and not host_matches("notopenai.com", "openai.com")


@pytest.mark.parametrize("host,category", [
    ("www.google-analytics.com", "tracker"), ("api.mixpanel.com", "tracker"),
    ("o123.ingest.sentry.io", "tracker"), ("api.openai.com", "llm_provider"),
    ("generativelanguage.googleapis.com", "llm_provider"), ("cdn.jsdelivr.net", "cdn_static"),
    ("www.youtube.com", "known_service"), ("fonts.googleapis.com", "cdn_static"),
    ("some-random-host.example.net", "unknown"),
])
def test_categories(host, category):
    assert cls(host)["category"] == category


def test_third_party_party_labels():
    assert cls("api.mixpanel.com")["party"] == "3p" and cls("unknown-host.net")["party"] == "3p"


def test_dynamic_and_local():
    assert cls("(dynamic)") == {"party": "n/a", "category": "dynamic", "label": "", "basis": "templated host",
                                "registrable_domain": ""}
    assert cls("192.168.110.107")["category"] == "local_network"
    assert cls("8.8.8.8")["category"] == "unknown"


def test_first_party_by_name_and_by_declaration():
    r = rec(name="Acme AI Helper")
    assert cls("api.acme.io", r)["basis"] == "name_match" and cls("api.acme.io", r)["party"] == "1p"
    r2 = rec(name="Something Else", manifest={"homepage_url": "https://www.vendor-site.com/x",
                                              "externally_connectable": {"matches": ["*://*.other-site.ai/*", "*://*/*"]}})
    assert cls("cdn.vendor-site.com", r2)["basis"] == "homepage"
    assert cls("app.other-site.ai", r2)["basis"] == "externally_connectable"
    assert set(own_domains(r2)) == {"vendor-site.com", "other-site.ai"}


def test_name_match_covers_cdn_and_usercontent_domains():
    r = rec(name="Monica: All-In-One AI Assist", folder="1M-plus__monica-all-in-one__abc")
    assert cls("files.monica-cdn.im", r)["party"] == "1p" and cls("monicausercontent.com", r)["party"] == "1p"
    g = rec(name="Smart Sidebar: Chat GPT", folder="100K-to-1M__smart-sidebar-chat-gpt__abc")
    assert cls("smartthings.com", g)["party"] == "3p"          # generic leading words never match


def test_name_match_never_claims_known_platforms():
    r = rec(name="Google Sheets AI Assistant", folder="1K-to-10K__google-sheets-ai-assistant__x")
    assert cls("www.google-analytics.com", r)["category"] == "tracker"
    assert cls("www.google.com", r)["category"] == "known_service" and cls("www.google.com", r)["party"] == "3p"
    assert cls("api.openai.com", rec(name="OpenAI Helper"))["category"] == "llm_provider"


def test_short_labels_not_name_matched():
    assert cls("x.ai.io", rec(name="AI Tool Pro"))["party"] == "3p"


def test_classify_record_merges_sources_and_orders():
    r = rec(manifest={"distinct_hosts": ["generativelanguage.googleapis.com", "only-in-manifest.net"]},
            scan={"endpoints": [
                {"host": "generativelanguage.googleapis.com", "first_party": True, "near_sink": True, "url_count": 2,
                 "urls": ["https://generativelanguage.googleapis.com/v1"], "schemes": ["https"]},
                {"host": "api.mixpanel.com", "first_party": False, "near_sink": False, "url_count": 1,
                 "urls": ["https://api.mixpanel.com/track"], "schemes": ["https"]}]})
    classify_record(r, LISTS)
    by = {e["host"]: e for e in r.endpoints}
    assert by["generativelanguage.googleapis.com"]["sources"] == ["code", "manifest"]
    assert by["only-in-manifest.net"]["sources"] == ["manifest"] and by["only-in-manifest.net"]["category"] == "unknown"
    assert r.endpoints[0]["category"] == "tracker"                     # trackers sort first


def test_shared_endpoints_csv(tmp_path):
    def mk(i, hosts):
        r = rec(name=f"Ext{i}", ext_id=f"id{i}", tier="1M+" if i == 1 else "<100",
                scan={"endpoints": [{"host": h, "first_party": True, "near_sink": i == 1, "url_count": 1,
                                     "urls": ["https://" + h], "schemes": ["https"]} for h in hosts]})
        return classify_record(r, LISTS)
    recs = [mk(1, ["api.mixpanel.com", "solo.net"]), mk(2, ["api.mixpanel.com"]), mk(3, ["api.mixpanel.com", "ext3.io"])]
    rows = build_shared(recs)
    assert [r["host"] for r in rows] == ["api.mixpanel.com"] and rows[0]["n_extensions"] == 3
    assert rows[0]["n_near_network_call"] == 1 and rows[0]["tiers"] == "1M+;<100"
    p = write_shared_csv(rows, tmp_path)
    assert list(csv.DictReader(p.open()))[0]["extensions"] == "Ext1; Ext2; Ext3"
