import copy
import csv

import pytest

from extscan.outputs import ENDPOINT_COLUMNS, SUMMARY_COLUMNS, write_endpoints, write_summary
from extscan.record import Record
from extscan.report import build_report
from extscan.scoring import load_scoring_config, score_all, score_record

CFG = load_scoring_config()

FLAGS = {"high_risk_permissions": [], "high_risk_optional_permissions": [], "broad_content_script": False,
         "broad_cs_document_start": False, "broad_cs_all_frames": False, "broad_cs_main_world": False,
         "csp_remote_script": False, "non_store_update_url": False, "broad_host": False,
         "has_high_risk_permission": False}


def sig(**fp):
    groups = {"dom_harvest": {}, "network_sinks": {}, "sensitive": {}, "remote_code": {}, "obfuscation": {}}
    for name, n in fp.items():
        groups["dom_harvest" if name in ("page_text", "page_html", "form_inputs", "selection", "password_field")
                else "network_sinks" if name in ("fetch", "xhr", "send_beacon") else "remote_code"][name] = {
            "first_party": n, "vendor": 0}
    return {"signals": groups, "obfuscation": {"level": "none"}, "coverage": {}}


def rec(i="a", name="Ext", tier="1M+", flags=None, scan=None, endpoints=None, **kw):
    f = {**FLAGS, **(flags or {})}
    return Record(ext_id=i, name=name, folder=f"t__{i}__x", tier=tier, ingest_status="ok",
                  manifest={"flags": f, "permissions": ["storage"]}, scan=scan or sig(), endpoints=endpoints or [], **kw)


def ep(host, category, label="", near=False, fpc=True, sources=("code",)):
    return {"host": host, "category": category, "label": label, "near_sink": near, "in_first_party_code": fpc,
            "sources": list(sources), "party": "3p", "registrable_domain": host, "basis": "", "url_count": 1,
            "sample_url": ""}


def test_weights_sum_to_100():
    assert sum(c["weight"] for c in CFG.values()) == 100


def test_quiet_extension_scores_zero():
    s = score_record(rec(), CFG)
    assert s["total"] == 0 and s["top_reasons"] == []


def test_injection_requires_broad_content_script():
    narrow = rec(flags={"broad_cs_document_start": True, "broad_cs_all_frames": True, "broad_cs_main_world": True})
    assert score_record(narrow, CFG)["components"]["injection_reach"]["points"] == 0
    full = rec(flags={"broad_content_script": True, "broad_cs_document_start": True,
                      "broad_cs_all_frames": True, "broad_cs_main_world": True})
    assert score_record(full, CFG)["components"]["injection_reach"]["points"] == 15
    base = rec(flags={"broad_content_script": True})
    assert score_record(base, CFG)["components"]["injection_reach"]["points"] == 1.5


def test_permissions_cap_and_optional_discount():
    r = rec(flags={"high_risk_permissions": ["cookies", "debugger", "history", "proxy"]})
    assert score_record(r, CFG)["components"]["permissions"]["points"] == 15
    r = rec(flags={"high_risk_permissions": ["cookies"], "high_risk_optional_permissions": ["history"]})
    assert score_record(r, CFG)["components"]["permissions"]["points"] == pytest.approx(15 * (1 / 3 + 0.5 / 3), abs=0.01)


def test_presence_not_counts():
    one, many = rec(scan=sig(page_text=1)), rec(scan=sig(page_text=5000))
    assert score_record(one, CFG)["total"] == score_record(many, CFG)["total"]


def test_vendor_only_signals_ignored():
    scan = sig()
    scan["signals"]["dom_harvest"]["page_text"] = {"first_party": 0, "vendor": 99}
    assert score_record(rec(scan=scan), CFG)["components"]["page_harvesting"]["points"] == 0


def test_exfil_combination_needs_both_halves():
    assert score_record(rec(scan=sig(page_text=1)), CFG)["components"]["exfil_path"]["points"] == 0
    only_sink = score_record(rec(scan=sig(fetch=3)), CFG)["components"]["exfil_path"]["points"]
    both = score_record(rec(scan=sig(fetch=3, page_text=1)), CFG)["components"]["exfil_path"]["points"]
    assert only_sink == pytest.approx(20 * 0.25) and both == pytest.approx(20 * 0.60)


def test_llm_endpoint_counts_from_manifest_or_code_only():
    code = rec(endpoints=[ep("api.openai.com", "llm_provider", "OpenAI")])
    vendor_only = rec(endpoints=[ep("api.openai.com", "llm_provider", "OpenAI", fpc=False)])
    assert score_record(code, CFG)["components"]["exfil_path"]["points"] == pytest.approx(5)
    assert score_record(vendor_only, CFG)["components"]["exfil_path"]["points"] == 0


def test_third_party_trackers_count_anywhere_unknown_only_near_sink_in_first_party():
    r = rec(endpoints=[ep("api.mixpanel.com", "tracker", "Mixpanel (analytics)", fpc=False),
                       ep("a.example", "unknown", near=True), ep("b.example", "unknown"),
                       ep("c.example", "unknown", near=True, fpc=False)])
    tp = score_record(r, CFG)["components"]["third_party"]
    assert tp["points"] == pytest.approx(15 * (0.6 / 3 + 0.4 / 3))


def test_code_risk_flags_and_credentials():
    scan = sig(eval=1)
    scan["obfuscation"]["level"] = "suspected_obfuscated"
    scan["signals"]["sensitive"]["key_google"] = {"first_party": 1, "vendor": 0}
    r = rec(scan=scan, flags={"non_store_update_url": True})
    reasons = [d["reason"] for d in score_record(r, CFG)["components"]["code_risk"]["details"]]
    assert any("eval" in x for x in reasons) and any("key_google" in x for x in reasons)
    assert score_record(r, CFG)["components"]["code_risk"]["points"] == pytest.approx(10 * 0.8)


def test_store_data_does_not_change_score():
    base = rec(scan=sig(page_text=1, fetch=1))
    withstore = copy.deepcopy(base)
    withstore.store = {"user_count": 9_000_000, "privacy_practices": {"status": "declares_no_collection"}}
    assert score_record(base, CFG)["total"] == score_record(withstore, CFG)["total"]


def test_top_reasons_sorted_by_points_and_limited():
    r = rec(flags={"high_risk_permissions": ["cookies"], "broad_content_script": True, "broad_cs_main_world": True},
            scan=sig(page_text=1, fetch=1))
    s = score_record(r, CFG)
    pts = [float(x.rsplit("(", 1)[1].rstrip(")")) for x in s["top_reasons"]]
    assert pts == sorted(pts, reverse=True) and len(pts) == 4
    assert "reads page text" in s["top_reasons"][0]


def test_unscored_records_and_rank_ties():
    recs = [rec("a", "Alpha", scan=sig(page_text=1)), rec("b", "Beta", scan=sig(page_text=1)),
            rec("c", "Gamma", tier="<100", scan=sig(page_text=1, fetch=1)), rec("d", "Delta", tier="<100"),
            Record(ext_id="x", name="Broken", folder="t__x__y", tier="1M+", ingest_status="failed")]
    assert score_all(recs, CFG) == 4
    by = {r.ext_id: r for r in recs}
    assert by["c"].score["rank_overall"] == 1 and by["c"].score["rank_in_tier"] == 1
    assert by["a"].score["rank_overall"] == 2 and by["b"].score["rank_overall"] == 2     # tie shares a rank
    assert by["d"].score["rank_overall"] == 4 and by["d"].score["rank_in_tier"] == 2
    assert by["a"].score["tier_size"] == 2 and by["x"].score == {}


def test_csv_outputs_and_report(tmp_path):
    recs = [rec("a", "Alpha", scan=sig(page_text=1, fetch=1), endpoints=[ep("api.openai.com", "llm_provider", "OpenAI")]),
            rec("b", "Beta", tier="<100")]
    recs[1].store = {"user_count": 3, "privacy_policy_url": "https://x/p",
                     "privacy_practices": {"status": "declared_collection", "data_types_collected": ["Website content"]}}
    score_all(recs, CFG)
    rows = list(csv.DictReader(write_summary(recs, tmp_path).open()))
    assert list(rows[0].keys()) == SUMMARY_COLUMNS
    assert [r["name"] for r in rows] == ["Alpha", "Beta"] and rows[0]["suspicion_rank"] == "1"
    assert rows[0]["privacy_status"] == "not_scraped" and rows[0]["llm_providers"] == "OpenAI"
    assert rows[1]["privacy_status"] == "declared_collection" and rows[1]["declared_data_types"] == "Website content"
    erows = list(csv.DictReader(write_endpoints(recs, tmp_path).open()))
    assert list(erows[0].keys()) == ENDPOINT_COLUMNS and erows[0]["host"] == "api.openai.com"
    text = build_report(recs, top=5)
    assert "Alpha" in text and "Top of each tier" in text and "not used in the score" in text
    assert "No scored records" in build_report([Record(ingest_status="ok")])
