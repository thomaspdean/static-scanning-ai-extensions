import json
import urllib.error

import pytest

from extscan.config import ExtractLimits, Settings
from extscan.record import Record
from extscan.scrape import (Blocked, fetch_with_retry, load_scrape_config, parse_count, parse_store_page,
                            scrape_all, scrape_record, tier_for)

CFG = load_scrape_config()


def page(privacy_html, extra=""):
    # Shaped after the real store page as cached in Oct 2026 (text trimmed, names changed).
    return f"""<html><head><title>Acme AI - Chrome Web Store</title><script>var junk = "1,000 users";</script>
<style>.x{{}}</style></head><body>
<div>Skip to main content</div><h1>Acme AI</h1><div>Acme Inc</div>
<div>4.6</div><div>(</div><div>1.2K ratings</div><div>)</div><div>Share</div>
<div>Extension</div><div>Tools</div><div>2,000,000 users</div><div>Add to Chrome</div>
<h2>Overview</h2><p>Great tool, 5,000 users love it</p><div>4.6 out of 5</div><div>1.2K ratings</div>
<h2>Details</h2><div>Version</div><div>1.2.3</div><div>Updated</div><div>March 3, 2026</div>
<div>Offered by</div><div>Acme Inc</div><div>Size</div><div>5.4MiB</div><div>Languages</div><div>English</div>
<div>Developer</div><div>Acme Inc</div><a href="https://acme.example/">Website</a><div>Email</div><div>a@acme.example</div>
{privacy_html}{extra}<div>Support</div><a href="acme.example/help">support site</a>
<h2>Related</h2><div>Location</div><a href="https://myaccount.google.com/privacypolicy">Privacy Policy</a>
</body></html>"""


COLLECT = """<h2>Privacy</h2><div>Manage extensions and learn how they're being used in your organization</div>
<div>Try Chrome Enterprise Core</div>
<div>Acme AI has disclosed the following information regarding the collection and usage of your data. More detailed information can be found in the developer's</div>
<a href="https://acme.example/privacy">privacy policy</a><div>.</div>
<div>Acme AI handles the following:</div>
<div>Personally identifiable information</div><div>Website content</div><div>See details</div>
<div>This developer declares that your data is</div>
<div>Not being sold to third parties, outside of the</div><div>approved use cases</div>
<div>Not being used or transferred for purposes that are unrelated to the item's core functionality</div>
<div>Not being used or transferred to determine creditworthiness or for lending purposes</div>"""

NONE = """<h2>Privacy</h2><div>The developer has disclosed that it will not collect or use your data.</div>
<a href="https://acme.example/privacy">privacy policy</a>"""

NO_LIST = """<h2>Privacy</h2><div>Acme AI has disclosed the following information regarding the collection and usage of your data.</div>"""


def test_parse_count():
    assert parse_count("2,000,000 users") == 2_000_000
    assert parse_count("1.5M users") == 1_500_000 and parse_count("900 users") == 900
    assert parse_count("10,000+ users") == 10_000 and parse_count("no count") is None


def test_parse_full_page_with_collection():
    r = parse_store_page(page(COLLECT), CFG)
    assert (r["name"], r["user_count"], r["rating"], r["rating_count"]) == ("Acme AI", 2_000_000, 4.6, "1.2K")
    assert r["category"] == "Tools"
    assert (r["version"], r["updated"], r["size"], r["languages"]) == ("1.2.3", "March 3, 2026", "5.4MiB", "English")
    assert r["developer_name"] == "Acme Inc"
    assert r["website"] == "https://acme.example/" and r["privacy_policy_url"] == "https://acme.example/privacy"
    assert r["support_url"] == "https://acme.example/help"          # bare domain gets a scheme
    pp = r["privacy_practices"]
    assert pp["status"] == "declared_collection"
    assert pp["data_types_collected"] == ["Personally identifiable information", "Website content"]
    assert pp["certifications"] == {"not_sold": True, "not_unrelated_use": True, "not_lending": True}
    assert r["parse_status"] == "ok" and r["parse_issues"] == []


def test_script_text_and_related_section_ignored():
    r = parse_store_page(page(NONE), CFG)
    assert r["user_count"] == 2_000_000                       # not "1,000 users" in <script> or "5,000 users" in prose
    pp = r["privacy_practices"]
    assert pp["status"] == "declares_no_collection" and pp["data_types_collected"] == []   # "Location" is under Related
    assert r["privacy_policy_url"] == "https://acme.example/privacy"      # not the store's own google.com link


def test_no_privacy_section_is_partial():
    r = parse_store_page(page(""), CFG)
    assert r["privacy_practices"]["status"] == "no_section" and r["parse_status"] == "partial"
    assert any("privacy_practices" in i for i in r["parse_issues"])


def test_disclosure_without_type_list():
    r = parse_store_page(page(NO_LIST), CFG)
    assert r["privacy_practices"]["status"] == "no_types_listed" and r["parse_status"] == "partial"
    assert r["privacy_practices"]["certifications"]["not_sold"] is None


def test_no_ratings_and_missing_developer_fields():
    html = ("<html><body><div>X</div><div>Extension</div><div>Tools</div><div>3 users</div><div>0 out of 5</div>"
            "<div>No ratings</div><div>Developer</div><div>Email</div><div>a@b.c</div></body></html>")
    r = parse_store_page(html, CFG)
    assert (r["rating"], r["rating_count"], r["developer_name"], r["website"]) == (0.0, "0", "", "")


def test_unrecognised_page_fails_loudly():
    r = parse_store_page("<html><body><div>Completely different layout</div></body></html>", CFG)
    assert r["parse_status"] == "failed" and r["user_count"] is None and len(r["parse_issues"]) >= 3


def test_not_found_page():
    r = parse_store_page("<html><body><h1>Item not found</h1></body></html>", CFG)
    assert r["parse_status"] == "not_found"


def test_tier_for():
    t = CFG["tiers"]
    assert [tier_for(n, t) for n in (50, 100, 999, 1000, 2_000_000)] == ["<100", "100 to 500", "500 to 1K", "1K to 10K", "1M+"]


# ---------- fetching ----------

def settings(tmp_path):
    return Settings(tmp_path, tmp_path / "in", tmp_path / "w", tmp_path / "w/u", tmp_path / "out", ExtractLimits())


def rec(i="abc", tier="1M+"):
    return Record(ext_id=i, folder=f"t__x__{i}", name="Acme AI", tier=tier, ingest_status="ok")


class Fake:
    def __init__(self, responses):
        self.responses, self.calls = list(responses), []

    def __call__(self, url):
        self.calls.append(url)
        r = self.responses.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


def test_scrape_record_caches_and_reuses(tmp_path):
    st, f = settings(tmp_path), Fake([(200, "https://x/final", page(COLLECT))])
    r = scrape_record(rec(), st, CFG, f, sleep=lambda s: None)
    assert r.store["fetch_status"] == "ok" and r.store["user_count"] == 2_000_000
    assert r.store["tier_check"] == {"meta_tier": "1M+", "store_tier": "1M+", "consistent": True}
    assert (tmp_path / "cache/store/abc.html").is_file() and (tmp_path / "cache/store/abc.json").is_file()
    again = scrape_record(rec(), st, CFG, Fake([]), sleep=lambda s: None)      # cache hit: fetcher never called
    assert again.store["from_cache"] is True and again.store["user_count"] == 2_000_000
    refreshed = scrape_record(rec(), st, CFG, Fake([(200, "u", page(NONE))]), refresh=True, sleep=lambda s: None)
    assert refreshed.store["privacy_practices"]["status"] == "declares_no_collection"


def test_no_fetch_mode_makes_no_requests_and_reparses_cache(tmp_path):
    st = settings(tmp_path)
    scrape_record(rec(), st, CFG, Fake([(200, "u", page(COLLECT))]), sleep=lambda s: None)
    assert scrape_record(rec(), st, CFG, None).store["parse_status"] == "ok"
    miss = scrape_record(rec("zzz"), st, CFG, None)
    assert miss.store["fetch_status"] == "not_fetched" and miss.store["parse_status"] == "not_parsed"


def test_tier_inconsistency_flagged(tmp_path):
    r = scrape_record(rec(tier="1K to 10K"), settings(tmp_path), CFG, Fake([(200, "u", page(COLLECT))]), sleep=lambda s: None)
    assert r.store["tier_check"]["consistent"] is False


def test_404_is_cached_but_errors_are_not(tmp_path):
    st = settings(tmp_path)
    r = scrape_record(rec(), st, CFG, Fake([(404, "u", "<html>Item not found</html>")]), sleep=lambda s: None)
    assert r.store["fetch_status"] == "not_found" and r.store["parse_status"] == "not_found"
    scrape_record(rec("err"), st, CFG, Fake([(500, "u", "")] * 3), sleep=lambda s: None)
    assert not (tmp_path / "cache/store/err.json").exists()


def test_retry_backoff():
    sleeps = []
    f = Fake([(503, "u", ""), urllib.error.URLError("boom"), (200, "u", "ok")])
    assert fetch_with_retry("u", f, CFG, sleeps.append)[0] == 200
    assert sleeps == [CFG["store"]["backoff_s"], CFG["store"]["backoff_s"] * 2] and len(f.calls) == 3


def test_stops_after_consecutive_blocks_and_paces_requests(tmp_path):
    st = settings(tmp_path)
    cfg = json.loads(json.dumps(CFG))
    cfg["store"]["retries"] = 0
    blocked = Fake([(429, "u", "")] * 3)
    recs = [rec(f"b{i}") for i in range(5)]
    with pytest.raises(Blocked):
        scrape_all(recs, st, cfg, blocked, sleep=lambda s: None)
    assert len(blocked.calls) == 3
    sleeps = []
    ok = Fake([(200, "u", page(COLLECT))] * 2)
    scrape_all([rec("p1"), rec("p2")], st, cfg, ok, sleep=sleeps.append)
    assert len(sleeps) == 1 and sleeps[0] > 0                     # waits between live requests, not before the first
