from __future__ import annotations

import argparse
import collections
import sys

from .config import load_settings
from .ingest import ingest_all
from .analyze_manifest import analyze_record, load_permission_tiers
from .outputs import write_endpoints, write_summary
from .report import build_report
from .scoring import load_scoring_config, score_all
from .classify import build_shared, classify_record, load_lists, write_shared_csv
from .scrape import Blocked, default_fetcher, load_scrape_config, scrape_all
from .js_scan import load_scan_config, scan_records
from .record import STATUS_OK, read_records, write_record, write_records, write_schema


def cmd_ingest(args) -> int:
    st = load_settings()
    recs = ingest_all(st, args.only)
    write_schema(st.out_dir)
    write_records(recs, st.out_dir, prune=not args.only)   # a full ingest replaces the record set
    counts = collections.Counter(r.ingest_status for r in recs)
    print(f"loaded={counts[STATUS_OK]} total={len(recs)} "
          + " ".join(f"{k}={v}" for k, v in sorted(counts.items()) if k != STATUS_OK))
    for r in recs:
        if r.ingest_status != STATUS_OK:
            print(f"  [{r.ingest_status}] {r.folder}: {r.ingest_reason}")
    return 0


def cmd_analyze(args) -> int:
    st = load_settings()
    tiers = load_permission_tiers()
    recs = read_records(st.out_dir)
    for r in recs:
        if args.only and not any(o in r.folder for o in args.only):
            continue
        analyze_record(r, st, tiers)
        write_record(r, st.out_dir)
    print(f"analyzed={sum(bool(r.manifest) for r in recs)} of {len(recs)} records")
    return 0


def cmd_scan(args) -> int:
    st = load_settings()
    cfg = load_scan_config()
    recs = read_records(st.out_dir)
    sel = [r for r in recs if not args.only or any(o in r.folder for o in args.only)]

    def done(r):                      # write each record as it finishes so a crash loses nothing
        write_record(r, st.out_dir)
        print(f"  scanned {r.folder[:60]}  files={r.scan['coverage']['files_scanned']}", flush=True)

    scan_records(sel, st, cfg, progress=done)
    print(f"scanned={sum(bool(r.scan) for r in recs)} of {len(recs)} records")
    return 0


def cmd_classify(args) -> int:
    st = load_settings()
    lists = load_lists()
    recs = read_records(st.out_dir)
    for r in recs:
        if args.only and not any(o in r.folder for o in args.only):
            continue
        if r.ingest_status == STATUS_OK and (r.scan or r.manifest):
            classify_record(r, lists)
            write_record(r, st.out_dir)
    rows = build_shared(recs)
    path = write_shared_csv(rows, st.out_dir)
    print(f"classified={sum(bool(r.endpoints) for r in recs)} of {len(recs)} records; "
          f"{len(rows)} shared third-party hosts -> {path.relative_to(st.root)}")
    return 0


def cmd_scrape(args) -> int:
    st = load_settings()
    cfg = load_scrape_config()
    if args.delay is not None:
        cfg["store"]["delay_s"] = args.delay
    recs = read_records(st.out_dir)
    sel = [r for r in recs if not args.only or any(o in r.folder for o in args.only)]
    fetch = None if args.no_fetch else default_fetcher(cfg)

    def done(r):
        write_record(r, st.out_dir)
        s = r.store
        src = "cache" if s.get("from_cache") else "live"
        print(f"  {r.folder[:56]:56} {s['fetch_status']:11} parse={s['parse_status']:10} users={s.get('user_count')} "
              f"privacy={s.get('privacy_practices', {}).get('status', '-')} [{src}]", flush=True)

    try:
        scrape_all(sel, st, cfg, fetch, refresh=args.refresh, progress=done)
    except Blocked as e:
        print(f"STOPPED: {e}", file=sys.stderr)
        return 1
    stores = [r.store for r in sel if r.store]
    bad = [r for r in sel if r.store and r.store["parse_status"] not in ("ok",)]
    print(f"scraped={len(stores)} parse_ok={len(stores) - len(bad)} needs_attention={len(bad)}")
    for r in bad:
        print(f"  {r.folder[:56]}: {'; '.join(r.store['parse_issues'])}")
    return 0


def cmd_score(args) -> int:
    st = load_settings()
    recs = read_records(st.out_dir)
    n = score_all(recs, load_scoring_config())
    for r in recs:
        write_record(r, st.out_dir)
    summary = write_summary(recs, st.out_dir)
    endpoints = write_endpoints(recs, st.out_dir)
    print(f"scored={n} of {len(recs)} records -> {summary.relative_to(st.root)}, {endpoints.relative_to(st.root)}")
    if n < len(recs):
        print(f"  {len(recs) - n} record(s) not scored (failed ingest, or missing analyze/scan)")
    return 0


def cmd_report(args) -> int:
    st = load_settings()
    print(build_report(read_records(st.out_dir), top=args.top, tier=args.tier))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="extscan", description="Static scanner for GenAI browser extensions")
    sub = p.add_subparsers(dest="cmd", required=True)
    ing = sub.add_parser("ingest", help="verify and unpack extensions, write one JSON file per extension in out/records/")
    ing.add_argument("--only", nargs="*", help="substring filter on folder name")
    ing.set_defaults(func=cmd_ingest)
    an = sub.add_parser("analyze", help="manifest analysis: fields and derived flags")
    an.add_argument("--only", nargs="*", help="substring filter on folder name")
    an.set_defaults(func=cmd_analyze)
    sc = sub.add_parser("scan", help="JS/HTML signal scan")
    sc.add_argument("--only", nargs="*", help="substring filter on folder name")
    sc.set_defaults(func=cmd_scan)
    cl = sub.add_parser("classify", help="label endpoint hosts by party/category, write shared_endpoints.csv")
    cl.add_argument("--only", nargs="*", help="substring filter on folder name")
    cl.set_defaults(func=cmd_classify)
    sr = sub.add_parser("scrape", help="fetch Chrome Web Store pages: users, developer links, privacy practices")
    sr.add_argument("--only", nargs="*", help="substring filter on folder name")
    sr.add_argument("--refresh", action="store_true", help="ignore the cache and re-fetch")
    sr.add_argument("--no-fetch", action="store_true", help="parse cached pages only; make no network requests")
    sr.add_argument("--delay", type=float, help="seconds between live requests (default from config/scrape.yaml)")
    sr.set_defaults(func=cmd_scrape)
    sco = sub.add_parser("score", help="score and rank extensions; write out/summary.csv and out/endpoints.csv")
    sco.set_defaults(func=cmd_score)
    rep = sub.add_parser("report", help="print the ranking and population summary")
    rep.add_argument("--top", type=int, default=15, help="rows in the ranking table (default 15)")
    rep.add_argument("--tier", help="restrict the table to one tier, e.g. '1M+'")
    rep.set_defaults(func=cmd_report)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
