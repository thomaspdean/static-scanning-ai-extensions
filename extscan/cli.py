from __future__ import annotations

import argparse
import collections
import sys

from .config import load_settings
from .ingest import ingest_all
from .analyze_manifest import analyze_record, load_permission_tiers
from .js_scan import load_scan_config, scan_records
from .record import STATUS_OK, read_records, write_records, write_schema


def cmd_ingest(args) -> int:
    st = load_settings()
    recs = ingest_all(st, args.only)
    write_schema(st.out_dir)
    write_records(recs, st.out_dir)
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
    done = 0
    for r in recs:
        if args.only and not any(o in r.folder for o in args.only):
            continue
        analyze_record(r, st, tiers)
        done += bool(r.manifest)
    write_records(recs, st.out_dir)
    print(f"analyzed={done} of {len(recs)} records")
    return 0


def cmd_scan(args) -> int:
    st = load_settings()
    cfg = load_scan_config()
    recs = read_records(st.out_dir)
    sel = [r for r in recs if not args.only or any(o in r.folder for o in args.only)]
    scan_records(sel, st, cfg,
                 progress=lambda r: print(f"  scanned {r.folder[:60]}  files={r.scan['coverage']['files_scanned']}", flush=True))
    write_records(recs, st.out_dir)
    print(f"scanned={sum(bool(r.scan) for r in recs)} of {len(recs)} records")
    return 0


def _stub(name: str, stage: int):
    def run(args) -> int:
        print(f"'{name}' is not implemented yet (Stage {stage}).", file=sys.stderr)
        return 2
    return run


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="extscan", description="Static scanner for GenAI browser extensions")
    sub = p.add_subparsers(dest="cmd", required=True)
    ing = sub.add_parser("ingest", help="verify and unpack extensions, write out/records.jsonl")
    ing.add_argument("--only", nargs="*", help="substring filter on folder name")
    ing.set_defaults(func=cmd_ingest)
    an = sub.add_parser("analyze", help="manifest analysis: fields and derived flags (Stage 2)")
    an.add_argument("--only", nargs="*", help="substring filter on folder name")
    an.set_defaults(func=cmd_analyze)
    sc = sub.add_parser("scan", help="JS/HTML signal scan (Stage 3)")
    sc.add_argument("--only", nargs="*", help="substring filter on folder name")
    sc.set_defaults(func=cmd_scan)
    for name, stage, h in [("classify", 4, "endpoint classification"), ("scrape", 5, "Chrome Web Store scraping"),
                           ("score", 6, "scoring and outputs"), ("report", 6, "console report")]:
        s = sub.add_parser(name, help=f"{h} (Stage {stage}, stub)")
        s.set_defaults(func=_stub(name, stage))
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
