from __future__ import annotations

import argparse
import collections
import sys

from .config import load_settings
from .ingest import ingest_all
from .record import STATUS_OK, write_records, write_schema


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
    for name, stage, h in [("analyze", 2, "manifest analysis"), ("scan", 3, "JS/HTML scanning"),
                           ("classify", 4, "endpoint classification"), ("scrape", 5, "Chrome Web Store scraping"),
                           ("score", 6, "scoring and outputs"), ("report", 6, "console report")]:
        s = sub.add_parser(name, help=f"{h} (Stage {stage}, stub)")
        s.set_defaults(func=_stub(name, stage))
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
