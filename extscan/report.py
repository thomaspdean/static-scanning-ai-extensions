"""Console report: top-N ranking, per-tier leaders, and a population summary."""
from __future__ import annotations

from collections import Counter

from .record import Record
from .scoring import COMPONENTS

TIER_ORDER = ["1M+", "100K to 1M", "10K to 100K", "1K to 10K", "500 to 1K", "100 to 500", "<100"]


def _clip(s: str, n: int) -> str:
    s = " ".join(str(s).split())
    return s if len(s) <= n else s[:n - 1] + "…"


def _table(rows: list[list[str]], header: list[str], widths: list[int]) -> str:
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    lines = [fmt.format(*header), fmt.format(*["-" * w for w in widths])]
    lines += [fmt.format(*[_clip(c, w) for c, w in zip(r, widths)]) for r in rows]
    return "\n".join(lines)


def build_report(recs: list[Record], top: int = 15, tier: str | None = None) -> str:
    scored = sorted((r for r in recs if r.score), key=lambda r: (r.score["rank_overall"], r.name.lower()))
    out: list[str] = []
    if not scored:
        return "No scored records. Run `extscan ingest`, `analyze`, `scan`, `classify`, then `extscan score`."
    pool = [r for r in scored if not tier or r.tier == tier]
    out.append(f"Suspicion ranking: {len(scored)} extensions scored of {len(recs)} records"
               + (f" (showing tier {tier})" if tier else ""))
    out.append("Leads from static analysis, not proof. Store data is not used in the score.\n")
    rows = [[str(r.score["rank_overall"]), r.name, r.tier, f"{r.score['total']:.1f}", r.score["top_reasons"][0]
             if r.score["top_reasons"] else "-"] for r in pool[:top]]
    out.append(_table(rows, ["#", "Extension", "Tier", "Score", "Top reason"], [3, 34, 11, 5, 70]))

    out.append("\nTop of each tier")
    for t in TIER_ORDER:
        members = [r for r in scored if r.tier == t]
        if members:
            lead = ", ".join(f"{_clip(r.name, 26)} ({r.score['total']:.0f})" for r in members[:3])
            out.append(f"  {t:<12} n={len(members):<3} {lead}")

    out.append("\nAverage points by component (max = weight)")
    for c in COMPONENTS:
        pts = [r.score["components"][c]["points"] for r in scored]
        w = scored[0].score["components"][c]["weight"]
        out.append(f"  {c:<16} {sum(pts) / len(pts):5.1f} / {w:g}")

    flag = Counter()
    for r in scored:
        f = r.manifest["flags"]
        for k in ("broad_host", "broad_cs_document_start", "broad_cs_all_frames", "broad_cs_main_world",
                  "has_high_risk_permission"):
            flag[k] += bool(f[k])
        s = r.scan["signals"]
        flag["reads page text/HTML"] += any(s.get("dom_harvest", {}).get(n, {}).get("first_party", 0)
                                            for n in ("page_text", "page_html"))
        flag["tracker endpoint"] += any(e["category"] == "tracker" for e in r.endpoints)
        flag["LLM provider endpoint"] += any(e["category"] == "llm_provider" for e in r.endpoints)
        flag["suspected obfuscation"] += r.scan["obfuscation"]["level"] == "suspected_obfuscated"
    out.append(f"\nPopulation (of {len(scored)} scored)")
    for k, v in flag.items():
        out.append(f"  {k:<28} {v:>3}  ({100 * v / len(scored):.0f}%)")
    notes = sum(bool(r.score["notes"]) for r in scored)
    out.append(f"\n{notes} extension(s) have scan-coverage notes; see the `notes` column in out/summary.csv.")
    return "\n".join(out)
