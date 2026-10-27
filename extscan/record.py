"""Per-extension record and schema writer.

Stage 1 fills `source`, `ingest` and the resolved identity fields. The remaining
sections exist as empty placeholders so the output shape is stable across stages.
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1

# Ingest outcomes. Anything other than "ok" means later stages skip the record.
STATUS_OK = "ok"
STATUS_SKIPPED = "skipped"            # meta.json status != ok
STATUS_HASH_MISMATCH = "hash_mismatch"
STATUS_FAILED = "failed"              # missing/corrupt zip, unsafe archive, bad manifest...


@dataclass
class Record:
    # identity / source (Stage 1)
    ext_id: str = ""
    tier: str = ""
    folder: str = ""
    name: str = ""                    # resolved (__MSG_ expanded)
    raw_name: str = ""
    description: str = ""
    version: str = ""
    manifest_version: int | None = None
    zip_sha256_expected: str = ""
    zip_sha256_actual: str = ""
    # ingest outcome (Stage 1)
    ingest_status: str = ""
    ingest_reason: str = ""
    unpacked_path: str = ""
    file_count: int = 0
    unpacked_bytes: int = 0
    # later stages: empty placeholders
    manifest: dict[str, Any] = field(default_factory=dict)    # Stage 2
    scan: dict[str, Any] = field(default_factory=dict)        # Stage 3
    endpoints: list[dict[str, Any]] = field(default_factory=list)  # Stage 4
    store: dict[str, Any] = field(default_factory=dict)       # Stage 5
    score: dict[str, Any] = field(default_factory=dict)       # Stage 6

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Record":
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in d.items() if k in known})


def schema() -> dict[str, Any]:
    """Describe the record: field name -> {type, stage}."""
    stage = {
        "manifest": 2, "scan": 3, "endpoints": 4, "store": 5, "score": 6,
    }
    out = {}
    for f in fields(Record):
        out[f.name] = {"type": str(f.type), "stage": stage.get(f.name, 1)}
    return {"schema_version": SCHEMA_VERSION, "record": out}


def write_schema(out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    p = out_dir / "schema.json"
    p.write_text(json.dumps(schema(), indent=2) + "\n", encoding="utf-8")
    return p


_SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]+$")
_STAGE_FIELDS = ("manifest", "scan", "endpoints", "store", "score")


def records_dir(out_dir: Path) -> Path:
    return out_dir / "records"


def record_filename(rec: Record) -> str:
    """`<ext_id>.json`; falls back to the folder name when the id is missing or unsafe."""
    name = rec.ext_id if _SAFE_NAME.match(rec.ext_id or "") else rec.folder
    return f"{name}.json"


def _atomic_write(path: Path, text: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def _index_entry(rec: Record) -> dict[str, Any]:
    return {"file": record_filename(rec), "ext_id": rec.ext_id, "folder": rec.folder, "tier": rec.tier,
            "name": rec.name, "ingest_status": rec.ingest_status,
            "stages_filled": [f for f in _STAGE_FIELDS if getattr(rec, f)]}


def read_index(out_dir: Path) -> dict[str, dict[str, Any]]:
    p = out_dir / "index.json"
    try:
        return {e["file"]: e for e in json.loads(p.read_text(encoding="utf-8"))["records"]}
    except (OSError, ValueError, KeyError):
        return {}


def _write_index(out_dir: Path, entries: dict[str, dict[str, Any]]) -> None:
    rows = sorted(entries.values(), key=lambda e: e["folder"])
    _atomic_write(out_dir / "index.json", json.dumps({"schema_version": SCHEMA_VERSION, "records": rows}, indent=1) + "\n")


def write_record(rec: Record, out_dir: Path, update_index: bool = True) -> Path:
    """Write one record to out/records/<ext_id>.json (atomic) and refresh its index entry."""
    d = records_dir(out_dir)
    d.mkdir(parents=True, exist_ok=True)
    p = d / record_filename(rec)
    _atomic_write(p, json.dumps(rec.to_dict(), indent=2, ensure_ascii=False) + "\n")
    if update_index:
        entries = read_index(out_dir)
        entries[p.name] = _index_entry(rec)
        _write_index(out_dir, entries)
    return p


def write_records(records: list[Record], out_dir: Path, prune: bool = False) -> None:
    """Write many records and one index update. With prune=True, other record files are deleted."""
    entries = {} if prune else read_index(out_dir)
    for r in records:
        p = write_record(r, out_dir, update_index=False)
        entries[p.name] = _index_entry(r)
    if prune:
        keep = set(entries)
        for old in records_dir(out_dir).glob("*.json"):
            if old.name not in keep:
                old.unlink()
    out_dir.mkdir(parents=True, exist_ok=True)
    _write_index(out_dir, entries)


def read_records(out_dir: Path) -> list[Record]:
    d = records_dir(out_dir)
    recs = [Record.from_dict(json.loads(p.read_text(encoding="utf-8"))) for p in sorted(d.glob("*.json"))]
    return sorted(recs, key=lambda r: r.folder)
