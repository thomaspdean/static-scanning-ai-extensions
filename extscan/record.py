"""Per-extension record and schema writer.

Stage 1 fills `source`, `ingest` and the resolved identity fields. The remaining
sections exist as empty placeholders so the output shape is stable across stages.
"""
from __future__ import annotations

import json
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


def write_records(records: list[Record], out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    p = out_dir / "records.jsonl"
    with p.open("w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r.to_dict(), ensure_ascii=False) + "\n")
    return p
