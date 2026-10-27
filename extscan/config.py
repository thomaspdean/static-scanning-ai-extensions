from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class ExtractLimits:
    max_files: int = 20000
    max_file_bytes: int = 100_000_000
    max_total_bytes: int = 1_000_000_000
    max_ratio: int = 200


@dataclass(frozen=True)
class Settings:
    root: Path
    input_dir: Path
    work_dir: Path
    unpacked_dir: Path
    out_dir: Path
    extract: ExtractLimits


def load_settings(root: Path | None = None, config_file: Path | None = None) -> Settings:
    root = Path(root or PROJECT_ROOT).resolve()
    cfg_path = config_file or root / "config" / "settings.yaml"
    raw = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
    p = raw.get("paths", {})
    return Settings(
        root=root,
        input_dir=root / p.get("input_dir", "extension-targets"),
        work_dir=root / p.get("work_dir", "work"),
        unpacked_dir=root / p.get("unpacked_dir", "work/unpacked"),
        out_dir=root / p.get("out_dir", "out"),
        extract=ExtractLimits(**raw.get("extract", {})),
    )
