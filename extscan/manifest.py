"""Read manifest.json and resolve __MSG_*__ placeholders."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

_MSG = re.compile(r"^__MSG_([A-Za-z0-9_@]+)__$")


class ManifestError(Exception):
    pass


def read_manifest(ext_dir: Path) -> dict[str, Any]:
    path = ext_dir / "manifest.json"
    if not path.is_file():
        raise ManifestError("manifest.json missing")
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ManifestError(f"manifest.json unparseable: {e}") from e
    if not isinstance(data, dict):
        raise ManifestError("manifest.json is not an object")
    return data


def _locale_dirs(ext_dir: Path, default_locale: str | None) -> list[Path]:
    root = ext_dir / "_locales"
    if not root.is_dir():
        return []
    avail = {p.name.lower(): p for p in root.iterdir() if p.is_dir()}
    order: list[str] = []
    for loc in (default_locale, "en", "en_us", "en_gb"):
        if loc:
            order.append(loc.lower().replace("-", "_"))
    found = [avail[k] for k in order if k in avail]
    found += [p for k, p in sorted(avail.items()) if p not in found]
    return found


def resolve_msg(value: Any, ext_dir: Path, default_locale: str | None) -> str:
    """Expand a `__MSG_key__` string; return the input unchanged if it can't be resolved."""
    if not isinstance(value, str):
        return "" if value is None else str(value)
    m = _MSG.match(value.strip())
    if not m:
        return value
    key = m.group(1).lower()
    for d in _locale_dirs(ext_dir, default_locale):
        f = d / "messages.json"
        try:
            msgs = json.loads(f.read_text(encoding="utf-8-sig"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if not isinstance(msgs, dict):
            continue
        for k, v in msgs.items():  # keys are case-insensitive in Chrome
            if k.lower() == key and isinstance(v, dict) and isinstance(v.get("message"), str):
                return v["message"]
    return value
