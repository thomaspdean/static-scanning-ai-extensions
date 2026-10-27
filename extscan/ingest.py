"""Load meta.json rows, verify hashes, and extract archives safely."""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import stat
import zipfile
from pathlib import Path, PurePosixPath

from .config import ExtractLimits, Settings
from .manifest import ManifestError, read_manifest, resolve_msg
from .record import (STATUS_FAILED, STATUS_HASH_MISMATCH, STATUS_OK,
                     STATUS_SKIPPED, Record)

_SAFE_ID = re.compile(r"^[A-Za-z0-9._-]+$")


class UnsafeArchive(Exception):
    pass


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _safe_member_path(name: str) -> PurePosixPath:
    """Validate a zip member name; return a relative POSIX path or raise."""
    if "\x00" in name or "\\" in name:
        raise UnsafeArchive(f"suspicious member name: {name!r}")
    p = PurePosixPath(name)
    if p.is_absolute() or re.match(r"^[A-Za-z]:", name):
        raise UnsafeArchive(f"absolute path in archive: {name!r}")
    if ".." in p.parts:
        raise UnsafeArchive(f"path traversal in archive: {name!r}")
    return p


def safe_extract(zip_path: Path, dest: Path, limits: ExtractLimits) -> tuple[int, int]:
    """Extract into `dest` (must not exist). Returns (file_count, total_bytes).

    Guards: zip-slip, absolute paths, symlinks, file count, per-file and total size
    (measured on bytes actually written, not header claims), and compression ratio.
    """
    zsize = max(zip_path.stat().st_size, 1)
    dest.mkdir(parents=True)
    dest_real = dest.resolve()
    files = total = 0
    try:
        with zipfile.ZipFile(zip_path) as zf:
            infos = zf.infolist()
            if len(infos) > limits.max_files:
                raise UnsafeArchive(f"too many entries: {len(infos)}")
            if sum(i.file_size for i in infos) > limits.max_total_bytes:
                raise UnsafeArchive("declared uncompressed size exceeds cap")
            for info in infos:
                rel = _safe_member_path(info.filename)
                mode = info.external_attr >> 16
                if stat.S_ISLNK(mode):
                    raise UnsafeArchive(f"symlink in archive: {info.filename!r}")
                target = (dest / Path(*rel.parts)).resolve()
                if not target.is_relative_to(dest_real):
                    raise UnsafeArchive(f"escapes destination: {info.filename!r}")
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                written = 0
                with zf.open(info) as src, target.open("wb") as out:
                    while chunk := src.read(1 << 16):
                        written += len(chunk)
                        total += len(chunk)
                        if written > limits.max_file_bytes:
                            raise UnsafeArchive(f"file too large: {info.filename!r}")
                        if total > limits.max_total_bytes:
                            raise UnsafeArchive("total extracted size exceeds cap")
                        out.write(chunk)
                files += 1
            if total / zsize > limits.max_ratio:
                raise UnsafeArchive(f"compression ratio {total // zsize}:1 exceeds cap")
    except BaseException:
        shutil.rmtree(dest, ignore_errors=True)
        raise
    return files, total


def load_meta(input_dir: Path) -> list[tuple[Path, dict]]:
    """Return (folder_path, meta) for each subfolder, sorted. Unreadable meta -> {'_error': msg}."""
    rows = []
    for d in sorted(p for p in input_dir.iterdir() if p.is_dir()):
        mp = d / "meta.json"
        try:
            meta = json.loads(mp.read_text(encoding="utf-8-sig"))
            if not isinstance(meta, dict):
                raise ValueError("not an object")
        except (OSError, ValueError) as e:
            meta = {"_error": f"meta.json unreadable: {e}", "folder": d.name}
        rows.append((d, meta))
    return rows


def ingest_one(folder: Path, meta: dict, st: Settings) -> Record:
    rec = Record(
        ext_id=str(meta.get("id") or ""),
        tier=str(meta.get("tier") or ""),
        folder=folder.name,
        raw_name=str(meta.get("name") or ""),
        name=str(meta.get("name") or ""),
        version=str(meta.get("version") or ""),
        manifest_version=meta.get("manifest_version"),
        zip_sha256_expected=str(meta.get("zip_sha256") or ""),
    )

    def fail(status: str, reason: str) -> Record:
        rec.ingest_status, rec.ingest_reason = status, reason
        return rec

    if "_error" in meta:
        return fail(STATUS_FAILED, meta["_error"])
    if meta.get("status") != "ok":
        return fail(STATUS_SKIPPED, f"meta status={meta.get('status')!r}: {meta.get('error')}")
    if not _SAFE_ID.match(rec.ext_id):
        return fail(STATUS_FAILED, f"unsafe or missing id: {rec.ext_id!r}")

    zip_path = folder / f"{meta.get('folder') or folder.name}.zip"
    if not zip_path.is_file():
        return fail(STATUS_FAILED, f"zip not found: {zip_path.name}")
    rec.zip_sha256_actual = sha256_file(zip_path)
    if rec.zip_sha256_actual != rec.zip_sha256_expected:
        return fail(STATUS_HASH_MISMATCH, "zip_sha256 does not match meta.json")

    dest = st.unpacked_dir / rec.ext_id
    if dest.exists():
        shutil.rmtree(dest)
    try:
        rec.file_count, rec.unpacked_bytes = safe_extract(zip_path, dest, st.extract)
    except UnsafeArchive as e:
        return fail(STATUS_FAILED, f"unsafe archive: {e}")
    except (zipfile.BadZipFile, OSError) as e:
        return fail(STATUS_FAILED, f"extract error: {e}")
    rec.unpacked_path = str(dest.relative_to(st.root))

    try:
        mf = read_manifest(dest)
    except ManifestError as e:
        return fail(STATUS_FAILED, str(e))
    loc = mf.get("default_locale")
    rec.raw_name = str(mf.get("name", rec.raw_name))
    rec.name = resolve_msg(mf.get("name"), dest, loc) or rec.name
    rec.description = resolve_msg(mf.get("description"), dest, loc)
    rec.version = str(mf.get("version", rec.version))
    rec.manifest_version = mf.get("manifest_version", rec.manifest_version)
    rec.ingest_status = STATUS_OK
    return rec


def ingest_all(st: Settings, only: list[str] | None = None) -> list[Record]:
    st.unpacked_dir.mkdir(parents=True, exist_ok=True)
    out = []
    for folder, meta in load_meta(st.input_dir):
        if only and not any(o in folder.name for o in only):
            continue
        out.append(ingest_one(folder, meta, st))
    return out
