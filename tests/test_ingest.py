import hashlib
import json
import stat
import zipfile

import pytest

from extscan.config import ExtractLimits
from extscan.ingest import UnsafeArchive, ingest_one, safe_extract
from extscan.manifest import resolve_msg


def make_zip(path, entries, symlinks=()):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
        for name, target in symlinks:
            zi = zipfile.ZipInfo(name)
            zi.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(zi, target)


def test_zip_slip(tmp_path):
    z = tmp_path / "a.zip"
    make_zip(z, {"../evil.txt": "x"})
    with pytest.raises(UnsafeArchive):
        safe_extract(z, tmp_path / "out", ExtractLimits())
    assert not (tmp_path / "out").exists() and not (tmp_path / "evil.txt").exists()


def test_absolute_path(tmp_path):
    z = tmp_path / "a.zip"
    make_zip(z, {"/etc/x": "x"})
    with pytest.raises(UnsafeArchive):
        safe_extract(z, tmp_path / "out", ExtractLimits())


def test_symlink(tmp_path):
    z = tmp_path / "a.zip"
    make_zip(z, {"manifest.json": "{}"}, symlinks=[("link", "/etc/passwd")])
    with pytest.raises(UnsafeArchive, match="symlink"):
        safe_extract(z, tmp_path / "out", ExtractLimits())


def test_size_caps(tmp_path):
    z = tmp_path / "a.zip"
    make_zip(z, {"big.js": "a" * 5000})
    with pytest.raises(UnsafeArchive):
        safe_extract(z, tmp_path / "o1", ExtractLimits(max_file_bytes=1000))
    with pytest.raises(UnsafeArchive):
        safe_extract(z, tmp_path / "o2", ExtractLimits(max_total_bytes=1000))
    with pytest.raises(UnsafeArchive, match="ratio"):
        safe_extract(z, tmp_path / "o3", ExtractLimits(max_ratio=2))
    with pytest.raises(UnsafeArchive):
        safe_extract(z, tmp_path / "o4", ExtractLimits(max_files=0))


def test_normal_extract(tmp_path):
    z = tmp_path / "a.zip"
    make_zip(z, {"manifest.json": "{}", "js/a.js": "1"})
    assert safe_extract(z, tmp_path / "out", ExtractLimits()) == (2, 3)
    assert (tmp_path / "out/js/a.js").read_text() == "1"


def _project(tmp_path, meta_over=None, zip_entries=None, corrupt_hash=False):
    root = tmp_path / "proj"
    (root / "config").mkdir(parents=True)
    (root / "extension-targets").mkdir()
    folder = root / "extension-targets" / "tier__x__abc"
    folder.mkdir()
    zp = folder / "tier__x__abc.zip"
    make_zip(zp, zip_entries or {"manifest.json": json.dumps({"name": "X", "version": "1", "manifest_version": 3})})
    sha = hashlib.sha256(zp.read_bytes()).hexdigest()
    meta = {"id": "abc", "tier": "1M+", "folder": "tier__x__abc", "status": "ok", "name": "X",
            "zip_sha256": "0" * 64 if corrupt_hash else sha}
    meta.update(meta_over or {})
    return _st(root), folder, meta


def _st(root):
    from extscan.config import Settings
    return Settings(root, root / "extension-targets", root / "work", root / "work/unpacked",
                    root / "out", ExtractLimits())


def test_ingest_ok_and_bom_and_msg(tmp_path):
    mf = "﻿" + json.dumps({"name": "__MSG_appName__", "default_locale": "en", "version": "2",
                                "manifest_version": 3, "description": "__MSG_desc__"})
    st, folder, meta = _project(tmp_path, zip_entries={
        "manifest.json": mf,
        "_locales/en/messages.json": json.dumps({"appName": {"message": "Real Name"}, "DESC": {"message": "d"}}),
    })
    r = ingest_one(folder, meta, st)
    assert r.ingest_status == "ok", r.ingest_reason
    assert (r.name, r.raw_name, r.description, r.version) == ("Real Name", "__MSG_appName__", "d", "2")
    assert (st.unpacked_dir / "abc" / "manifest.json").is_file()


def test_ingest_hash_mismatch(tmp_path):
    st, folder, meta = _project(tmp_path, corrupt_hash=True)
    r = ingest_one(folder, meta, st)
    assert r.ingest_status == "hash_mismatch"
    assert not (st.unpacked_dir / "abc").exists()


def test_ingest_skips_non_ok(tmp_path):
    st, folder, meta = _project(tmp_path, {"status": "not_found", "error": "404"})
    r = ingest_one(folder, meta, st)
    assert r.ingest_status == "skipped" and "404" in r.ingest_reason


def test_ingest_bad_manifest(tmp_path):
    st, folder, meta = _project(tmp_path, zip_entries={"manifest.json": "{not json"})
    assert ingest_one(folder, meta, st).ingest_status == "failed"


def test_ingest_unsafe_id(tmp_path):
    st, folder, meta = _project(tmp_path, {"id": "../x"})
    assert ingest_one(folder, meta, st).ingest_status == "failed"


def test_msg_unresolved_returns_input(tmp_path):
    assert resolve_msg("__MSG_nope__", tmp_path, "en") == "__MSG_nope__"
    assert resolve_msg("Plain", tmp_path, None) == "Plain"
