import json

from extscan.record import (Record, read_index, read_records, record_filename, records_dir,
                            write_record, write_records)


def rec(ext_id, folder, **kw):
    return Record(ext_id=ext_id, folder=folder, tier="1M+", name=ext_id, ingest_status="ok", **kw)


def test_one_file_per_record_and_roundtrip(tmp_path):
    a, b = rec("aaa", "t__a__aaa", manifest={"x": 1}), rec("bbb", "t__b__bbb")
    write_records([b, a], tmp_path)
    assert sorted(p.name for p in records_dir(tmp_path).glob("*.json")) == ["aaa.json", "bbb.json"]
    got = read_records(tmp_path)
    assert [r.ext_id for r in got] == ["aaa", "bbb"] and got[0].manifest == {"x": 1}


def test_index_tracks_filled_stages(tmp_path):
    write_records([rec("aaa", "t__a__aaa")], tmp_path)
    assert read_index(tmp_path)["aaa.json"]["stages_filled"] == []
    r = rec("aaa", "t__a__aaa", scan={"v": 1})
    write_record(r, tmp_path)
    e = read_index(tmp_path)["aaa.json"]
    assert e["stages_filled"] == ["scan"] and e["tier"] == "1M+"
    assert len(read_index(tmp_path)) == 1


def test_unsafe_or_missing_id_uses_folder_name(tmp_path):
    assert record_filename(rec("../x", "tier__ok")) == "tier__ok.json"
    assert record_filename(rec("", "tier__ok")) == "tier__ok.json"
    write_record(rec("../x", "tier__ok"), tmp_path)
    assert (records_dir(tmp_path) / "tier__ok.json").is_file() and not (tmp_path / "x.json").exists()


def test_partial_write_keeps_others_and_prune_removes_them(tmp_path):
    write_records([rec("aaa", "t__a__aaa"), rec("bbb", "t__b__bbb")], tmp_path)
    write_records([rec("aaa", "t__a__aaa", scan={"v": 1})], tmp_path)           # e.g. ingest --only
    assert {r.ext_id for r in read_records(tmp_path)} == {"aaa", "bbb"}
    write_records([rec("aaa", "t__a__aaa")], tmp_path, prune=True)               # full ingest
    assert [r.ext_id for r in read_records(tmp_path)] == ["aaa"]
    assert list(read_index(tmp_path)) == ["aaa.json"]


def test_no_tmp_files_left_and_valid_json(tmp_path):
    write_record(rec("aaa", "t__a__aaa"), tmp_path)
    assert not list(tmp_path.rglob("*.tmp"))
    json.loads((records_dir(tmp_path) / "aaa.json").read_text())
