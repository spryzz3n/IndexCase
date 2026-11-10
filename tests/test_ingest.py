import json
from datetime import UTC, datetime

from indexcase.ingest.evtx_reader import find_logs, iter_records
from indexcase.normalize.schema import SCHEMA, empty_row, read_events, write_events
from indexcase.timeutil import iso, parse_ts


def _record(rid: int, eid: int = 4624) -> dict:
    return {
        "Event": {
            "System": {
                "EventID": eid,
                "EventRecordID": rid,
                "Channel": "Security",
                "Computer": "WS01.lab.local",
                "TimeCreated": {"#attributes": {"SystemTime": "2026-03-02T09:00:00.000000Z"}},
            },
            "EventData": {"TargetUserName": "alice"},
        }
    }


def test_jsonl_reader_skips_bad_lines(tmp_path):
    logs = tmp_path / "ws01"
    logs.mkdir()
    lines = [json.dumps(_record(1)), "", "not json", "[1, 2]", json.dumps(_record(2))]
    (logs / "security.jsonl").write_text("\n".join(lines), encoding="utf-8")
    (logs / "notes.txt").write_text("ignored", encoding="utf-8")

    files = find_logs(tmp_path)
    assert [f.name for f in files] == ["security.jsonl"]
    records = list(iter_records(files[0]))
    assert [r["Event"]["System"]["EventRecordID"] for r in records] == [1, 2]


def test_parse_ts_normalizes_to_utc():
    assert parse_ts("2026-03-02T09:00:00.500000Z") == datetime(
        2026, 3, 2, 9, 0, 0, 500000, tzinfo=UTC
    )
    assert parse_ts("2026-03-02T14:30:00+05:30") == datetime(2026, 3, 2, 9, 0, tzinfo=UTC)
    assert parse_ts("2026-03-02T09:00:00") == datetime(2026, 3, 2, 9, 0, tzinfo=UTC)
    assert parse_ts("garbage") is None
    assert parse_ts(None) is None
    assert iso(datetime(2026, 3, 2, 9, 0, tzinfo=UTC)) == "2026-03-02T09:00:00.000Z"


def test_schema_round_trip(tmp_path):
    row = empty_row()
    row.update(
        event_ref="ws01:Security:1",
        ts_utc=datetime(2026, 3, 2, 9, 0, tzinfo=UTC),
        host="ws01",
        channel="Security",
        event_id=4624,
        category="logon",
        user="lab\alice",
        logon_type=3,
    )
    path = tmp_path / "case.parquet"
    write_events([row], path)

    back = read_events(path)
    assert back == [row]
    assert set(back[0]) == set(SCHEMA)
