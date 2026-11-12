from datetime import UTC, datetime, timedelta

from indexcase.normalize.resolve import (
    HostResolver,
    apply_resolution,
    build_resolver,
    load_static_map,
)
from indexcase.normalize.schema import empty_row

T0 = datetime(2026, 11, 1, 9, 0, tzinfo=UTC)


def row(category: str, ts: datetime, **fields) -> dict:
    r = empty_row()
    r.update(category=category, ts_utc=ts, **fields)
    return r


def test_resolver_picks_nearest_in_time():
    res = HostResolver()
    res.observe("10.0.0.50", "old", T0)
    res.observe("10.0.0.50", "new", T0 + timedelta(hours=1))
    assert res.resolve("10.0.0.50", T0 + timedelta(minutes=1)) == "old"
    assert res.resolve("10.0.0.50", T0 + timedelta(minutes=58)) == "new"
    assert res.resolve("10.9.9.9", T0) is None
    assert res.resolve(None, T0) is None


def test_strong_beats_weak_and_static_beats_both():
    res = HostResolver()
    res.observe("10.0.0.11", "spoofed", T0, strong=False)
    res.observe("10.0.0.11", "ws01", T0 + timedelta(hours=5))
    assert res.resolve("10.0.0.11", T0) == "ws01"
    res.add_static("10.0.0.11", "pinned")
    assert res.resolve("10.0.0.11", T0) == "pinned"


def test_weak_used_when_nothing_stronger():
    res = HostResolver()
    res.observe("10.0.0.12", "ws02", T0, strong=False)
    assert res.resolve("10.0.0.12", T0) == "ws02"


def test_logon_source_resolved_from_sysmon():
    rows = [
        row(
            "net_conn", T0,
            src_ip="10.0.0.11", src_host="ws01",
            dst_ip="10.0.0.12", dst_host="ws02", dst_port=445,
        ),
        row(
            "logon", T0 + timedelta(seconds=1),
            host="ws02", logon_type=3, src_ip="10.0.0.11", src_host="spoofed",
        ),
    ]
    apply_resolution(rows, build_resolver(rows))
    assert rows[1]["src_host"] == "ws01"  # the resolved IP beats the client-supplied name


def test_net_conn_keeps_own_host_and_fills_missing_destination():
    rows = [
        row("net_conn", T0, src_ip="10.0.0.12", src_host="ws02", dst_ip="10.0.0.13"),
        row("net_conn", T0, src_ip="10.0.0.13", src_host="ws03", dst_ip="10.0.0.12"),
    ]
    apply_resolution(rows, build_resolver(rows))
    assert rows[0]["src_host"] == "ws02"
    assert rows[0]["dst_host"] == "ws03"


def test_load_static_map(tmp_path):
    path = tmp_path / "ips.csv"
    path.write_text("ip,host\n10.0.0.21,WS01.corp.local\nbad\n", encoding="utf-8")
    assert load_static_map(path) == {"10.0.0.21": "ws01"}
