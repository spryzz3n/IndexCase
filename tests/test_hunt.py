from datetime import UTC, datetime, timedelta
from itertools import count
from pathlib import Path

import pytest

from indexcase.hunt.matcher import Matcher, hunt
from indexcase.normalize.schema import empty_row
from indexcase.profile.models import load_profile

PROFILE = Path(__file__).resolve().parents[1] / "profiles" / "labworm.yaml"
T0 = datetime(2026, 11, 1, 9, 0, tzinfo=UTC)
WORM_SHA256 = "85a7bef889d2be5d3ff145fc8e1d1af1250431fd70bd4f17de47b0edfb64ee2b"
SYSMON = "Microsoft-Windows-Sysmon/Operational"
_ids = count(1)


@pytest.fixture(scope="module")
def profile():
    return load_profile(PROFILE)


def ev(host: str, ts: datetime, category: str = "process", channel: str = SYSMON, **fields):
    r = empty_row()
    r.update(
        event_ref=f"{host}:{channel}:{next(_ids)}",
        ts_utc=ts,
        host=host,
        channel=channel,
        category=category,
        **fields,
    )
    return r


def worm_start(host: str, ts: datetime) -> dict:
    return ev(
        host,
        ts,
        process_path=r"C:\Windows\Temp\svchost32.exe",
        parent_path=r"C:\Windows\System32\services.exe",
        sha256=WORM_SHA256,
    )


def test_hunt_separates_infected_suspected_and_clean(profile):
    events = [
        ev("ws01", T0 - timedelta(hours=2), process_path=r"C:\Windows\explorer.exe"),
        worm_start("ws01", T0),
        # ws02: only the weak file name and path, no hash
        ev("ws02", T0, "file_create", file_path=r"C:\Windows\Temp\svchost32.exe"),
        ev("ws03", T0, process_path=r"C:\Windows\System32\notepad.exe"),
    ]
    result = hunt(events, profile)

    ws01 = result["hosts"]["ws01"]
    assert ws01["status"] == "infected"
    assert ws01["t_first_seen"] == "2026-11-01T09:00:00.000Z"
    assert ws01["first_seen_at_log_start"] is False
    assert {m["indicator"] for m in ws01["matches"]} >= {
        "sha256:85a7bef889d2",
        "behavior:service-launch",
    }
    assert result["hosts"]["ws02"]["status"] == "suspected"
    assert result["hosts"]["ws02"]["score"] == 0.8
    assert "ws03" not in result["hosts"]
    assert set(result["coverage"]) == {"ws01", "ws02", "ws03"}


def test_first_seen_at_log_start_is_flagged(profile):
    events = [worm_start("ws01", T0 + timedelta(minutes=2))]
    events.insert(0, ev("ws01", T0, process_path=r"C:\Windows\explorer.exe"))
    result = hunt(events, profile)
    assert result["hosts"]["ws01"]["first_seen_at_log_start"] is True


def test_first_seen_is_earliest_match_and_hosts_are_time_ordered(profile):
    events = [
        ev("ws02", T0 - timedelta(hours=1), process_path=r"C:\Windows\explorer.exe"),
        worm_start("ws02", T0 + timedelta(minutes=30)),
        ev("ws01", T0 - timedelta(hours=1), process_path=r"C:\Windows\explorer.exe"),
        worm_start("ws01", T0 + timedelta(minutes=10)),
        ev("ws01", T0, "dns", dns_query="c2.lab.local"),
    ]
    result = hunt(events, profile)
    assert list(result["hosts"]) == ["ws01", "ws02"]
    assert result["hosts"]["ws01"]["t_first_seen"] == "2026-11-01T09:00:00.000Z"


def test_matcher_caches_by_event_ref(profile):
    m = Matcher(profile)
    e = worm_start("ws01", T0)
    first = m.match(e)
    assert m.match(e) is first
    assert m.weight(e) == 1.0


def test_coverage_records_channel_starts(profile):
    events = [
        ev("ws01", T0, channel="Security", category="logon"),
        ev("ws01", T0 + timedelta(minutes=5)),
    ]
    cov = hunt(events, profile)["coverage"]["ws01"]
    assert cov["events"] == 2
    assert cov["channels"] == {
        "Security": "2026-11-01T09:00:00.000Z",
        SYSMON: "2026-11-01T09:05:00.000Z",
    }
