from datetime import UTC, datetime, timedelta
from itertools import count
from pathlib import Path

import pytest

from indexcase.correlate.chains import Correlator
from indexcase.correlate.index import EventIndex
from indexcase.hunt.matcher import hunt
from indexcase.normalize.schema import empty_row
from indexcase.profile.models import load_profile

PROFILE = Path(__file__).resolve().parents[1] / "profiles" / "labworm.yaml"
T0 = datetime(2026, 11, 1, 9, 0, tzinfo=UTC)
WORM = r"C:\Windows\Temp\svchost32.exe"
WORM_SHA256 = "85a7bef889d2be5d3ff145fc8e1d1af1250431fd70bd4f17de47b0edfb64ee2b"
SEC, SYS = "Security", "System"
SYSMON = "Microsoft-Windows-Sysmon/Operational"
_ids = count(1)


@pytest.fixture(scope="module")
def profile():
    return load_profile(PROFILE)


def ev(host, ts, category, channel=SEC, **fields):
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


def at(s):
    return T0 + timedelta(seconds=s)


def start(host, t, parent=r"C:\Windows\System32\services.exe"):
    return ev(host, t, "process", SYSMON, process_path=WORM, parent_path=parent, sha256=WORM_SHA256)


def background(*hosts):
    # an hour of quiet log before the incident, so first-seen is not at log start
    return [ev(h, T0 - timedelta(hours=1), "process", SYSMON, process_path="x.exe") for h in hosts]


def psexec_push(src, dst, t, lid="0xa1", src_ip=None, user="lab\\helpdesk1", tie=True):
    """Network logon, admin-share write, service install and payload start on dst."""
    return [
        ev(dst, at(t), "logon", logon_type=3, logon_id=lid, user=user, src_host=src, src_ip=src_ip),
        ev(dst, at(t), "privilege", logon_id=lid, user=user),
        ev(dst, at(t + 1), "share_access", logon_id=lid, file_path="\\\\*\\ADMIN$"),
        ev(
            dst,
            at(t + 2),
            "service_install",
            logon_id=lid if tie else None,
            service_name="LabWormSvc",
            process_path=WORM,
        ),
        ev(dst, at(t + 2), "service_install", SYS, service_name="LabWormSvc", process_path=WORM),
        start(dst, at(t + 3)),
    ]


def correlate(events, profile):
    h = hunt(events, profile)
    return Correlator(events, h, profile, index=EventIndex(events)).edges()


def test_service_push_tied_by_logon_id(profile):
    events = background("ws01", "ws02") + [start("ws01", at(0), r"C:\x\explorer.exe")]
    events += psexec_push("ws01", "ws02", 60)
    (edge,) = correlate(events, profile)

    assert (edge["src"], edge["dst"]) == ("ws01", "ws02")
    assert edge["technique"] == "T1021.002+T1569.002"
    assert edge["account"] == "lab\\helpdesk1"
    assert edge["logon_id"] == "0xa1"
    assert edge["notes"] == []
    core = edge["evidence"]["core"]
    assert len(core) == 4  # logon, 4697, 7045, payload start
    assert len(edge["evidence"]["support"]) == 2  # admin share, privileges


def test_time_only_tie_is_noted(profile):
    events = background("ws01", "ws02") + psexec_push("ws01", "ws02", 60, tie=False)
    (edge,) = correlate(events, profile)
    assert edge["src"] == "ws01"
    assert "logon tied to execution by time only" in edge["notes"]


def test_local_session_gives_no_edge(profile):
    events = background("ws02") + [
        ev("ws02", at(0), "logon", logon_type=2, logon_id="0xb2", user="lab\\alice"),
        ev(
            "ws02",
            at(5),
            "service_install",
            logon_id="0xb2",
            service_name="LabWormSvc",
            process_path=WORM,
        ),
        start("ws02", at(6)),
    ]
    assert correlate(events, profile) == []


def test_unresolved_source_becomes_ip_node(profile):
    events = background("ws02") + psexec_push(None, "ws02", 60, src_ip="10.10.10.100")
    (edge,) = correlate(events, profile)
    assert edge["src"] == "ip:10.10.10.100"


def test_source_side_auth_when_target_has_no_logon(profile):
    events = background("ws01", "ws02") + [
        ev(
            "ws01",
            at(50),
            "logon_explicit",
            user="lab\\helpdesk1",
            src_host="ws01",
            dst_host="ws02",
        ),
        ev("ws02", at(60), "service_install", SYS, service_name="LabWormSvc", process_path=WORM),
        start("ws02", at(61)),
    ]
    (edge,) = correlate(events, profile)
    assert edge["src"] == "ws01"
    assert edge["logon_id"] is None
    assert any("4648" in n for n in edge["notes"])


def test_unrelated_service_ignored(profile):
    events = background("ws01", "ws02") + [start("ws02", at(0), r"C:\x\explorer.exe")]
    events += [
        ev(
            "ws02",
            at(60),
            "logon",
            logon_type=3,
            logon_id="0xc3",
            user="lab\\svc_sccm",
            src_host="ws01",
        ),
        ev(
            "ws02",
            at(61),
            "service_install",
            logon_id="0xc3",
            service_name="CcmExec",
            process_path=r"C:\Windows\CCM\CcmExec.exe",
        ),
    ]
    assert correlate(events, profile) == []


def test_index_lookups():
    events = [
        ev("ws01", at(10), "net_conn", SYSMON, dst_host="ws02", dst_ip="10.0.0.12"),
        ev("ws01", at(0), "net_conn", SYSMON, dst_host="ws03"),
    ]
    idx = EventIndex(events)
    assert [e["dst_host"] for e in idx.on("ws01", "net_conn")] == ["ws03", "ws02"]
    assert len(idx.to("ws02", "net_conn", at(5), at(15))) == 1
    assert idx.to("ws02", "net_conn", at(11)) == []
    assert len(idx.to("ip:10.0.0.12", "net_conn")) == 1
