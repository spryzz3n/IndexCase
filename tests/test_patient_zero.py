from datetime import UTC, datetime, timedelta
from itertools import count
from pathlib import Path

import pytest

from indexcase.correlate.index import EventIndex
from indexcase.graph.patient_zero import naive_baseline, rank
from indexcase.hunt.matcher import Matcher
from indexcase.normalize.schema import empty_row
from indexcase.profile.models import load_profile
from indexcase.timeutil import iso

PROFILE = Path(__file__).resolve().parents[1] / "profiles" / "labworm.yaml"
T0 = datetime(2026, 11, 1, 9, 0, tzinfo=UTC)
WORM = r"C:\Windows\Temp\svchost32.exe"
WORM_SHA256 = "85a7bef889d2be5d3ff145fc8e1d1af1250431fd70bd4f17de47b0edfb64ee2b"
SYSMON = "Microsoft-Windows-Sysmon/Operational"
_ids = count(1)


@pytest.fixture(scope="module")
def matcher():
    return Matcher(load_profile(PROFILE))


def mins(m):
    return T0 + timedelta(minutes=m)


def proc(host, t, path, parent, guid=None, parent_guid=None, **fields):
    r = empty_row()
    r.update(
        event_ref=f"{host}:{SYSMON}:{next(_ids)}",
        ts_utc=t,
        host=host,
        channel=SYSMON,
        category="process",
        process_path=path,
        parent_path=parent,
        process_guid=guid,
        parent_guid=parent_guid,
        **fields,
    )
    return r


def node(name, kind="infected", minute=None, truncated=False):
    return {
        "id": name,
        "kind": kind,
        "t_first_seen": iso(mins(minute)) if minute is not None else None,
        "first_seen_at_log_start": truncated,
    }


def edge(src, dst, minute):
    return {"src": src, "dst": dst, "t_logon": mins(minute)}


def chain():
    """ws01 -> ws02 -> ws03, ten minutes apart."""
    nodes = [node("ws01", minute=0), node("ws02", minute=10), node("ws03", minute=20)]
    return nodes, [edge("ws01", "ws02", 9), edge("ws02", "ws03", 19)]


def test_single_root_of_a_chain(matcher):
    nodes, tree = chain()
    (top,) = rank(nodes, tree, EventIndex([]), matcher, {})
    assert top["host"] == "ws01"
    assert top["rank"] == 1
    assert top["reaches"] == ["ws01", "ws02", "ws03"]
    assert top["terms"] == {
        "earliness": 1.0,
        "coverage": 1.0,
        "initial_access": 0.0,
        "completeness": 1.0,
        "unexplained_auth": 0.0,
    }
    assert top["score"] == 0.8
    assert top["reason"] == (
        "ws01: first seen 09:00:00 UTC (earliest), reaches 3 of 3 infected hosts."
    )


def test_initial_access_ancestor_found_through_the_process_tree(matcher):
    nodes, tree = chain()
    events = [
        proc("ws01", mins(-1), r"C:\Program Files\Office\WINWORD.EXE", r"C:\x\explorer.exe", "{w}"),
        proc("ws01", mins(-1), r"C:\Windows\System32\cmd.exe", "winword.exe", "{c}", "{w}"),
        proc("ws01", mins(0), WORM, r"C:\Windows\System32\cmd.exe", "{m}", "{c}",
             sha256=WORM_SHA256),
    ]  # fmt: skip
    (top,) = rank(nodes, tree, EventIndex(events), matcher, {})
    assert top["terms"]["initial_access"] == 1.0
    assert top["score"] == 1.0
    assert "winword.exe is an ancestor of the first malicious process" in top["reason"]


def test_coverage_beats_a_slightly_earlier_isolated_host(matcher):
    nodes, tree = chain()
    nodes.append(node("ws09", minute=-1))  # infected a minute earlier, spread nowhere
    first, second = rank(nodes, tree, EventIndex([]), matcher, {})
    assert (first["host"], second["host"]) == ("ws01", "ws09")
    assert first["first_infected_host"] == "ws01"
    assert second["reaches"] == ["ws09"]


def test_truncated_log_and_unexplained_logon_lower_the_score(matcher):
    nodes, tree = chain()
    nodes[0]["first_seen_at_log_start"] = True
    (top,) = rank(nodes, tree, EventIndex([]), matcher, {"ws01": ["ws01:Security:7"]})
    assert top["terms"]["completeness"] == 0.0
    assert top["terms"]["unexplained_auth"] == 1.0
    assert top["score"] == pytest.approx(0.55)
    assert top["unexplained_refs"] == ["ws01:Security:7"]
    assert "the real start may be earlier" in top["reason"]


def test_unresolved_source_ranked_with_its_first_push(matcher):
    nodes = [node("ip:10.10.10.100", kind="unresolved_ip"), node("ws02", minute=10)]
    tree = [edge("ip:10.10.10.100", "ws02", 9)]
    (top,) = rank(nodes, tree, EventIndex([]), matcher, {})
    assert top["host"] == "ip:10.10.10.100"
    assert top["first_infected_host"] == "ws02"
    assert top["t_first_activity"] == iso(mins(9))
    assert "never resolved to a host with logs" in top["reason"]
    assert "first activity 09:09:00 UTC" in top["reason"]


def test_nothing_to_rank_without_infected_hosts(matcher):
    nodes = [node("ws01", kind="suspected", minute=0)]
    assert rank(nodes, [], EventIndex([]), matcher, {}) == []


def test_naive_baseline_is_the_earliest_infected_host():
    hunt_result = {
        "hosts": {
            "ws02": {"status": "infected", "t_first_seen": iso(mins(10))},
            "ws01": {"status": "infected", "t_first_seen": iso(mins(5))},
            "ws00": {"status": "suspected", "t_first_seen": iso(mins(0))},
        }
    }
    assert naive_baseline(hunt_result) == {"host": "ws01", "t_first_seen": iso(mins(5))}
    assert naive_baseline({"hosts": {}}) is None
