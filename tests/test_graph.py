from datetime import UTC, datetime, timedelta

from indexcase.graph.build import build_forest, node_kind

T0 = datetime(2026, 11, 1, 9, 0, tzinfo=UTC)


def edge(src, dst, score, minute=0, label=None):
    if label is None:
        label = "confirmed" if score >= 0.7 else "probable" if score >= 0.4 else "candidate"
    return {
        "src": src,
        "dst": dst,
        "score": score,
        "label": label,
        "t_exec": T0 + timedelta(minutes=minute),
    }


def hunt_result(infected=(), suspected=(), logged=()):
    hosts = {h: {"status": "infected", "score": 1.0, "t_first_seen": None} for h in infected}
    hosts |= {h: {"status": "suspected", "score": 0.6, "t_first_seen": None} for h in suspected}
    coverage = dict.fromkeys([*hosts, *logged], {})
    return {"hosts": hosts, "coverage": coverage}


def parents(nodes):
    return {n["id"]: n["parent"] for n in nodes}


def test_best_parent_wins_and_others_kept_as_alternatives():
    edges = [
        edge("ws01", "ws03", 0.55, minute=5),
        edge("ws02", "ws03", 0.95, minute=6),
        edge("ws01", "ws02", 0.90, minute=1),
    ]
    nodes, tree, alt = build_forest(edges, hunt_result(["ws01", "ws02", "ws03"]))
    assert parents(nodes) == {"ws01": None, "ws02": "ws01", "ws03": "ws02"}
    assert [(e["src"], e["dst"]) for e in tree] == [("ws01", "ws02"), ("ws02", "ws03")]
    assert [e["src"] for e in alt["ws03"]] == ["ws01"]


def test_equal_scores_prefer_the_earlier_execution():
    edges = [edge("ws02", "ws03", 0.8, minute=9), edge("ws01", "ws03", 0.8, minute=2)]
    nodes, _, _ = build_forest(edges, hunt_result(["ws01", "ws02", "ws03"]))
    assert parents(nodes)["ws03"] == "ws01"


def test_candidates_never_enter_the_tree():
    edges = [edge("ws01", "ws02", 0.3)]
    nodes, tree, alt = build_forest(edges, hunt_result(["ws01", "ws02"]))
    assert tree == [] and alt == {}
    assert parents(nodes) == {"ws01": None, "ws02": None}


def test_cycle_broken_at_its_weakest_edge():
    # clock skew can make both directions look plausible
    edges = [
        edge("ws01", "ws02", 0.9, minute=1),
        edge("ws02", "ws01", 0.6, minute=2),
        edge("ip:10.10.10.100", "ws01", 0.5, minute=0),
    ]
    nodes, tree, _ = build_forest(edges, hunt_result(["ws01", "ws02"]))
    assert parents(nodes) == {
        "ip:10.10.10.100": None,
        "ws01": "ip:10.10.10.100",
        "ws02": "ws01",
    }
    assert len(tree) == 2


def test_cycle_with_no_fallback_leaves_a_root():
    edges = [edge("ws01", "ws02", 0.9), edge("ws02", "ws01", 0.6)]
    nodes, tree, alt = build_forest(edges, hunt_result(["ws01", "ws02"]))
    assert parents(nodes) == {"ws01": None, "ws02": "ws01"}
    assert [e["src"] for e in alt["ws01"]] == ["ws02"]


def test_node_kinds():
    hr = hunt_result(infected=["ws01"], suspected=["ws02"], logged=["ws04"])
    assert node_kind("ws01", hr) == "infected"
    assert node_kind("ws02", hr) == "suspected"
    assert node_kind("ws04", hr) == "transit"
    assert node_kind("ws05", hr) == "no_logs"
    assert node_kind("ip:10.10.10.100", hr) == "unresolved_ip"


def test_inferred_edge_links_host_without_logs():
    edges = [
        edge("ws01", "ws03", 0.45, minute=1, label="inferred"),
        edge("ws03", "ws02", 0.9, minute=5),
    ]
    nodes, _, _ = build_forest(edges, hunt_result(["ws01", "ws02"]))
    by_id = {n["id"]: n for n in nodes}
    assert by_id["ws03"]["kind"] == "no_logs"
    assert by_id["ws03"]["parent"] == "ws01"
    assert by_id["ws02"]["parent"] == "ws03"
