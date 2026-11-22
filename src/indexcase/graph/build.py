"""Prune scored edges to one best parent per host. The result is a forest."""

from __future__ import annotations

from collections import defaultdict

import networkx as nx


def node_kind(name: str, hunt_result: dict) -> str:
    host = hunt_result["hosts"].get(name)
    if host:
        return host["status"]  # infected | suspected
    if name.startswith("ip:"):
        return "unresolved_ip"
    return "transit" if name in hunt_result["coverage"] else "no_logs"


def build_forest(edges: list[dict], hunt_result: dict) -> tuple[list[dict], list[dict], dict]:
    """Return (nodes, tree_edges, alt_parents)."""
    incoming: dict[str, list[dict]] = defaultdict(list)
    for e in edges:
        if e["label"] != "candidate":
            incoming[e["dst"]].append(e)
    for lst in incoming.values():
        lst.sort(key=lambda e: (-e["score"], e["t_exec"]))

    # Start from the best parent everywhere. Clock tolerance can produce
    # A -> B and B -> A at once; break each cycle at its weakest edge and let
    # that host fall back to its next-best parent.
    choice = dict.fromkeys(incoming, 0)
    while True:
        g = nx.DiGraph()
        for dst, i in choice.items():
            if i < len(incoming[dst]):
                e = incoming[dst][i]
                g.add_edge(e["src"], dst, score=e["score"])
        try:
            cycle = nx.find_cycle(g)
        except nx.NetworkXNoCycle:
            break
        weakest = min(cycle, key=lambda uv: g.edges[uv[0], uv[1]]["score"])
        choice[weakest[1]] += 1

    tree, alt = [], {}
    for dst, i in choice.items():
        if i < len(incoming[dst]):
            tree.append(incoming[dst][i])
        others = [e for j, e in enumerate(incoming[dst]) if j != i]
        if others:
            alt[dst] = others
    tree.sort(key=lambda e: e["t_exec"])

    parent = {e["dst"]: e["src"] for e in tree}
    names = set(hunt_result["hosts"]) | set(parent) | set(parent.values())
    nodes = []
    for name in sorted(names):
        host = hunt_result["hosts"].get(name, {})
        nodes.append(
            {
                "id": name,
                "kind": node_kind(name, hunt_result),
                "match_score": host.get("score"),
                "t_first_seen": host.get("t_first_seen"),
                "first_seen_at_log_start": host.get("first_seen_at_log_start", False),
                "parent": parent.get(name),
            }
        )
    return nodes, tree, alt
