"""Rank the roots of the propagation forest and explain each ranking."""

from __future__ import annotations

import networkx as nx

from indexcase.config import DEFAULT, Config
from indexcase.correlate.index import EventIndex
from indexcase.hunt.matcher import Matcher
from indexcase.normalize.mappers import basename
from indexcase.timeutil import iso, parse_ts

# a malicious process descending from one of these points at user-driven initial access
INITIAL_ACCESS = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "msaccess.exe",
    "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "brave.exe",
    "thunderbird.exe", "acrord32.exe", "acrobat.exe",
    "7zfm.exe", "7zg.exe", "winrar.exe", "winzip32.exe",
}  # fmt: skip

_NO_LOG_REASON = {
    "transit": "no profile match on this host, but it pushed the malware to others",
    "no_logs": "no logs were collected for this host",
    "unresolved_ip": "source address never resolved to a host with logs",
}


def initial_access(host: str, idx: EventIndex, matcher: Matcher) -> str | None:
    """Name of an Office / browser / mail / archive ancestor of the first malicious processes."""
    hits = [p for p in idx.on(host, "process") if matcher.weight(p) > 0][:5]
    for proc in hits:
        cur = proc
        for _ in range(8):
            name = basename(cur["parent_path"])
            if name in INITIAL_ACCESS:
                return name
            cur = idx.by_guid.get((host, cur["parent_guid"])) if cur["parent_guid"] else None
            if cur is None:
                break
    return None


def naive_baseline(hunt_result: dict) -> dict | None:
    """Patient zero = infected host with the earliest first-seen."""
    infected = [(v["t_first_seen"], h) for h, v in hunt_result["hosts"].items()
                if v["status"] == "infected" and v["t_first_seen"]]  # fmt: skip
    if not infected:
        return None
    t, host = min(infected)
    return {"host": host, "t_first_seen": t}


def rank(
    nodes: list[dict],
    tree: list[dict],
    idx: EventIndex,
    matcher: Matcher,
    unexplained: dict[str, list[str]],
    cfg: Config = DEFAULT,
) -> list[dict]:
    by_id = {n["id"]: n for n in nodes}
    g = nx.DiGraph()
    g.add_nodes_from(by_id)
    g.add_edges_from((e["src"], e["dst"]) for e in tree)

    infected = {n["id"] for n in nodes if n["kind"] == "infected"}
    if not infected:
        return []
    first_seen = {n["id"]: parse_ts(n["t_first_seen"]) for n in nodes if n["t_first_seen"]}

    roots = []
    for r in (n for n in g if g.in_degree(n) == 0):
        reach = (nx.descendants(g, r) | {r}) & infected
        if not reach:
            continue
        # no first-seen: fall back to the first time it pushed the malware, if it ever did
        pushes = [e["t_logon"] for e in tree if e["src"] == r]
        t_root = first_seen.get(r) or (min(pushes) if pushes else None)
        roots.append((r, reach, t_root))

    times = [first_seen[h] for h in infected if h in first_seen]
    times += [t for _, _, t in roots if t is not None]
    t_min = min(times) if times else None
    span = (max(times) - t_min).total_seconds() if times else 0.0

    w = cfg.root
    out = []
    for r, reach, t_root in roots:
        node = by_id[r]
        kind = node["kind"]
        has_match = kind in ("infected", "suspected")
        if t_root is None:
            earliness = 0.0
        else:
            earliness = 1.0 if span == 0 else 1.0 - (t_root - t_min).total_seconds() / span
        coverage = len(reach) / len(infected)
        ancestor = initial_access(r, idx, matcher) if has_match else None
        truncated = bool(node["first_seen_at_log_start"])
        timed = r in first_seen
        if kind == "infected":
            completeness = 0.0 if truncated or not timed else 1.0
        else:
            completeness = 0.5 if kind in ("suspected", "transit") else 0.0
        unexpl = 1.0 if r in unexplained else 0.0

        score = (
            w.earliness * earliness
            + w.coverage * coverage
            + w.initial_access * (1.0 if ancestor else 0.0)
            + w.completeness * completeness
            - w.unexplained_auth * unexpl
        )

        clock = t_root.strftime("%H:%M:%S") if t_root else None
        if has_match and timed:
            parts = [f"first seen {clock} UTC" + (" (earliest)" if t_root == t_min else "")]
        else:
            parts = [_NO_LOG_REASON[kind]]
        if clock and not timed:
            parts.append(f"first activity {clock} UTC")
        parts.append(f"reaches {len(reach)} of {len(infected)} infected hosts")
        if ancestor:
            parts.append(f"{ancestor} is an ancestor of the first malicious process")
        if truncated:
            parts.append(
                "first-seen sits at the start of its log, so the real start may be earlier"
            )
        if unexpl:
            parts.append("unexplained inbound network logon from another matched host just before")

        first_infected = min(reach, key=lambda h: (h not in first_seen, str(first_seen.get(h)), h))
        out.append(
            {
                "host": r,
                "kind": kind,
                "score": round(max(0.0, score), 3),
                "t_first_activity": iso(t_root),
                "first_infected_host": first_infected,
                "reaches": sorted(reach),
                "terms": {
                    "earliness": round(earliness, 3),
                    "coverage": round(coverage, 3),
                    "initial_access": 1.0 if ancestor else 0.0,
                    "completeness": completeness,
                    "unexplained_auth": unexpl,
                },
                "unexplained_refs": unexplained.get(r, []),
                "reason": f"{r}: " + ", ".join(parts) + ".",
            }
        )

    out.sort(key=lambda c: (-c["score"], c["t_first_activity"] or "~", c["host"]))
    for i, c in enumerate(out, 1):
        c["rank"] = i
    return out
