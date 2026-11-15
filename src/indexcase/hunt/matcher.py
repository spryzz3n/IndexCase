"""Score hosts against a malware profile and find when each was first seen infected."""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta

from indexcase.config import DEFAULT, Config
from indexcase.normalize.mappers import basename
from indexcase.profile.models import Indicator, MalwareProfile
from indexcase.timeutil import iso

# indicator kind -> (event fields to test, compare on basename only)
_FIELDS: dict[str, tuple[tuple[str, ...], bool]] = {
    "sha256": (("sha256",), False),
    "filenames": (("process_path", "file_path"), True),
    "paths": (("process_path", "file_path"), False),
    "pipes": (("pipe_name",), False),
    "registry_set": (("registry_key",), False),
    "domains": (("dns_query",), False),
    "cmdline": (("cmdline",), False),
    "services": (("service_name",), False),
    "tasks": (("task_name",), False),
}


@dataclass(frozen=True)
class CompiledIndicator:
    id: str
    weight: float
    test: Callable[[dict], bool]


def _string_test(ind: Indicator) -> Callable[[str], bool]:
    if ind.regex is not None:
        rx = re.compile(ind.regex)
        return lambda s: rx.search(s) is not None
    want = ind.value.casefold()
    return lambda s: s.casefold() == want


def _field_test(ind: Indicator, fields: tuple[str, ...], base: bool) -> Callable[[dict], bool]:
    check = _string_test(ind)

    def test(ev: dict) -> bool:
        for f in fields:
            v = ev[f]
            if v and check(basename(v) if base else v):
                return True
        return False

    return test


def compile_profile(profile: MalwareProfile) -> list[CompiledIndicator]:
    out: list[CompiledIndicator] = []
    for kind, (fields, base) in _FIELDS.items():
        for i, ind in enumerate(getattr(profile.indicators, kind)):
            label = ind.value if ind.value is not None else f"#{i}"
            if kind == "sha256":
                label = label[:12]
            name = f"{ind.origin}:{label}" if ind.origin else f"{kind}:{label}"
            out.append(CompiledIndicator(name, ind.weight, _field_test(ind, fields, base)))
    for b in profile.behaviors:
        parent, child = re.compile(b.parent), re.compile(b.child)

        def test(ev: dict, parent=parent, child=child) -> bool:
            return bool(
                ev["parent_path"]
                and ev["process_path"]
                and parent.search(ev["parent_path"])
                and child.search(ev["process_path"])
            )

        out.append(CompiledIndicator(f"behavior:{b.name}", b.weight, test))
    return out


class Matcher:
    """Matches single events against a profile, with a per-event cache."""

    def __init__(self, profile: MalwareProfile) -> None:
        self.profile = profile
        self.indicators = compile_profile(profile)
        self._cache: dict[str, list[CompiledIndicator]] = {}

    def match(self, ev: dict) -> list[CompiledIndicator]:
        ref = ev["event_ref"]
        hit = self._cache.get(ref)
        if hit is None:
            hit = [c for c in self.indicators if c.test(ev)]
            self._cache[ref] = hit
        return hit

    def weight(self, ev: dict) -> float:
        return max((c.weight for c in self.match(ev)), default=0.0)


def coverage(events: list[dict]) -> dict[str, dict]:
    """First and last event per host and per channel: what the logs can and cannot show."""
    cov: dict[str, dict] = {}
    for ev in events:
        ts = ev["ts_utc"]
        c = cov.setdefault(ev["host"], {"start": ts, "end": ts, "events": 0, "channels": {}})
        c["start"] = min(c["start"], ts)
        c["end"] = max(c["end"], ts)
        c["events"] += 1
        ch = c["channels"]
        ch[ev["channel"]] = min(ch.get(ev["channel"], ts), ts)
    return cov


def hunt(
    events: list[dict],
    profile: MalwareProfile,
    matcher: Matcher | None = None,
    cfg: Config = DEFAULT,
) -> dict:
    """Score every host against the profile."""
    matcher = matcher or Matcher(profile)
    cov = coverage(events)
    threshold = profile.matching.infected_threshold

    # host -> indicator id -> [weight, count, first_ts, first_ref]
    per_host: dict[str, dict[str, list]] = defaultdict(dict)
    first_hit: dict[str, dict] = {}
    for ev in events:
        hits = matcher.match(ev)
        if not hits:
            continue
        host = ev["host"]
        if host not in first_hit or ev["ts_utc"] < first_hit[host]["ts_utc"]:
            first_hit[host] = ev
        for c in hits:
            slot = per_host[host].get(c.id)
            if slot is None:
                per_host[host][c.id] = [c.weight, 1, ev["ts_utc"], ev["event_ref"]]
            else:
                slot[1] += 1
                if ev["ts_utc"] < slot[2]:
                    slot[2], slot[3] = ev["ts_utc"], ev["event_ref"]

    hosts: dict[str, dict] = {}
    margin = timedelta(seconds=cfg.log_start_margin_s)
    for host, inds in per_host.items():
        score = round(sum(v[0] for v in inds.values()), 3)
        if score >= threshold:
            status = "infected"
        elif score >= 0.5 * threshold:
            status = "suspected"
        else:
            continue
        first = first_hit.get(host)
        at_log_start = False
        if first is not None:
            # the log for that channel starts right where the infection does:
            # the real start is probably earlier and has rolled over
            channel_start = cov[host]["channels"][first["channel"]]
            at_log_start = first["ts_utc"] - channel_start <= margin
        ordered = sorted(inds.items(), key=lambda kv: (kv[1][2], kv[0]))
        hosts[host] = {
            "status": status,
            "score": score,
            "t_first_seen": iso(first["ts_utc"]) if first else None,
            "first_seen_ref": first["event_ref"] if first else None,
            "first_seen_at_log_start": at_log_start,
            "matches": [
                {
                    "indicator": ind,
                    "weight": v[0],
                    "count": v[1],
                    "first_ts": iso(v[2]),
                    "first_ref": v[3],
                }
                for ind, v in ordered
            ],
        }

    def by_time(item: tuple[str, dict]) -> tuple:
        t = item[1]["t_first_seen"]
        return (t is None, t or "", item[0])

    return {
        "profile": profile.name,
        "infected_threshold": threshold,
        "hosts": dict(sorted(hosts.items(), key=by_time)),
        "coverage": {
            h: {
                "start": iso(c["start"]),
                "end": iso(c["end"]),
                "events": c["events"],
                "channels": {ch: iso(t) for ch, t in sorted(c["channels"].items())},
            }
            for h, c in sorted(cov.items())
        },
    }
