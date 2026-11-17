"""Time-sorted lookups over normalized events."""

from __future__ import annotations

from bisect import bisect_left, bisect_right
from collections import defaultdict
from datetime import datetime


class _Series:
    __slots__ = ("events", "ts")

    def __init__(self) -> None:
        self.events: list[dict] = []
        self.ts: list[datetime] = []

    def add(self, ev: dict) -> None:
        self.events.append(ev)
        self.ts.append(ev["ts_utc"])

    def between(self, t0: datetime | None, t1: datetime | None) -> list[dict]:
        lo = 0 if t0 is None else bisect_left(self.ts, t0)
        hi = len(self.ts) if t1 is None else bisect_right(self.ts, t1)
        return self.events[lo:hi]


class EventIndex:
    def __init__(self, events: list[dict]) -> None:
        self._on: dict[tuple[str, str], _Series] = defaultdict(_Series)
        self._to: dict[tuple[str, str], _Series] = defaultdict(_Series)
        self._to_ip: dict[tuple[str, str], _Series] = defaultdict(_Series)
        self.logons: dict[tuple[str, str], list[dict]] = defaultdict(list)
        self.children: dict[tuple[str, str], list[dict]] = defaultdict(list)
        self.by_guid: dict[tuple[str, str], dict] = {}

        for ev in sorted(events, key=lambda e: e["ts_utc"]):
            host, cat = ev["host"], ev["category"]
            self._on[(host, cat)].add(ev)
            if ev["dst_host"] and ev["dst_host"] != host:
                self._to[(ev["dst_host"], cat)].add(ev)
            if ev["dst_ip"]:
                self._to_ip[(ev["dst_ip"], cat)].add(ev)
            if cat == "logon" and ev["logon_id"]:
                self.logons[(host, ev["logon_id"])].append(ev)
            if cat == "process":
                if ev["parent_guid"]:
                    self.children[(host, ev["parent_guid"])].append(ev)
                if ev["process_guid"]:
                    self.by_guid[(host, ev["process_guid"])] = ev

    def on(self, host: str, cat: str, t0=None, t1=None) -> list[dict]:
        """Events of a category logged by `host`."""
        s = self._on.get((host, cat))
        return s.between(t0, t1) if s else []

    def to(self, dst: str, cat: str, t0=None, t1=None) -> list[dict]:
        """Events logged elsewhere that point at `dst` (a host name or 'ip:<addr>')."""
        if dst.startswith("ip:"):
            s = self._to_ip.get((dst[3:], cat))
        else:
            s = self._to.get((dst, cat))
        return s.between(t0, t1) if s else []
