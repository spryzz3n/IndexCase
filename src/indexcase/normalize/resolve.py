"""IP -> host resolution from what the logs themselves show.

Observation sources, all timestamped so DHCP churn is handled:
  * strong: Sysmon 3, the logging host's own address (SourceIp when it
    initiated the connection, DestinationIp otherwise), and the remote name
    when Sysmon resolved it.
  * weak: 4624 type 3 with both WorkstationName and IpAddress. The client
    chooses WorkstationName, so this is used only when nothing stronger exists.
  * static: an optional map supplied by the analyst (DHCP / DNS export).
"""

from __future__ import annotations

import csv
from bisect import bisect_left
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from indexcase.normalize.mappers import norm_host, norm_ip

Obs = dict[str, list[tuple[datetime, str]]]


def _nearest(obs: list[tuple[datetime, str]], ts: datetime) -> str:
    i = bisect_left(obs, (ts, ""))
    near = [obs[j] for j in (i - 1, i) if 0 <= j < len(obs)]
    return min(near, key=lambda o: abs(o[0] - ts))[1]


class HostResolver:
    def __init__(self) -> None:
        self._strong: Obs = defaultdict(list)
        self._weak: Obs = defaultdict(list)
        self._static: dict[str, str] = {}
        self._sorted = True

    def observe(self, ip: str | None, host: str | None, ts: datetime, strong: bool = True) -> None:
        if ip and host:
            (self._strong if strong else self._weak)[ip].append((ts, host))
            self._sorted = False

    def add_static(self, ip: str, host: str) -> None:
        self._static[ip] = host

    def resolve(self, ip: str | None, ts: datetime) -> str | None:
        """Host that held `ip` closest in time to `ts`."""
        if not ip:
            return None
        if ip in self._static:
            return self._static[ip]
        if not self._sorted:
            for table in (self._strong, self._weak):
                for lst in table.values():
                    lst.sort()
            self._sorted = True
        for table in (self._strong, self._weak):
            obs = table.get(ip)
            if obs:
                return _nearest(obs, ts)
        return None


def load_static_map(path: Path) -> dict[str, str]:
    """CSV with two columns: ip,host (header optional)."""
    out: dict[str, str] = {}
    with path.open(newline="", encoding="utf-8") as fh:
        for row in csv.reader(fh):
            if len(row) < 2:
                continue
            ip, host = norm_ip(row[0]), norm_host(row[1])
            if ip and host:
                out[ip] = host
    return out


def build_resolver(rows: list[dict], static: dict[str, str] | None = None) -> HostResolver:
    res = HostResolver()
    for ip, host in (static or {}).items():
        res.add_static(ip, host)
    for r in rows:
        cat = r["category"]
        if cat == "net_conn":
            res.observe(r["src_ip"], r["src_host"], r["ts_utc"])
            res.observe(r["dst_ip"], r["dst_host"], r["ts_utc"])
        elif cat == "logon" and r["logon_type"] == 3:
            res.observe(r["src_ip"], r["src_host"], r["ts_utc"], strong=False)
    return res


def apply_resolution(rows: list[dict], resolver: HostResolver) -> None:
    """Fill src_host / dst_host in place.

    A resolved source IP overrides WorkstationName, because the client chooses
    that field (Impacket sends arbitrary or empty names).
    """
    for r in rows:
        if r["src_ip"] and (r["category"] != "net_conn" or not r["src_host"]):
            host = resolver.resolve(r["src_ip"], r["ts_utc"])
            if host:
                r["src_host"] = host
        if r["dst_ip"] and not r["dst_host"]:
            r["dst_host"] = resolver.resolve(r["dst_ip"], r["ts_utc"])
