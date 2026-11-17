"""Evidence-chain finders: turn "malware ran on B" into A -> B edges.

An edge needs a remote-execution anchor on B (a service install) that is tied
to the malware profile, plus an authentication that says where it came from.
Everything else is supporting evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta

from indexcase.config import DEFAULT, Config
from indexcase.correlate.index import EventIndex
from indexcase.hunt.matcher import Matcher
from indexcase.normalize.mappers import bare_user, basename
from indexcase.profile.models import MalwareProfile

TECHNIQUES = {
    "service": ("T1021.002+T1569.002", "SMB + service execution"),
}

# SYSTEM, LOCAL SERVICE, NETWORK SERVICE sessions never identify a remote caller
SYSTEM_LOGON_IDS = {"0x3e7", "0x3e5", "0x3e4"}

_ADMIN_SHARE = re.compile(r"(?i)\\(admin|c|ipc)\$")
_TOOL_PIPE = re.compile(r"(?i)\\?(psexesvc|remcom)")


@dataclass
class Anchor:
    kind: str
    ev: dict
    weight: float
    refs: list[str]


def _human(ev: dict) -> bool:
    name = bare_user(ev["user"])
    return bool(name) and not name.endswith("$") and name != "anonymous logon"


def _source(ev: dict) -> str | None:
    if ev["src_host"]:
        return ev["src_host"]
    return f"ip:{ev['src_ip']}" if ev["src_ip"] else None


class Correlator:
    def __init__(
        self,
        events: list[dict],
        hunt_result: dict,
        profile: MalwareProfile,
        matcher: Matcher | None = None,
        cfg: Config = DEFAULT,
        index: EventIndex | None = None,
    ) -> None:
        self.cfg = cfg
        self.idx = index or EventIndex(events)
        self.m = matcher or Matcher(profile)
        self.hosts: dict[str, dict] = hunt_result["hosts"]
        self.window = timedelta(minutes=profile.matching.window_minutes)
        self.tol = timedelta(seconds=profile.matching.clock_tolerance_seconds)
        hint = profile.propagation.service_name_regex
        self._svc_hint = re.compile(hint) if hint else None

    # --- anchors ---------------------------------------------------------------

    def _payload(self, host: str, t: datetime, follow_s: int, parents: set[str]) -> dict | None:
        """First profile-matching process started by one of `parents` shortly after `t`."""
        for p in self.idx.on(host, "process", t, t + timedelta(seconds=follow_s)):
            if basename(p["parent_path"]) in parents and self.m.weight(p) > 0:
                return p
        return None

    def _service_anchors(self, host: str) -> list[Anchor]:
        groups: list[list[dict]] = []
        for ev in self.idx.on(host, "service_install"):
            last = groups[-1][0] if groups else None
            same = (
                last is not None
                and last["service_name"] == ev["service_name"]
                and ev["ts_utc"] - last["ts_utc"] <= timedelta(seconds=5)
            )
            if same:
                groups[-1].append(ev)  # 4697 and 7045 for the same install
            else:
                groups.append([ev])

        out = []
        for g in groups:
            ev = next((e for e in g if e["logon_id"]), g[0])
            weight = max(self.m.weight(e) for e in g)
            refs = [e["event_ref"] for e in g]
            payload = self._payload(
                host, g[0]["ts_utc"], self.cfg.service_follow_s, {"services.exe"}
            )
            if payload:
                weight = max(weight, self.m.weight(payload))
                refs.append(payload["event_ref"])
            if weight == 0:
                name = ev["service_name"] or ""
                if not (self._svc_hint and self._svc_hint.search(name)):
                    continue
                weight = 0.3
            out.append(Anchor("service", ev, weight, refs))
        return out

    def anchors(self, host: str) -> list[Anchor]:
        return self._service_anchors(host)

    # --- authentication --------------------------------------------------------

    def _find_logon(self, host: str, anchor: Anchor) -> tuple[dict | None, bool, int, bool]:
        """Return (logon, tied_by_logon_id, distinct_sources_in_window, is_local)."""
        t = anchor.ev["ts_utc"]
        lid = anchor.ev["logon_id"]
        if lid and lid not in SYSTEM_LOGON_IDS:
            sessions = [
                s for s in self.idx.logons.get((host, lid), []) if s["ts_utc"] <= t + self.tol
            ]
            remote = [
                s for s in sessions if s["logon_type"] == 3 and _source(s) not in (None, host)
            ]
            if remote:
                return remote[-1], True, 1, False
            if sessions:
                return None, False, 0, True  # started from a local or interactive session

        cands = [
            s
            for s in self.idx.on(host, "logon", t - self.window, t + self.tol)
            if s["logon_type"] == 3 and _human(s) and _source(s) not in (None, host)
        ]
        if not cands:
            return None, False, 0, False
        before = [s for s in cands if s["ts_utc"] <= t] or cands
        return before[-1], False, len({_source(s) for s in cands}), False

    def _source_side_auth(self, host: str, t: datetime) -> dict | None:
        """4648 on the source or a DC service ticket for the target, when B has no 4624."""
        for cat in ("logon_explicit", "kerberos"):
            evs = [
                e
                for e in self.idx.to(host, cat, t - self.window, t + self.tol)
                if e["src_host"] and e["src_host"] != host and _human(e)
            ]
            if evs:
                return evs[-1]
        return None

    # --- edges -----------------------------------------------------------------

    def _edge(self, dst: str, a: Anchor) -> dict | None:
        t_exec = a.ev["ts_utc"]
        logon, tied, n_sources, local = self._find_logon(dst, a)
        if local:
            return None

        core, support, notes = list(a.refs), [], []
        if logon is not None:
            src = _source(logon)
            t_logon, account, lid = logon["ts_utc"], logon["user"], logon["logon_id"]
            core.insert(0, logon["event_ref"])
            if not tied:
                notes.append("logon tied to execution by time only")
                if n_sources > 1:
                    notes.append(f"{n_sources} possible sources in the window; nearest logon used")
        else:
            alt = self._source_side_auth(dst, t_exec)
            if alt is None:
                return None
            src = alt["src_host"]
            t_logon, account, lid = alt["ts_utc"], alt["user"], None
            support.append(alt["event_ref"])
            notes.append("no network logon on the target; source taken from 4648 / DC ticket")
        if src == dst:
            return None

        # transfer: payload written over an admin share, or seen landing on disk
        for s in self.idx.on(dst, "share_access", t_logon - self.tol, t_exec + self.tol):
            same_session = (lid and s["logon_id"] == lid) or (not lid and _source(s) == src)
            if same_session and _ADMIN_SHARE.search(s["file_path"] or ""):
                support.append(s["event_ref"])
                break
        for f in self.idx.on(dst, "file_create", t_exec - self.window, t_exec + self.tol):
            if self.m.weight(f) > 0:
                support.append(f["event_ref"])
                break

        if lid:
            for p in self.idx.on(dst, "privilege", t_logon - self.tol, t_exec + self.tol):
                if p["logon_id"] == lid:
                    support.append(p["event_ref"])
                    break
        for p in self.idx.on(dst, "pipe", t_logon - self.tol, t_exec + timedelta(seconds=60)):
            if _TOOL_PIPE.search(p["pipe_name"] or ""):
                support.append(p["event_ref"])
                break

        technique, name = TECHNIQUES[a.kind]
        return {
            "src": src,
            "dst": dst,
            "technique": technique,
            "technique_name": name,
            "t_logon": t_logon,
            "t_exec": t_exec,
            "account": account,
            "logon_id": lid,
            "evidence": {"core": core, "support": list(dict.fromkeys(support))},
            "notes": notes,
        }

    def edges(self) -> list[dict]:
        """One edge per source, target and technique: the earliest execution."""
        first: dict[tuple, dict] = {}
        for dst in self.hosts:
            for anchor in self.anchors(dst):
                e = self._edge(dst, anchor)
                if e is not None:
                    first.setdefault((e["src"], e["dst"], e["technique"]), e)
        return sorted(first.values(), key=lambda e: (e["t_exec"], e["src"], e["dst"]))
