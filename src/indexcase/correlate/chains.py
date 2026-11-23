"""Evidence-chain finders: turn "malware ran on B" into scored A -> B edges.

An edge needs a remote-execution anchor on B (service install, WmiPrvSE child,
scheduled task) that is tied to the malware profile, plus an authentication
that says where it came from. Everything else only raises the score.
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
from indexcase.timeutil import parse_ts

TECHNIQUES = {
    "service": ("T1021.002+T1569.002", "SMB + service execution"),
    "wmi": ("T1047", "WMI"),
    "task": ("T1053.005", "Scheduled task"),
    "unknown": ("unknown", "Inferred from source-side evidence"),
}

# SYSTEM, LOCAL SERVICE, NETWORK SERVICE sessions never identify a remote caller
SYSTEM_LOGON_IDS = {"0x3e7", "0x3e5", "0x3e4"}
LATERAL_PORTS = {135, 445, 5985, 5986}

_ADMIN_SHARE = re.compile(r"(?i)\\(admin|c|ipc)\$")
_TOOL_PIPE = re.compile(r"(?i)\\?(psexesvc|remcom)")
_REMOTE_TOOL = re.compile(
    r"(?i)\b(wmic|schtasks|psexec\w*|sc|invoke-wmimethod|invoke-cimmethod|invoke-command)\b"
)


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
        self.coverage: dict[str, dict] = hunt_result["coverage"]
        self.window = timedelta(minutes=profile.matching.window_minutes)
        self.tol = timedelta(seconds=profile.matching.clock_tolerance_seconds)
        self.first_seen: dict[str, datetime] = {
            h: parse_ts(v["t_first_seen"]) for h, v in self.hosts.items() if v["t_first_seen"]
        }
        infected = [t for h, t in self.first_seen.items() if self.hosts[h]["status"] == "infected"]
        self.incident_start = min(infected) if infected else None
        hint = profile.propagation.service_name_regex
        self._svc_hint = re.compile(hint) if hint else None
        self._baseline_cache: dict[tuple, float] = {}

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

    def _wmi_anchors(self, host: str) -> list[Anchor]:
        out = []
        for p in self.idx.on(host, "process"):
            if basename(p["parent_path"]) != "wmiprvse.exe":
                continue
            weight, refs = self.m.weight(p), [p["event_ref"]]
            if p["process_guid"]:
                # wmiexec.py runs cmd.exe /Q /c <payload>: the payload is a grandchild
                for child in self.idx.children.get((host, p["process_guid"]), []):
                    w = self.m.weight(child)
                    if w > weight:
                        weight = w
                        refs = [p["event_ref"], child["event_ref"]]
            if weight > 0:
                out.append(Anchor("wmi", p, weight, refs))
        return out

    def _task_anchors(self, host: str) -> list[Anchor]:
        out = []
        for ev in self.idx.on(host, "task_create"):
            weight, refs = self.m.weight(ev), [ev["event_ref"]]
            payload = self._payload(
                host, ev["ts_utc"], self.cfg.task_follow_s, {"svchost.exe", "taskeng.exe"}
            )
            if payload:
                weight = max(weight, self.m.weight(payload))
                refs.append(payload["event_ref"])
            if weight > 0:
                out.append(Anchor("task", ev, weight, refs))
        return out

    def anchors(self, host: str) -> list[Anchor]:
        return self._service_anchors(host) + self._wmi_anchors(host) + self._task_anchors(host)

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

    def _baseline(self, account: str | None, src: str, dst: str) -> float:
        """1.0 when this account logs on from src to dst on most days before the incident."""
        if self.incident_start is None or not account:
            return 0.0
        key = (bare_user(account), src, dst)
        if key not in self._baseline_cache:
            start = self.incident_start - timedelta(days=self.cfg.baseline_days)
            days = {
                s["ts_utc"].date()
                for s in self.idx.on(dst, "logon", start, self.incident_start - self.window)
                if s["logon_type"] == 3 and bare_user(s["user"]) == key[0] and _source(s) == src
            }
            self._baseline_cache[key] = 1.0 if len(days) >= self.cfg.baseline_min_days else 0.0
        return self._baseline_cache[key]

    # --- edges -----------------------------------------------------------------

    def _edge(self, dst: str, a: Anchor) -> dict | None:
        cfg, w = self.cfg, self.cfg.edge
        t_exec = a.ev["ts_utc"]
        logon, tied, n_sources, local = self._find_logon(dst, a)
        if local:
            return None

        core, support, notes = list(a.refs), [], []
        if logon is not None:
            src, auth = _source(logon), 1.0
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
            src, auth = alt["src_host"], 0.5
            t_logon, account, lid = alt["ts_utc"], alt["user"], None
            support.append(alt["event_ref"])
            notes.append("no network logon on the target; source taken from 4648 / DC ticket")
        if src == dst:
            return None

        # transfer: payload written over an admin share, or seen landing on disk
        transfer_refs = []
        for s in self.idx.on(dst, "share_access", t_logon - self.tol, t_exec + self.tol):
            same_session = (lid and s["logon_id"] == lid) or (not lid and _source(s) == src)
            if same_session and _ADMIN_SHARE.search(s["file_path"] or ""):
                transfer_refs.append(s["event_ref"])
                break
        for f in self.idx.on(dst, "file_create", t_exec - self.window, t_exec + self.tol):
            if self.m.weight(f) > 0:
                transfer_refs.append(f["event_ref"])
                break
        transfer = 1.0 if transfer_refs else 0.0
        support += transfer_refs

        if lid:
            for p in self.idx.on(dst, "privilege", t_logon - self.tol, t_exec + self.tol):
                if p["logon_id"] == lid:
                    support.append(p["event_ref"])
                    break
        for p in self.idx.on(dst, "pipe", t_logon - self.tol, t_exec + timedelta(seconds=60)):
            if _TOOL_PIPE.search(p["pipe_name"] or ""):
                support.append(p["event_ref"])
                break
        support += self._source_side_support(src, dst, t_logon, t_exec, account)

        window_s = self.window.total_seconds()
        gap = min(1.0, max(0.0, (t_exec - t_logon).total_seconds() / window_s))
        exec_term = 1.0 if tied else 0.5
        match = 1.0 if a.weight >= cfg.strong_weight else 0.5
        # a routine admin logon is only a problem when time is all that links it to the run
        baseline = 0.0 if tied else self._baseline(account, src, dst)
        if baseline:
            notes.append("this account logs on from this source to this host routinely")

        score = min(
            1.0, w.auth * auth + w.transfer * transfer + w.exec * exec_term + w.match * match
        )
        score -= w.gap_penalty * gap + w.baseline_penalty * baseline
        src_first = self.first_seen.get(src)
        if src_first is not None and t_exec + self.tol < src_first:
            score -= w.order_penalty
            notes.append("source shows the malware only after this execution")
        if self.hosts[dst]["status"] == "suspected":
            score = min(score, cfg.suspected_cap)
            notes.append("target is only a suspected match")
        score = round(max(0.0, score), 3)

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
            "score": score,
            "label": self._label(score),
            "terms": {
                "auth": auth,
                "transfer": transfer,
                "exec": exec_term,
                "match": match,
                "gap": round(gap, 3),
                "baseline": baseline,
            },
            "evidence": {"core": core, "support": list(dict.fromkeys(support))},
            "notes": notes,
        }

    def _source_side_support(
        self, src: str, dst: str, t_logon: datetime, t_exec: datetime, account: str | None
    ) -> list[str]:
        refs = []
        t0, t1 = t_logon - self.window, t_exec + self.tol
        if not src.startswith("ip:"):
            for n in self.idx.on(src, "net_conn", t0, t1):
                if n["dst_host"] == dst and n["dst_port"] in LATERAL_PORTS:
                    refs.append(n["event_ref"])
                    break
            for e in self.idx.on(src, "logon_explicit", t0, t1):
                if e["dst_host"] == dst:
                    refs.append(e["event_ref"])
                    break
            for p in self.idx.on(src, "process", t0, t1):
                cmd = (p["cmdline"] or "").lower()
                if dst in cmd and _REMOTE_TOOL.search(cmd):
                    refs.append(p["event_ref"])
                    break
        want = bare_user(account)
        for k in self.idx.to(dst, "kerberos", t0, t1):
            if want and bare_user(k["user"]) == want:
                refs.append(k["event_ref"])
                break
        return refs

    def _label(self, score: float) -> str:
        if score >= self.cfg.confirmed:
            return "confirmed"
        return "probable" if score >= self.cfg.probable else "candidate"

    def _inferred(self, edges: list[dict]) -> list[dict]:
        """Edges into sources we hold no logs for, from what other hosts saw."""
        first_use: dict[str, datetime] = {}
        for e in edges:
            if e["src"] not in self.coverage:
                first_use[e["src"]] = min(first_use.get(e["src"], e["t_logon"]), e["t_logon"])

        out = []
        for node, t in first_use.items():
            t0 = t - timedelta(seconds=self.cfg.inferred_lookback_s)
            found: dict[str, dict] = {}
            for cat in ("logon_explicit", "kerberos", "net_conn"):
                for ev in self.idx.to(node, cat, t0, t):
                    src = ev["src_host"]
                    if not src or src == node or src not in self.hosts:
                        continue
                    if cat == "net_conn" and ev["dst_port"] not in LATERAL_PORTS:
                        continue
                    if cat == "kerberos" and not _human(ev):
                        continue
                    score = (
                        self.cfg.inferred_score_net
                        if cat == "net_conn"
                        else self.cfg.inferred_score_auth
                    )
                    slot = found.setdefault(src, {"score": 0.0, "refs": [], "t": ev["ts_utc"]})
                    slot["score"] = max(slot["score"], score)
                    slot["refs"].append(ev["event_ref"])
                    slot["t"] = min(slot["t"], ev["ts_utc"])
            for src, info in found.items():
                technique, name = TECHNIQUES["unknown"]
                out.append(
                    {
                        "src": src,
                        "dst": node,
                        "technique": technique,
                        "technique_name": name,
                        "t_logon": info["t"],
                        "t_exec": info["t"],
                        "account": None,
                        "logon_id": None,
                        "score": info["score"],
                        "label": "inferred",
                        "terms": {},
                        "evidence": {"core": [], "support": info["refs"][:10]},
                        "notes": [
                            "no logs for the target; inferred from source-side evidence only"
                        ],
                    }
                )
        return out

    def edges(self) -> list[dict]:
        best: dict[tuple, dict] = {}
        for dst in self.hosts:
            for anchor in self.anchors(dst):
                e = self._edge(dst, anchor)
                if e is None:
                    continue
                key = (e["src"], e["dst"], e["technique"])
                cur = best.get(key)
                if cur is None or (e["score"], cur["t_exec"]) > (cur["score"], e["t_exec"]):
                    best[key] = e
        edges = list(best.values())
        edges += self._inferred(edges)
        return sorted(edges, key=lambda e: (e["t_exec"], e["src"], e["dst"]))

    def unexplained_inbound(self, edges: list[dict]) -> dict[str, list[str]]:
        """Network logons from other matched hosts just before first-seen that no edge explains."""
        explained = {(e["src"], e["dst"]) for e in edges if e["label"] != "candidate"}
        out: dict[str, list[str]] = {}
        for host, t in self.first_seen.items():
            refs = [
                s["event_ref"]
                for s in self.idx.on(host, "logon", t - self.window, t + self.tol)
                if s["logon_type"] == 3
                and _human(s)
                and _source(s) in self.hosts
                and _source(s) != host
                and (_source(s), host) not in explained
            ]
            if refs:
                out[host] = refs[:5]
        return out
