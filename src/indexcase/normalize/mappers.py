"""One mapper per (channel, event_id). Unmapped events are dropped."""

from __future__ import annotations

import html
import ipaddress
import json
import re
from collections.abc import Callable

from indexcase.normalize.schema import empty_row
from indexcase.timeutil import parse_ts

SECURITY = "security"
SYSTEM = "system"
SYSMON = "microsoft-windows-sysmon/operational"

_NULLS = {"", "-", "::1", "127.0.0.1", "localhost", "(null)"}
_SHA256 = re.compile(r"SHA256=([0-9A-Fa-f]{64})")
_TASK_CMD = re.compile(r"<Command>(.*?)</Command>", re.S)
_TASK_ARGS = re.compile(r"<Arguments>(.*?)</Arguments>", re.S)


def clean(value) -> str | None:
    if value is None:
        return None
    s = str(value).strip()
    return None if s.lower() in _NULLS else s


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def norm_ip(value) -> str | None:
    s = clean(value)
    if s is None:
        return None
    s = s.lower().removeprefix("::ffff:")
    if not is_ip(s) or ipaddress.ip_address(s).is_loopback:
        return None
    return s


def norm_host(value) -> str | None:
    s = clean(value)
    if s is None:
        return None
    s = s.lower().lstrip("\\").rstrip("$")
    if not s or is_ip(s):
        return None
    return s.split(".")[0]


def norm_user(name, domain=None) -> str | None:
    n = clean(name)
    if n is None:
        return None
    d = clean(domain)
    if "\\" in n or d is None:
        return n.lower()
    return f"{d}\\{n}".lower()


def bare_user(user: str | None) -> str | None:
    """Account name without domain prefix or @realm, for joins across log sources."""
    if not user:
        return None
    return user.rsplit("\\", 1)[-1].split("@", 1)[0].lower()


def norm_logon_id(value) -> str | None:
    s = clean(value)
    if s is None:
        return None
    try:
        return hex(int(s, 16) if s.lower().startswith("0x") else int(s))
    except ValueError:
        return s.lower()


def to_int(value) -> int | None:
    s = clean(value)
    if s is None:
        return None
    try:
        return int(s, 16) if s.lower().startswith("0x") else int(s)
    except ValueError:
        return None


def basename(path: str | None) -> str:
    if not path:
        return ""
    return path.replace("/", "\\").rsplit("\\", 1)[-1].strip('"').lower()


# --- Security -----------------------------------------------------------------


def _m4624(d: dict, r: dict) -> None:
    r["category"] = "logon"
    r["user"] = norm_user(d.get("TargetUserName"), d.get("TargetDomainName"))
    r["logon_id"] = norm_logon_id(d.get("TargetLogonId"))
    r["logon_type"] = to_int(d.get("LogonType"))
    r["auth_package"] = clean(d.get("AuthenticationPackageName"))
    r["src_ip"] = norm_ip(d.get("IpAddress"))
    r["src_host"] = norm_host(d.get("WorkstationName"))
    r["dst_host"] = r["host"]


def _m4648(d: dict, r: dict) -> None:
    r["category"] = "logon_explicit"
    r["user"] = norm_user(d.get("TargetUserName"), d.get("TargetDomainName"))
    r["logon_id"] = norm_logon_id(d.get("SubjectLogonId"))
    r["src_host"] = r["host"]
    r["dst_host"] = norm_host(d.get("TargetServerName"))
    r["dst_ip"] = norm_ip(d.get("IpAddress"))
    r["process_path"] = clean(d.get("ProcessName"))


def _m4672(d: dict, r: dict) -> None:
    r["category"] = "privilege"
    r["user"] = norm_user(d.get("SubjectUserName"), d.get("SubjectDomainName"))
    r["logon_id"] = norm_logon_id(d.get("SubjectLogonId"))


def _m4688(d: dict, r: dict) -> None:
    r["category"] = "process"
    r["user"] = norm_user(d.get("SubjectUserName"), d.get("SubjectDomainName"))
    r["logon_id"] = norm_logon_id(d.get("SubjectLogonId"))
    r["process_path"] = clean(d.get("NewProcessName"))
    r["parent_path"] = clean(d.get("ParentProcessName"))
    r["cmdline"] = clean(d.get("CommandLine"))


def _m4697(d: dict, r: dict) -> None:
    r["category"] = "service_install"
    r["user"] = norm_user(d.get("SubjectUserName"), d.get("SubjectDomainName"))
    r["logon_id"] = norm_logon_id(d.get("SubjectLogonId"))
    r["service_name"] = clean(d.get("ServiceName"))
    r["file_path"] = clean(d.get("ServiceFileName"))
    r["cmdline"] = r["file_path"]


def _task(d: dict, r: dict) -> None:
    r["user"] = norm_user(d.get("SubjectUserName"), d.get("SubjectDomainName"))
    r["logon_id"] = norm_logon_id(d.get("SubjectLogonId"))
    r["task_name"] = clean(d.get("TaskName"))
    content = str(d.get("TaskContent") or "")
    cmd = _TASK_CMD.search(content)
    if cmd:
        args = _TASK_ARGS.search(content)
        parts = [cmd.group(1).strip(), args.group(1).strip() if args else ""]
        r["cmdline"] = html.unescape(" ".join(p for p in parts if p))
        r["file_path"] = html.unescape(parts[0])


def _m4698(d: dict, r: dict) -> None:
    r["category"] = "task_create"
    _task(d, r)


def _m4699(d: dict, r: dict) -> None:
    r["category"] = "task_delete"
    _task(d, r)


def _m5140(d: dict, r: dict) -> None:
    r["category"] = "share_access"
    r["user"] = norm_user(d.get("SubjectUserName"), d.get("SubjectDomainName"))
    r["logon_id"] = norm_logon_id(d.get("SubjectLogonId"))
    r["src_ip"] = norm_ip(d.get("IpAddress"))
    share = clean(d.get("ShareName")) or ""
    rel = clean(d.get("RelativeTargetName")) or ""
    r["file_path"] = "\\".join(p for p in (share.rstrip("\\"), rel.lstrip("\\")) if p) or None
    r["dst_host"] = r["host"]


def _kerberos(d: dict, r: dict) -> None:
    r["category"] = "kerberos"
    r["user"] = norm_user(d.get("TargetUserName"), d.get("TargetDomainName"))
    r["src_ip"] = norm_ip(d.get("IpAddress"))
    service = clean(d.get("ServiceName"))
    if service and service.lower() != "krbtgt":
        r["dst_host"] = norm_host(service.split("/")[-1])
        r["service_name"] = service


def _m4776(d: dict, r: dict) -> None:
    r["category"] = "ntlm"
    r["user"] = norm_user(d.get("TargetUserName"))
    r["src_host"] = norm_host(d.get("Workstation"))


# --- System -------------------------------------------------------------------


def _m7045(d: dict, r: dict) -> None:
    r["category"] = "service_install"
    r["service_name"] = clean(d.get("ServiceName"))
    r["file_path"] = clean(d.get("ImagePath"))
    r["cmdline"] = r["file_path"]


# --- Sysmon -------------------------------------------------------------------


def _s1(d: dict, r: dict) -> None:
    r["category"] = "process"
    r["user"] = norm_user(d.get("User"))
    r["logon_id"] = norm_logon_id(d.get("LogonId"))
    r["process_path"] = clean(d.get("Image"))
    r["process_guid"] = clean(d.get("ProcessGuid"))
    r["parent_path"] = clean(d.get("ParentImage"))
    r["parent_guid"] = clean(d.get("ParentProcessGuid"))
    r["parent_cmdline"] = clean(d.get("ParentCommandLine"))
    r["cmdline"] = clean(d.get("CommandLine"))
    m = _SHA256.search(str(d.get("Hashes") or ""))
    r["sha256"] = m.group(1).lower() if m else None


def _s3(d: dict, r: dict) -> None:
    r["category"] = "net_conn"
    initiated = str(d.get("Initiated")).lower() == "true"
    r["user"] = norm_user(d.get("User"))
    r["process_path"] = clean(d.get("Image"))
    r["process_guid"] = clean(d.get("ProcessGuid"))
    r["src_ip"] = norm_ip(d.get("SourceIp"))
    r["dst_ip"] = norm_ip(d.get("DestinationIp"))
    r["dst_port"] = to_int(d.get("DestinationPort"))
    r["src_host"] = r["host"] if initiated else norm_host(d.get("SourceHostname"))
    r["dst_host"] = norm_host(d.get("DestinationHostname")) if initiated else r["host"]


def _s11(d: dict, r: dict) -> None:
    r["category"] = "file_create"
    r["process_path"] = clean(d.get("Image"))
    r["process_guid"] = clean(d.get("ProcessGuid"))
    r["file_path"] = clean(d.get("TargetFilename"))


def _s13(d: dict, r: dict) -> None:
    r["category"] = "registry"
    r["process_path"] = clean(d.get("Image"))
    r["process_guid"] = clean(d.get("ProcessGuid"))
    r["registry_key"] = clean(d.get("TargetObject"))


def _s17(d: dict, r: dict) -> None:
    r["category"] = "pipe"
    r["process_path"] = clean(d.get("Image"))
    r["process_guid"] = clean(d.get("ProcessGuid"))
    r["pipe_name"] = clean(d.get("PipeName"))


def _s22(d: dict, r: dict) -> None:
    r["category"] = "dns"
    r["process_path"] = clean(d.get("Image"))
    r["process_guid"] = clean(d.get("ProcessGuid"))
    q = clean(d.get("QueryName"))
    r["dns_query"] = q.lower().rstrip(".") if q else None


MAPPERS: dict[tuple[str, int], Callable[[dict, dict], None]] = {
    (SECURITY, 4624): _m4624,
    (SECURITY, 4648): _m4648,
    (SECURITY, 4672): _m4672,
    (SECURITY, 4688): _m4688,
    (SECURITY, 4697): _m4697,
    (SECURITY, 4698): _m4698,
    (SECURITY, 4699): _m4699,
    (SECURITY, 5140): _m5140,
    (SECURITY, 5145): _m5140,
    (SECURITY, 4768): _kerberos,
    (SECURITY, 4769): _kerberos,
    (SECURITY, 4776): _m4776,
    (SYSTEM, 7045): _m7045,
    (SYSMON, 1): _s1,
    (SYSMON, 3): _s3,
    (SYSMON, 11): _s11,
    (SYSMON, 13): _s13,
    (SYSMON, 17): _s17,
    (SYSMON, 18): _s17,
    (SYSMON, 22): _s22,
}


def _event_id(system: dict) -> int:
    eid = system.get("EventID")
    if isinstance(eid, dict):
        eid = eid.get("#text")
    return int(eid)


def normalize_record(rec: dict) -> dict | None:
    """Turn one parsed EVTX record into a NormalizedEvent row, or None if unmapped."""
    try:
        event = rec["Event"]
        system = event["System"]
        channel = str(system.get("Channel") or "")
        mapper = MAPPERS.get((channel.lower(), _event_id(system)))
        if mapper is None:
            return None
        ts = parse_ts(system["TimeCreated"]["#attributes"]["SystemTime"])
        host = norm_host(system.get("Computer"))
    except (KeyError, TypeError, ValueError):
        return None
    if ts is None or host is None:
        return None

    data = event.get("EventData")
    if not isinstance(data, dict):
        data = {}

    row = empty_row()
    row["event_ref"] = f"{host}:{channel}:{system.get('EventRecordID')}"
    row["ts_utc"] = ts
    row["host"] = host
    row["channel"] = channel
    row["event_id"] = _event_id(system)
    mapper(data, row)
    row["raw"] = json.dumps(data, default=str, separators=(",", ":"))
    return row
