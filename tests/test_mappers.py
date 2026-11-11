"""Mapper tests on hand-built records, shaped like the JSON the EVTX parser emits."""

from datetime import UTC, datetime

import pytest

from indexcase.normalize.mappers import (
    bare_user,
    basename,
    norm_host,
    norm_ip,
    norm_logon_id,
    normalize_record,
)

SECURITY = "Security"
SYSTEM = "System"
SYSMON = "Microsoft-Windows-Sysmon/Operational"


def rec(channel: str, event_id, data: dict, host: str = "WS02.lab.local", rid: int = 7) -> dict:
    return {
        "Event": {
            "System": {
                "EventID": event_id,
                "EventRecordID": rid,
                "Channel": channel,
                "Computer": host,
                "TimeCreated": {"#attributes": {"SystemTime": "2026-03-02T09:00:01.250000Z"}},
            },
            "EventData": data,
        }
    }


def test_common_fields():
    row = normalize_record(rec(SECURITY, 4672, {"SubjectUserName": "bob"}))
    assert row["event_ref"] == "ws02:Security:7"
    assert row["ts_utc"] == datetime(2026, 3, 2, 9, 0, 1, 250000, tzinfo=UTC)
    assert row["host"] == "ws02"
    assert row["channel"] == SECURITY
    assert row["event_id"] == 4672
    assert row["raw"] == '{"SubjectUserName":"bob"}'


def test_4624_network_logon():
    row = normalize_record(
        rec(SECURITY, 4624, {
            "TargetUserName": "helpdesk1", "TargetDomainName": "LAB", "TargetLogonId": "0x1A2B3",
            "LogonType": "3", "AuthenticationPackageName": "Kerberos",
            "WorkstationName": "WS01", "IpAddress": "::ffff:10.0.0.11",
        })
    )  # fmt: skip
    assert row["category"] == "logon"
    assert row["user"] == "lab\\helpdesk1"
    assert row["logon_id"] == "0x1a2b3"
    assert row["logon_type"] == 3
    assert row["auth_package"] == "Kerberos"
    assert row["src_ip"] == "10.0.0.11"
    assert row["src_host"] == "ws01"
    assert row["dst_host"] == "ws02"


def test_placeholders_become_null():
    row = normalize_record(
        rec(SECURITY, 4624, {"TargetUserName": "alice", "LogonType": 3,
                             "WorkstationName": "-", "IpAddress": "::1"})
    )  # fmt: skip
    assert row["src_ip"] is None
    assert row["src_host"] is None


def test_4648_explicit_credentials_point_at_target():
    row = normalize_record(
        rec(SECURITY, 4648, {
            "TargetUserName": "helpdesk1", "TargetDomainName": "LAB", "SubjectLogonId": "0x3e7",
            "TargetServerName": "ws03.lab.local", "ProcessName": "C:\\Windows\\System32\\sc.exe",
        }, host="WS02")
    )  # fmt: skip
    assert row["category"] == "logon_explicit"
    assert (row["src_host"], row["dst_host"]) == ("ws02", "ws03")
    assert row["process_path"].endswith("sc.exe")


def test_4688_process_creation():
    row = normalize_record(
        rec(SECURITY, 4688, {
            "SubjectUserName": "alice", "SubjectDomainName": "LAB", "SubjectLogonId": "0x5000",
            "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
            "ParentProcessName": "C:\\Windows\\explorer.exe", "CommandLine": "cmd.exe /c whoami",
        })
    )  # fmt: skip
    assert row["category"] == "process"
    assert row["logon_id"] == "0x5000"
    assert basename(row["process_path"]) == "cmd.exe"
    assert basename(row["parent_path"]) == "explorer.exe"
    assert row["cmdline"] == "cmd.exe /c whoami"


def test_service_install_from_system_and_security():
    system = normalize_record(
        rec(SYSTEM, {"#attributes": {"Qualifiers": 16384}, "#text": 7045},
            {"ServiceName": "PSEXESVC", "ImagePath": "%SystemRoot%\\PSEXESVC.exe"})
    )  # fmt: skip
    assert system["event_id"] == 7045
    assert system["category"] == "service_install"
    assert system["service_name"] == "PSEXESVC"
    assert system["logon_id"] is None  # 7045 carries no logon id

    security = normalize_record(
        rec(SECURITY, 4697, {"SubjectLogonId": "0x1a2b3", "ServiceName": "PSEXESVC",
                             "ServiceFileName": "%SystemRoot%\\PSEXESVC.exe"})
    )  # fmt: skip
    assert security["category"] == "service_install"
    assert security["logon_id"] == "0x1a2b3"
    assert security["file_path"] == "%SystemRoot%\\PSEXESVC.exe"


def test_task_created_command_and_arguments():
    xml = (
        "<Task><Actions><Exec><Command>C:\\Windows\\Temp\\a.exe</Command>"
        "<Arguments>--run &amp; exit</Arguments></Exec></Actions></Task>"
    )
    row = normalize_record(
        rec(SECURITY, 4698, {"SubjectLogonId": "0x77", "TaskName": "\\Updater", "TaskContent": xml})
    )
    assert row["category"] == "task_create"
    assert row["task_name"] == "\\Updater"
    assert row["file_path"] == "C:\\Windows\\Temp\\a.exe"
    assert row["cmdline"] == "C:\\Windows\\Temp\\a.exe --run & exit"


def test_5145_share_path():
    row = normalize_record(
        rec(SECURITY, 5145, {"SubjectLogonId": "0x1a2b3", "IpAddress": "10.0.0.11",
                             "ShareName": "\\\\*\\ADMIN$", "RelativeTargetName": "Temp\\a.exe"})
    )  # fmt: skip
    assert row["category"] == "share_access"
    assert row["file_path"] == "\\\\*\\ADMIN$\\Temp\\a.exe"
    assert row["src_ip"] == "10.0.0.11"


def test_dc_ticket_names_the_target_host():
    row = normalize_record(
        rec(SECURITY, 4769, {"TargetUserName": "helpdesk1@LAB.LOCAL", "ServiceName": "WS03$",
                             "IpAddress": "::ffff:10.0.0.12"}, host="DC01.lab.local")
    )  # fmt: skip
    assert row["category"] == "kerberos"
    assert row["dst_host"] == "ws03"
    assert row["src_ip"] == "10.0.0.12"
    assert bare_user(row["user"]) == "helpdesk1"


def test_sysmon_process_with_hash():
    row = normalize_record(
        rec(SYSMON, 1, {
            "ProcessGuid": "{p1}", "ParentProcessGuid": "{p0}", "LogonId": "0x3E7",
            "Image": "C:\\Windows\\Temp\\a.exe",
            "ParentImage": "C:\\Windows\\System32\\services.exe",
            "CommandLine": "a.exe", "User": "NT AUTHORITY\\SYSTEM",
            "Hashes": "MD5=00,SHA256=" + "AB" * 32 + ",IMPHASH=00",
        })
    )  # fmt: skip
    assert row["category"] == "process"
    assert row["sha256"] == "ab" * 32
    assert (row["process_guid"], row["parent_guid"]) == ("{p1}", "{p0}")
    assert row["logon_id"] == "0x3e7"
    assert row["user"] == "nt authority\\system"


def test_sysmon_network_connection_direction():
    out = normalize_record(
        rec(SYSMON, 3, {"Initiated": "true", "SourceIp": "10.0.0.12", "DestinationIp": "10.0.0.13",
                        "DestinationHostname": "ws03.lab.local", "DestinationPort": "445"})
    )  # fmt: skip
    assert (out["src_host"], out["dst_host"], out["dst_port"]) == ("ws02", "ws03", 445)

    inbound = normalize_record(
        rec(SYSMON, 3, {"Initiated": "false", "SourceIp": "10.0.0.11",
                        "SourceHostname": "ws01.lab.local", "DestinationIp": "10.0.0.12",
                        "DestinationPort": "445"})
    )  # fmt: skip
    assert (inbound["src_host"], inbound["dst_host"]) == ("ws01", "ws02")


@pytest.mark.parametrize(
    ("event_id", "field", "value", "column"),
    [
        (11, "TargetFilename", "C:\\Windows\\Temp\\a.exe", "file_path"),
        (13, "TargetObject", "HKLM\\Software\\Run\\Updater", "registry_key"),
        (17, "PipeName", "\\labworm_ws02", "pipe_name"),
        (22, "QueryName", "C2.LAB.LOCAL.", "dns_query"),
    ],
)
def test_sysmon_artefacts(event_id, field, value, column):
    row = normalize_record(rec(SYSMON, event_id, {"Image": "a.exe", field: value}))
    expected = "c2.lab.local" if column == "dns_query" else value
    assert row[column] == expected


def test_unmapped_and_malformed_records_are_dropped():
    assert normalize_record(rec(SECURITY, 4634, {})) is None
    assert normalize_record(rec("Application", 1000, {})) is None
    assert normalize_record({"Event": {"System": {"EventID": 4624}}}) is None
    assert normalize_record({}) is None


def test_helpers():
    assert norm_host("\\\\WS01.lab.local") == "ws01"
    assert norm_host("WS01$") == "ws01"
    assert norm_host("10.0.0.5") is None
    assert norm_ip("::ffff:10.0.0.5") == "10.0.0.5"
    assert norm_ip("127.0.0.1") is None
    assert norm_ip("not-an-ip") is None
    assert norm_logon_id("0x3E7") == "0x3e7"
    assert norm_logon_id("999") == "0x3e7"
    assert bare_user("LAB\\Helpdesk1") == "helpdesk1"
    assert basename('"C:\\Windows\\System32\\cmd.exe"') == "cmd.exe"
