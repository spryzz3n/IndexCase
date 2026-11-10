"""The NormalizedEvent table. Every later stage reads only these columns."""

from __future__ import annotations

from pathlib import Path

import polars as pl

CATEGORIES = (
    "logon",
    "logon_explicit",
    "privilege",
    "kerberos",
    "ntlm",
    "process",
    "service_install",
    "task_create",
    "task_delete",
    "share_access",
    "file_create",
    "net_conn",
    "pipe",
    "registry",
    "dns",
)

SCHEMA: dict[str, pl.DataType] = {
    "event_ref": pl.String,  # {host}:{channel}:{record_id}, used as evidence citation
    "ts_utc": pl.Datetime("us", "UTC"),
    "host": pl.String,  # lower-case short name of the machine that logged the event
    "channel": pl.String,
    "event_id": pl.Int32,
    "category": pl.String,
    "user": pl.String,  # domain\user, lower-case
    "logon_id": pl.String,  # hex, lower-case
    "logon_type": pl.Int32,
    "auth_package": pl.String,
    "src_ip": pl.String,
    "src_host": pl.String,
    "dst_ip": pl.String,
    "dst_host": pl.String,
    "dst_port": pl.Int32,
    "process_path": pl.String,
    "process_guid": pl.String,
    "parent_path": pl.String,
    "parent_guid": pl.String,
    "parent_cmdline": pl.String,
    "cmdline": pl.String,
    "sha256": pl.String,
    "file_path": pl.String,
    "service_name": pl.String,
    "task_name": pl.String,
    "pipe_name": pl.String,
    "registry_key": pl.String,
    "dns_query": pl.String,
    "raw": pl.String,  # original EventData as JSON
}


def empty_row() -> dict:
    return dict.fromkeys(SCHEMA)


def write_events(rows: list[dict], path: Path) -> None:
    df = pl.DataFrame(rows, schema=SCHEMA, orient="row").sort("ts_utc")
    path.parent.mkdir(parents=True, exist_ok=True)
    df.write_parquet(path)


def read_events(path: Path) -> list[dict]:
    return pl.read_parquet(path).sort("ts_utc").to_dicts()
