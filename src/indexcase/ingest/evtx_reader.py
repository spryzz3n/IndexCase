"""Read event logs into JSON-like dict records.

Two inputs are accepted: native .evtx files, and .jsonl files holding one
record per line in the layout `evtx_dump -o jsonl` writes.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

LOG_SUFFIXES = {".evtx", ".jsonl"}


def find_logs(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    return sorted(p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in LOG_SUFFIXES)


def _iter_evtx(path: Path) -> Iterator[dict]:
    from evtx import PyEvtxParser

    parser = PyEvtxParser(str(path))
    for rec in parser.records_json():
        try:
            yield json.loads(rec["data"])
        except (KeyError, TypeError, ValueError):
            continue


def _iter_jsonl(path: Path) -> Iterator[dict]:
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if isinstance(rec, dict):
                yield rec


def iter_records(path: Path) -> Iterator[dict]:
    """Yield one dict per event record. Corrupt records are skipped."""
    if path.suffix.lower() == ".jsonl":
        yield from _iter_jsonl(path)
    else:
        yield from _iter_evtx(path)
