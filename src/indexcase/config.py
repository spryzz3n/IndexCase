"""Weights and thresholds."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    # seconds after a service install in which the payload must start
    service_follow_s: int = 60

    # a first-seen this close to the start of a host's log is probably truncated
    log_start_margin_s: int = 600


DEFAULT = Config()
