"""Weights and thresholds."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class EdgeWeights:
    auth: float = 0.35
    transfer: float = 0.15
    exec: float = 0.35
    match: float = 0.15
    gap_penalty: float = 0.10
    baseline_penalty: float = 0.30
    # source shows the malware only after it supposedly pushed it to the target
    order_penalty: float = 0.30


@dataclass(frozen=True)
class Config:
    edge: EdgeWeights = field(default_factory=EdgeWeights)

    confirmed: float = 0.70
    probable: float = 0.40
    # edges into a "suspected" host can never be confirmed
    suspected_cap: float = 0.69

    # seconds after a service install / task creation in which the payload must start
    service_follow_s: int = 60
    task_follow_s: int = 120

    # account -> host pairs seen on this many of the previous days are routine
    baseline_days: int = 7
    baseline_min_days: int = 4

    # a first-seen this close to the start of a host's log is probably truncated
    log_start_margin_s: int = 600

    # indicator weight at or above which a match counts as strong
    strong_weight: float = 0.7


DEFAULT = Config()
