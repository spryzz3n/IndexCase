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
class RootWeights:
    earliness: float = 0.30
    coverage: float = 0.35
    initial_access: float = 0.20
    completeness: float = 0.15
    unexplained_auth: float = 0.10


@dataclass(frozen=True)
class Config:
    edge: EdgeWeights = field(default_factory=EdgeWeights)
    root: RootWeights = field(default_factory=RootWeights)

    confirmed: float = 0.70
    probable: float = 0.40
    # edges into a "suspected" host can never be confirmed
    suspected_cap: float = 0.69

    # seconds after a service install / task creation in which the payload must start
    service_follow_s: int = 60
    task_follow_s: int = 120

    # inferred edges into hosts we have no logs for
    inferred_lookback_s: int = 1800
    inferred_score_auth: float = 0.45
    inferred_score_net: float = 0.40

    # account -> host pairs seen on this many of the previous days are routine
    baseline_days: int = 7
    baseline_min_days: int = 4

    # a first-seen this close to the start of a host's log is probably truncated
    log_start_margin_s: int = 600

    # indicator weight at or above which a match counts as strong
    strong_weight: float = 0.7


DEFAULT = Config()
