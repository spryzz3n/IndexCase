"""Malware profile: weighted indicators and behaviours, loaded from YAML."""

from __future__ import annotations

import re
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


def _check_regex(pattern: str | None) -> str | None:
    if pattern is not None:
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ValueError(f"invalid regex {pattern!r}: {exc}") from exc
    return pattern


class Indicator(BaseModel):
    model_config = ConfigDict(extra="forbid")

    value: str | None = None
    regex: str | None = None
    weight: float = Field(gt=0, le=1)
    # where a derived indicator came from, e.g. "yara:RuleName"
    origin: str | None = None

    _regex_ok = field_validator("regex")(_check_regex)

    @model_validator(mode="after")
    def _one_of(self) -> Indicator:
        if (self.value is None) == (self.regex is None):
            raise ValueError("an indicator needs exactly one of 'value' or 'regex'")
        return self


class Indicators(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sha256: list[Indicator] = []
    filenames: list[Indicator] = []
    paths: list[Indicator] = []
    pipes: list[Indicator] = []
    registry_set: list[Indicator] = []
    domains: list[Indicator] = []
    cmdline: list[Indicator] = []
    services: list[Indicator] = []
    tasks: list[Indicator] = []


class Behavior(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    parent: str
    child: str
    weight: float = Field(gt=0, le=1)

    _regex_ok = field_validator("parent", "child")(_check_regex)


class Propagation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    techniques: list[str] = []
    service_name_regex: str | None = None

    _regex_ok = field_validator("service_name_regex")(_check_regex)


class Matching(BaseModel):
    model_config = ConfigDict(extra="forbid")

    infected_threshold: float = Field(default=1.0, gt=0)
    window_minutes: float = Field(default=5, gt=0)
    clock_tolerance_seconds: float = Field(default=120, ge=0)


class MalwareProfile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    version: int = 1
    description: str = ""
    indicators: Indicators = Indicators()
    behaviors: list[Behavior] = []
    propagation: Propagation = Propagation()
    matching: Matching = Matching()


def load_profile(path: Path) -> MalwareProfile:
    with path.open(encoding="utf-8") as fh:
        return MalwareProfile.model_validate(yaml.safe_load(fh))
