from pathlib import Path

import pytest
from pydantic import ValidationError

from indexcase.profile.models import MalwareProfile, load_profile

PROFILE = Path(__file__).resolve().parents[1] / "profiles" / "labworm.yaml"


def test_labworm_profile_loads():
    profile = load_profile(PROFILE)
    assert profile.name == "LabWorm-v1"
    assert profile.indicators.sha256[0].weight == 1.0
    assert profile.behaviors[0].name == "service-launch"
    assert profile.matching.window_minutes == 5


@pytest.mark.parametrize(
    "indicator",
    [
        {"value": "a", "regex": "a", "weight": 0.5},
        {"weight": 0.5},
        {"regex": "(", "weight": 0.5},
        {"value": "a", "weight": 1.5},
    ],
)
def test_bad_indicators_rejected(indicator):
    with pytest.raises(ValidationError):
        MalwareProfile.model_validate({"name": "x", "indicators": {"filenames": [indicator]}})


def test_unknown_fields_rejected():
    with pytest.raises(ValidationError):
        MalwareProfile.model_validate({"name": "x", "indicator": {}})


def test_bad_behavior_regex_rejected():
    with pytest.raises(ValidationError):
        MalwareProfile.model_validate(
            {"name": "x", "behaviors": [{"name": "b", "parent": "(", "child": "c", "weight": 0.5}]}
        )
