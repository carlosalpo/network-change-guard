import json
from pathlib import Path

import pytest

from changeguard.model import load_policy

ROOT = Path(__file__).parents[1]


@pytest.fixture
def baseline():
    return (ROOT / "examples/before.cfg").read_text()


@pytest.fixture
def policy():
    return load_policy((ROOT / "examples/policy.json").read_text())


@pytest.fixture
def policy_text(policy):
    return json.dumps(policy)
