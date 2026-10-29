import json
from pathlib import Path

import pytest

from changeguard.engine import review
from changeguard.model import load_policy, parse_snapshot

ROOT = Path(__file__).parents[1] / "docs/evidence/iosv-15.9-20261029"


@pytest.mark.parametrize(
    "case,status",
    [
        ("unchanged", "pass"),
        ("management-shutdown", "block"),
        ("ospf-cost-change", "review"),
    ],
)
def test_sanitized_device_output(case, status):
    before = parse_snapshot((ROOT / "before.cfg").read_text())
    filename = "before.cfg" if case == "unchanged" else f"{case}.cfg"
    candidate = parse_snapshot((ROOT / filename).read_text())
    policy = load_policy((ROOT / "policy.json").read_text())
    result = review(before, candidate, policy)
    recorded = json.loads((ROOT / case / "report.json").read_text())
    assert result["status"] == status
    for key in [
        "findings",
        "changes",
        "summary",
        "before_sha256",
        "candidate_sha256",
        "policy_sha256",
    ]:
        assert result[key] == recorded[key]
