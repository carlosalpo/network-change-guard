import json
import stat

import pytest

from changeguard.cli import main


def arguments(tmp_path, baseline, policy, candidate=None):
    (tmp_path / "before.cfg").write_text(baseline)
    (tmp_path / "after.cfg").write_text(candidate or baseline)
    (tmp_path / "policy.json").write_text(json.dumps(policy))
    return [
        "review",
        "--before",
        str(tmp_path / "before.cfg"),
        "--candidate",
        str(tmp_path / "after.cfg"),
        "--policy",
        str(tmp_path / "policy.json"),
        "--output",
        str(tmp_path / "report"),
    ]


@pytest.mark.parametrize(
    "old,new,exit_code",
    [
        ("Primary lab path", "Updated path label", 0),
        (" description Isolated management", " shutdown", 1),
        ("ip ospf cost 10", "ip ospf cost 200", 3),
        ("version 15.9", "", 2),
    ],
)
def test_exit_contract(tmp_path, baseline, policy, old, new, exit_code):
    assert main(arguments(tmp_path, baseline, policy, baseline.replace(old, new))) == exit_code
    assert (tmp_path / "report/report.json").exists() == (exit_code != 2)


def test_output_is_private_and_not_reused(tmp_path, baseline, policy):
    args = arguments(tmp_path, baseline, policy)
    assert main(args) == 0
    report = tmp_path / "report/report.json"
    original = report.read_bytes()
    assert stat.S_IMODE(report.stat().st_mode) == 0o600
    assert stat.S_IMODE(report.parent.stat().st_mode) == 0o700
    assert main(args) == 2
    assert report.read_bytes() == original


def test_no_source_values_in_console(tmp_path, baseline, policy, capsys):
    candidate = baseline.replace("SYNTHETIC-NONFUNCTIONAL-HASH", "VERYPRIVATEVALUE")
    assert main(arguments(tmp_path, baseline, policy, candidate)) == 3
    output = capsys.readouterr()
    assert "VERYPRIVATEVALUE" not in output.out + output.err
    assert str(tmp_path) not in output.out + output.err


def test_no_raw_input_in_errors(tmp_path, baseline, policy, capsys):
    candidate = baseline.replace("hostname branch-lab", "hostname |PRIVATE-MARKUP|")
    assert main(arguments(tmp_path, baseline, policy, candidate)) == 2
    assert "PRIVATE-MARKUP" not in capsys.readouterr().err
