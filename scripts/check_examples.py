"""Exercise the installed CLI; intentionally blocked examples must fail as expected."""

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = {
    "before": (0, "pass"),
    "description-only": (0, "pass"),
    "management-shutdown": (1, "block"),
    "telnet-enabled": (1, "block"),
    "required-route-removed": (1, "block"),
    "ospf-cost-change": (3, "review"),
    "unknown-feature": (3, "review"),
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    results = []
    for name, (code, status) in EXPECTED.items():
        destination = args.output / name
        process = subprocess.run(
            [
                sys.executable,
                "-m",
                "changeguard.cli",
                "review",
                "--before",
                str(ROOT / "examples/before.cfg"),
                "--candidate",
                str(ROOT / "examples" / f"{name}.cfg"),
                "--policy",
                str(ROOT / "examples/policy.json"),
                "--output",
                str(destination),
            ],
            capture_output=True,
            text=True,
        )
        if process.returncode != code:
            raise RuntimeError(f"Unexpected exit for {name}: {process.returncode}")
        report = json.loads((destination / "report.json").read_text())
        if report["status"] != status:
            raise RuntimeError(f"Unexpected decision for {name}")
        results.append({"case": name, "exit_code": code, "decision": status})
        print(f"{name}: expected {status} / exit {code}; verified")
    (args.output / "matrix.json").write_text(json.dumps(results, indent=2) + "\n")


if __name__ == "__main__":
    main()
