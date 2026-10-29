import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__
from .engine import review
from .model import InputError, load_policy, parse_snapshot, read_text

EXIT_CODES = {"pass": 0, "block": 1, "review": 3}


def markdown(result):
    lines = [
        "# Network Change Guard",
        "",
        f"Decision: **{result['status']}**",
        "",
        "This is a bounded policy review, not approval to deploy.",
        "",
        "| Severity | Rule | Scope | Finding |",
        "|---|---|---|---|",
    ]
    for f in result["findings"]:
        lines.append(f"| {f['severity']} | {f['code']} | {f['scope']} | {f['message']} |")
    if not result["findings"]:
        lines.append("| — | — | — | Modeled checks passed; no substantive change detected. |")
    lines += [
        "",
        "## Changes",
        "",
        "| Scope | Kind | Added | Removed | Description only |",
        "|---|---|---|---|---|",
    ]
    for c in result["changes"]:
        lines.append(
            f"| {c['scope']} | {c['kind']} | {c['added']} | {c['removed']} | "
            f"{'yes' if c['cosmetic'] else 'no'} |"
        )
    lines += [
        "",
        "## Input identity",
        "",
        f"Baseline SHA-256: `{result['before_sha256']}`",
        f"Candidate SHA-256: `{result['candidate_sha256']}`",
        f"Canonical policy SHA-256: `{result['policy_sha256']}`",
        "",
        "Raw commands, hostnames, addresses, credential values and input paths are omitted.",
        "Interface names, process IDs, counts and fingerprints remain; review before sharing.",
        "Counts are structural line counts, not executable configuration operations.",
    ]
    return "\n".join(lines) + "\n"


def write_reports(result, directory):
    out = Path(directory)
    out.mkdir(parents=True, mode=0o700, exist_ok=False)
    for name, text in {
        "report.md": markdown(result),
        ".report.json.pending": json.dumps(result, indent=2) + "\n",
    }.items():
        fd = os.open(out / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(text)
    (out / ".report.json.pending").replace(out / "report.json")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Review complete Cisco IOS snapshots offline")
    parser.add_argument(
        "--version", action="version", version=f"Network Change Guard {__version__}"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser("review", help="Compare snapshots and enforce a JSON policy")
    command.add_argument("--before", required=True, type=Path)
    command.add_argument("--candidate", required=True, type=Path)
    command.add_argument("--policy", required=True, type=Path)
    command.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        before = parse_snapshot(read_text(args.before))
        candidate = parse_snapshot(read_text(args.candidate))
        policy = load_policy(read_text(args.policy))
        result = review(before, candidate, policy)
        result["tool_version"] = __version__
        write_reports(result, args.output)
    except InputError as exc:
        print(f"Input error: {exc}. No decision produced.", file=sys.stderr)
        return 2
    except OSError:
        print(
            "Output error: use a new writable directory. No current report confirmed.",
            file=sys.stderr,
        )
        return 2
    print(
        f"Decision: {result['status']}; blockers={result['summary']['blockers']}; "
        f"reviews={result['summary']['reviews']}; "
        f"changed_scopes={result['summary']['changed_scopes']}"
    )
    return EXIT_CODES[result["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
