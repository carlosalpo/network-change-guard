"""Bounded snapshot reader and strict JSON policy validation."""

import hashlib
import ipaddress
import json
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path

MAX_BYTES = 2_000_000
INTERFACE = re.compile(r"[A-Za-z][A-Za-z0-9/-]*(?:\.[0-9]+)?\Z")


class InputError(ValueError):
    """An input cannot be assessed reliably; messages never include source content."""


def read_text(path):
    try:
        if not Path(path).is_file():
            raise InputError("Input must be a regular file")
        with Path(path).open("rb") as stream:
            raw = stream.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise InputError("Input exceeds the 2 MB limit")
        return raw.decode("utf-8")
    except (OSError, UnicodeError) as exc:
        raise InputError("Input could not be read as UTF-8") from exc


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


@dataclass(frozen=True)
class Snapshot:
    sha256: str
    blocks: dict[str, tuple[str, ...]]
    globals: tuple[str, ...]


def parse_snapshot(text):
    if len(text.encode()) > MAX_BYTES:
        raise InputError("Snapshot exceeds the 2 MB limit")
    parsing_text = text.removeprefix("\ufeff")
    if any(
        unicodedata.category(c) in {"Cc", "Cf", "Zl", "Zp"} and c not in "\r\n"
        for c in parsing_text
    ):
        raise InputError("Snapshot contains control characters or tabs")
    lines = parsing_text.replace("\r\n", "\n").splitlines()
    blocks, globals_ = {}, []
    header, body = None, []
    ended = False
    versions = hostnames = 0
    index = 0

    def finish():
        nonlocal header, body
        if header is not None:
            if body or header.startswith(("interface ", "router ", "line ", "banner ")):
                if header in blocks:
                    raise InputError("Duplicate configuration block")
                blocks[header] = tuple(body)
            else:
                globals_.append(header)
        header, body = None, []

    while index < len(lines):
        raw = lines[index].rstrip()
        index += 1
        if not raw or raw.lstrip().startswith("!"):
            continue
        if ended:
            raise InputError("Content appears after the snapshot end marker")
        if raw.startswith(" "):
            if header is None:
                raise InputError("Indented command has no parent block")
            body.append(raw)
            continue
        finish()
        if raw == "Building configuration..." or re.fullmatch(
            r"Current configuration\s*:\s*\d+ bytes", raw
        ):
            if versions or hostnames or globals_ or blocks:
                raise InputError("Collection header appears inside configuration")
            continue
        if raw == "end":
            ended = True
            continue
        if raw.startswith("version "):
            versions += 1
            if not re.fullmatch(r"version \d+(?:\.\d+)*(?:\S*)", raw):
                raise InputError("Invalid version marker")
        if raw.startswith("hostname "):
            hostnames += 1
            if not re.fullmatch(r"hostname [A-Za-z0-9][A-Za-z0-9._-]{0,62}", raw):
                raise InputError("Invalid hostname marker")
        if raw.startswith("interface ") and not INTERFACE.fullmatch(raw[10:]):
            raise InputError("Unsupported interface identifier")
        if raw in {"configure terminal", "conf t", "exit", "write memory"}:
            raise InputError("Expected a full snapshot, not an interactive command script")
        if raw.startswith("banner "):
            match = re.fullmatch(r"banner ([a-z][a-z-]*) (.+)", raw)
            if not match:
                raise InputError("Unsupported banner format")
            tail = match[2]
            delimiter = tail[:2] if tail.startswith("^") and len(tail) >= 2 else tail[0]
            banner_body = [tail[len(delimiter) :]]
            while delimiter not in banner_body[-1]:
                if index >= len(lines):
                    raise InputError("Unterminated banner")
                banner_body.append(lines[index])
                index += 1
            if banner_body[-1].split(delimiter, 1)[1].strip():
                raise InputError("Content follows banner terminator")
            header, body = f"banner {match[1]}", banner_body
            finish()
        else:
            header = raw
    finish()
    if not ended or versions != 1 or hostnames != 1:
        raise InputError("Full snapshots require one version, one hostname and a final end marker")
    return Snapshot(digest(text), blocks, tuple(globals_))


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InputError("Duplicate policy key")
        result[key] = value
    return result


def load_policy(text):
    try:
        policy = json.loads(text.removeprefix("\ufeff"), object_pairs_hook=unique_object)
    except (ValueError, RecursionError) as exc:
        raise InputError("Policy must be valid JSON with unique keys") from exc
    keys = {
        "schema_version",
        "protected_interfaces",
        "required_ospf_processes",
        "required_routes",
        "required_vty_lines",
        "max_changed_scopes",
    }
    if not isinstance(policy, dict) or set(policy) != keys:
        raise InputError("Policy has missing or unknown fields")
    if type(policy["schema_version"]) is not int or policy["schema_version"] != 1:
        raise InputError("Unsupported policy schema version")
    interfaces = policy["protected_interfaces"]
    if (
        not isinstance(interfaces, list)
        or not interfaces
        or any(not isinstance(i, str) or not INTERFACE.fullmatch(i) for i in interfaces)
        or len(set(interfaces)) != len(interfaces)
    ):
        raise InputError("Protected interfaces must be unique full interface names")
    processes = policy["required_ospf_processes"]
    if (
        not isinstance(processes, list)
        or any(
            not isinstance(p, str) or not re.fullmatch(r"[1-9][0-9]{0,4}", p) or int(p) > 65535
            for p in processes
        )
        or len(set(processes)) != len(processes)
    ):
        raise InputError("OSPF processes must be unique canonical numeric strings")
    vty = policy["required_vty_lines"]
    if not isinstance(vty, list) or len(vty) != 2 or any(type(n) is not int for n in vty):
        raise InputError("VTY coverage must contain two integers")
    if not 0 <= vty[0] <= vty[1] <= 99:
        raise InputError("VTY range is outside the supported 0-99 range")
    limit = policy["max_changed_scopes"]
    if type(limit) is not int or not 1 <= limit <= 10000:
        raise InputError("Changed-scope limit must be an integer from 1 to 10000")
    routes = policy["required_routes"]
    if not isinstance(routes, list):
        raise InputError("Required routes must be a list")
    route_keys = []
    for route in routes:
        if not isinstance(route, dict) or set(route) != {"prefix", "next_hop"}:
            raise InputError("Required route needs only prefix and next_hop")
        try:
            prefix = ipaddress.IPv4Network(route["prefix"], strict=True)
            hop = ipaddress.IPv4Address(route["next_hop"])
            if str(prefix) != route["prefix"] or str(hop) != route["next_hop"]:
                raise ValueError
            if hop.is_multicast or hop.is_unspecified or hop.is_loopback:
                raise ValueError
        except (TypeError, ValueError, ipaddress.AddressValueError) as exc:
            raise InputError("Required route must use canonical IPv4 prefix and next hop") from exc
        route_keys.append((str(prefix), str(hop)))
    if len(set(route_keys)) != len(route_keys):
        raise InputError("Duplicate required route")
    return policy
