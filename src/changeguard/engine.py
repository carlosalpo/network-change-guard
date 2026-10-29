"""Conservative change classification and explicit candidate invariants."""

import ipaddress
import json
import re
from collections import Counter

from .model import InputError, digest


def scope_name(header):
    if header.startswith("interface "):
        return header
    if re.fullmatch(r"router ospf [0-9]{1,5}", header):
        return header
    if re.fullmatch(r"line vty [0-9]{1,2}(?: [0-9]{1,2})?", header):
        return header
    if header.startswith("banner "):
        return "banner"
    return "opaque block " + digest(header)[:12]


def direct(lines):
    return [line[1:] for line in lines if line.startswith(" ") and not line.startswith("  ")]


def addresses(lines):
    values = []
    for line in direct(lines):
        if not line.startswith("ip address "):
            continue
        match = re.fullmatch(r"ip address (\S+) (\S+)( secondary)?", line)
        if not match:
            return None
        try:
            address = ipaddress.IPv4Interface(f"{match[1]}/{match[2]}")
        except ValueError as exc:
            raise InputError("Invalid static IPv4 interface address") from exc
        values.append((str(address), bool(match[3])))
    if len(values) != len(set(values)) or sum(not secondary for _, secondary in values) > 1:
        raise InputError("Ambiguous IPv4 interface address statements")
    return sorted(values)


def static_routes(snapshot):
    routes = set()
    for line in snapshot.globals:
        match = re.fullmatch(r"ip route (\S+) (\S+) (\S+)(?: ([0-9]+))?", line)
        if match:
            try:
                prefix = ipaddress.IPv4Network(f"{match[1]}/{match[2]}", strict=True)
                hop = ipaddress.IPv4Address(match[3])
                if match[4] and not 1 <= int(match[4]) <= 255:
                    raise ValueError
            except ValueError:
                continue
            routes.add((str(prefix), str(hop)))
    return routes


def review(before, candidate, policy):
    findings, changes = [], []

    def finding(code, severity, scope, message):
        findings.append({"code": code, "severity": severity, "scope": scope, "message": message})

    for name in policy["protected_interfaces"]:
        header = "interface " + name
        if header not in before.blocks:
            raise InputError("A protected interface is absent from the baseline")
        if header not in candidate.blocks:
            finding("MGMT_REMOVED", "block", header, "Protected interface is absent.")
            continue
        old, new = before.blocks[header], candidate.blocks[header]
        commands = direct(new)
        if "shutdown" in commands:
            finding("MGMT_SHUTDOWN", "block", header, "Protected interface is shut down.")
        a, b = addresses(old), addresses(new)
        if a is None or b is None or any(line.startswith("  ") for line in (*old, *new)):
            finding(
                "MGMT_UNSUPPORTED",
                "review",
                header,
                "Protected interface uses addressing or nesting outside the static IPv4 profile.",
            )
        elif not a:
            raise InputError("Protected baseline interface needs a static IPv4 address")
        elif a != b:
            finding(
                "MGMT_ADDRESS_CHANGED",
                "block",
                header,
                "Protected static IPv4 addresses differ from the baseline.",
            )

        def vrf(body):
            return [
                c for c in direct(body) if c.startswith(("vrf forwarding ", "ip vrf forwarding "))
            ]

        if vrf(old) != vrf(new):
            finding(
                "MGMT_VRF_CHANGED", "block", header, "Protected interface routing context changed."
            )
        if any(c.startswith(("no ip address", "no shutdown")) for c in commands):
            finding(
                "NONCANONICAL_INTERFACE",
                "review",
                header,
                "Review noncanonical interface commands against device-generated output.",
            )

    coverage = set()
    local_auth_used = False
    for header, body in candidate.blocks.items():
        if not header.startswith("line vty"):
            continue
        match = re.fullmatch(r"line vty ([0-9]{1,2})(?: ([0-9]{1,2}))?", header)
        if not match:
            raise InputError("Unsupported VTY range")
        first, last = int(match[1]), int(match[2] or match[1])
        if first > last:
            raise InputError("Invalid VTY range")
        numbers = set(range(first, last + 1))
        if coverage & numbers:
            raise InputError("Overlapping VTY ranges are ambiguous")
        coverage |= numbers
        commands = direct(body)
        transports = [c for c in commands if c.startswith("transport input ")]
        if transports != ["transport input ssh"]:
            finding(
                "VTY_SSH_ONLY", "block", header, "Every VTY range must explicitly accept SSH only."
            )
        auth = [c for c in commands if c == "login" or c.startswith(("login ", "no login"))]
        if auth == ["login local"]:
            local_auth_used = True
        elif len(auth) == 1 and auth[0].startswith("login authentication "):
            finding(
                "VTY_AAA_REVIEW",
                "review",
                header,
                "AAA authentication is outside this local-login profile; verify its method list.",
            )
        else:
            finding(
                "VTY_AUTH",
                "block",
                header,
                "VTY authentication is absent, ambiguous or outside the accepted login forms.",
            )
        if any(c.startswith("  ") for c in body):
            finding("VTY_NESTING", "review", header, "Nested VTY commands need manual review.")
    first, last = policy["required_vty_lines"]
    if not set(range(first, last + 1)) <= coverage:
        finding(
            "VTY_COVERAGE",
            "block",
            "management",
            "Required VTY lines are missing from the candidate snapshot.",
        )
    local_accounts = [
        c
        for c in candidate.globals
        if re.fullmatch(r"username \S+(?: privilege (?:[0-9]|1[0-5]))? (?:secret|password) .+", c)
    ]
    if local_auth_used and not local_accounts:
        finding(
            "LOCAL_ACCOUNT_MISSING",
            "block",
            "management",
            "Local VTY authentication has no recognized local credential statement.",
        )
    if any(c.startswith("aaa ") for c in candidate.globals):
        finding(
            "AAA_REVIEW",
            "review",
            "management",
            "AAA behavior requires validation beyond this local-login profile.",
        )

    for process in policy["required_ospf_processes"]:
        header = "router ospf " + process
        if header not in candidate.blocks or "shutdown" in direct(candidate.blocks[header]):
            finding(
                "OSPF_REQUIRED",
                "block",
                header,
                "Required OSPF process is missing or explicitly shut down.",
            )
        elif any(c.startswith("  ") for c in candidate.blocks[header]):
            finding(
                "OSPF_NESTING",
                "review",
                header,
                "Required OSPF process contains nesting outside this profile.",
            )
    routes = static_routes(candidate)
    for index, route in enumerate(policy["required_routes"], 1):
        if (route["prefix"], route["next_hop"]) not in routes:
            finding(
                "ROUTE_REQUIRED",
                "block",
                f"required route {index}",
                "Required IPv4 prefix/next-hop pair is absent or uses unsupported route syntax.",
            )

    if before.globals != candidate.globals:
        a, b = Counter(before.globals), Counter(candidate.globals)
        changes.append(
            {
                "scope": "global commands",
                "kind": "modified",
                "cosmetic": False,
                "added": sum((b - a).values()),
                "removed": sum((a - b).values()),
            }
        )
    for header in sorted(before.blocks.keys() | candidate.blocks.keys()):
        old, new = before.blocks.get(header), candidate.blocks.get(header)
        if old == new:
            continue
        a, b = Counter(old or ()), Counter(new or ())
        differing = list((a - b).elements()) + list((b - a).elements())
        cosmetic = bool(
            old is not None
            and new is not None
            and differing
            and header.startswith("interface ")
            and all(line.startswith(" description ") for line in differing)
            and tuple(c for c in old if not c.startswith(" description "))
            == tuple(c for c in new if not c.startswith(" description "))
        )
        changes.append(
            {
                "scope": scope_name(header),
                "kind": "added" if old is None else "removed" if new is None else "modified",
                "cosmetic": cosmetic,
                "added": sum((b - a).values()),
                "removed": sum((a - b).values()),
            }
        )
    if any(not change["cosmetic"] for change in changes):
        finding(
            "CHANGE_REVIEW",
            "review",
            "change set",
            "Non-description changes require review, including changes outside modeled rules.",
        )
    if len(changes) > policy["max_changed_scopes"]:
        finding(
            "CHANGE_SCOPE_LIMIT",
            "block",
            "change set",
            "The number of changed configuration scopes exceeds the policy limit.",
        )
    status = (
        "block"
        if any(f["severity"] == "block" for f in findings)
        else ("review" if findings else "pass")
    )
    findings.sort(key=lambda f: (f["severity"] != "block", f["code"], f["scope"]))
    return {
        "schema_version": 1,
        "status": status,
        "before_sha256": before.sha256,
        "candidate_sha256": candidate.sha256,
        "policy_sha256": digest(json.dumps(policy, sort_keys=True)),
        "scope": "Cisco IOS static snapshots; policy checks, not deployment approval",
        "summary": {
            "changed_scopes": len(changes),
            "blockers": sum(f["severity"] == "block" for f in findings),
            "reviews": sum(f["severity"] == "review" for f in findings),
        },
        "changes": changes,
        "findings": findings,
    }
