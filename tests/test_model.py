import hashlib
import json

import pytest

from changeguard.model import InputError, load_policy, parse_snapshot, read_text


@pytest.mark.parametrize(
    "transform",
    [
        lambda s: s.replace("end\n", ""),
        lambda s: s.replace("version 15.9", ""),
        lambda s: s.replace("hostname branch-lab", ""),
        lambda s: s + "configure terminal\n",
        lambda s: s.replace("version 15.9", "version 15.9\nversion 15.9"),
        lambda s: s.replace("hostname branch-lab", "hostname branch-lab\nhostname other"),
        lambda s: s.replace("end", "interface GigabitEthernet0/0\n shutdown\nend"),
        lambda s: s.replace(" ip ospf cost 10", "\tip ospf cost 10"),
        lambda s: s + "\x00",
        lambda s: s.replace("description", "descr\u202eiption"),
        lambda s: s.replace("description", "description\u2028"),
        lambda s: " orphan\n" + s,
        lambda s: s.replace("end", "banner motd ^C\nno terminator\nend"),
    ],
)
def test_malformed_snapshots_fail_closed(baseline, transform):
    with pytest.raises(InputError):
        parse_snapshot(transform(baseline))


def test_banner_cannot_inject_configuration(baseline):
    text = baseline.replace(
        "end", "banner motd ^C\ninterface GigabitEthernet9/9\n shutdown\nend\n^C\nend"
    )
    snapshot = parse_snapshot(text)
    assert "interface GigabitEthernet9/9" not in snapshot.blocks
    assert "banner motd" in snapshot.blocks


@pytest.mark.parametrize("kind", ["motd", "login", "exec", "incoming", "prompt-timeout"])
def test_inline_banner(baseline, kind):
    snapshot = parse_snapshot(baseline.replace("end", f"banner {kind} #Private notice#\nend"))
    assert f"banner {kind}" in snapshot.blocks


def test_collection_headers_and_crlf(baseline):
    text = "Building configuration...\n\nCurrent configuration : 2458 bytes\n" + baseline
    assert parse_snapshot(text.replace("\n", "\r\n")).blocks == parse_snapshot(baseline).blocks


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", True),
        ("schema_version", 2),
        ("protected_interfaces", []),
        ("protected_interfaces", ["Gi0/0\nshutdown"]),
        ("protected_interfaces", ["GigabitEthernet0/0", "GigabitEthernet0/0"]),
        ("required_ospf_processes", ["01"]),
        ("required_ospf_processes", [True]),
        ("required_ospf_processes", ["1", "1"]),
        ("required_ospf_processes", ["65536"]),
        ("required_ospf_processes", ["9" * 5000]),
        ("required_vty_lines", [True, 4]),
        ("required_vty_lines", [4, 0]),
        ("required_vty_lines", [0, 100]),
        ("required_vty_lines", "0 4"),
        ("max_changed_scopes", True),
        ("max_changed_scopes", 0),
        ("required_routes", [{"prefix": "203.0.113.1/24", "next_hop": "198.18.0.2"}]),
        ("required_routes", [{"prefix": "203.0.113.0/24", "next_hop": "0.0.0.0"}]),
        ("required_routes", [{"prefix": "203.0.113.0/24", "next_hop": "224.0.0.1"}]),
        ("required_routes", [{"prefix": "::/0", "next_hop": "198.18.0.2"}]),
    ],
)
def test_strict_policy_types_and_addresses(policy, field, value):
    policy[field] = value
    with pytest.raises(InputError):
        load_policy(json.dumps(policy))


def test_unknown_and_duplicate_policy_keys(policy_text):
    with pytest.raises(InputError):
        load_policy(policy_text.replace('"schema_version": 1', '"schema_version": 1, "typo": 2'))
    with pytest.raises(InputError):
        load_policy(
            policy_text.replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1')
        )


def test_missing_and_oversized_inputs(tmp_path):
    with pytest.raises(InputError):
        read_text(tmp_path / "missing")
    path = tmp_path / "large"
    path.write_bytes(b"x" * 2_000_001)
    with pytest.raises(InputError, match="2 MB"):
        read_text(path)


def test_command_patch_rejected():
    with pytest.raises(InputError):
        parse_snapshot("interface GigabitEthernet0/0\n shutdown\nend\n")


def test_fingerprint_preserves_utf8_bom_and_crlf(tmp_path, baseline, policy_text):
    raw = ("\ufeff" + baseline.replace("\n", "\r\n")).encode("utf-8")
    path = tmp_path / "export.cfg"
    path.write_bytes(raw)
    snapshot = parse_snapshot(read_text(path))
    assert snapshot.sha256 == hashlib.sha256(raw).hexdigest()
    assert snapshot.blocks == parse_snapshot(baseline).blocks
    assert load_policy("\ufeff" + policy_text) == load_policy(policy_text)
