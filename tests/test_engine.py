import json
from pathlib import Path

import pytest

from changeguard.cli import markdown
from changeguard.engine import review
from changeguard.model import InputError, parse_snapshot


def assess(baseline, candidate, policy):
    return review(parse_snapshot(baseline), parse_snapshot(candidate), policy)


@pytest.mark.parametrize(
    "filename,status",
    [
        ("before", "pass"),
        ("description-only", "pass"),
        ("management-shutdown", "block"),
        ("telnet-enabled", "block"),
        ("required-route-removed", "block"),
        ("ospf-cost-change", "review"),
        ("unknown-feature", "review"),
    ],
)
def test_published_examples(baseline, policy, filename, status):
    candidate = (Path(__file__).parents[1] / "examples" / f"{filename}.cfg").read_text()
    assert assess(baseline, candidate, policy)["status"] == status


@pytest.mark.parametrize(
    "old,new,code",
    [
        ("ip address 192.0.2.11", "ip address 192.0.2.12", "MGMT_ADDRESS_CHANGED"),
        (" description Isolated management", " vrf forwarding PRIVATE", "MGMT_VRF_CHANGED"),
        (" description Isolated management", " shutdown", "MGMT_SHUTDOWN"),
        (" transport input ssh", " transport input all", "VTY_SSH_ONLY"),
        (" transport input ssh", "", "VTY_SSH_ONLY"),
        (" login local", " no login", "VTY_AUTH"),
        (" login local", " login", "VTY_AUTH"),
        ("line vty 0 4", "line vty 0 3", "VTY_COVERAGE"),
        ("router ospf 1", "router ospf 2", "OSPF_REQUIRED"),
        (" router-id 198.19.0.1", " shutdown\n router-id 198.19.0.1", "OSPF_REQUIRED"),
        ("ip route 203.0.113.0 255.255.255.0 198.18.0.2", "", "ROUTE_REQUIRED"),
        (
            "ip route 203.0.113.0 255.255.255.0 198.18.0.2",
            "ip route 203.0.113.0 255.255.255.0 198.18.0.6",
            "ROUTE_REQUIRED",
        ),
        (
            "username labadmin privilege 15 secret 5 SYNTHETIC-NONFUNCTIONAL-HASH",
            "",
            "LOCAL_ACCOUNT_MISSING",
        ),
    ],
)
def test_invariant_failures(baseline, policy, old, new, code):
    result = assess(baseline, baseline.replace(old, new), policy)
    assert result["status"] == "block"
    assert code in {f["code"] for f in result["findings"]}


def test_management_interface_removal(baseline, policy):
    candidate = baseline.replace(
        "interface GigabitEthernet0/0\n description Isolated management\n"
        " ip address 192.0.2.11 255.255.255.0\n",
        "",
    )
    assert "MGMT_REMOVED" in {f["code"] for f in assess(baseline, candidate, policy)["findings"]}


def test_bad_baseline_policy_never_passes(baseline, policy):
    policy["protected_interfaces"] = ["GigabitEthernet9/9"]
    with pytest.raises(InputError):
        assess(baseline, baseline, policy)


@pytest.mark.parametrize(
    "command",
    [
        "ip address dhcp",
        "ip address negotiated",
        "ip address 192.0.2.11 255.255.255.0 tag 10",
    ],
)
def test_unknown_management_addressing_needs_review(baseline, policy, command):
    candidate = baseline.replace("ip address 192.0.2.11 255.255.255.0", command)
    result = assess(baseline, candidate, policy)
    assert result["status"] == "review"
    assert "MGMT_UNSUPPORTED" in {f["code"] for f in result["findings"]}


def test_existing_insecure_state_blocks_even_without_diff(baseline, policy):
    insecure = baseline.replace("transport input ssh", "transport input telnet")
    result = assess(insecure, insecure, policy)
    assert result["status"] == "block"
    assert result["changes"] == []


def test_aaa_never_auto_approves(baseline, policy):
    aaa = baseline.replace("ip ssh version 2", "aaa new-model\nip ssh version 2")
    assert assess(aaa, aaa, policy)["status"] == "review"
    aaa = aaa.replace("login local", "login authentication default")
    assert assess(aaa, aaa, policy)["status"] == "review"


def test_second_vty_range_is_checked(baseline, policy):
    candidate = baseline.replace("end", "line vty 5 15\n login local\n transport input telnet\nend")
    result = assess(baseline, candidate, policy)
    assert result["status"] == "block"
    assert any(f["scope"] == "line vty 5 15" for f in result["findings"])


def test_overlapping_vty_ranges_are_invalid(baseline, policy):
    candidate = baseline.replace("end", "line vty 4 15\n login local\n transport input ssh\nend")
    with pytest.raises(InputError, match="Overlapping"):
        assess(baseline, candidate, policy)


def test_secret_and_unknown_block_values_never_enter_reports(baseline, policy):
    secret = "UNIQUE-PRIVATE-TOKEN-DO-NOT-PRINT"
    candidate = baseline.replace("SYNTHETIC-NONFUNCTIONAL-HASH", secret)
    candidate = candidate.replace("end", f"key chain {secret}\n key 1\n  key-string {secret}\nend")
    result = assess(baseline, candidate, policy)
    rendered = json.dumps(result) + markdown(result)
    for private in [secret, "192.0.2.11", "branch-lab", "labadmin", "key-string"]:
        assert private not in rendered
    assert result["status"] == "review"


def test_order_sensitive_global_rules_not_treated_as_equal(baseline, policy):
    old = baseline.replace("ip ssh version 2", "access-list 10 permit any\naccess-list 10 deny any")
    new = old.replace(
        "access-list 10 permit any\naccess-list 10 deny any",
        "access-list 10 deny any\naccess-list 10 permit any",
    )
    result = assess(old, new, policy)
    assert result["status"] == "review"
    assert result["summary"]["changed_scopes"] == 1


def test_nested_reorder_not_hidden_by_description_change(baseline, policy):
    old = baseline.replace(
        " description Primary lab path", " description old\n custom a\n custom b"
    )
    new = old.replace(
        " description old\n custom a\n custom b", " description new\n custom b\n custom a"
    )
    assert assess(old, new, policy)["status"] == "review"


def test_change_scope_limit(baseline, policy):
    policy["max_changed_scopes"] = 1
    candidate = baseline.replace("description Isolated management", "description New management")
    candidate = candidate.replace("description Primary lab path", "description New primary")
    result = assess(baseline, candidate, policy)
    assert result["status"] == "block"
    assert "CHANGE_SCOPE_LIMIT" in {f["code"] for f in result["findings"]}


def test_repeated_review_is_deterministic(baseline, policy):
    candidate = baseline.replace("ip ospf cost 10", "ip ospf cost 200")
    assert assess(baseline, candidate, policy) == assess(baseline, candidate, policy)


def test_unknown_routing_changes_cannot_pass(baseline, policy):
    candidate = baseline.replace(
        "end", "router bgp 64512\n neighbor 192.0.2.100 remote-as 64513\nend"
    )
    assert assess(baseline, candidate, policy)["status"] == "review"


def test_description_does_not_hide_shutdown(baseline, policy):
    candidate = baseline.replace(
        " description Isolated management", " description Update\n shutdown"
    )
    assert assess(baseline, candidate, policy)["status"] == "block"


def test_secondary_management_address_change_is_blocked(baseline, policy):
    candidate = baseline.replace(
        " description Isolated management",
        " description Isolated management\n ip address 192.0.2.20 255.255.255.0 secondary",
    )
    assert assess(baseline, candidate, policy)["status"] == "block"
