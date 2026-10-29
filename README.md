# Network Change Guard

[![CI](https://github.com/carlosalpo/network-change-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/carlosalpo/network-change-guard/actions/workflows/ci.yml)

**Review network configuration changes before they become an outage.**

A text diff shows that a line changed. A network reviewer needs to know whether
the change removes management access, loses a required route, disables a routing
process or weakens remote access. Network Change Guard compares two complete
Cisco IOS configuration snapshots against an explicit JSON policy and produces
a deterministic review in JSON and Markdown.

The tool runs offline, has no runtime dependencies and never connects to a device.
It is a bounded pre-change check that can sit beside a pull request, a change
ticket or an Ansible workflow.

## A review decision with a precise meaning

| Decision | Exit code | Meaning |
|---|---|---|
| `pass` | 0 | Modeled candidate checks hold, and there is no substantive change; only interface descriptions may differ |
| `block` | 1 | A defined invariant or change-scope limit is violated |
| Input/output error | 2 | No current review can be relied on; fix the inputs or destination |
| `review` | 3 | No blocker found, but a technical change or unsupported semantic detail needs human review |

`pass` does not mean safe to deploy. A routing-cost change, a new BGP block, a
credential rotation or an unknown feature cannot silently become a pass just
because none of the specific blocking rules matched.

## Try the examples

Requires Python 3.11 or newer. From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'

ncg review --before examples/before.cfg \
  --candidate examples/description-only.cfg \
  --policy examples/policy.json --output reports/description-review
```

The result is `pass`. Open `report.md` or `report.json` in the new directory.
Now try a management outage:

```bash
ncg review --before examples/before.cfg \
  --candidate examples/management-shutdown.cfg \
  --policy examples/policy.json --output reports/shutdown-review
```

This intentionally exits with code 1 and reports `MGMT_SHUTDOWN`. The
[example matrix](examples/README.md) also covers Telnet exposure, a removed route,
an OSPF cost change and an unmodeled feature. Run the entire matrix with:

```bash
python scripts/check_examples.py --output reports/example-matrix
pytest -q
```

All committed configurations are synthetic or explicitly sanitized lab fixtures.
The credential placeholders are nonfunctional. These files are review inputs,
not deployable device configurations.

## What the rules protect

| Area | Check |
|---|---|
| Management interfaces | Preserve existence, static IPv4 addresses and routing context; reject shutdown |
| Remote access | Require explicit SSH-only transport and configured authentication on every VTY range |
| VTY coverage | Ensure the policy's required terminal lines are represented |
| Local login | Require a recognized local credential statement when local authentication is used |
| OSPF | Preserve required process IDs and reject an explicit process shutdown |
| Static routing | Retain each required IPv4 prefix/next-hop pair within the supported route syntax |
| Change size | Limit changed configuration scopes, including a single global-command scope |
| Unmodeled changes | Require review for any substantive change outside the description-only allowance |

See [rule semantics](docs/rules.md) for what each check proves and what it does not.
AAA, IPv6 routing, ACL reachability, BGP policy, route selection and operational
health are not modeled. A policy is intentionally more specific than a risk score.

## Use your own snapshots

Keep device exports under `private/` or outside the repository. Provide complete
before/desired snapshots in IOS running-configuration form, with `version`,
`hostname` and final `end` markers. Command patches are not supported. The parser
checks structure but cannot prove a file is complete or genuinely collected from
a device. Use a trusted collection process and the right baseline.

Copy [examples/policy.json](examples/policy.json) to a private policy, then set
full interface names, required OSPF processes, required routes, VTY coverage and
the scope limit. Unknown policy fields, duplicate keys and ambiguous ranges are
rejected. Reports bind the decision to snapshot and canonical-policy hashes.

```bash
ncg review --before private/before.cfg --candidate private/candidate.cfg \
  --policy private/policy.json --output reports/change-0042
```

Output directories cannot be reused. Reports use private file permissions and
omit raw commands, credential values, hostnames, IP addresses and source paths.
Interface names, process IDs, structural counts and hashes remain. This is
deliberately a summary, not a sanitized full-config diff or a general secret scanner.
Review reports before sharing. See [privacy and integration](docs/integration.md).

## How it works

The reader separates global statements, parent/child blocks and multiline banners.
The policy evaluator checks candidate invariants, while a separate comparison
detects additions, removals and ordering changes. Every substantive change requires
review even when the evaluator does not understand its protocol. Renderers receive
only allowlisted findings and structural summaries, not the source configuration.

This separation prevents unsupported syntax from being mistaken for a fully
understood change and prevents a report template from accidentally printing secrets.
It does not make the tool a complete IOS parser or a reachability simulator.

## Validation and scope

[Validation evidence](docs/validation.md) describes automated tests, the end-to-end
example matrix and the device-format compatibility check. CI runs on Python 3.11,
3.12 and 3.13 without contacting a network device. See the recorded evidence for
the exact tested boundaries.

The complementary [Network Lab Factory](https://github.com/carlosalpo/network-lab-factory)
builds a dedicated environment and collects forwarding evidence. Change Guard
reviews configuration intent. Neither replaces the other's checks.

## Roadmap

- Additional, separately tested vendor/platform profiles.
- More explicit policy assertions with observed operational evidence.
- Reviewable approval records bound to the exact input hashes.

Automatic deployment, rollback execution and broad compliance certification are
outside this release.

## Author and license

Created by [Carlos Alvarado](https://github.com/carlosalpo), Technology Solutions Architect.
MIT licensed. Cisco IOS is a separate product with its own licensing and requirements.
