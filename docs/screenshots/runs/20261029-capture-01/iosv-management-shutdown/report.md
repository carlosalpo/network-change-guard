# Network Change Guard

Decision: **block**

This is a bounded policy review, not approval to deploy.

| Severity | Rule | Scope | Finding |
|---|---|---|---|
| block | MGMT_SHUTDOWN | interface GigabitEthernet0/0 | Protected interface is shut down. |
| review | CHANGE_REVIEW | change set | Non-description changes require review, including changes outside modeled rules. |

## Changes

| Scope | Kind | Added | Removed | Description only |
|---|---|---|---|---|
| interface GigabitEthernet0/0 | modified | 1 | 0 | no |

## Input identity

Baseline SHA-256: `e87c9a16ffceda1becddabf3909583fe87b78ac09365e3324f0e6a3d26d67ab9`
Candidate SHA-256: `fa2503da6599c10dd28266052a7ba93c164005e4e6a5f6cabc25fd33b471f0da`
Canonical policy SHA-256: `53d46f0eef2e5f63b55f6091c472ec2f5d8329dfa36639d56c026bb1c01c3943`

Raw commands, hostnames, addresses, credential values and input paths are omitted.
Interface names, process IDs, counts and fingerprints remain; review before sharing.
Counts are structural line counts, not executable configuration operations.
