# Network Change Guard

Decision: **block**

This is a bounded policy review, not approval to deploy.

| Severity | Rule | Scope | Finding |
|---|---|---|---|
| block | VTY_SSH_ONLY | line vty 0 4 | Every VTY range must explicitly accept SSH only. |
| review | CHANGE_REVIEW | change set | Non-description changes require review, including changes outside modeled rules. |

## Changes

| Scope | Kind | Added | Removed | Description only |
|---|---|---|---|---|
| line vty 0 4 | modified | 1 | 1 | no |

## Input identity

Baseline SHA-256: `b720fa8facd2b515dd6579e30901bbb9cd45a9346cc33717594cf5977e09edf6`
Candidate SHA-256: `a454ad23e8744453def12945cd6d07e9a76256ba5ffaa439b4b022f1b1280a3f`
Canonical policy SHA-256: `d0014c7dfe3e36be3ce889d190bd02bc7ed8947d48d05d323b553e7e1a7fc903`

Raw commands, hostnames, addresses, credential values and input paths are omitted.
Interface names, process IDs, counts and fingerprints remain; review before sharing.
Counts are structural line counts, not executable configuration operations.
