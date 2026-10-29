# Network Change Guard

Decision: **block**

This is a bounded policy review, not approval to deploy.

| Severity | Rule | Scope | Finding |
|---|---|---|---|
| block | ROUTE_REQUIRED | required route 1 | Required IPv4 prefix/next-hop pair is absent or uses unsupported route syntax. |
| review | CHANGE_REVIEW | change set | Non-description changes require review, including changes outside modeled rules. |

## Changes

| Scope | Kind | Added | Removed | Description only |
|---|---|---|---|---|
| global commands | modified | 0 | 1 | no |

## Input identity

Baseline SHA-256: `b720fa8facd2b515dd6579e30901bbb9cd45a9346cc33717594cf5977e09edf6`
Candidate SHA-256: `3980b3435a761983eb9925ce00073cd3cbe0cdd137df9d2981173a871c3a182f`
Canonical policy SHA-256: `d0014c7dfe3e36be3ce889d190bd02bc7ed8947d48d05d323b553e7e1a7fc903`

Raw commands, hostnames, addresses, credential values and input paths are omitted.
Interface names, process IDs, counts and fingerprints remain; review before sharing.
Counts are structural line counts, not executable configuration operations.
