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

Baseline SHA-256: `b720fa8facd2b515dd6579e30901bbb9cd45a9346cc33717594cf5977e09edf6`
Candidate SHA-256: `6a3ec6d586abcabccb058e56ba2bfeed321877c060fa9e8987acf910b8e08452`
Canonical policy SHA-256: `d0014c7dfe3e36be3ce889d190bd02bc7ed8947d48d05d323b553e7e1a7fc903`

Raw commands, hostnames, addresses, credential values and input paths are omitted.
Interface names, process IDs, counts and fingerprints remain; review before sharing.
Counts are structural line counts, not executable configuration operations.
