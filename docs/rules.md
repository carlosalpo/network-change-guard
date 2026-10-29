# Rule semantics and limits

Policies use schema version 1. Every field in the example policy is required;
unknown fields and duplicate JSON keys are invalid. Full interface names are
matched exactly. Process IDs use canonical decimal strings. Static route policy
entries use canonical IPv4 CIDR prefixes and next-hop addresses.

## Management

`protected_interfaces` compares the same named interface in both snapshots.
The baseline must contain that interface with a static IPv4 address. The candidate
must retain it, its primary/secondary address set and its VRF forwarding statement,
and must not contain `shutdown`. Multiple primary address statements are invalid.
Dynamic addressing and nested interface commands require review. A change to a
protected interface description can pass if every modeled invariant still holds.

This checks configuration intent. It does not prove that a physical link is up,
that an ACL permits a controller, that a gateway is reachable or that a console
fallback exists. Interface identifiers are case-sensitive; abbreviations are not
expanded. IPv6 management is outside the profile.

## Remote access

Every configured `line vty` block must contain exactly `transport input ssh`.
This also checks ranges beyond `required_vty_lines`. Ranges must not overlap.
The required inclusive range must be covered; the tool does not know the number
of VTY lines actually present on an unseen device.

The local-login profile accepts exactly `login local`, with at least one recognized
top-level `username ... secret/password ...` statement. It does not validate a
password/hash, user authorization, privilege, SSH keys or protocol negotiation.
The deliberately nonfunctional example credential is sufficient for this static
presence check but could never establish a real login.

`login authentication ...` and any top-level AAA statements require review rather
than a pass. Missing or ambiguous authentication blocks the candidate. `transport
input none` blocks too: this profile is designed to preserve SSH management access,
not merely to prohibit Telnet.

Cisco describes the roles of SSH, local/AAA authentication and VTY transport in
[Configure SSH on Routers](https://www.cisco.com/c/en/us/support/docs/security-vpn/secure-shell-ssh/4145-ssh.html).
These rules cover a small local-login profile rather than the full authentication model.

## Routing

`required_ospf_processes` requires a matching `router ospf <id>` block without an
explicit `shutdown`. It does not prove adjacency formation, advertised networks,
area consistency, authentication or reachability. Changes to OSPF commands require
review even when the process remains present.

`required_routes` recognizes `ip route <network> <mask> <IPv4-next-hop>` with an
optional administrative distance from 1 to 255. It checks that the exact prefix
and next-hop pair exists. Interface-only, VRF, tracked and named routes are not
interpreted; they cannot satisfy this assertion. It does not determine whether
the route is active, preferred or usable. A distance or cost change always requires
review even if the presence check still holds.

## Structural comparison

Existing interface-description changes are the sole automatic change allowance.
Adding/removing an entire block, changing credentials, reordering ACL entries or
changing an unsupported feature requires review. Global statements form one scope;
each parent block forms another. Added/removed counts describe text structure, not
commands to execute. `max_changed_scopes` limits this count, not the number of devices
affected or a measured outage radius.

Unknown **unchanged** content is retained for comparison but is not certified by
the rules. Unsupported details specifically encountered in modeled management,
VTY or OSPF fields trigger review. A pass is not a universal syntax or security audit.

## Snapshot contract

Use complete configurations collected/generated through a trusted process. The
reader accepts common collection headers, comments, CRLF and bounded multiline
banners; rejects control/invisible separator characters, missing markers, duplicate
blocks and ambiguous VTY ranges; and limits files to 2 MB. It does not emulate a
sequence of CLI edits. Input/output errors return code 2 without a current decision.

The complete-snapshot distinction also matters in IOS itself: Cisco differentiates
configuration replacement from merging partial configuration commands in its
[configuration replacement documentation](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/config-mgmt/configuration/15mt/config-mgmt-15-mt-book/cm-config-rollback.html).
This project executes neither operation and does not generate rollback commands.
