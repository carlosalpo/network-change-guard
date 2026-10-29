# Validation record

This release combines unit/CLI tests, a seven-case end-to-end example matrix and
a format check against a configuration read from a dedicated IOSv 15.9(3)M6 router
on 2026-10-29. The tool evaluates files; it does not implement a deployment path.

## Device-format check

The router belonged to the synthetic Network Lab Factory experiment on EVE-NG
Professional 7.2.0-4. A temporary console helper started only that router, read
`show running-config` and `show version`, and stopped it in a `finally` block.
Existing topology files were checked against their pre-capture hashes. No candidate
configuration was sent to the router.

The captured configuration stayed on the EVE host. The same review engine evaluated
it there using three inputs:

| Input | Observed decision |
|---|---|
| Original snapshot compared with itself | `pass` |
| In-memory copy with protected Gi0/0 shut down | `block` |
| In-memory copy with a changed OSPF interface cost | `review` |

The original format exposed an `incoming` banner not covered by the first parser
draft. Banner handling was expanded and regression cases added before the run passed.

The [exported evidence](evidence/iosv-15.9-20261029/capture.json) includes a **reduced,
sanitized fixture**, not the untouched router configuration. Credentials were
replaced with a nonfunctional placeholder; hostname/descriptions were replaced;
unrelated globals, banners, certificate material and blocks were omitted. Only
allowlisted lab sections and synthetic addresses were exported. Reports in that
directory were regenerated from the exported fixture so they can be replayed.
The original in-place outcomes are recorded separately in `capture.json`.

The check validates this format and these static decisions. It is not evidence of
safe deployment, live traffic behavior, universal IOS compatibility or a security
certification. The preceding capture used a separate private test helper; that
helper is not a feature of the public CLI.

## Automated coverage

Tests cover:

- Management removal, shutdown, IPv4/secondary address and routing-context changes.
- Required route/OSPF presence, SSH-only VTY coverage and local-login prerequisites.
- AAA and unsupported-addressing review paths, unknown routing changes and ACL ordering.
- Description-only changes, mixed description/technical changes and scope limits.
- Missing/truncated snapshots, duplicate blocks/keys, overlapping ranges and malformed policies.
- Multiline/inline banners, control characters, oversized files and collection headers.
- Credential/input-path omission, deterministic output, private permissions and stale-output refusal.
- CLI exit codes and replay of the sanitized device-format evidence.

The seven committed demonstration cases exercise the installed CLI and assert
the expected pass/block/review decision and exit code. The workflow tests Python
3.11, 3.12 and 3.13 on Linux and uploads only reports made from synthetic examples.
Local development checks also run on macOS. CI does not contact EVE-NG.

## Reproduce

```bash
python -m pip install -e '.[dev]'
ruff check src tests scripts
ruff format --check src tests scripts
pytest -q
python scripts/check_examples.py --output reports/reproduction
```

Each review's JSON records the source snapshot and canonical-policy fingerprints.
The published release identifies the source code. File hashes bind a review to
specific bytes; they do not authenticate a collector, a reviewer or a deployment.
