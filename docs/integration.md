# Privacy and integration

## A local change-review workflow

1. Collect a trusted baseline through your existing process.
2. Prepare the intended complete candidate snapshot separately.
3. Select a policy that explicitly names the management interfaces and required routing intent.
4. Run `ncg review` into a new private report directory.
5. Treat exit 1 as blocked, exit 2 as an invalid run and exit 3 as requiring review.
6. Compare the report hashes with the inputs you reviewed. Obtain normal change approval,
   test in a dedicated lab and use your established deployment/recovery procedure.

The tool has no `apply`, SSH session, credential store or rollback executor.
Reviewing a file does not authorize deploying it. Baseline provenance, approval
identity and protection of the policy itself belong to the surrounding workflow.

## CI use

For a repository containing **only synthetic lab inputs**, the basic gate is:

```yaml
- name: Review the candidate
  run: |
    ncg review --before examples/before.cfg \
      --candidate examples/description-only.cfg \
      --policy examples/policy.json --output reports/review
```

The step fails on every result except `pass`. Do not add `|| true` or treat exit 3
as a successful gate. A human approval path should be separate and tied to the
exact input hashes; the tool does not implement that approval path.

This repository's CI tests the intentionally blocked/review examples by asserting
their expected exit codes. That test harness is not a production approval gate.
It publishes artifacts only from the committed synthetic examples. For real
configurations, keep inputs private and choose controlled report retention and
access. A public CI job is not an appropriate place for private network backups.

## Output minimization

Reports do not contain raw command lines, raw diffs, filenames, device hostnames,
IP addresses or credential values. Interface/process labels are narrowly formatted;
unmodeled block labels become opaque fingerprints. Markdown uses only these
bounded identifiers and fixed finding text. This avoids relying on a secret-keyword
denylist that could miss a new vendor command.

Reports still contain interface names, process IDs, configuration fingerprints and
change counts. Hashes are identifiers, not signatures, encryption or proof of
authenticity; predictable inputs can be guessed. Review the reports before sharing.
The tool is not a general redaction or secret-detection service.

New output directories use mode 0700 and report files use mode 0600, subject to
the operating system's permission model. Existing directories are rejected to
avoid confusing stale and current results. `report.json` is published only after
the Markdown and complete JSON content have been written. Always check the process
exit code; never select an arbitrary old report after a failed run.
