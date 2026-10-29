# Synthetic review scenarios

All candidates are **complete snapshots**, not command patches. Addresses use
documentation and benchmarking ranges. The credential statement contains an
intentionally nonfunctional placeholder. These fixtures must not be deployed.

| Candidate | Expected exit | Decision | Reason |
|---|---|---|---|
| `before.cfg` | 0 | pass | Unchanged, modeled invariants hold |
| `description-only.cfg` | 0 | pass | Only an interface description changes |
| `management-shutdown.cfg` | 1 | block | Protected management interface shut down |
| `telnet-enabled.cfg` | 1 | block | VTY accepts Telnet in addition to SSH |
| `required-route-removed.cfg` | 1 | block | Required prefix/next-hop pair absent |
| `ospf-cost-change.cfg` | 3 | review | Routing preference change needs human assessment |
| `unknown-feature.cfg` | 3 | review | Unmodeled global command changed |

Example (from the repository root):

```bash
ncg review --before examples/before.cfg \
  --candidate examples/management-shutdown.cfg \
  --policy examples/policy.json --output reports/management-shutdown
```

Exit 1 is the expected result for this example. See `report.md` and `report.json`
inside the new output directory. Existing output directories are never reused.
