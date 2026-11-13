# ScanBrief

ScanBrief turns Nessus v2 exports into a local review queue and a deduplicated service inventory. Compare two exports to see what changed between assessments.

## Run the example

Requires Python 3.10+ and uses only the standard library. Extract the archive and run from its project directory.

```bash
python3 scanbrief.py examples/current.nessus --baseline examples/baseline.nessus --output demo
```

Replace the sample inputs with your exports. Use a new output directory each run. Add `--min-severity high` for a smaller triage queue.

| File | Contents |
| --- | --- |
| `triage.json` | Findings sorted by severity, with host, endpoint, plugin ID and remediation text |
| `services.csv` | Unique reported nonzero-port endpoints with observed service labels |

Findings deduplicate by host, protocol, port and plugin ID. When repeated entries disagree on severity, ScanBrief keeps the highest severity. The service inventory and baseline comparison use all observations, regardless of the triage filter.

The comparison separates findings on hosts present in both scans from hosts missing entirely. Treat a finding that disappeared as **not observed**. Scan scope, credentials and plugin coverage can change between exports. The service inventory reflects what the export reported and does not independently verify reachability.

ScanBrief reads trusted local exports. The reports can contain internal addresses and remediation details.
