# ScanBrief

Turn Nessus v2 exports into a triage queue and service inventory.

## Quick start

Use Python 3.10 or newer. The CLI runs locally with the standard library. From the repository root, run:

```sh
python3 scanbrief.py examples/current.nessus --baseline examples/baseline.nessus --output demo
```

The sample yields one endpoint and one finding at the default threshold. The comparison records a severity increase, a newly observed informational plugin, and a plugin absent from the current scan.

## Input and output

| Input | Format | Output or purpose |
| --- | --- | --- |
| Current scan | Nessus v2 XML | `triage.json` and `services.csv` |
| `--baseline` | Earlier Nessus v2 XML | Added and absent observations, severity changes, and host coverage |
| `--min-severity` | `info`, `low`, `medium`, `high`, or `critical` | Filters triage findings only |

Use a fresh output directory for each run. The service CSV includes observed nonzero ports even when no findings meet the triage threshold.

## Interpreting results

Host IP is preferred over hostname. Findings are keyed by host, protocol, port and plugin ID. Duplicate findings retain the highest severity. Missing observations do not establish remediation. Compare scan scope, authentication, and plugin coverage first.

## Troubleshooting

- Use the included fixture first to confirm the command and working directory.
- Check the input path and required fields if the CLI exits with status 2.
- Keep real assessment exports and generated reports in your private workspace.

## Verify locally

```sh
python3 -m unittest discover -s tests -v
```

## Review workflow

Review host coverage before comparing findings. A missing host can indicate a change in scanner scope or reachability. Check service inventory independently of the finding severity threshold.
