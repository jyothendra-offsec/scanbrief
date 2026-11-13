"""Build a local triage report from Nessus v2 exports."""
import argparse
import csv
import json
import xml.etree.ElementTree as ET
from pathlib import Path

SEVERITIES = ("info", "low", "medium", "high", "critical")


def load_scan(path):
    hosts, findings, services = set(), {}, {}
    with path.open("rb") as stream:
        context = ET.iterparse(stream, events=("start", "end"))
        _, root = next(context)
        if root.tag != "NessusClientData_v2":
            raise ValueError("expected a Nessus v2 XML export")
        for event, node in context:
            if event != "end" or node.tag != "ReportHost":
                continue
            host = (node.findtext("./HostProperties/tag[@name='host-ip']")
                    or node.get("name") or "").strip()
            if not host:
                raise ValueError("report host has no IP or name")
            hosts.add(host)
            for item in node.findall("ReportItem"):
                plugin = item.attrib["pluginID"]
                port = int(item.attrib["port"])
                severity = int(item.attrib["severity"])
                if not 0 <= severity < len(SEVERITIES) or not 0 <= port <= 65535:
                    raise ValueError("invalid port or severity")
                protocol = item.get("protocol", "").lower()
                service = item.get("svc_name", "").strip()
                endpoint = (host, protocol, port)
                if port:
                    names = services.setdefault(endpoint, set())
                    if service and service != "unknown":
                        names.add(service)
                key = (*endpoint, plugin)
                row = dict(host=host, protocol=protocol, port=port, plugin=plugin,
                           severity=severity, name=item.get("pluginName", ""),
                           remediation=(item.findtext("solution") or "").strip())
                if key not in findings or severity > findings[key]["severity"]:
                    findings[key] = row
            node.clear()
    if not hosts:
        raise ValueError("export contains no report hosts")
    return hosts, findings, services


def compare(current_hosts, current, previous):
    previous_hosts, old, _ = previous
    return {
        "new_on_common_hosts": sorted(k for k in current.keys() - old.keys()
                                      if k[0] in previous_hosts),
        "not_observed_on_common_hosts": sorted(k for k in old.keys() - current.keys()
                                               if k[0] in current_hosts),
        "new_hosts": sorted(current_hosts - previous_hosts),
        "missing_hosts": sorted(previous_hosts - current_hosts),
        "severity_changes": [
            {"key": k, "before": old[k]["severity"], "after": current[k]["severity"]}
            for k in sorted(current.keys() & old.keys())
            if old[k]["severity"] != current[k]["severity"]
        ],
    }


def csv_safe(value):
    # Prevent spreadsheet formulas from executing when opening the inventory.
    if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scan", type=Path)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--min-severity", choices=SEVERITIES, default="medium")
    parser.add_argument("--output", type=Path, required=True, help="New output directory")
    args = parser.parse_args()
    try:
        hosts, findings, services = load_scan(args.scan)
        report = {
            "hosts": sorted(hosts),
            "minimum_severity": args.min_severity,
            "findings": sorted(
                (row for row in findings.values()
                 if row["severity"] >= SEVERITIES.index(args.min_severity)),
                key=lambda row: (-row["severity"], row["host"], row["port"],
                                 row["protocol"], row["plugin"]),
            ),
        }
        if args.baseline:
            report["comparison"] = compare(hosts, findings, load_scan(args.baseline))
        args.output.mkdir()
        with (args.output / "triage.json").open("w", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2)
            stream.write("\n")
        with (args.output / "services.csv").open("w", encoding="utf-8", newline="") as stream:
            writer = csv.writer(stream)
            writer.writerow(("host", "protocol", "port", "reported_services"))
            for (host, protocol, port), names in sorted(services.items()):
                writer.writerow(map(csv_safe, (host, protocol, port, "; ".join(sorted(names)))))
    except (OSError, ValueError, KeyError, ET.ParseError) as exc:
        parser.exit(2, f"scanbrief: {exc}\n")
    print(f"{len(hosts)} hosts · {len(services)} endpoints · {len(report['findings'])} findings")


if __name__ == "__main__":
    main()
