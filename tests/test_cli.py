import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(*args):
    return subprocess.run([sys.executable, "scanbrief.py", *args],
                          cwd=ROOT, capture_output=True, text=True, check=False)


class CliTests(unittest.TestCase):
    def test_comparison_and_service_deduplication(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report"
            result = run("examples/current.nessus", "--baseline", "examples/baseline.nessus",
                         "--output", output)
            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads((output / "triage.json").read_text())
            self.assertEqual([row["severity"] for row in data["findings"]], [3])
            self.assertEqual(data["comparison"]["severity_changes"][0]["after"], 3)
            self.assertEqual(len((output / "services.csv").read_text().splitlines()), 2)
            repeated = run("examples/current.nessus", "--output", output)
            self.assertEqual(repeated.returncode, 2)

    def test_invalid_xml(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "bad.nessus"
            source.write_text("<broken>")
            result = run(source, "--output", Path(directory) / "report")
            self.assertEqual(result.returncode, 2)
            self.assertNotIn("Traceback", result.stderr)
