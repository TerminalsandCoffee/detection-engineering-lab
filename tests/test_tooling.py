"""Offline regression tests for the public detection tooling commands."""

import contextlib
import csv
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import requests

ROOT = Path(__file__).resolve().parents[1]
VALID = '''[metadata]
creation_date = "2026/01/02"
[rule]
author = ["Lab Author"]
description = "A fixture detection"
from = "now-6m"
enabled = false
name = "Archive, inspect"
risk_score = 50
severity = "medium"
type = "query"
rule_id = "00000000-0000-0000-0000-000000000001"
query = "event.action: archive"
[[rule.threat]]
framework = "MITRE ATT&CK"
[rule.threat.tactic]
id = "TA0009"
name = "Collection"
reference = "https://attack.mitre.org/tactics/TA0009/"
[[rule.threat.technique]]
id = "T1074"
name = "Data Staged"
reference = "https://attack.mitre.org/techniques/T1074/"
[[rule.threat.technique.subtechnique]]
id = "T1074.001"
name = "Local Data Staging"
reference = "https://attack.mitre.org/techniques/T1074/001/"
'''


class ToolingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.project = Path(self.temp.name)
        shutil.copytree(ROOT / "development", self.project / "development", ignore=shutil.ignore_patterns("__pycache__"))
        self.detections = self.project / "detections"
        self.detections.mkdir()
        (self.detections / "fixture.toml").write_text(VALID, encoding="utf-8")

    def run_script(self, name, *args, cwd=None):
        return subprocess.run(
            [sys.executable, str(self.project / "development" / name), *map(str, args)],
            cwd=cwd or self.project,
            capture_output=True, text=True, encoding="utf-8", check=False,
        )

    def import_script(self, name):
        # Imports must not start validation, HTTP requests, or report writes.
        path = self.project / "development" / name
        spec = importlib.util.spec_from_file_location("tool_under_test", path)
        module = importlib.util.module_from_spec(spec)
        sys.modules.pop("_common", None)
        with patch.object(sys, "path", [str(path.parent), *sys.path]):
            spec.loader.exec_module(module)
        return module

    def test_validation_finds_rules_when_run_from_development(self):
        (self.detections / "fixture.toml").write_text(VALID.replace("risk_score = 50", "risk_score = true"))
        result = self.run_script("validation.py", cwd=self.project / "development")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("risk_score", result.stdout + result.stderr)
        self.assertNotIn("Validation Passed", result.stdout)

    def test_validation_rejects_missing_or_empty_input(self):
        empty = self.project / "empty"
        empty.mkdir()
        for target in (empty, self.project / "missing"):
            with self.subTest(target=target):
                result = self.run_script("validation.py", "--detections-dir", target)
                self.assertNotEqual(result.returncode, 0)

    def test_validation_handles_invalid_shapes_without_traceback(self):
        for invalid in (VALID.replace('"2026/01/02"', '2026-01-02'), VALID.replace('"2026/01/02"', '"2026/02/30"'), '[metadata]\ncreation_date="2026/01/02"\nrule=[]'):
            with self.subTest(invalid=invalid):
                (self.detections / "fixture.toml").write_text(invalid)
                result = self.run_script("validation.py")
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("Traceback", result.stderr)

    def test_validation_rejects_duplicate_uuid_ignoring_case(self):
        first = VALID.replace("00000000-0000-0000-0000-000000000001", "abcdefab-0000-0000-0000-000000000001")
        (self.detections / "fixture.toml").write_text(first)
        (self.detections / "second.toml").write_text(first.replace("abcdefab", "ABCDEFAB"))
        result = self.run_script("validation.py")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Duplicate", result.stdout + result.stderr)

    def test_dry_run_rejects_invalid_toml(self):
        (self.detections / "fixture.toml").write_text("[rule\n")
        result = self.run_script("toml_to_json.py", "--dry-run")
        self.assertNotEqual(result.returncode, 0)

    def test_dry_run_preserves_lookback_and_disabled_state(self):
        result = self.run_script("toml_to_json.py", "--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"from": "now-6m"', result.stdout)
        self.assertIn('"enabled": false', result.stdout)

    def test_query_payload_defaults_kql_and_preserves_explicit_language(self):
        result = self.run_script("toml_to_json.py", "--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"language": "kuery"', result.stdout)
        self.rule_language = self.detections / "fixture.toml"
        self.rule_language.write_text(VALID.replace('type = "query"', 'type = "query"\nlanguage = "lucene"'))
        result = self.run_script("toml_to_json.py", "--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"language": "lucene"', result.stdout)
        self.rule_language.write_text(VALID.replace('type = "query"', 'type = "query"\nlanguage = "invalid"'))
        self.assertNotEqual(self.run_script("toml_to_json.py", "--dry-run").returncode, 0)

    def test_http_update_failure_never_reports_success(self):
        module = self.import_script("update_alert.py")
        failed = requests.Response()
        failed.status_code = 500
        failed._content = b'{"status_code":500,"message":"fixture error"}'
        failed.url = "https://invalid.example/rules"
        output = io.StringIO()
        environment = {"ELASTIC_KEY":"OFFLINE_FIXTURE", "ELASTIC_URL":failed.url, "CHANGED_FILES":"detections/fixture.toml"}
        with patch.dict(os.environ, environment), patch.object(sys, "argv", ["update_alert.py"]), patch.object(module.requests, "put", return_value=failed), patch.object(module.requests, "post", side_effect=AssertionError("Unexpected POST")), contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            old_cwd = Path.cwd()
            os.chdir(self.project)
            try:
                code = module.main()
            except SystemExit as exc:
                code = exc.code
            finally:
                os.chdir(old_cwd)
        self.assertEqual(code, 1, output.getvalue())
        self.assertNotIn("Updated:", output.getvalue())

    def test_changed_file_preview_matches_exact_paths_without_network(self):
        (self.detections / "prefix_fixture.toml").write_text(VALID.replace("000000000001", "000000000002").replace("Archive, inspect", "Selected detection"))
        module = self.import_script("update_alert.py")
        output = io.StringIO()
        environment = {"ELASTIC_KEY":"OFFLINE_FIXTURE", "ELASTIC_URL":"https://invalid.example/rules", "CHANGED_FILES":"detections/prefix_fixture.toml"}
        with patch.dict(os.environ, environment), patch.object(sys, "argv", ["update_alert.py", "--dry-run"]), patch.object(module.requests, "put", side_effect=AssertionError("Preview made HTTP request")), contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            old_cwd = Path.cwd()
            os.chdir(self.project)
            try:
                code = module.main()
            finally:
                os.chdir(old_cwd)
        self.assertEqual(code, 0, output.getvalue())
        self.assertIn("Selected detection", output.getvalue())
        self.assertNotIn("Archive, inspect", output.getvalue())

    def test_csv_quotes_fields_and_creates_metrics_from_development(self):
        result = self.run_script("toml_to_csv.py", cwd=self.project / "development")
        self.assertEqual(result.returncode, 0, result.stderr)
        with (self.project / "metrics/detectiondata.csv").open(encoding="utf-8", newline="") as handle:
            rows = list(csv.reader(handle))
        self.assertEqual(len(rows[0]), 8)
        self.assertEqual(len(rows[1]), 8)
        self.assertEqual(rows[1][0], "Archive, inspect")

    def test_navigator_keeps_every_mapping_with_tactic_shortnames(self):
        second = '''
[[rule.threat]]
framework = "MITRE ATT&CK"
[rule.threat.tactic]
id = "TA0006"
name = "Credential Access"
reference = "https://attack.mitre.org/tactics/TA0006/"
[[rule.threat.technique]]
id = "T1110"
name = "Brute Force"
reference = "https://attack.mitre.org/techniques/T1110/"
[[rule.threat.technique]]
id = "T1555"
name = "Credentials from Password Stores"
reference = "https://attack.mitre.org/techniques/T1555/"
'''
        (self.detections / "fixture.toml").write_text(VALID + second)
        (self.project / "metrics").mkdir()
        result = self.run_script("toml_to_navigator.py")
        self.assertEqual(result.returncode, 0, result.stderr)
        layer = json.loads((self.project / "metrics/navigator.json").read_text())
        self.assertIn("navigator", layer["versions"])
        self.assertIn("layer", layer["versions"])
        self.assertEqual(
            {(item["techniqueID"], item["tactic"]) for item in layer["techniques"]},
            {("T1074", "collection"), ("T1074.001", "collection"), ("T1110", "credential-access"), ("T1555", "credential-access")},
        )

    def test_monthly_reports_include_previous_year_and_escape_table_cells(self):
        dated = VALID.replace('"2026/01/02"', '"2025/12/02"').replace("Archive, inspect", "Archive | inspect")
        (self.detections / "fixture.toml").write_text(dated)
        for script, filename in (("toml_to_report.py", "latestdetections.md"), ("toml_to_md.py", "recentdetections.md")):
            with self.subTest(script=script):
                result = self.run_script(script, "--as-of", "2026-02-15")
                self.assertEqual(result.returncode, 0, result.stderr)
                report = (self.project / "metrics" / filename).read_text(encoding="utf-8")
                older = report.split("## Two Months Ago", 1)[1]
                self.assertIn("Archive \\| inspect", older)


if __name__ == "__main__":
    unittest.main()
