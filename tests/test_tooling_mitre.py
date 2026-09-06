"""ATT&CK mapping checks with a deliberately small, offline catalog fixture."""

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from test_tooling import ROOT, VALID


class MitreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.project = Path(self.temp.name)
        shutil.copytree(ROOT / "development", self.project / "development", ignore=shutil.ignore_patterns("__pycache__"))
        (self.project / "detections").mkdir()
        self.rule = self.project / "detections/fixture.toml"
        self.rule.write_text(VALID)
        self.catalog = self.project / "catalog.json"
        shutil.copy2(ROOT / "tests/fixtures/mitre-catalog.json", self.catalog)
        # Offline stand-in for the old unconditional fetch. The marker makes
        # any network attempt observable without allowing a real request.
        (self.project / "development/requests.py").write_text('''
import json
from pathlib import Path
class Response:
    def json(self):
        return json.loads((Path(__file__).resolve().parents[1] / "catalog.json").read_text())
def get(*args, **kwargs):
    (Path(__file__).resolve().parents[1] / "network-attempted").touch()
    return Response()
''')

    def run_validation(self):
        return subprocess.run([sys.executable, str(self.project / "development/mitre.py"), "--attack-data", str(self.catalog)], cwd=self.project, text=True, capture_output=True, check=False)

    def test_valid_snapshot_runs_without_network(self):
        result = self.run_validation()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.project / "network-attempted").exists())

    def test_unknown_subtechnique_is_rejected(self):
        self.rule.write_text(VALID.replace("T1074.001", "T1074.999"))
        result = self.run_validation()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("T1074.999", result.stdout + result.stderr)

    def test_valid_tactic_must_belong_to_the_technique(self):
        self.rule.write_text(VALID.replace("TA0009", "TA0002").replace("Collection", "Execution"))
        result = self.run_validation()
        self.assertNotEqual(result.returncode, 0)

    def test_second_technique_and_subtechnique_are_checked(self):
        for suffix in ('''\n[[rule.threat.technique]]
id="T9999"
name="Unknown technique"
reference="https://attack.mitre.org/techniques/T9999/"
''', '''\n[[rule.threat.technique.subtechnique]]
id="T1074.999"
name="Unknown subtechnique"
reference="https://attack.mitre.org/techniques/T1074/999/"
'''):
            with self.subTest(suffix=suffix):
                self.rule.write_text(VALID + suffix)
                self.assertNotEqual(self.run_validation().returncode, 0)

    def test_revoked_and_deprecated_subtechniques_are_rejected(self):
        original = json.loads(self.catalog.read_text())
        for field in ("revoked", "x_mitre_deprecated"):
            with self.subTest(field=field):
                modified = json.loads(json.dumps(original))
                modified["objects"][3][field] = True
                self.catalog.write_text(json.dumps(modified))
                self.assertNotEqual(self.run_validation().returncode, 0)

    def test_subtechnique_requires_its_catalog_parent_relationship(self):
        catalog = json.loads(self.catalog.read_text())
        catalog["objects"][-1]["target_ref"] = "attack-pattern--wrong-parent"
        self.catalog.write_text(json.dumps(catalog))
        self.assertNotEqual(self.run_validation().returncode, 0)


if __name__ == "__main__":
    unittest.main()
