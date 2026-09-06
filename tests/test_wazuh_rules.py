"""Offline rule regressions, plus opt-in real Wazuh logtest checks.

The offline regex checks use Python's compatible subset, not a Wazuh emulator.
Run `bash tests/wazuh_logtest.sh` for the native ruleset and PCRE2 check.
"""

import json
import os
from pathlib import Path
import re
import subprocess
import unittest
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
RULE_PATH = ROOT / "detections/wazuh-rules/powershell_exec_via_bat.xml"
DECODER_PATH = ROOT / "detections/decoders/local_decoder.xml"
CASES = json.loads((ROOT / "tests/fixtures/wazuh/sysmon_cases.json").read_text(encoding="utf-8"))


def field_value(event, name):
    value = event
    for part in name.split("."):
        if not isinstance(value, dict) or part not in value:
            return ""
        value = value[part]
    return str(value)


class WazuhRuleTests(unittest.TestCase):
    def test_native_process_creation_parent(self):
        rule = ET.parse(RULE_PATH).getroot().find("rule")
        self.assertEqual(rule.get("id"), "100001")
        self.assertEqual(rule.findtext("if_sid"), "61603")

    def test_all_dynamic_fields_use_explicit_pcre2(self):
        fields = ET.parse(RULE_PATH).getroot().findall("rule/field")
        self.assertEqual(len(fields), 3)
        for field in fields:
            with self.subTest(field=field.get("name")):
                self.assertEqual(field.get("type"), "pcre2")

    def test_synthetic_process_and_batch_boundaries(self):
        fields = ET.parse(RULE_PATH).getroot().findall("rule/field")
        for case in CASES:
            # Event/channel routing is exercised by native logtest, not emulated here.
            if case.get("native_only"):
                continue
            with self.subTest(case=case["name"]):
                matches = all(re.search(field.text, field_value(case["event"], field.get("name")))
                              for field in fields)
                self.assertEqual(matches, case["match"])

    def test_custom_app_decoder_uses_stock_timestamp_parent(self):
        decoder = ET.parse(DECODER_PATH).getroot()
        self.assertEqual(decoder.findtext("parent"), "windows-date-format")
        self.assertEqual(decoder.findtext("use_own_name"), "true")
        prematch = decoder.find("prematch")
        self.assertEqual(prematch.get("type"), "pcre2")
        self.assertEqual(prematch.get("offset"), "after_parent")
        self.assertIsNotNone(re.search(prematch.text, "CustomApp: synthetic health check"))
        self.assertIsNone(re.search(prematch.text, "OtherApp: synthetic health check"))


@unittest.skipUnless(os.environ.get("WAZUH_LOGTEST"), "native Wazuh runtime not selected")
class NativeWazuhTests(unittest.TestCase):
    def logtest(self, event):
        result = subprocess.run(
            [os.environ["WAZUH_LOGTEST"]], input=event + "\n", text=True,
            capture_output=True, timeout=30,
        )
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, 0, output)
        # logtest may exit zero even when its daemon connection fails.
        self.assertNotRegex(output, r"(?im)(?:ERROR:|CRITICAL:|Wazuh-logtest error)")
        self.assertIn("**Phase 2: Completed decoding.", output, output)
        return output

    def test_native_sysmon_cases(self):
        for case in CASES:
            with self.subTest(case=case["name"]):
                output = self.logtest(json.dumps(case["event"], separators=(",", ":")))
                # Official Wazuh test adapter routes decoded JSON through rule 60000.
                self.assertRegex(output, r"(?m)^\s*name: 'json'$", output)
                self.assertIn("**Phase 3: Completed filtering (rules).", output, output)
                rule_ids = re.findall(r"(?m)^\s*id: '([0-9]+)'$", output)
                self.assertEqual(len(rule_ids), 1, output)
                self.assertEqual(rule_ids[0] == "100001", case["match"], output)
                if case["match"]:
                    self.assertRegex(output, r"(?m)^\s*level: '5'$", output)

    def test_native_custom_app_decoder(self):
        output = self.logtest("2026-09-06 12:00:00 CustomApp: synthetic health check")
        self.assertRegex(output, r"(?m)^\s*name: 'custom-app-decoder'$", output)
        output = self.logtest("2026-09-06 12:00:00 OtherApp: synthetic health check")
        self.assertNotIn("name: 'custom-app-decoder'", output)


if __name__ == "__main__":
    unittest.main()
