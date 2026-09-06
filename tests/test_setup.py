"""Local setup checks: render templates and inspect configuration; never deploy AWS."""

import base64
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
SETUP = ROOT / "setup" / "terraform"
TERRAFORM = os.environ.get("TERRAFORM_BIN") or shutil.which("terraform")
POWERSHELL = shutil.which("pwsh") or shutil.which("powershell")
BASH = shutil.which("bash") if os.name != "nt" else None
if os.name == "nt":
    git_bash = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Git/bin/bash.exe"
    BASH = str(git_bash) if git_bash.is_file() else None


def terraform_expression(expression):
    """Use an empty directory: no AWS provider, state, backend, or credentials."""
    with tempfile.TemporaryDirectory(prefix="detection-setup-test-") as directory:
        env = {**os.environ, "CHECKPOINT_DISABLE": "1", "TF_IN_AUTOMATION": "1"}
        result = subprocess.run(
            [TERRAFORM, f"-chdir={directory}", "console", "-no-color"],
            input=f"jsonencode({expression})\n",
            capture_output=True,
            text=True,
            encoding="utf-8",
            env=env,
            timeout=30,
        )
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)
        return json.loads(json.loads(result.stdout.strip()))


def render_template(name, values):
    path = (SETUP / "scripts" / name).as_posix()
    return terraform_expression(
        f"templatefile({json.dumps(path)}, {json.dumps(values)})"
    )


class SysmonConfigTests(unittest.TestCase):
    def test_required_events_are_enabled_in_lab_config(self):
        root = ET.parse(SETUP / "sysmon-lab.xml").getroot()
        self.assertEqual(root.tag, "Sysmon")
        self.assertEqual(root.findtext("HashAlgorithms"), "sha256")
        for event in ("ProcessCreate", "NetworkConnect", "FileCreate", "RegistryEvent"):
            with self.subTest(event=event):
                filters = root.findall(f"EventFiltering/{event}")
                self.assertEqual(len(filters), 1)
                self.assertEqual(filters[0].attrib["onmatch"], "exclude")
                self.assertEqual(len(filters[0]), 0, "An empty exclude filter enables these lab events")


@unittest.skipUnless(TERRAFORM, "Terraform CLI not available for provider-free expression checks")
class TerraformTemplateTests(unittest.TestCase):
    def test_admin_cidr_validation_accepts_only_single_ipv4(self):
        source = (SETUP / "variables.tf").read_text(encoding="utf-8")
        section = source.split('variable "allowed_ip" {', 1)[1].split('\nvariable "', 1)[0]
        expression = re.search(r"condition\s*=\s*(.+)", section).group(1)
        cases = {
            "203.0.113.10/32": True,
            "0.0.0.0/0": False,
            "10.0.0.0/8": False,
            "203.0.113.0/24": False,
            "::1/128": False,
            "not-an-ip/32": False,
            "999.1.1.1/32": False,
        }
        expressions = [expression.replace("var.allowed_ip", json.dumps(value)) for value in cases]
        self.assertEqual(terraform_expression("[" + ",".join(expressions) + "]"), list(cases.values()))

    def test_branch_agent_compatibility_precondition(self):
        source = (SETUP / "main.tf").read_text(encoding="utf-8")
        precondition = source.split("precondition {", 1)[1]
        expression = re.search(r"condition\s*=\s*(.+)", precondition).group(1)
        expressions = []
        for agent, branch in (("4.14.7", "4.14"), ("4.15.0", "4.14"), ("4.1.7", "4.14")):
            expressions.append(
                expression.replace("var.wazuh_agent_version", json.dumps(agent))
                .replace('${var.wazuh_branch}', branch)
            )
        self.assertEqual(terraform_expression("[" + ",".join(expressions) + "]"), [True, False, False])

    def test_linux_bootstrap_renders_as_first_boot_shell_script(self):
        script = render_template("install-wazuh.sh.tftpl", {"wazuh_branch": "4.14"})
        self.assertTrue(script.startswith("#!/bin/bash\nset -euo pipefail\n"))
        self.assertIn("https://packages.wazuh.com/4.14/wazuh-install.sh", script)
        self.assertNotIn("${wazuh_branch}", script)
        self.assertLessEqual(len(script.encode("utf-8")), 16 * 1024)

    @unittest.skipUnless(BASH, "Bash not available for syntax-only checks")
    def test_linux_bootstrap_shell_syntax(self):
        script = render_template("install-wazuh.sh.tftpl", {"wazuh_branch": "4.14"})
        result = subprocess.run(
            [BASH, "-n"], input=script, capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_windows_bootstrap_renders_and_fits_ec2_limit(self):
        config = (SETUP / "sysmon-lab.xml").read_bytes()
        script = render_template("install-windows.ps1.tftpl", {
            "manager_ip": "10.0.1.10",
            "wazuh_agent_version": "4.14.7",
            "sysmon_config_base64": base64.b64encode(config).decode("ascii"),
        })
        self.assertTrue(script.startswith("<powershell>\n"))
        self.assertTrue(script.rstrip().endswith("</powershell>"))
        self.assertIn("$managerIp = '10.0.1.10'", script)
        self.assertIn("$agentVersion = '4.14.7'", script)
        self.assertLessEqual(len(script.encode("utf-8")), 16 * 1024)
        embedded = re.search(r"FromBase64String\('([^']+)'\)", script).group(1)
        self.assertEqual(base64.b64decode(embedded), config)

    @unittest.skipUnless(POWERSHELL, "PowerShell not available for parser/helper checks")
    def test_powershell_parses_and_channel_helper_preserves_existing_config(self):
        script = render_template("install-windows.ps1.tftpl", {
            "manager_ip": "10.0.1.10",
            "wazuh_agent_version": "4.14.7",
            "sysmon_config_base64": base64.b64encode((SETUP / "sysmon-lab.xml").read_bytes()).decode("ascii"),
        })
        # Parse the entire bootstrap, but execute only the pure configuration helper.
        bootstrap = script.removeprefix("<powershell>\n").rsplit("</powershell>", 1)[0]
        checker = r'''
param([string]$BootstrapPath)
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($BootstrapPath, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
$function = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Add-WazuhEventChannel' }, $true)
if (-not $function) { throw 'Missing channel helper' }
. ([scriptblock]::Create($function.Extent.Text))
$original = '<ossec_config><client><server><address>10.0.1.10</address></server></client></ossec_config><ossec_config><localfile><location>Security</location><log_format>eventchannel</log_format></localfile></ossec_config>'
$channel = 'Microsoft-Windows-Sysmon/Operational'
$updated = Add-WazuhEventChannel $original $channel
$xml = [xml]('<root>' + $updated + '</root>')
if ($xml.SelectNodes('//localfile[location="Microsoft-Windows-Sysmon/Operational"]').Count -ne 1) { throw 'Expected one Sysmon subscription' }
if ($xml.SelectSingleNode('//localfile[location="Microsoft-Windows-Sysmon/Operational"]/log_format').InnerText -ne 'eventchannel') { throw 'Wrong log format' }
if ($xml.SelectSingleNode('//address').InnerText -ne '10.0.1.10') { throw 'Lost manager address' }
if ($xml.SelectNodes('//localfile[location="Security"]').Count -ne 1) { throw 'Lost existing event subscription' }
if ((Add-WazuhEventChannel $updated $channel) -ne $updated) { throw 'Duplicate subscription on rerun' }
$rejected = $false
try { Add-WazuhEventChannel '<broken />' $channel } catch { $rejected = $true }
if (-not $rejected) { throw 'Expected malformed configuration rejection' }
Write-Output 'PowerShell parser and configuration helper checks passed'
'''
        with tempfile.TemporaryDirectory(prefix="detection-powershell-test-") as directory:
            path = Path(directory)
            (path / "bootstrap.ps1").write_text(bootstrap, encoding="utf-8")
            (path / "check.ps1").write_text(checker, encoding="utf-8")
            result = subprocess.run(
                [POWERSHELL, "-NoProfile", "-NonInteractive", "-File", str(path / "check.ps1"), str(path / "bootstrap.ps1")],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("checks passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
