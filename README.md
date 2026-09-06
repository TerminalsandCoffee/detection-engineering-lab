# Threat Detection Lab

[![Validate detection lab](https://github.com/TerminalsandCoffee/detection-engineering-lab/actions/workflows/toml_mitre_validation.yml/badge.svg?branch=main)](https://github.com/TerminalsandCoffee/detection-engineering-lab/actions/workflows/toml_mitre_validation.yml)

A detection engineering lab built around a repeatable workflow: **observe behavior, capture telemetry, write a detection, test it, and tune the result.**

The repository brings together a three-host AWS lab, Windows/Sysmon telemetry, a native Wazuh example, an Elastic query collection, and Python tools for validation and reporting.

<img width="640" alt="Threat Detection Lab project illustration" src="https://github.com/user-attachments/assets/a3e85dd0-7987-43a5-926d-7b778484dc9c" />

## Overview

| Component | What is here |
|---|---|
| [AWS lab](setup/README.md) | Terraform for a Wazuh server, Windows target with Sysmon and a Wazuh agent, and Kali host |
| [Detection collection](detections/README.md) | Ten TOML detections with Elastic/KQL queries and ATT&CK mappings |
| [Native Wazuh rule](detections/wazuh-rules/powershell_exec_via_bat.xml) | A Sysmon process-creation rule for PowerShell launched by a BAT file |
| [Development tools](development/README.md) | Schema and ATT&CK checks, report exports, and explicit Elastic API utilities |
| [Metrics](metrics/README.md) | Detection inventory and ATT&CK Navigator mappings |
| [Theory](theory/README.md) | Security operations, detection lifecycle, and reference frameworks |

The TOML queries use Elastic field names and are not directly deployable as Wazuh XML. The AWS setup collects Windows/Sysmon events; Zeek and Elastic Endpoint telemetry used by other examples require their own sensors and ingestion. [Detection prerequisites](detections/README.md) explain each dependency.

## Quick start: inspect and validate locally

Use Python 3.11 or newer. These steps need no AWS account or SIEM credentials.

```bash
git clone https://github.com/TerminalsandCoffee/detection-engineering-lab.git
cd detection-engineering-lab
python -m venv .venv
```

Activate the environment with `.venv\Scripts\Activate.ps1` in Windows PowerShell or `source .venv/bin/activate` on macOS/Linux, then run:

```bash
python -m pip install -r requirements.txt
python development/validation.py
python -m unittest discover -s tests -v
python development/toml_to_json.py --dry-run
```

To check mappings against MITRE's published Enterprise ATT&CK data (network access required):

```bash
python development/mitre.py
```

Generate the inventory and Navigator layer:

```bash
python development/toml_to_csv.py
python development/toml_to_navigator.py
```

See [development usage](development/README.md) for offline mapping checks, output options, and the optional Elastic upload commands.

## Follow a detection from signal to alert

Start with [PowerShell execution via a BAT file](detections/powershell_exec_via_bat.toml). It has a corresponding [Wazuh XML rule](detections/wazuh-rules/powershell_exec_via_bat.xml), which makes it a useful example for comparing query metadata with a native SIEM implementation.

1. Review the [telemetry prerequisites and expected behavior](detections/README.md).
2. Run the local tests against the synthetic event fixtures.
3. Follow the [setup guide](setup/README.md) to provision your own lab and confirm Sysmon events reach Wazuh.
4. Run the [container fixture tests](tests/fixtures/wazuh/README.md), install the custom XML rule, and check the manager configuration before restarting it.
5. Record the alert, a benign comparison, and any tuning decisions.

A valid file, correct ATT&CK mapping, or matching fixture is one piece of evidence. End-to-end coverage also depends on sensor configuration, event delivery, field mappings, rule loading, and the surrounding workload. The repository does not claim that all ten queries have been replayed against a live Elastic deployment.

## Repository Structure

```text
detections/                 TOML collection, native Wazuh rules, decoder examples
development/                Validators, Elastic utilities, report exporters
metrics/                    Committed inventory and Navigator outputs
setup/terraform/            Canonical three-host AWS lab
setup/wazuh/tf-deployment/   Historical single-host prototype; see its README
theory/                     Detection engineering reference material
tests/                      Regression tests and synthetic fixtures
.github/workflows/          Validation workflows and historical integration paths
```

## Detection Format

Rules preserve their original filenames, identifiers, creation dates, and author metadata. Use an existing [TOML example](detections/powershell_exec_via_bat.toml) as the schema reference:

```toml
[metadata]
creation_date = "2026/09/06"

[rule]
author = ["Your name"]
name = "Example PowerShell Process"
description = "Study example; tune and test against your process telemetry."
rule_id = "0ae618f8-a41b-4c72-a818-6c0b78fd386b"
risk_score = 50
severity = "medium"
type = "query"
language = "kuery"
query = 'process.name : "powershell.exe"'

[[rule.threat]]
framework = "MITRE ATT&CK"
[[rule.threat.technique]]
id = "T1059"
name = "Command and Scripting Interpreter"
reference = "https://attack.mitre.org/techniques/T1059/"
[[rule.threat.technique.subtechnique]]
id = "T1059.001"
name = "PowerShell"
reference = "https://attack.mitre.org/techniques/T1059/001/"
[rule.threat.tactic]
id = "TA0002"
name = "Execution"
reference = "https://attack.mitre.org/tactics/TA0002/"
```

Generate a new UUID for a new rule. Choose the actual telemetry source, scope, language, and false-positive handling before deployment.

## Theory & Documentation

- [Security Operations](theory/security-operations.md)
- [Detection Engineering Workflow](theory/detection-engineering-workflow.md)
- [Frameworks](theory/frameworks.md)
- [Setup and telemetry checks](setup/README.md)
- [Development commands](development/README.md)

### Detection Requirements

- Valid TOML, required fields, unique UUIDs, and correctly typed scores and thresholds
- Valid ATT&CK identifiers, names, tactics, and sub-technique relationships
- Documented telemetry, field mappings, and query-language assumptions
- Positive, negative, and edge-case evidence from the intended engine
- A review of benign matches before operational use

## Validation and deployment

Repository checks run without production credentials. Infrastructure provisioning and rule installation are explicit operator steps; pushing a rule does not run Terraform or upload it to a live SIEM. Historical integration filenames remain available for readers arriving from earlier walkthroughs.

For a cloud lab, begin with [setup/README.md](setup/README.md), inspect the Terraform plan, and verify the instances and telemetry after provisioning. AWS resources incur charges until removed; the setup guide includes teardown and cleanup checks.

## Credits and project history

Maintained by [Rafael Martinez / Terminals & Coffee](https://github.com/TerminalsandCoffee). The original TOML collection credits **Anthony Isherwood** in its author metadata; those credits are retained. This repository builds on that learning material with lab infrastructure, tooling, and Wazuh examples.

Earlier articles may show Elastic infrastructure or older deployment defaults. The repository name, existing file paths, and Git history are retained; the setup guide describes the current Wazuh-based environment.

## License

[MIT License](LICENSE).

## Resources

- [MITRE ATT&CK](https://attack.mitre.org/)
- [Wazuh custom rules](https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html)
- [Wazuh rule testing](https://documentation.wazuh.com/current/user-manual/ruleset/testing.html)
- [Kibana Query Language reference](https://www.elastic.co/docs/reference/query-languages/kql)
