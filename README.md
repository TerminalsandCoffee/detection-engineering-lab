# Threat Detection Lab

A hands-on lab for building, deploying, and validating threat detection rules using Wazuh SIEM — complete with Terraform-deployed attack/defend infrastructure and MITRE ATT&CK mappings.

<img width="1024" height="1024" alt="image" src="https://github.com/user-attachments/assets/a3e85dd0-7987-43a5-926d-7b778484dc9c" />


## Overview

This repository is a full detection engineering lab environment. It includes TOML-formatted detection rules, a Terraform-deployed Wazuh SIEM with Windows targets and Kali attacker, and Python tooling for validation, reporting, and CI/CD.

What you get:
- **Detection rules** mapped to MITRE ATT&CK tactics and techniques
- **Lab infrastructure** (Wazuh Manager + Windows Server + Kali Linux) deployed via Terraform on AWS
- **Development tooling** for validation, MITRE mapping checks, and metrics generation
- **Theory docs** covering detection engineering workflows and security frameworks

Modern detection programs also emphasize:
- **Detection-as-code** practices (versioning, CI validation, peer review)
- **Schema normalization** (ECS, OCSF, or equivalent) to keep rules portable
- **Threat emulation coverage** (Atomic Red Team, CALDERA) to validate logic
- **Telemetry quality** (field completeness, logging policy, and data drift monitoring)

## Repository Structure

```
detection-engineering-lab/
├── detections/          # TOML-formatted detection rules
├── development/         # Python scripts for validation and conversion
├── metrics/             # Generated metrics, reports, and visualizations
├── theory/              # Documentation on detection engineering concepts
└── .github/workflows/   # GitHub Actions workflows (currently disabled)
```

## Detection Format

Each detection rule is stored as a TOML file with the following structure:

```toml
[metadata]
creation_date = "YYYY/MM/DD"

[rule]
author = ["Author Name"]
description = "Detection description"
name = "Detection Name"
risk_score = 50
severity = "medium"
type = "query"
rule_id = "unique-uuid"
query = "your detection query here"

[[rule.threat]]
framework = "MITRE ATT&CK"
[[rule.threat.technique]]
id = "T1059"
name = "Command and Scripting Interpreter"
reference = "https://attack.mitre.org/techniques/T1059/"

[rule.threat.tactic]
id = "TA0002"
name = "Execution"
reference = "https://attack.mitre.org/tactics/TA0002/"
```

## Theory & Documentation

Explore detection engineering concepts in the `theory/` directory:

- **[Security Operations](theory/security-operations.md)**: Overview of SecOps functions
- **[Detection Engineering Workflow](theory/detection-engineering-workflow.md)**: Workflow documentation
- **[Frameworks](theory/frameworks.md)**: Security frameworks (MITRE ATT&CK, Cyber Kill Chain, F3EAD)


### Detection Requirements

- Valid TOML syntax
- All required fields present
- Valid MITRE ATT&CK technique/tactic mappings
- Sub-techniques included when applicable
- Unique `rule_id` (UUID format)
- Descriptive `name` and `description`
- Appropriate `risk_score` and `severity`
- Documented data sources and assumptions (what logs/fields the rule relies on)

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Resources

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Wazuh Documentation](https://documentation.wazuh.com/)
- [Detection Engineering Best Practices](https://github.com/DetectionEngineering)



