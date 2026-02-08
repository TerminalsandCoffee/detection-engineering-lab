# Development Scripts

Python utilities for managing detection rules lifecycle.

## Scripts

| Script | Purpose |
|--------|---------|
| `validation.py` | Validates TOML syntax and required fields |
| `mitre.py` | Validates MITRE ATT&CK technique/tactic mappings |
| `toml_to_json.py` | Uploads detections to SIEM API (Elastic-compatible) |
| `update_alert.py` | Updates existing rules (used in CI/CD) |
| `toml_to_csv.py` | Exports detections to CSV for reporting |
| `toml_to_md.py` | Generates markdown documentation |
| `toml_to_navigator.py` | Creates ATT&CK Navigator layer JSON |
| `toml_to_report.py` | Generates detection coverage reports |

## Usage

```bash
# Validate all detections
python validation.py

# Validate MITRE mappings
python mitre.py

# Upload to SIEM (requires ELASTIC_KEY env var — legacy Elastic-compatible)
python toml_to_json.py --dry-run  # Preview
python toml_to_json.py            # Upload

# Generate reports
python toml_to_csv.py
python toml_to_navigator.py
```

## Environment Variables

- `ELASTIC_KEY`: API key for SIEM (legacy Elastic-compatible)
- `ELASTIC_URL`: (optional) Override default SIEM endpoint
- `CHANGED_FILES`: Used by `update_alert.py` in CI/CD pipelines
