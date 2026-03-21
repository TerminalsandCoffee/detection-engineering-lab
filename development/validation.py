try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # Python <=3.10
    import tomli as tomllib

import os
import re
import sys
from uuid import UUID

DETECTIONS_DIR = "detections"
SUPPORTED_RULE_TYPES = {
    "query": ["description", "name", "rule_id", "risk_score", "severity", "type", "query"],
    "eql": ["description", "name", "rule_id", "risk_score", "severity", "type", "query", "language"],
    "threshold": ["description", "name", "rule_id", "risk_score", "severity", "type", "query", "threshold"],
}
SUPPORTED_SEVERITIES = {"low", "medium", "high", "critical"}
DATE_PATTERN = re.compile(r"^\d{4}/\d{2}/\d{2}$")
seen_rule_ids = set()
failure = 0


def fail(message: str) -> None:
    global failure
    print(message)
    failure = 1


for root, _, files in os.walk(DETECTIONS_DIR):
    for file in sorted(files):
        if not file.endswith(".toml"):
            continue

        full_path = os.path.join(root, file)
        try:
            with open(full_path, "rb") as toml_file:
                alert = tomllib.load(toml_file)
        except Exception as exc:
            fail(f"Unable to parse {full_path}: {exc}")
            continue

        metadata = alert.get("metadata", {})
        rule = alert.get("rule", {})

        creation_date = metadata.get("creation_date")
        if not creation_date:
            fail(f"The metadata table does not contain a creation_date on: {full_path}")
        elif not DATE_PATTERN.match(creation_date):
            fail(f"creation_date must use YYYY/MM/DD in: {full_path}")

        rule_type = rule.get("type")
        if rule_type not in SUPPORTED_RULE_TYPES:
            fail(f"Unsupported or missing rule type in {full_path}: {rule_type}")
            continue

        missing_fields = [field for field in SUPPORTED_RULE_TYPES[rule_type] if field not in rule]
        if missing_fields:
            fail(f"The following rule fields do not exist in {full_path}: {missing_fields}")
            continue

        try:
            UUID(str(rule["rule_id"]))
        except (ValueError, TypeError):
            fail(f"rule_id must be a valid UUID in: {full_path}")

        if rule["rule_id"] in seen_rule_ids:
            fail(f"Duplicate rule_id found in: {full_path}")
        else:
            seen_rule_ids.add(rule["rule_id"])

        severity = str(rule["severity"]).lower()
        if severity not in SUPPORTED_SEVERITIES:
            fail(f"severity must be one of {sorted(SUPPORTED_SEVERITIES)} in: {full_path}")

        risk_score = rule.get("risk_score")
        if not isinstance(risk_score, int) or not 0 <= risk_score <= 100:
            fail(f"risk_score must be an integer from 0 to 100 in: {full_path}")

        print(f"Validation Passed for: {full_path}")

if failure != 0:
    sys.exit(1)
