"""Shared local TOML loading for the public command-line tools (Python 3.11+)."""

from datetime import datetime
from pathlib import Path
import re
import tomllib
from uuid import UUID

ROOT = Path(__file__).resolve().parents[1]
DETECTIONS_DIR = ROOT / "detections"
METRICS_DIR = ROOT / "metrics"


def add_detections_argument(parser):
    parser.add_argument("--detections-dir", type=Path, default=DETECTIONS_DIR,
                        help="TOML directory (default: repository detections/)")


def detection_files(directory):
    directory = Path(directory)
    if not directory.is_dir():
        raise ValueError(f"Detections directory not found: {directory}")
    files = sorted(directory.rglob("*.toml"))
    if not files:
        raise ValueError(f"No TOML detections found in: {directory}")
    return files


def _named_id_errors(value, pattern, label):
    if not isinstance(value, dict):
        return [f"{label} must be a table"]
    errors = []
    if not isinstance(value.get("id"), str) or not re.fullmatch(pattern, value["id"]):
        errors.append(f"{label}.id has an invalid format")
    for key in ("name", "reference"):
        if not isinstance(value.get(key), str) or not value[key].strip():
            errors.append(f"{label}.{key} must be a nonempty string")
    return errors


def validation_errors(alert):
    errors = []
    metadata = alert.get("metadata")
    date = metadata.get("creation_date") if isinstance(metadata, dict) else None
    try:
        if not isinstance(date, str) or not re.fullmatch(r"\d{4}/\d{2}/\d{2}", date):
            raise ValueError
        datetime.strptime(date, "%Y/%m/%d")
    except ValueError:
        errors.append("metadata.creation_date must be a valid YYYY/MM/DD date string")
    rule = alert.get("rule")
    if not isinstance(rule, dict):
        return errors + ["rule must be a table"]
    if rule.get("type") not in ("query", "eql", "threshold"):
        errors.append("Unsupported or missing rule type")
    for field in ("name", "description", "query", "rule_id"):
        if not isinstance(rule.get(field), str) or not rule[field].strip():
            errors.append(f"rule.{field} must be a nonempty string")
    try:
        if not isinstance(rule.get("rule_id"), str):
            raise ValueError
        UUID(rule["rule_id"])
    except ValueError:
        errors.append("rule.rule_id must be a valid UUID string")
    if type(rule.get("risk_score")) is not int or not 0 <= rule["risk_score"] <= 100:
        errors.append("rule.risk_score must be an integer from 0 to 100")
    if rule.get("severity") not in ("low", "medium", "high", "critical"):
        errors.append("rule.severity must be low, medium, high, or critical")
    authors = rule.get("author")
    if not isinstance(authors, list) or not authors or not all(isinstance(author, str) and author.strip() for author in authors):
        errors.append("rule.author must be a nonempty list of names")
    if "enabled" in rule and type(rule["enabled"]) is not bool:
        errors.append("rule.enabled must be a boolean")
    if rule.get("type") == "eql" and rule.get("language") != "eql":
        errors.append("EQL rules require language = 'eql'")
    if rule.get("type") in ("query", "threshold") and rule.get("language", "kuery") not in ("kuery", "lucene"):
        errors.append("Query and threshold language must be 'kuery' or 'lucene'")
    if rule.get("type") == "threshold":
        threshold = rule.get("threshold")
        if not isinstance(threshold, dict) or type(threshold.get("value")) is not int or threshold["value"] < 1:
            errors.append("Threshold rules require a positive integer threshold.value")
        if not isinstance(threshold, dict) or not isinstance(threshold.get("field"), list) or not all(isinstance(field, str) for field in threshold["field"]):
            errors.append("Threshold rules require threshold.field as a list of strings")
    threats = rule.get("threat")
    if not isinstance(threats, list) or not threats:
        return errors + ["rule.threat must be a nonempty list"]
    for threat in threats:
        if not isinstance(threat, dict) or threat.get("framework") != "MITRE ATT&CK":
            errors.append("Each threat must declare framework = 'MITRE ATT&CK'")
            continue
        errors.extend(_named_id_errors(threat.get("tactic"), r"TA\d{4}", "tactic"))
        techniques = threat.get("technique")
        if not isinstance(techniques, list) or not techniques:
            errors.append("Each threat requires a nonempty technique list")
            continue
        for technique in techniques:
            errors.extend(_named_id_errors(technique, r"T\d{4}", "technique"))
            if not isinstance(technique, dict):
                continue
            children = technique.get("subtechnique", [])
            if not isinstance(children, list):
                errors.append("subtechnique must be a list")
                continue
            for child in children:
                errors.extend(_named_id_errors(child, r"T\d{4}\.\d{3}", "subtechnique"))
                if isinstance(child, dict) and isinstance(child.get("id"), str) and child["id"].split(".")[0] != technique.get("id"):
                    errors.append("Subtechnique ID must belong to its parent technique")
    return errors


def load_detection(path):
    try:
        with Path(path).open("rb") as handle:
            alert = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ValueError(f"{path}: {exc}") from exc
    errors = validation_errors(alert)
    if errors:
        raise ValueError(f"{path}: " + "; ".join(errors))
    return alert


def load_detections(directory):
    """Validate the full input before any exporter writes or sends data."""
    loaded, failures, seen = [], [], set()
    for path in detection_files(directory):
        try:
            alert = load_detection(path)
            rule_id = str(UUID(alert["rule"]["rule_id"]))
            if rule_id in seen:
                raise ValueError(f"{path}: Duplicate rule_id {rule_id}")
            seen.add(rule_id)
            loaded.append((path, alert))
        except ValueError as exc:
            failures.append(str(exc))
    if failures:
        raise ValueError("\n".join(failures))
    return loaded


def mappings(rule):
    """Yield every tactic/technique/subtechnique combination, without [0] loss."""
    for threat in rule["threat"]:
        for technique in threat["technique"]:
            for child in technique.get("subtechnique") or [None]:
                yield threat["tactic"], technique, child


def build_payload(alert):
    errors = validation_errors(alert)
    if errors:
        raise ValueError("; ".join(errors))
    # The rule table is the API payload; metadata is local-only. Preserve
    # scheduling, language, index, thresholds and explicit disabled state.
    payload = dict(alert["rule"])
    payload.setdefault("enabled", True)
    if payload["type"] in ("query", "threshold"):
        # Historical examples in this repository are KQL. Elastic requires
        # an explicit language; retain an explicitly configured Lucene query.
        payload.setdefault("language", "kuery")
    return payload
