"""Validate every TOML ATT&CK mapping against an official catalog or local snapshot."""

import argparse
import json
from pathlib import Path
import sys

from _common import add_detections_argument, load_detections, mappings

ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"


def load_attack_data(path=None):
    if path is not None:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    import requests
    try:
        response = requests.get(ATTACK_URL, headers={"Accept": "application/json"}, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as exc:
        raise ValueError(f"Unable to load ATT&CK catalog: {exc}") from exc


def catalog_index(data):
    if not isinstance(data, dict) or not isinstance(data.get("objects"), list):
        raise ValueError("ATT&CK catalog must contain a STIX objects list")
    by_id, parents = {}, set()
    for item in data["objects"]:
        if not isinstance(item, dict):
            raise ValueError("ATT&CK catalog objects must be JSON objects")
        if item.get("type") in ("attack-pattern", "x-mitre-tactic"):
            for reference in item.get("external_references", []):
                if reference.get("source_name") == "mitre-attack" and reference.get("external_id"):
                    by_id[reference["external_id"]] = item
        if item.get("type") == "relationship" and item.get("relationship_type") == "subtechnique-of" and not item.get("revoked") and not item.get("x_mitre_deprecated"):
            parents.add((item.get("source_ref"), item.get("target_ref")))
    if not any(item.get("type") == "x-mitre-tactic" for item in by_id.values()) or not any(item.get("type") == "attack-pattern" for item in by_id.values()):
        raise ValueError("ATT&CK catalog must contain tactics and techniques")
    return by_id, parents


def mapping_errors(rule, by_id, parents):
    errors = []

    def check_entry(entry, expected_type):
        identifier = entry["id"]
        official = by_id.get(identifier)
        if not official or official.get("type") != expected_type:
            errors.append(f"Unknown ATT&CK identifier: {identifier}")
            return None
        if official.get("revoked") or official.get("x_mitre_deprecated"):
            errors.append(f"Revoked or deprecated ATT&CK identifier: {identifier}")
        if entry["name"] != official.get("name"):
            errors.append(f"{identifier} name mismatch: expected {official.get('name')!r}, got {entry['name']!r}")
        return official

    for tactic, technique, child in mappings(rule):
        official_tactic = check_entry(tactic, "x-mitre-tactic")
        official_technique = check_entry(technique, "attack-pattern")
        if official_technique and official_technique.get("x_mitre_is_subtechnique"):
            errors.append(f"{technique['id']} is a subtechnique, not a parent technique")
        entries = [(technique, official_technique)]
        if child:
            official_child = check_entry(child, "attack-pattern")
            entries.append((child, official_child))
            if official_child and (not official_child.get("x_mitre_is_subtechnique") or not official_technique or (official_child.get("id"), official_technique.get("id")) not in parents):
                errors.append(f"{child['id']} is not a catalog subtechnique of {technique['id']}")
        if official_tactic:
            shortname = official_tactic.get("x_mitre_shortname")
            for entry, official in entries:
                if official:
                    phases = {phase.get("phase_name") for phase in official.get("kill_chain_phases", []) if phase.get("kill_chain_name") == "mitre-attack"}
                    if shortname not in phases:
                        errors.append(f"{entry['id']} is not mapped to tactic {tactic['id']} ({tactic['name']})")
    return list(dict.fromkeys(errors))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    add_detections_argument(parser)
    parser.add_argument("--attack-data", type=Path, help="Use a local enterprise ATT&CK STIX JSON snapshot without network access")
    args = parser.parse_args(argv)
    try:
        detections = load_detections(args.detections_dir)
        by_id, parents = catalog_index(load_attack_data(args.attack_data))
    except (ValueError, OSError) as exc:
        print(f"ATT&CK validation failed: {exc}", file=sys.stderr)
        return 1
    failures = 0
    for path, alert in detections:
        errors = mapping_errors(alert["rule"], by_id, parents)
        for error in errors:
            print(f"{path}: {error}", file=sys.stderr)
        failures += bool(errors)
    source = args.attack_data or ATTACK_URL
    print(f"Checked {len(detections)} TOML rules against {source}; files with mapping errors: {failures}.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
