"""Deterministic serialization shared by the existing report entry points."""

import argparse
from collections import Counter
import csv
from datetime import date
import io
import json
from pathlib import Path
import sys

from dateutil.relativedelta import relativedelta

from _common import METRICS_DIR, add_detections_argument, load_detections, mappings


def csv_report(detections):
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["name", "date", "author", "risk_score", "severity", "tactic", "technique", "subtechnique"])
    for _, alert in detections:
        rule = alert["rule"]
        tactic_names, techniques, children = [], [], []
        for tactic, technique, child in mappings(rule):
            tactic_names.append(tactic["name"])
            techniques.append(f"{technique['id']} - {technique['name']}")
            children.append(f"{child['id']} - {child['name']}" if child else "none")
        writer.writerow([
            rule["name"], alert["metadata"]["creation_date"], "; ".join(rule["author"]),
            rule["risk_score"], rule["severity"], "; ".join(tactic_names),
            "; ".join(techniques), "; ".join(children),
        ])
    return output.getvalue()


def navigator_report(detections):
    counts = Counter()
    for _, alert in detections:
        covered = set()
        for tactic, technique, child in mappings(alert["rule"]):
            shortname = tactic["name"].lower().replace(" ", "-")
            covered.add((technique["id"], shortname))
            if child:
                covered.add((child["id"], shortname))
        counts.update(covered)
    layer = {
        "name": "Custom Detections",
        "versions": {"navigator": "4.9.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Count of TOML rules mapped to each technique/tactic. Mapping counts are not validated detection coverage.",
        "techniques": [
            {"techniqueID": identifier, "tactic": tactic, "score": count, "enabled": True}
            for (identifier, tactic), count in sorted(counts.items())
        ],
        "gradient": {"colors": ["#ff6666ff", "#ffe766ff", "#8ec843ff"], "minValue": 0, "maxValue": max(counts.values(), default=1)},
    }
    return json.dumps(layer, indent=2) + "\n"


def markdown_cell(value):
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\\", "\\\\").replace("|", "\\|").replace("\n", "<br>")


def monthly_report(detections, as_of):
    lines = ["# Detection Report", "", f"As of {as_of.isoformat()}; grouped by original creation date.", ""]
    for offset, title in enumerate(("Current Month", "Last Month", "Two Months Ago")):
        month = (as_of - relativedelta(months=offset)).strftime("%Y/%m")
        lines.extend([f"## {title}", "", "| Alert | Date | Author | Risk Score | Severity |", "| --- | --- | --- | --- | --- |"])
        matching = [alert for _, alert in detections if alert["metadata"]["creation_date"].startswith(month + "/")]
        for alert in matching:
            rule = alert["rule"]
            values = [rule["name"], alert["metadata"]["creation_date"], "; ".join(rule["author"]), rule["risk_score"], rule["severity"]]
            lines.append("| " + " | ".join(map(markdown_cell, values)) + " |")
        lines.append("")
        if not matching:
            lines.extend(["No detections created in this month.", ""])
    return "\n".join(lines)


def report_main(kind, argv=None):
    filenames = {"csv": "detectiondata.csv", "navigator": "navigator.json", "recent": "recentdetections.md", "latest": "latestdetections.md"}
    parser = argparse.ArgumentParser(description=f"Generate {filenames[kind]} from local TOML detections")
    add_detections_argument(parser)
    parser.add_argument("--output-dir", type=Path, default=METRICS_DIR)
    if kind in ("recent", "latest"):
        parser.add_argument("--as-of", type=date.fromisoformat, default=date.today(), help="Report date, YYYY-MM-DD (default: today)")
    args = parser.parse_args(argv)
    try:
        detections = load_detections(args.detections_dir)
        if kind == "csv":
            content = csv_report(detections)
        elif kind == "navigator":
            content = navigator_report(detections)
        else:
            content = monthly_report(detections, args.as_of)
        args.output_dir.mkdir(parents=True, exist_ok=True)
        path = args.output_dir / filenames[kind]
        path.write_text(content, encoding="utf-8", newline="")
    except (ValueError, OSError) as exc:
        print(f"Report failed: {exc}", file=sys.stderr)
        return 1
    print(f"Wrote {path} from {len(detections)} TOML rules.")
    return 0
