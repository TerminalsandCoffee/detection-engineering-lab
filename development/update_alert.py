"""Update CHANGED_FILES in Elastic; --dry-run previews without credentials or HTTP."""

import argparse
import json
import os
from pathlib import Path
import re
import sys

import requests

from _common import ROOT, add_detections_argument, build_payload, load_detections
from toml_to_json import REQUEST_TIMEOUT, api_configuration, response_result, upload_detection


def select_changed(detections, text, directory):
    # Keep the original space/comma-separated format; JSON arrays support spaces.
    tokens = json.loads(text) if text.lstrip().startswith("[") else re.split(r"[\s,]+", text.strip())
    if not isinstance(tokens, list) or not all(isinstance(token, str) for token in tokens):
        raise ValueError("CHANGED_FILES must contain paths, or a JSON array of paths")
    selected = set()
    for token in tokens:
        token = token.replace("\\", "/")
        if not token.endswith(".toml"):
            continue
        matching = []
        for path, _ in detections:
            names = {path.as_posix(), path.relative_to(Path(directory)).as_posix()}
            if path.is_relative_to(ROOT):
                names.add(path.relative_to(ROOT).as_posix())
            if "/" not in token:
                names.add(path.name)  # Legacy basename support, only if unambiguous.
            if token.removeprefix("./") in names:
                matching.append(path)
        if len(matching) != 1:
            raise ValueError(f"Changed TOML path is missing or ambiguous: {token}")
        selected.add(matching[0])
    return [(path, alert) for path, alert in detections if path in selected]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="Preview selected payloads without uploading")
    add_detections_argument(parser)
    args = parser.parse_args(argv)
    changed = os.environ.get("CHANGED_FILES", "").strip()
    if not changed:
        print("No changed files specified")
        return 0
    try:
        directory = args.detections_dir.resolve()
        detections = select_changed(load_detections(directory), changed, directory)
        if not args.dry_run and detections:
            url, headers = api_configuration()
    except (ValueError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    failures = 0
    for path, alert in detections:
        print(f"Processing: {path}")
        payload = build_payload(alert)
        if args.dry_run:
            print(f"  Payload: {json.dumps(payload, indent=2)}")
            continue
        try:
            response = requests.put(url, headers=headers, json=payload, timeout=REQUEST_TIMEOUT)
            if response.status_code == 404:
                result = upload_detection(url, headers, payload)
                action = "Created"
            else:
                result = response_result(response)
                action = "Updated"
            print(f"  {action}: {result.get('name', path.name)} ({result['id']})")
        except (requests.RequestException, ValueError) as exc:
            print(f"  Error updating {path.name}: {exc}", file=sys.stderr)
            failures += 1
    print(f"Processed {len(detections)} changed TOML rules; failures: {failures}.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
