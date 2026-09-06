"""Upload TOML rules to the Elastic Security rules endpoint, or preview with --dry-run."""

import argparse
import json
import os
import sys

import requests

from _common import add_detections_argument, build_payload, load_detection, load_detections

REQUEST_TIMEOUT = 30


def api_configuration():
    key, url = os.environ.get("ELASTIC_KEY"), os.environ.get("ELASTIC_URL")
    if not key or not url:
        raise ValueError("ELASTIC_KEY and ELASTIC_URL must be set for uploads")
    return url, {"Content-Type": "application/json", "kbn-xsrf": "true", "Authorization": f"ApiKey {key}"}


def response_result(response):
    response.raise_for_status()
    result = response.json()
    if not isinstance(result, dict) or not result.get("id"):
        raise ValueError("API response did not contain a rule id")
    return result


def upload_detection(url, headers, payload):
    response = requests.post(url, headers=headers, json=payload, timeout=REQUEST_TIMEOUT)
    return response_result(response)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="Print validated payloads without network access")
    add_detections_argument(parser)
    args = parser.parse_args(argv)
    try:
        detections = load_detections(args.detections_dir)
        if not args.dry_run:
            url, headers = api_configuration()
    except ValueError as exc:
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
            result = upload_detection(url, headers, payload)
            print(f"  Uploaded: {result.get('name', path.name)} ({result['id']})")
        except (requests.RequestException, ValueError) as exc:
            print(f"  Error uploading {path.name}: {exc}", file=sys.stderr)
            failures += 1
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
