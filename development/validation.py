"""Validate local TOML rule schemas. Does not validate query execution."""

import argparse
import sys

from _common import add_detections_argument, load_detections


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    add_detections_argument(parser)
    args = parser.parse_args(argv)
    try:
        detections = load_detections(args.detections_dir)
    except ValueError as exc:
        print(f"Validation failed: {exc}", file=sys.stderr)
        return 1
    for path, _ in detections:
        print(f"Validation Passed for: {path}")
    print(f"Validated {len(detections)} TOML rules (schema only).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
