"""Export TOML detection metadata as a correctly quoted CSV."""
import sys
from _reports import report_main


def main(argv=None):
    return report_main("csv", argv)


if __name__ == "__main__":
    sys.exit(main())
