"""Generate metrics/recentdetections.md, optionally with --as-of YYYY-MM-DD."""
import sys
from _reports import report_main


def main(argv=None):
    return report_main("recent", argv)


if __name__ == "__main__":
    sys.exit(main())
