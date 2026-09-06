"""Export every TOML technique/tactic mapping to an ATT&CK Navigator layer."""
import sys
from _reports import report_main


def main(argv=None):
    return report_main("navigator", argv)


if __name__ == "__main__":
    sys.exit(main())
