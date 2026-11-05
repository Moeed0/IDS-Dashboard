#!/usr/bin/env python3
"""Save how many rules each engine loaded, which the Overview shows on the
engine cards (IDS_RULE_COUNTS_FILE, .runtime/engine_rule_counts.json):

    .venv/bin/python scripts/save_rule_counts.py --snort 48757 --suricata-log

Snort's number is the "total rules loaded" line of
`sudo snort -c /usr/local/etc/snort/snort.lua -T`. Suricata's is read from its
log, or given with --suricata. Restart the dashboard afterwards
(`sudo systemctl restart ids-dashboard`): it reads the counts when it starts.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from ids.config import get_settings, read_rule_counts, write_rule_counts  # noqa: E402

SURICATA_LOG = "/var/log/suricata/suricata.log"
LOADED_RE = re.compile(r"(\d+) rules successfully loaded")


def suricata_count(log: Path) -> int:
    """The rules Suricata loaded when it last started, from its log."""
    found = None
    with log.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            match = LOADED_RE.search(line)
            if match:
                found = int(match.group(1))
    if found is None:
        raise ValueError(f'no "rules successfully loaded" line in {log}')
    return found


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--snort", type=int, help="the rules Snort loaded")
    parser.add_argument("--suricata", type=int, help="the rules Suricata loaded")
    parser.add_argument(
        "--suricata-log", nargs="?", const=SURICATA_LOG,
        help=f"read Suricata's count from its log (default: {SURICATA_LOG})",
    )
    args = parser.parse_args()

    settings = get_settings()
    counts = read_rule_counts(settings.rule_counts_file)
    if args.snort is not None:
        counts["snort"] = args.snort
    if args.suricata is not None:
        counts["suricata"] = args.suricata
    elif args.suricata_log:
        try:
            counts["suricata"] = suricata_count(Path(args.suricata_log))
        except (OSError, ValueError) as error:
            sys.exit(f"Could not read Suricata's count: {error}")
    if args.snort is None and args.suricata is None and not args.suricata_log:
        parser.error("give --snort, --suricata or --suricata-log")

    write_rule_counts(settings.rule_counts_file, counts)
    print(f"Saved {counts} in {settings.rule_counts_file}")


if __name__ == "__main__":
    main()
