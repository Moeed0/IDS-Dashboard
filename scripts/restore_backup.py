#!/usr/bin/env python3
"""Put a backup back in place of a damaged alert database, in one go.

Stop the collector and the dashboard first, then run it as your user:
    sudo systemctl stop ids-collector ids-dashboard
    .venv/bin/python scripts/restore_backup.py            # the newest backup
    .venv/bin/python scripts/restore_backup.py backups/ids_live-<time>.db.gz
    sudo systemctl start ids-collector ids-dashboard

It checks the backup, keeps the damaged database beside the new one
(ids_live-replaced-<time>.db, to delete once all is well), and sets the
collector to read the engines' logs again from the start. Started again, the
collector stores the alerts made after the backup that the logs still hold;
the ones the backup has are skipped. Alerts deleted by hand after the backup
come back too, while their log lines are still there.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from ids.config import get_settings  # noqa: E402
from ids.db_backup import DatabaseDamaged, newest_backup, restore_database  # noqa: E402

PROGRAMS = ("live_dual_collector.py", "dashboard_api.py")


def running_programs(proc_dir: Path = Path("/proc")) -> set[str]:
    """Which of PROGRAMS run now, from each process's command line."""
    found = set()
    for process in proc_dir.iterdir():
        if not process.name.isdigit():
            continue
        try:
            arguments = (process / "cmdline").read_bytes().split(b"\0")
        except OSError:
            # Ended meanwhile, or not ours to read.
            continue
        found.update(
            program for program in PROGRAMS
            if any(argument.endswith(program.encode()) for argument in arguments[1:])
        )
    return found


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("backup", nargs="?", type=Path, help="the backup to restore (default: the newest)")
    parser.add_argument("--yes", action="store_true", help="don't ask before restoring")
    arguments = parser.parse_args()
    settings = get_settings()

    running = running_programs()
    if running:
        sys.exit(
            f"Still running: {', '.join(sorted(running))}. Stop them first:\n"
            "    sudo systemctl stop ids-collector ids-dashboard"
        )
    backup = arguments.backup or newest_backup(settings.backup_dir)
    if backup is None or not backup.is_file():
        sys.exit(f"No backup found{f' at {backup}' if backup else f' in {settings.backup_dir}'}.")

    print(f"Restore {backup} as {settings.db_file},")
    print(f"and read the engines' logs again from the start ({settings.state_file}).")
    if not arguments.yes and input("Go ahead? [y/N] ").strip().lower() not in ("y", "yes"):
        sys.exit("Nothing changed.")

    try:
        kept = restore_database(backup, settings.db_file, settings.state_file)
    except DatabaseDamaged as exc:
        sys.exit(f"Nothing changed: {exc}. Name an older one: scripts/restore_backup.py <backup>")

    print("Restored.")
    if kept.exists():
        print(f"The replaced database is kept as {kept}; delete it once all is well.")
    print("Now start the collector and the dashboard:")
    print("    sudo systemctl start ids-collector ids-dashboard")


if __name__ == "__main__":
    main()
