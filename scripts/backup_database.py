#!/usr/bin/env python3
"""Check the alert database, then make a gzipped copy of it in IDS_BACKUP_DIR
and keep the newest IDS_BACKUP_KEEP of them. The ids-backup timer runs it
every night (deploy/systemd/ids-backup.timer):
    .venv/bin/python scripts/backup_database.py
A damaged database isn't copied: this ends with an error, the status panel
says so, and scripts/restore_backup.py puts the newest backup back.
"""
from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from ids.config import get_settings  # noqa: E402
from ids.db_backup import DatabaseDamaged, backup_database  # noqa: E402


def main() -> None:
    settings = get_settings()
    if not settings.backup_keep:
        print("IDS_BACKUP_KEEP is 0: no backups.")
        return
    try:
        made = backup_database(settings.db_file, settings.backup_dir, settings.backup_keep)
    except DatabaseDamaged as exc:
        sys.exit(
            f"{settings.db_file} is damaged ({exc}), so it wasn't backed up.\n"
            "Restore the newest backup: .venv/bin/python scripts/restore_backup.py"
        )
    print(f"Backed up {settings.db_file} as {made} ({made.stat().st_size / 1e6:.0f} MB)")


if __name__ == "__main__":
    main()
