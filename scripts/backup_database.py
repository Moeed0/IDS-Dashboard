#!/usr/bin/env python3
"""Make a gzipped copy of the alert database in IDS_BACKUP_DIR and keep the
newest IDS_BACKUP_KEEP of them. The ids-backup timer runs it every night
(deploy/systemd/ids-backup.timer):
    .venv/bin/python scripts/backup_database.py
To restore one, stop the collector and the dashboard, then:
    gunzip -c backups/ids_live-<time>.db.gz > ids_live.db
"""
from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from ids.config import get_settings  # noqa: E402
from ids.db_backup import backup_database  # noqa: E402


def main() -> None:
    settings = get_settings()
    if not settings.backup_keep:
        print("IDS_BACKUP_KEEP is 0: no backups.")
        return
    made = backup_database(settings.db_file, settings.backup_dir, settings.backup_keep)
    print(f"Backed up {settings.db_file} as {made} ({made.stat().st_size / 1e6:.0f} MB)")


if __name__ == "__main__":
    main()
