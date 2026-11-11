"""
A nightly copy of the alert database, gzipped, so the newest alerts (the ones
not yet in the alert archive) survive a damaged or lost database file.

SQLite's backup copies a consistent snapshot while the collector keeps
writing. The copy is made in the backup folder and gzipped next to it, then
renamed into place, so a half-made backup never has a backup's name. The
newest ``keep`` backups stay.
"""

from __future__ import annotations

import gzip
import os
import shutil
import sqlite3
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

PATTERN = "ids_live-*.db.gz"


def backup_database(
    db_path: Path | str, folder: Path | str, keep: int, *, now: datetime | None = None,
) -> Path:
    """Copies the database to ``folder`` as ids_live-<time>.db.gz, and removes
    all but the newest ``keep`` backups. The new backup's path."""
    if keep < 1:
        raise ValueError("keep must be >= 1")

    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    target = folder / f"ids_live-{(now or datetime.now()):%Y%m%d-%H%M%S}.db.gz"
    part = target.with_name(f"{target.name}.part")

    with tempfile.TemporaryDirectory(dir=folder) as scratch:
        copy = Path(scratch) / "ids_live.db"
        source = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=30)
        destination = sqlite3.connect(copy)
        try:
            source.backup(destination)
        finally:
            destination.close()
            source.close()

        with copy.open("rb") as plain, gzip.open(part, "wb", compresslevel=6) as packed:
            shutil.copyfileobj(plain, packed, 1 << 20)

    os.replace(part, target)

    for old in sorted(folder.glob(PATTERN))[:-keep]:
        old.unlink()

    return target


def backup_summary(folder: Path | str) -> dict[str, Any]:
    """How many backups there are, their size, and when the newest was made
    (epoch ms; None without one), for the status panel."""
    found = []
    for path in Path(folder).glob(PATTERN):
        try:
            found.append(path.stat())
        except OSError:
            # Removed meanwhile, by a newer backup.
            continue

    return {
        "count": len(found),
        "bytes": sum(stat.st_size for stat in found),
        "newest_ms": int(max(stat.st_mtime for stat in found) * 1000) if found else None,
    }
