"""
A nightly copy of the alert database, gzipped, so the newest alerts (the ones
not yet in the alert archive) survive a damaged or lost database file.

Each night the database is checked first (SQLite's quick_check), and the
result is kept in the backup folder's health.json for the status panel. A
damaged database is not backed up, so it never pushes out the good backups.

SQLite's backup copies a consistent snapshot while the collector keeps
writing. The copy is made in the backup folder and gzipped next to it, then
renamed into place, so a half-made backup never has a backup's name. The
newest ``keep`` backups stay.

``restore_database`` puts a backup back in place of a damaged database and
sets the collector to read the engines' logs again from the start, which
brings back the alerts stored after the backup that the logs still hold
(alerts already in the backup are skipped as duplicates).
"""

from __future__ import annotations

import gzip
import json
import os
import shutil
import sqlite3
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

PATTERN = "ids_live-*.db.gz"
HEALTH_FILE = "health.json"


class DatabaseDamaged(Exception):
    """quick_check found a problem in the database."""


def check_database(db_path: Path | str) -> str | None:
    """SQLite's quick_check of the database: None when it is whole, else
    the first problem it found."""
    try:
        connection = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=30)
        try:
            found = connection.execute("PRAGMA quick_check").fetchone()[0]
        finally:
            connection.close()
    except sqlite3.DatabaseError as exc:
        # "file is not a database", or too damaged to start the check.
        return str(exc)
    return None if found == "ok" else found


def _write_health(folder: Path, problem: str | None, now: datetime) -> None:
    part = folder / f"{HEALTH_FILE}.part"
    part.write_text(json.dumps({"checked_ms": int(now.timestamp() * 1000), "problem": problem}))
    os.replace(part, folder / HEALTH_FILE)


def backup_database(
    db_path: Path | str, folder: Path | str, keep: int, *, now: datetime | None = None,
) -> Path:
    """Checks the database, then copies it to ``folder`` as
    ids_live-<time>.db.gz and removes all but the newest ``keep`` backups.
    The new backup's path; DatabaseDamaged, with nothing copied or removed,
    when the check finds a problem."""
    if keep < 1:
        raise ValueError("keep must be >= 1")

    now = now or datetime.now()
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    problem = check_database(db_path)
    _write_health(folder, problem, now)
    if problem is not None:
        raise DatabaseDamaged(problem)

    target = folder / f"ids_live-{now:%Y%m%d-%H%M%S}.db.gz"
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
    (epoch ms; None without one), for the status panel; and when the
    database was last checked (``checked_ms``) and the problem found then
    (``problem``; both None before the first check)."""
    found = []
    for path in Path(folder).glob(PATTERN):
        try:
            found.append(path.stat())
        except OSError:
            # Removed meanwhile, by a newer backup.
            continue
    try:
        health = json.loads((Path(folder) / HEALTH_FILE).read_text())
    except (OSError, ValueError):
        health = {}

    return {
        "count": len(found),
        "bytes": sum(stat.st_size for stat in found),
        "newest_ms": int(max(stat.st_mtime for stat in found) * 1000) if found else None,
        "checked_ms": health.get("checked_ms"),
        "problem": health.get("problem"),
    }


def newest_backup(folder: Path | str) -> Path | None:
    """The newest backup in ``folder`` (by the time in its name)."""
    found = sorted(Path(folder).glob(PATTERN))
    return found[-1] if found else None


def restore_database(
    backup: Path | str, db_path: Path | str, state_file: Path | str, *, now: datetime | None = None,
) -> Path:
    """Puts ``backup`` in place of the database at ``db_path``, and sets
    every log position in the collector's ``state_file`` back to the start.

    The backup is unpacked and checked next to the database first, so a
    damaged backup changes nothing. The database it replaces (with its -wal
    and -shm files) is kept beside it as ids_live-replaced-<time>.db, and
    the state file as <name>.before-restore. Only while the collector and
    the dashboard are stopped. The kept database's path (which doesn't
    exist when there was no database)."""
    now = now or datetime.now()
    backup, db_path, state_file = Path(backup), Path(db_path), Path(state_file)
    restoring = db_path.with_name(f"{db_path.name}.restoring")
    try:
        with gzip.open(backup, "rb") as packed, restoring.open("wb") as plain:
            shutil.copyfileobj(packed, plain, 1 << 20)
        problem = check_database(restoring)
        if problem is not None:
            raise DatabaseDamaged(f"the backup {backup.name} is damaged too: {problem}")
    except BaseException:
        restoring.unlink(missing_ok=True)
        raise
    finally:
        # The check's read leaves the (empty) -wal and -shm of a WAL database.
        for suffix in ("-wal", "-shm"):
            Path(f"{restoring}{suffix}").unlink(missing_ok=True)

    kept = db_path.with_name(f"{db_path.stem}-replaced-{now:%Y%m%d-%H%M%S}{db_path.suffix}")
    for suffix in ("", "-wal", "-shm"):
        old = Path(f"{db_path}{suffix}")
        if old.exists():
            os.replace(old, f"{kept}{suffix}")
    os.replace(restoring, db_path)

    if state_file.exists():
        state = json.loads(state_file.read_text())
        shutil.copy2(state_file, state_file.with_name(f"{state_file.name}.before-restore"))
        for position in state.values():
            if isinstance(position, dict) and "offset" in position:
                position["offset"] = 0
        part = state_file.with_name(f"{state_file.name}.part")
        part.write_text(json.dumps(state, indent=2, sort_keys=True))
        os.replace(part, state_file)

    if backup.parent.exists():
        # The database is whole again: the status panel no longer says damaged.
        _write_health(backup.parent, None, now)

    return kept
