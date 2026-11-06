"""
Alerts that leave the database are kept in zips instead of being deleted.

The collector keeps the newest IDS_ALERT_RETENTION alerts in the database.
Every minute the ones over that limit move to the archive folder: each one,
as a line of JSON with all its columns, goes to the file of its day (PKT) in
days/. Once a period of IDS_ALERT_ARCHIVE_ZIP_DAYS days has wholly left the
database, its day files are packed into one zip,
alerts_<first day>_to_<last day>.zip, with a .jsonl file for each day. The
newest zips that cover IDS_ALERT_ARCHIVE_DAYS are kept: 30 days in 10-day
zips is 3 zips.

A day file grows by one gzip member a minute. The database records each
file's size in the transaction that deletes the alerts, so after a crash a
file is cut back to its recorded size and the alerts still in the database
are added again: none is lost, and none is kept twice.
"""

from __future__ import annotations

import gzip
import json
import math
import os
import shutil
import sqlite3
import zipfile
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import BinaryIO
from zoneinfo import ZoneInfo

# Days run in the dashboard's time zone.
PKT = ZoneInfo("Asia/Karachi")
DAY_FOLDER = "days"
DAY_SUFFIX = ".jsonl.gz"
# Periods count from this day, so a period's days don't depend on when the
# archive started.
EPOCH = date(1970, 1, 1)


@dataclass
class ArchiveRun:
    """What one run did."""

    moved: int = 0
    packed: list[Path] = field(default_factory=list)
    removed: list[Path] = field(default_factory=list)


def archive_old_alerts(
    conn: sqlite3.Connection,
    max_rows: int,
    folder: Path,
    *,
    days: int,
    zip_days: int,
    now: datetime | None = None,
) -> ArchiveRun:
    """
    Moves the alerts past the newest max_rows into the archive, packs the
    periods that have wholly left the database, and removes the zips past
    the newest that cover ``days``.
    """
    if max_rows < 1:
        raise ValueError("max_rows must be >= 1")

    today = (now or datetime.now(tz=PKT)).astimezone(PKT).date()
    day_folder = Path(folder) / DAY_FOLDER
    day_folder.mkdir(parents=True, exist_ok=True)
    run = ArchiveRun()

    sizes = _cut_back(conn, day_folder)
    keep_from = conn.execute(
        "SELECT id FROM alerts ORDER BY id DESC LIMIT 1 OFFSET ?",
        (max_rows - 1,),
    ).fetchone()

    if keep_from is not None:
        rows = conn.execute(
            "SELECT * FROM alerts WHERE id < ? ORDER BY id",
            (keep_from[0],),
        )
        run.moved = _append_by_day(rows, day_folder, today, sizes)

        if run.moved:
            # The sizes and the deletion are one transaction.
            conn.executemany(
                """
                INSERT INTO alert_archive_files (name, size) VALUES (?, ?)
                ON CONFLICT(name) DO UPDATE SET size = excluded.size
                """,
                sizes.items(),
            )
            conn.execute(
                "DELETE FROM alerts WHERE id < ?",
                (keep_from[0],),
            )
            conn.commit()

    run.packed = _pack_finished_periods(conn, Path(folder), zip_days, today)
    run.removed = _remove_old_zips(Path(folder), math.ceil(days / zip_days))
    return run


def _cut_back(conn: sqlite3.Connection, day_folder: Path) -> dict[str, int]:
    """
    Cuts each day file back to its recorded size and removes the ones never
    recorded: what a run that stopped before deleting its alerts left. The
    recorded sizes of the files that are there.
    """
    recorded = dict(conn.execute("SELECT name, size FROM alert_archive_files"))
    sizes = {}

    for path in day_folder.glob(f"*{DAY_SUFFIX}"):
        size = recorded.get(path.name)

        if size is None:
            path.unlink()
            continue

        if path.stat().st_size > size:
            with path.open("r+b") as file:
                file.truncate(size)

        sizes[path.name] = size

    gone = [(name,) for name in recorded if name not in sizes]

    if gone:
        conn.executemany("DELETE FROM alert_archive_files WHERE name = ?", gone)
        conn.commit()

    return sizes


def _append_by_day(
    rows: sqlite3.Cursor,
    day_folder: Path,
    today: date,
    sizes: dict[str, int],
) -> int:
    """
    Adds the rows to the files of their days, as one gzip member each, and
    puts the files' new sizes in ``sizes``. How many rows it added.
    """
    names = [column[0] for column in rows.description]
    files: dict[str, tuple[gzip.GzipFile, BinaryIO]] = {}
    added = 0

    try:
        for row in rows:
            alert = dict(zip(names, row))
            name = f"{_day(alert.get('event_ts_utc'), today)}{DAY_SUFFIX}"

            if name not in files:
                raw = (day_folder / name).open("ab")
                files[name] = (gzip.GzipFile(fileobj=raw, mode="ab", compresslevel=6), raw)

            line = json.dumps(alert, ensure_ascii=False, separators=(",", ":"))
            files[name][0].write(f"{line}\n".encode("utf-8"))
            added += 1

    finally:
        for name, (member, raw) in files.items():
            member.close()
            raw.flush()
            os.fsync(raw.fileno())
            sizes[name] = os.fstat(raw.fileno()).st_size
            raw.close()

    if files:
        _sync_folder(day_folder)

    return added


def _day(event_ms: int | None, today: date) -> date:
    """The alert's PKT day; an alert without a time counts on the day it left."""
    if event_ms is None:
        return today

    return datetime.fromtimestamp(event_ms / 1000, tz=PKT).date()


def _period_start(day: date, zip_days: int) -> date:
    return EPOCH + timedelta(days=(day - EPOCH).days // zip_days * zip_days)


def _pack_finished_periods(
    conn: sqlite3.Connection,
    folder: Path,
    zip_days: int,
    today: date,
) -> list[Path]:
    """
    Packs the day files of each period that no alert in the database belongs
    to any more (with the database empty, each period that is over) into a
    zip, and removes them.
    """
    for part in folder.glob("*.zip.part"):
        part.unlink()

    oldest = conn.execute("SELECT MIN(event_ts_utc) FROM alerts").fetchone()[0]
    first_open = _day(oldest, today) if oldest is not None else today
    periods: dict[date, list[Path]] = {}

    for path in sorted((folder / DAY_FOLDER).glob(f"*{DAY_SUFFIX}")):
        day = date.fromisoformat(path.name.removesuffix(DAY_SUFFIX))
        periods.setdefault(_period_start(day, zip_days), []).append(path)

    packed = []

    for start, paths in sorted(periods.items()):
        if start + timedelta(days=zip_days) > first_open:
            continue

        packed.append(_pack(folder, start, zip_days, paths))
        conn.executemany(
            "DELETE FROM alert_archive_files WHERE name = ?",
            [(path.name,) for path in paths],
        )
        conn.commit()

        for path in paths:
            path.unlink()

    return packed


def _pack(folder: Path, start: date, zip_days: int, paths: list[Path]) -> Path:
    """One zip of the period's day files, each one a .jsonl file in it."""
    name = f"alerts_{start}_to_{start + timedelta(days=zip_days - 1)}"
    target = folder / f"{name}.zip"
    copy = 2

    # A period packed before gets another zip for the alerts of it that were
    # stored late (after a log was read again from its start, say).
    while target.exists():
        target = folder / f"{name}_{copy}.zip"
        copy += 1

    part = target.with_name(f"{target.name}.part")

    with zipfile.ZipFile(part, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for path in paths:
            with gzip.open(path, "rb") as source, archive.open(
                path.name.removesuffix(".gz"), "w", force_zip64=True
            ) as member:
                shutil.copyfileobj(source, member, 1 << 20)

    with part.open("rb") as file:
        os.fsync(file.fileno())

    os.replace(part, target)
    _sync_folder(folder)
    return target


def _remove_old_zips(folder: Path, keep: int) -> list[Path]:
    """Removes the zips of all but the newest ``keep`` periods."""
    zips = sorted(folder.glob("alerts_*_to_*.zip"))
    # A zip's name starts with its period's first day.
    starts = sorted({path.name[len("alerts_"):][:10] for path in zips})
    kept = set(starts[-keep:]) if keep else set()
    removed = [path for path in zips if path.name[len("alerts_"):][:10] not in kept]

    for path in removed:
        path.unlink()

    return removed


def _sync_folder(folder: Path) -> None:
    """Makes a new or renamed file's place in the folder last through a crash."""
    descriptor = os.open(folder, os.O_RDONLY)

    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
