"""
Each alert's UID: 7 characters, unique in this project, made from the
alert's minute.

A UID is a number written in Crockford's Base32 (digits and capitals without
I, L, O and U), so it reads the same in any case, 0/O and 1/I/L can't be
mixed up, and UIDs sort as their numbers do. Each minute, counted from 1 Nov
2026 UTC, has 16,384 numbers, from minute × 16,384. Seven characters hold the
minutes until late October 2030; later UIDs take an eighth character, so
they still never repeat.

The collector numbers the alerts as it stores them, in time order: each new
UID is the larger of its minute's first number and the last UID given + 1.
So UIDs only go up, and no number is ever given twice:

- the alerts of a minute get its numbers in order (the busiest minute
  before UIDs had 338 alerts);
- an alert stored after a later minute's alerts gets the next number, in
  that later minute;
- past 16,384 alerts in a minute (a flood), the UIDs count on into the next
  minutes' numbers, ahead of the clock, until a quieter time catches up.

The last UID given is the database's highest (the archive moves the oldest
alerts first), or, when higher, the one in the mark file the collector keeps
beside its state, which a restored backup can't take back. A missing time,
or one in the future (a wrong clock would push every later UID ahead),
counts as the time the alert is numbered.
"""

from __future__ import annotations

import os
import sqlite3
import sys
import time
from pathlib import Path

ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
LENGTH = 7
START_MS = 1_793_491_200_000  # 1 Nov 2026 00:00 UTC
PER_MINUTE = 16_384


def _counted_time(time_ms: int | None, now_ms: int) -> int:
    return now_ms if time_ms is None else min(time_ms, now_ms)


def uid_minute(time_ms: int | None, now_ms: int) -> int:
    """The minute (from 1 Nov 2026) an alert at ``time_ms`` is numbered
    in: ``now_ms``'s when the time is missing or later, and the first
    minute for a time before 1 Nov 2026."""
    return max(0, (_counted_time(time_ms, now_ms) - START_MS) // 60_000)


def uid_text(uid: int | None) -> str | None:
    """The UID as the page shows it: 7 characters (more after October
    2030); None without one."""
    if uid is None:
        return None
    text = ""
    while uid or len(text) < LENGTH:
        uid, digit = divmod(uid, 32)
        text = ALPHABET[digit] + text
    return text


def _read_mark(mark: Path | None) -> int:
    """The last UID given, as the mark file has it; -1 without one."""
    if mark is None:
        return -1
    try:
        return int(mark.read_text())
    except (OSError, ValueError):
        # None yet, or cut short by a crash: the database's highest stands.
        return -1


def _write_mark(mark: Path | None, last: int) -> None:
    if mark is None:
        return
    part = mark.with_name(f"{mark.name}.part")
    try:
        part.write_text(f"{last}\n")
        os.replace(part, mark)
    except OSError as error:
        # The alerts are still stored: the database's highest UID keeps the
        # numbers going up; only a restore could take them back.
        print(f"[!] UID mark {mark}: {error}", file=sys.stderr)


def assign_uids(conn: sqlite3.Connection, mark: Path | None = None) -> int:
    """Numbers the alerts that have no UID yet, in time order, after the
    last UID given: the database's highest, or ``mark``'s when higher. How
    many it numbered. Writes the new last UID to ``mark`` before the caller
    commits (a mark ahead of the database only leaves a gap). Finds the
    alerts and the highest UID through the unique index on uid (schema.py).
    Doesn't commit."""
    rows = conn.execute("SELECT id, event_ts_utc FROM alerts WHERE uid IS NULL").fetchall()
    if not rows:
        return 0

    now_ms = int(time.time() * 1000)
    highest = conn.execute("SELECT max(uid) FROM alerts").fetchone()[0]
    last = max(-1 if highest is None else highest, _read_mark(mark))
    rows.sort(key=lambda row: (_counted_time(row[1], now_ms), row[0]))
    numbered = []
    for alert_id, time_ms in rows:
        last = max(uid_minute(time_ms, now_ms) * PER_MINUTE, last + 1)
        numbered.append((last, alert_id))

    # Written in id order, the order the rows lie in the file: in time order
    # (which a restore mixes up) numbering 269k alerts took 61 s, not 17.
    numbered.sort(key=lambda pair: pair[1])
    conn.executemany("UPDATE alerts SET uid = ? WHERE id = ?", numbered)
    _write_mark(mark, last)
    return len(numbered)
