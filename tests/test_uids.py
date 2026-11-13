import sqlite3
import time

import pytest

from ids.db import insert_alert_batch
from ids.schema import ensure_schema
from ids.uids import PER_MINUTE, START_MS, uid_minute, uid_text

MINUTE = 60_000
# 11 Nov 2026 10:08:21 UTC (15:08:21 PKT): minute 15,008 from 1 November.
TIME_MS = START_MS + 15_008 * MINUTE + 21_000
FIRST = 15_008 * PER_MINUTE


def test_a_uid_is_seven_characters_that_sort_by_time():
    assert uid_text(0) == "0000000"
    assert uid_text(FIRST) == "07AG000"
    assert uid_text(FIRST + 1) == "07AG001"
    # The next minute's first.
    assert uid_text(FIRST + PER_MINUTE) == "07AGG00"
    # 15:29:12 PKT on 11 Nov, the minute's 20th alert.
    assert uid_text(15_029 * PER_MINUTE + 19) == "07ATG0K"
    assert uid_text(32 ** 7 - 1) == "ZZZZZZZ"
    # After October 2030 an eighth character, never a repeat.
    assert uid_text(32 ** 7) == "10000000"
    assert uid_text(None) is None
    texts = [uid_text(value) for value in (5, 31, 32, 1000, FIRST, 32 ** 7 - 1)]
    assert texts == sorted(texts)
    # Crockford's Base32: no I, L, O or U.
    assert not set("".join(uid_text(value) for value in range(0, 32 ** 7, 99_999_989))) & set("ILOU")


def test_the_minute_counts_from_1_november_2026():
    assert uid_minute(TIME_MS, now_ms=TIME_MS + MINUTE) == 15_008
    # No time, or a later one than now: now.
    assert uid_minute(None, now_ms=TIME_MS) == 15_008
    assert uid_minute(TIME_MS + 600 * MINUTE, now_ms=TIME_MS) == 15_008
    # Before 1 November 2026: the first minute.
    assert uid_minute(START_MS - 86_400_000, now_ms=TIME_MS) == 0


def _alert(number, time_ms):
    return {
        "engine": "suricata", "event_ts_utc": time_ms, "msg": f"alert {number}", "gid": 1,
        "sid": 2_000_000 + number, "rev": 1, "raw_json": "{}", "event_hash": f"hash-{number}",
    }


def _database(path):
    connection = sqlite3.connect(path)
    ensure_schema(connection)
    return connection


def _uids(connection):
    return [uid_text(uid) for (uid,) in connection.execute("SELECT uid FROM alerts ORDER BY id")]


def test_the_alerts_are_numbered_in_time_order_and_never_back(tmp_path):
    connection = _database(tmp_path / "ids.db")

    # Out of order, as the two engines' logs are read.
    insert_alert_batch(connection, [
        _alert(1, TIME_MS + 30_000), _alert(2, TIME_MS), _alert(3, TIME_MS + MINUTE),
    ])
    # Stored after the next minute's alert: the next number, in that minute.
    insert_alert_batch(connection, [_alert(4, TIME_MS + 1_000)])

    assert _uids(connection) == ["07AG001", "07AG000", "07AGG00", "07AGG01"]


def test_a_flood_counts_on_into_the_next_minutes_numbers(tmp_path):
    connection = _database(tmp_path / "ids.db")

    insert_alert_batch(connection, [_alert(number, TIME_MS) for number in range(PER_MINUTE + 2)])
    insert_alert_batch(connection, [_alert(99_999, TIME_MS + MINUTE)])

    uids = [uid for (uid,) in connection.execute("SELECT uid FROM alerts ORDER BY id")]
    assert uids[:PER_MINUTE] == list(range(FIRST, FIRST + PER_MINUTE))
    # The two past 16,384 take the next minute's first numbers, and that
    # minute's own alert the one after them.
    assert uids[PER_MINUTE:] == [FIRST + PER_MINUTE, FIRST + PER_MINUTE + 1, FIRST + PER_MINUTE + 2]


def test_a_duplicate_takes_no_number(tmp_path):
    connection = _database(tmp_path / "ids.db")

    insert_alert_batch(connection, [_alert(1, TIME_MS)])
    # A log read again: the alert the database has is skipped, and the next
    # alert gets the next number.
    insert_alert_batch(connection, [_alert(1, TIME_MS), _alert(2, TIME_MS)])

    assert _uids(connection) == ["07AG000", "07AG001"]


def test_the_numbers_of_archived_alerts_are_not_given_again(tmp_path):
    connection = _database(tmp_path / "ids.db")
    insert_alert_batch(connection, [_alert(number, TIME_MS) for number in (1, 2, 3)])

    # The archive moves the oldest alerts out; the highest UID stays.
    connection.execute("DELETE FROM alerts WHERE id IN (1, 2)")
    insert_alert_batch(connection, [_alert(4, TIME_MS)])

    assert _uids(connection) == ["07AG002", "07AG003"]


def test_a_restored_backup_cant_take_the_numbering_back(tmp_path):
    connection = _database(tmp_path / "ids.db")
    mark = tmp_path / "last_uid"
    insert_alert_batch(connection, [_alert(number, TIME_MS) for number in (1, 2, 3)], mark)
    assert mark.read_text() == f"{FIRST + 2}\n"

    # A backup from before these three: the database's highest UID is gone,
    # and the archive may have them.
    connection.execute("DELETE FROM alerts")
    insert_alert_batch(connection, [_alert(4, TIME_MS)], mark)

    assert _uids(connection) == ["07AG003"]
    assert mark.read_text() == f"{FIRST + 3}\n"


def test_a_damaged_mark_leaves_the_database_to_go_by(tmp_path):
    connection = _database(tmp_path / "ids.db")
    mark = tmp_path / "last_uid"
    insert_alert_batch(connection, [_alert(1, TIME_MS)], mark)

    mark.write_text("07AG")
    insert_alert_batch(connection, [_alert(2, TIME_MS)], mark)

    assert _uids(connection) == ["07AG000", "07AG001"]
    assert mark.read_text() == f"{FIRST + 1}\n"


def test_a_time_in_the_future_counts_as_now(tmp_path):
    connection = _database(tmp_path / "ids.db")

    before_ms = int(time.time() * 1000)
    # A wrong clock, ten years ahead: it doesn't push the UIDs after it.
    insert_alert_batch(connection, [_alert(1, before_ms + 10 * 365 * 86_400_000)])
    after_ms = int(time.time() * 1000)

    [(uid,)] = connection.execute("SELECT uid FROM alerts").fetchall()
    assert uid_minute(None, before_ms) <= uid // PER_MINUTE <= uid_minute(None, after_ms)


def _old_database(path):
    """A database from before UIDs: no uid column."""
    connection = sqlite3.connect(path)
    connection.execute(
        "CREATE TABLE alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, engine TEXT, "
        "event_ts_utc INTEGER, msg TEXT, event_hash TEXT)"
    )
    connection.executemany(
        "INSERT INTO alerts (engine, event_ts_utc, msg, event_hash) VALUES (?, ?, ?, ?)",
        [("snort", TIME_MS + number, f"alert {number}", f"hash-{number}") for number in range(5)]
        + [("snort", None, "no time or hash", None)],
    )
    connection.commit()
    return connection


def test_the_alerts_stored_before_uids_get_theirs(tmp_path):
    connection = _old_database(tmp_path / "ids.db")
    mark = tmp_path / "last_uid"

    before_ms = int(time.time() * 1000)
    ensure_schema(connection, mark)
    after_ms = int(time.time() * 1000)

    rows = connection.execute("SELECT id, uid FROM alerts ORDER BY id").fetchall()
    assert [uid_text(uid) for _, uid in rows[:5]] == ["07AG000", "07AG001", "07AG002", "07AG003", "07AG004"]
    # The one without a time: the minute it got its UID in.
    assert uid_minute(None, before_ms) <= rows[5][1] // PER_MINUTE <= uid_minute(None, after_ms)
    assert mark.read_text() == f"{rows[5][1]}\n"
    # Run again (every collector start), nothing changes.
    ensure_schema(connection, mark)
    assert connection.execute("SELECT id, uid FROM alerts ORDER BY id").fetchall() == rows
    # The index refuses a second alert with one of these UIDs.
    with pytest.raises(sqlite3.IntegrityError):
        connection.execute("INSERT INTO alerts (engine, uid) VALUES ('snort', ?)", (rows[0][1],))
