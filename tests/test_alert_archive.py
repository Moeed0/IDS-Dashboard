from __future__ import annotations

import gzip
import json
import sqlite3
import zipfile
from datetime import datetime, timezone

import pytest

from ids.alert_archive import archive_old_alerts
from ids.db import connect_database, insert_alert_batch
from ids.schema import ensure_schema


NOW = datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc)


def _ms(text):
    return int(datetime.fromisoformat(text).timestamp() * 1000)


def _add(conn, times, first=1):
    """An alert at each time, numbered from ``first``, oldest id first."""
    insert_alert_batch(conn, [
        {
            "engine": "suricata",
            "event_ts_utc": _ms(time),
            "msg": f"alert {number}",
            "gid": 1,
            "sid": 2000000 + number,
            "rev": 1,
            "raw_json": json.dumps({"number": number}),
            "event_hash": f"hash-{number}",
        }
        for number, time in enumerate(times, start=first)
    ])


def _database(tmp_path, times):
    conn = connect_database(tmp_path / "ids.db")
    ensure_schema(conn)
    _add(conn, times)
    return conn


def _ids(conn):
    return [row[0] for row in conn.execute("SELECT id FROM alerts ORDER BY id")]


def _day_file(folder, day):
    with gzip.open(folder / "days" / f"{day}.jsonl.gz", "rt", encoding="utf-8") as file:
        return [json.loads(line) for line in file]


def _archive(conn, max_rows, folder, days=30, zip_days=10):
    return archive_old_alerts(conn, max_rows, folder, days=days, zip_days=zip_days, now=NOW)


class StopsBeforeDeleting(sqlite3.Connection):
    """A connection that stops where the archived alerts would be deleted."""

    def execute(self, sql, *args):
        if sql.lstrip().startswith("DELETE FROM alerts "):
            raise OSError("stopped")
        return super().execute(sql, *args)


def test_the_alerts_past_the_limit_go_to_the_files_of_their_pkt_days(tmp_path):
    conn = _database(tmp_path, [
        "2026-11-05T10:00:00+05:00",
        "2026-11-05T23:59:00+05:00",
        # 19:30 UTC on 5 November, but 6 November in PKT.
        "2026-11-06T00:30:00+05:00",
        "2026-11-06T09:00:00+05:00",
        "2026-11-06T10:00:00+05:00",
    ])
    folder = tmp_path / "archive"

    run = _archive(conn, 2, folder)

    assert run.moved == 3
    assert _ids(conn) == [4, 5]
    assert [alert["msg"] for alert in _day_file(folder, "2026-11-05")] == ["alert 1", "alert 2"]
    [alert] = _day_file(folder, "2026-11-06")
    # Every column, as the database had it.
    assert (alert["id"], alert["engine"], alert["sid"], alert["raw_json"]) == (
        3, "suricata", 2000003, json.dumps({"number": 3}),
    )
    assert alert["event_ts_utc"] == _ms("2026-11-06T00:30:00+05:00")

    # A later run adds to the day's file.
    _add(conn, ["2026-11-06T11:00:00+05:00"], first=6)
    assert _archive(conn, 2, folder).moved == 1
    assert [alert["id"] for alert in _day_file(folder, "2026-11-06")] == [3, 4]
    assert dict(conn.execute("SELECT name, size FROM alert_archive_files")) == {
        name: (folder / "days" / name).stat().st_size
        for name in ("2026-11-05.jsonl.gz", "2026-11-06.jsonl.gz")
    }
    # Under the limit, nothing moves.
    assert _archive(conn, 5, folder).moved == 0
    assert _ids(conn) == [5, 6]


def test_a_run_stopped_before_deleting_its_alerts_loses_none_and_keeps_none_twice(tmp_path):
    conn = _database(tmp_path, [
        "2026-11-05T10:00:00+05:00",
        "2026-11-05T11:00:00+05:00",
        "2026-11-05T12:00:00+05:00",
        "2026-11-05T13:00:00+05:00",
    ])
    folder = tmp_path / "archive"
    _archive(conn, 3, folder)
    conn.close()
    day_file = folder / "days" / "2026-11-05.jsonl.gz"
    recorded_size = day_file.stat().st_size

    # This run adds alerts 2 and 3 to the day's file, then stops.
    stopping = sqlite3.connect(tmp_path / "ids.db", factory=StopsBeforeDeleting)
    with pytest.raises(OSError, match="stopped"):
        _archive(stopping, 1, folder)
    stopping.close()
    assert day_file.stat().st_size > recorded_size

    conn = connect_database(tmp_path / "ids.db")
    assert _ids(conn) == [2, 3, 4]
    assert _archive(conn, 1, folder).moved == 2
    assert [alert["id"] for alert in _day_file(folder, "2026-11-05")] == [1, 2, 3]
    assert _ids(conn) == [4]


def test_a_new_day_file_from_a_stopped_run_is_left_out(tmp_path):
    conn = _database(tmp_path, ["2026-11-05T10:00:00+05:00", "2026-11-05T11:00:00+05:00"])
    conn.close()
    folder = tmp_path / "archive"

    stopping = sqlite3.connect(tmp_path / "ids.db", factory=StopsBeforeDeleting)
    with pytest.raises(OSError, match="stopped"):
        _archive(stopping, 1, folder)
    stopping.close()
    assert (folder / "days" / "2026-11-05.jsonl.gz").exists()

    conn = connect_database(tmp_path / "ids.db")
    assert _archive(conn, 1, folder).moved == 1
    assert [alert["id"] for alert in _day_file(folder, "2026-11-05")] == [1]


def test_a_period_wholly_out_of_the_database_is_zipped_with_a_file_a_day(tmp_path):
    conn = _database(tmp_path, [
        "2026-11-03T08:00:00+05:00",
        "2026-11-04T08:00:00+05:00",
        "2026-11-12T23:00:00+05:00",
        # The next period, 13 to 22 November.
        "2026-11-13T01:00:00+05:00",
    ])
    folder = tmp_path / "archive"

    run = _archive(conn, 1, folder)

    zipped = folder / "alerts_2026-11-03_to_2026-11-12.zip"
    assert (run.moved, run.packed) == (3, [zipped])
    with zipfile.ZipFile(zipped) as archive:
        assert archive.namelist() == ["2026-11-03.jsonl", "2026-11-04.jsonl", "2026-11-12.jsonl"]
        lines = archive.read("2026-11-12.jsonl").decode("utf-8").splitlines()
    assert [json.loads(line)["msg"] for line in lines] == ["alert 3"]
    assert list((folder / "days").iterdir()) == []
    assert conn.execute("SELECT COUNT(*) FROM alert_archive_files").fetchone() == (0,)


def test_a_period_waits_while_the_database_holds_an_alert_of_it(tmp_path):
    conn = _database(tmp_path, ["2026-11-03T08:00:00+05:00", "2026-11-12T23:00:00+05:00"])
    folder = tmp_path / "archive"

    run = _archive(conn, 1, folder)

    assert (run.moved, run.packed) == (1, [])
    assert [alert["id"] for alert in _day_file(folder, "2026-11-03")] == [1]

    # With the database empty, a period is zipped once it is over (it ended
    # on 12 November).
    conn.execute("DELETE FROM alerts")
    conn.commit()
    assert _archive(conn, 1, folder).packed == [folder / "alerts_2026-11-03_to_2026-11-12.zip"]


def test_alerts_of_a_period_zipped_before_get_another_zip(tmp_path):
    conn = _database(tmp_path, ["2026-11-03T08:00:00+05:00", "2026-11-13T08:00:00+05:00"])
    folder = tmp_path / "archive"
    folder.mkdir()
    (folder / "alerts_2026-11-03_to_2026-11-12.zip").write_bytes(b"zipped before")

    run = _archive(conn, 1, folder)

    assert run.packed == [folder / "alerts_2026-11-03_to_2026-11-12_2.zip"]
    assert (folder / "alerts_2026-11-03_to_2026-11-12.zip").read_bytes() == b"zipped before"


def test_only_the_zips_of_the_newest_periods_the_archive_days_cover_stay(tmp_path):
    conn = _database(tmp_path, ["2026-11-20T08:00:00+05:00"])
    folder = tmp_path / "archive"
    folder.mkdir()
    names = [
        "alerts_2026-09-24_to_2026-10-03.zip",
        "alerts_2026-10-04_to_2026-10-13.zip",
        "alerts_2026-10-14_to_2026-10-23.zip",
        "alerts_2026-10-24_to_2026-11-02.zip",
        "alerts_2026-10-24_to_2026-11-02_2.zip",
        "alerts_2026-11-03_to_2026-11-12.zip",
    ]
    for name in names:
        (folder / name).write_bytes(b"")

    # 30 days in 10-day zips: the newest 3 periods.
    run = _archive(conn, 10, folder)

    assert sorted(path.name for path in run.removed) == names[:2]
    assert sorted(path.name for path in folder.glob("*.zip")) == names[2:]
    # 25 days still keep whole zips: 3.
    assert _archive(conn, 10, folder, days=25).removed == []
