import gzip
import sqlite3
from datetime import datetime

import pytest

from ids.dashboard_data import storage
from ids.db_backup import backup_database, backup_summary


def _database(path, rows):
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE alerts (id INTEGER PRIMARY KEY, msg TEXT)")
    connection.executemany("INSERT INTO alerts (msg) VALUES (?)", [(row,) for row in rows])
    connection.commit()
    connection.close()


def test_a_backup_is_a_gzipped_copy_that_restores(tmp_path):
    db_path = tmp_path / "ids_live.db"
    _database(db_path, ["one", "two"])
    folder = tmp_path / "backups"

    made = backup_database(db_path, folder, 3, now=datetime(2026, 11, 10, 3, 30))

    assert made == folder / "ids_live-20261110-033000.db.gz"
    # Only the backup is left in the folder: no part file, no scratch copy.
    assert [path.name for path in folder.iterdir()] == [made.name]
    restored = tmp_path / "restored.db"
    restored.write_bytes(gzip.decompress(made.read_bytes()))
    connection = sqlite3.connect(restored)
    assert connection.execute("SELECT msg FROM alerts ORDER BY id").fetchall() == [("one",), ("two",)]
    connection.close()


def test_only_the_newest_backups_stay(tmp_path):
    db_path = tmp_path / "ids_live.db"
    _database(db_path, ["one"])
    folder = tmp_path / "backups"

    for day in (7, 8, 9, 10):
        backup_database(db_path, folder, 2, now=datetime(2026, 11, day, 3, 30))

    assert sorted(path.name for path in folder.iterdir()) == [
        "ids_live-20261109-033000.db.gz", "ids_live-20261110-033000.db.gz",
    ]
    summary = backup_summary(folder)
    assert summary["count"] == 2
    assert summary["bytes"] == sum(path.stat().st_size for path in folder.iterdir())
    assert summary["newest_ms"] == int(max(path.stat().st_mtime for path in folder.iterdir()) * 1000)
    assert backup_summary(tmp_path / "none") == {"count": 0, "bytes": 0, "newest_ms": None}
    with pytest.raises(ValueError):
        backup_database(db_path, folder, 0)


def test_storage_gives_the_disk_and_what_the_alerts_take(tmp_path):
    db_path = tmp_path / "ids_live.db"
    _database(db_path, ["one"])
    archive = tmp_path / "archive"
    (archive / "days").mkdir(parents=True)
    (archive / "days" / "2026-11-13.jsonl.gz").write_bytes(b"12345")
    (archive / "alerts_2026-11-03_to_2026-11-12.zip").write_bytes(b"123")
    backups = tmp_path / "backups"
    backup_database(db_path, backups, 3)

    found = storage(db_path, archive, backups)

    assert 0 < found["disk_free"] <= found["disk_total"]
    assert found["database"] == db_path.stat().st_size
    assert found["archive"] == 8
    assert found["backups"] == backup_summary(backups)
    # Backups off, and no archive.
    without = storage(db_path, None, None)
    assert (without["archive"], without["backups"]) == (0, None)
