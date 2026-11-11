import gzip
import json
import sqlite3
from datetime import datetime

import pytest

from ids.dashboard_data import storage
from ids.db_backup import (
    DatabaseDamaged, backup_database, backup_summary, check_database, newest_backup, restore_database,
)


def _database(path, rows):
    connection = sqlite3.connect(path)
    # As the collector writes it, so its backups are WAL databases too.
    connection.execute("PRAGMA journal_mode=WAL")
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
    # Only the backup and the check's result are left in the folder: no part
    # file, no scratch copy.
    assert sorted(path.name for path in folder.iterdir()) == ["health.json", made.name]
    assert backup_summary(folder)["problem"] is None
    assert backup_summary(folder)["checked_ms"] == int(datetime(2026, 11, 10, 3, 30).timestamp() * 1000)
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

    assert sorted(path.name for path in folder.glob("*.gz")) == [
        "ids_live-20261109-033000.db.gz", "ids_live-20261110-033000.db.gz",
    ]
    summary = backup_summary(folder)
    assert summary["count"] == 2
    assert summary["bytes"] == sum(path.stat().st_size for path in folder.glob("*.gz"))
    assert summary["newest_ms"] == int(max(path.stat().st_mtime for path in folder.glob("*.gz")) * 1000)
    assert backup_summary(tmp_path / "none") == {
        "count": 0, "bytes": 0, "newest_ms": None, "checked_ms": None, "problem": None,
    }
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


def _damage(path):
    """Overwrites a page in the middle of the database, as a cut-off write can."""
    data = bytearray(path.read_bytes())
    middle = len(data) // 4096 // 2 * 4096
    data[middle:middle + 4096] = b"\xff" * 4096
    path.write_bytes(bytes(data))


def test_a_damaged_database_is_found_and_not_backed_up(tmp_path):
    db_path = tmp_path / "ids_live.db"
    _database(db_path, [f"alert {number} " * 20 for number in range(3000)])
    folder = tmp_path / "backups"
    good = backup_database(db_path, folder, 2, now=datetime(2026, 11, 9, 3, 30))
    assert check_database(db_path) is None

    _damage(db_path)
    with pytest.raises(DatabaseDamaged):
        backup_database(db_path, folder, 2, now=datetime(2026, 11, 10, 3, 30))
    # The good backup stays, and the panel learns of the damage.
    assert list(folder.glob("*.gz")) == [good]
    assert backup_summary(folder)["problem"]

    (tmp_path / "junk.db").write_bytes(b"not a database at all" * 100)
    assert check_database(tmp_path / "junk.db")


def test_a_restore_puts_the_backup_back_and_rereads_the_logs(tmp_path):
    db_path = tmp_path / "ids_live.db"
    _database(db_path, ["one", "two"])
    folder = tmp_path / "backups"
    backup_database(db_path, folder, 3, now=datetime(2026, 11, 9, 3, 30))
    newest = backup_database(db_path, folder, 3, now=datetime(2026, 11, 10, 3, 30))
    assert newest_backup(folder) == newest
    assert newest_backup(tmp_path / "none") is None

    state_file = tmp_path / "state.json"
    state = {
        "snort": {"path": "/var/log/snort/alert_json.txt", "inode": 7, "offset": 900},
        "suricata": {"path": "/var/log/suricata/eve.json", "inode": 8, "offset": 4000},
    }
    state_file.write_text(json.dumps(state))
    junk = b"garbage" * 600
    db_path.write_bytes(junk)
    (tmp_path / "ids_live.db-wal").write_bytes(b"wal")
    (folder / "health.json").write_text(json.dumps({"checked_ms": 1, "problem": "damaged"}))

    kept = restore_database(newest, db_path, state_file, now=datetime(2026, 11, 11, 12, 0))

    connection = sqlite3.connect(db_path)
    assert connection.execute("SELECT msg FROM alerts ORDER BY id").fetchall() == [("one",), ("two",)]
    connection.close()
    assert kept == tmp_path / "ids_live-replaced-20261111-120000.db"
    assert kept.read_bytes() == junk
    assert (tmp_path / "ids_live-replaced-20261111-120000.db-wal").read_bytes() == b"wal"
    assert sorted(path.name for path in tmp_path.iterdir()) == [
        "backups", "ids_live-replaced-20261111-120000.db", "ids_live-replaced-20261111-120000.db-shm",
        "ids_live-replaced-20261111-120000.db-wal",
        "ids_live.db", "state.json", "state.json.before-restore",
    ]
    # Every log is read again from the start; the rest of the state stays.
    after = json.loads(state_file.read_text())
    assert after == {engine: {**place, "offset": 0} for engine, place in state.items()}
    assert json.loads((tmp_path / "state.json.before-restore").read_text()) == state
    assert backup_summary(folder)["problem"] is None


def test_a_damaged_backup_changes_nothing(tmp_path):
    db_path = tmp_path / "ids_live.db"
    _database(db_path, [f"alert {number} " * 20 for number in range(3000)])
    folder = tmp_path / "backups"
    backup = backup_database(db_path, folder, 3, now=datetime(2026, 11, 10, 3, 30))
    plain = tmp_path / "plain.db"
    plain.write_bytes(gzip.decompress(backup.read_bytes()))
    _damage(plain)
    backup.write_bytes(gzip.compress(plain.read_bytes()))
    before = db_path.read_bytes()
    state_file = tmp_path / "state.json"
    state_file.write_text(json.dumps({"snort": {"offset": 900}}))
    files = sorted(path.name for path in tmp_path.iterdir())

    with pytest.raises(DatabaseDamaged):
        restore_database(backup, db_path, state_file)

    assert db_path.read_bytes() == before
    assert json.loads(state_file.read_text()) == {"snort": {"offset": 900}}
    # Nothing left from the unpacked backup either.
    assert sorted(path.name for path in tmp_path.iterdir()) == files
