from __future__ import annotations

import gzip
import json
from collections import Counter
import shutil
import sqlite3
import time
from pathlib import Path

from ids.config import get_settings
from ids.db import connect_database, insert_alert_batch
from ids.tailer import PersistentJsonTailer
from live_dual_collector import (
    PendingBatch,
    build_tailers,
    flush_pending,
    handle_line,
    log_files,
    run_periodic_retention,
    setup_database,
    stored_summary,
)


REPO_ROOT = Path(__file__).resolve().parents[1]


def _process_file(engine, tailer, pending):
    def callback(line, inode, offset):
        handle_line(
            engine,
            line,
            inode,
            offset,
            pending,
        )

    return tailer.poll(callback)


def test_dual_collector_ingests_both_engines_and_restarts_without_duplicates(
    tmp_path,
    monkeypatch,
):
    db_file = tmp_path / "ids.db"
    state_file = tmp_path / "state.json"
    snort_file = tmp_path / "alert_json.txt"
    suricata_file = tmp_path / "eve.json"

    shutil.copy2(
        REPO_ROOT
        / "tests/fixtures/snort_alert_json.txt",
        snort_file,
    )

    shutil.copy2(
        REPO_ROOT
        / "tests/fixtures/suricata_eve.json",
        suricata_file,
    )

    monkeypatch.setenv(
        "IDS_DB_FILE",
        str(db_file),
    )
    monkeypatch.setenv(
        "IDS_STATE_FILE",
        str(state_file),
    )
    monkeypatch.setenv(
        "IDS_SNORT_ALERT_FILE",
        str(snort_file),
    )
    monkeypatch.setenv(
        "IDS_SURICATA_EVE_FILE",
        str(suricata_file),
    )
    monkeypatch.setenv(
        "IDS_BATCH_SIZE",
        "20",
    )
    monkeypatch.setenv(
        "IDS_BATCH_FLUSH_MS",
        "100",
    )

    settings = get_settings()

    assert settings.db_file == db_file.resolve()
    assert settings.state_file == state_file.resolve()
    assert settings.snort_alert_file == snort_file.resolve()
    assert settings.suricata_eve_file == suricata_file.resolve()

    setup_database(settings)

    tailers = {
        "snort": PersistentJsonTailer(
            snort_file,
            state_file,
            "snort",
            start_at_end=False,
        ),
        "suricata": PersistentJsonTailer(
            suricata_file,
            state_file,
            "suricata",
            start_at_end=False,
        ),
    }

    pending = PendingBatch()

    snort_lines = _process_file(
        "snort",
        tailers["snort"],
        pending,
    )

    suricata_lines = _process_file(
        "suricata",
        tailers["suricata"],
        pending,
    )

    assert snort_lines > 0
    assert suricata_lines > 0

    flush_pending(
        settings,
        pending,
        tailers,
    )

    conn = sqlite3.connect(db_file)

    try:
        total = conn.execute(
            "SELECT COUNT(*) FROM alerts"
        ).fetchone()[0]

        snort_count = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE engine='snort'"
        ).fetchone()[0]

        suricata_count = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE engine='suricata'"
        ).fetchone()[0]

        distinct_hashes = conn.execute(
            "SELECT COUNT(DISTINCT event_hash) FROM alerts"
        ).fetchone()[0]

        assert total == 12
        assert snort_count == 9
        assert suricata_count == 3
        assert distinct_hashes == 12

    finally:
        conn.close()

    saved = json.loads(
        state_file.read_text(encoding="utf-8")
    )

    assert "snort" in saved
    assert "suricata" in saved

    # Fresh tailers simulate a process restart.
    restarted_tailers = {
        "snort": PersistentJsonTailer(
            snort_file,
            state_file,
            "snort",
            start_at_end=True,
        ),
        "suricata": PersistentJsonTailer(
            suricata_file,
            state_file,
            "suricata",
            start_at_end=True,
        ),
    }

    snort_replay = []
    suricata_replay = []

    restarted_tailers["snort"].poll(
        lambda line, inode, offset:
        snort_replay.append(line)
    )

    restarted_tailers["suricata"].poll(
        lambda line, inode, offset:
        suricata_replay.append(line)
    )

    assert snort_replay == []
    assert suricata_replay == []

    conn = sqlite3.connect(db_file)

    try:
        assert conn.execute(
            "SELECT COUNT(*) FROM alerts"
        ).fetchone()[0] == 12

        assert conn.execute(
            "SELECT COUNT(DISTINCT event_hash) FROM alerts"
        ).fetchone()[0] == 12

    finally:
        conn.close()


def test_dual_collector_keeps_alerts_ungrouped_for_manual_correlation(
    tmp_path,
    monkeypatch,
):

    db_file = tmp_path / "ids.db"
    state_file = tmp_path / "state.json"
    snort_file = tmp_path / "alert_json.txt"
    suricata_file = tmp_path / "eve.json"

    shutil.copy2(
        REPO_ROOT / "tests/fixtures/snort_alert_json.txt",
        snort_file,
    )

    shutil.copy2(
        REPO_ROOT / "tests/fixtures/suricata_eve.json",
        suricata_file,
    )

    monkeypatch.setenv("IDS_DB_FILE", str(db_file))
    monkeypatch.setenv("IDS_STATE_FILE", str(state_file))
    monkeypatch.setenv("IDS_SNORT_ALERT_FILE", str(snort_file))
    monkeypatch.setenv("IDS_SURICATA_EVE_FILE", str(suricata_file))

    settings = get_settings()

    setup_database(settings)

    tailers = {
        "snort": PersistentJsonTailer(
            snort_file,
            state_file,
            "snort",
            start_at_end=False,
        ),
        "suricata": PersistentJsonTailer(
            suricata_file,
            state_file,
            "suricata",
            start_at_end=False,
        ),
    }

    pending = PendingBatch()

    _process_file(
        "snort",
        tailers["snort"],
        pending,
    )

    _process_file(
        "suricata",
        tailers["suricata"],
        pending,
    )

    flush_pending(
        settings,
        pending,
        tailers,
    )

    conn = sqlite3.connect(db_file)

    try:
        total = conn.execute(
            "SELECT COUNT(*) FROM alerts"
        ).fetchone()[0]

        grouped = conn.execute(
            """
            SELECT COUNT(*)
            FROM alerts
            WHERE correlation_group_id IS NOT NULL
            """
        ).fetchone()[0]

        groups = conn.execute(
            """
            SELECT
                correlation_group_id,
                COUNT(*) AS alert_count,
                COUNT(DISTINCT engine) AS engine_count
            FROM alerts
            WHERE correlation_group_id IS NOT NULL
            GROUP BY correlation_group_id
            """
        ).fetchall()

        assert total == 12
        assert grouped == 0
        assert groups == []

    finally:
        conn.close()


def test_only_the_engines_in_ids_engines_are_read(monkeypatch, tmp_path):
    eve_file = tmp_path / "eve.json"
    monkeypatch.setenv("IDS_ENGINES", "suricata")
    monkeypatch.setenv("IDS_STATE_FILE", str(tmp_path / "state.json"))
    monkeypatch.setenv("IDS_SURICATA_EVE_FILE", str(eve_file))
    settings = get_settings()

    tailers = build_tailers(settings, start_at_end=False)

    assert log_files(settings) == {"suricata": eve_file.resolve()}
    assert list(tailers) == ["suricata"]
    assert tailers["suricata"].path == eve_file.resolve()


def test_the_alerts_past_the_limit_are_archived_or_with_0_archive_days_deleted(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setattr("ids.config.ENV_FILE", tmp_path / "no.env")
    monkeypatch.setenv("IDS_DB_FILE", str(tmp_path / "ids.db"))
    monkeypatch.setenv("IDS_ALERT_RETENTION", "1")
    monkeypatch.setenv("IDS_ALERT_ARCHIVE_DIR", str(tmp_path / "archive"))
    settings = get_settings()
    setup_database(settings)
    # 6 November 2026, 11:40 PKT.
    start_ms = 1793947200000

    def add(*numbers):
        conn = connect_database(settings.db_file)
        insert_alert_batch(conn, [
            {
                "engine": "snort",
                "event_ts_utc": start_ms + number,
                "msg": f"alert {number}",
                "event_hash": f"hash-{number}",
            }
            for number in numbers
        ])
        conn.close()

    def stored():
        conn = connect_database(settings.db_file)
        try:
            return [row[0] for row in conn.execute("SELECT msg FROM alerts ORDER BY id")]
        finally:
            conn.close()

    def archived():
        path = tmp_path / "archive" / "days" / "2026-11-06.jsonl.gz"
        with gzip.open(path, "rt", encoding="utf-8") as file:
            return [json.loads(line)["msg"] for line in file]

    add(1, 2, 3)
    # Due: the last run was an hour ago.
    run_periodic_retention(settings, time.monotonic() - 3600)
    assert stored() == ["alert 3"]
    assert archived() == ["alert 1", "alert 2"]

    monkeypatch.setenv("IDS_ALERT_ARCHIVE_DAYS", "0")
    settings = get_settings()
    add(4, 5)
    run_periodic_retention(settings, time.monotonic() - 3600)
    assert stored() == ["alert 5"]
    assert archived() == ["alert 1", "alert 2"]


def test_the_journal_gets_one_line_a_minute_of_the_alerts_stored(monkeypatch, tmp_path):
    monkeypatch.setattr("ids.config.ENV_FILE", tmp_path / "no.env")
    monkeypatch.setenv("IDS_DB_FILE", str(tmp_path / "ids.db"))
    monkeypatch.setenv("IDS_STATE_FILE", str(tmp_path / "state.json"))
    for engine, name in (("SNORT_ALERT", "alert_json.txt"), ("SURICATA_EVE", "eve.json")):
        (tmp_path / name).write_text("")
        monkeypatch.setenv(f"IDS_{engine}_FILE", str(tmp_path / name))
    settings = get_settings()
    setup_database(settings)
    tailers = build_tailers(settings, start_at_end=False)
    pending = PendingBatch()
    for number, engine in enumerate(("snort", "suricata", "suricata")):
        pending.rows.append({"engine": engine, "event_ts_utc": 1793947200000 + number, "event_hash": f"hash-{number}"})
    pending.record_position("suricata", (tmp_path / "eve.json").stat().st_ino, 0)

    written = flush_pending(settings, pending, tailers)

    assert written == {"snort": 1, "suricata": 2}
    assert stored_summary(written, settings) == "[STORED] 3 alerts in the last minute: snort 1, suricata 2"
    assert stored_summary(Counter(), settings) == "[STORED] 0 alerts in the last minute: snort 0, suricata 0"
