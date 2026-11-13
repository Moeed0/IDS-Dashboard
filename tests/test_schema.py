"""Tests for IDS SQLite schema initialization."""

import sqlite3

from ids.schema import ensure_schema


def test_ensure_schema_creates_correlation_lookup_index():
    conn = sqlite3.connect(":memory:")
    try:
        ensure_schema(conn)

        indexes = {
            row[1]
            for row in conn.execute("PRAGMA index_list('alerts')")
        }
        assert "idx_alerts_correlation_group_id" in indexes

        columns = [
            row[2]
            for row in conn.execute(
                "PRAGMA index_info('idx_alerts_correlation_group_id')"
            )
        ]
        assert columns == [
            "correlation_group_id",
            "community_id",
            "engine",
            "event_ts_utc",
        ]

        # Schema initialization should be safe to call repeatedly.
        ensure_schema(conn)
        indexes_after_second_call = {
            row[1]
            for row in conn.execute("PRAGMA index_list('alerts')")
        }
        assert "idx_alerts_correlation_group_id" in indexes_after_second_call
    finally:
        conn.close()


def test_ensure_schema_fills_the_app_of_older_snort_alerts_once():
    conn = sqlite3.connect(":memory:")
    try:
        # A database from before the app column: Snort's app_id is only in
        # each alert's raw JSON.
        conn.execute(
            "CREATE TABLE alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "engine TEXT, raw_json TEXT)"
        )
        conn.executemany(
            "INSERT INTO alerts (engine, raw_json) VALUES (?, ?)",
            [
                ("snort", '{"app_id": "IGMP", "msg": "x"}'),
                ("snort", '{"app_id": "", "msg": "x"}'),
                ("snort", '{"msg": "from before OpenAppID"}'),
                ("suricata", '{"app_id": "not Snort", "app_proto": "dns"}'),
            ],
        )

        ensure_schema(conn)

        assert [
            row[0] for row in conn.execute("SELECT app FROM alerts ORDER BY id")
        ] == ["IGMP", None, None, None]
        indexes = {row[1] for row in conn.execute("PRAGMA index_list('alerts')")}
        assert "idx_alerts_app" in indexes

        # Only when the column is new: a later start leaves the column as
        # the collector wrote it.
        conn.execute("UPDATE alerts SET app = 'kept' WHERE id = 1")
        ensure_schema(conn)
        assert conn.execute("SELECT app FROM alerts WHERE id = 1").fetchone()[0] == "kept"
    finally:
        conn.close()
