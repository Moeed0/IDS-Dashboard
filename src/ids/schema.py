from __future__ import annotations

import sqlite3
from pathlib import Path

from ids.uids import assign_uids


ALERT_BASE_COLUMNS = {
    "timestamp": "TEXT",
    "rule": "TEXT",
    "classification": "TEXT",
    "priority": "INTEGER",
    "protocol": "TEXT",
    "src": "TEXT",
    "dst": "TEXT",
    "snort_rule": "TEXT",
    "iface": "TEXT",
    "service": "TEXT",
    "src_addr": "TEXT",
    "src_port": "INTEGER",
    "dst_addr": "TEXT",
    "dst_port": "INTEGER",
    "direction": "TEXT",
    "pkt_len": "INTEGER",
    "action": "TEXT",
    "msg": "TEXT",
    "gid": "INTEGER",
    "sid": "INTEGER",
    "rev": "INTEGER",
    "ttl": "INTEGER",
    "tos": "INTEGER",
    "tcp_flags": "TEXT",
    "icmp_type": "INTEGER",
    "icmp_code": "INTEGER",
    "client_pkts": "INTEGER",
    "client_bytes": "INTEGER",
    "server_pkts": "INTEGER",
    "server_bytes": "INTEGER",
    "raw_json": "TEXT",
}


ALERT_PHASE1_COLUMNS = {
    "engine": "TEXT",
    "event_ts_utc": "INTEGER",
    "flow_id": "TEXT",
    "community_id": "TEXT",
    "severity": "INTEGER",
    "rule_key": "TEXT",
    "correlation_group_id": "TEXT",
    "event_hash": "TEXT",
    # The alert's 6-character UID, as its number (ids/uids.py).
    "uid": "INTEGER",
}


PACKET_BASE_COLUMNS = {
    "timestamp": "TEXT",
    "src": "TEXT",
    "dst": "TEXT",
    "protocol": "TEXT",
    "src_port": "INTEGER",
    "dst_port": "INTEGER",
    "size": "INTEGER",
    "info": "TEXT",
    "tcp_flags": "TEXT",
}


PACKET_PHASE1_COLUMNS = {
    "event_ts_utc": "INTEGER",
}


def _table_columns(
    conn: sqlite3.Connection,
    table: str,
) -> set[str]:
    allowed_tables = {"alerts", "packets"}

    if table not in allowed_tables:
        raise ValueError(f"Unsupported table: {table}")

    rows = conn.execute(
        f"PRAGMA table_info({table})"
    ).fetchall()

    return {row[1] for row in rows}


def _create_tables(conn: sqlite3.Connection) -> None:
    # The alert archive's day files and their sizes, recorded in the
    # transaction that deletes their alerts (ids/alert_archive.py).
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS alert_archive_files (
            name TEXT PRIMARY KEY,
            size INTEGER NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src TEXT,
            dst TEXT,
            protocol TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            size INTEGER,
            info TEXT,
            tcp_flags TEXT,
            event_ts_utc INTEGER
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            rule TEXT,
            classification TEXT,
            priority INTEGER,
            protocol TEXT,
            src TEXT,
            dst TEXT,
            snort_rule TEXT,
            iface TEXT,
            service TEXT,
            src_addr TEXT,
            src_port INTEGER,
            dst_addr TEXT,
            dst_port INTEGER,
            direction TEXT,
            pkt_len INTEGER,
            action TEXT,
            msg TEXT,
            gid INTEGER,
            sid INTEGER,
            rev INTEGER,
            ttl INTEGER,
            tos INTEGER,
            tcp_flags TEXT,
            icmp_type INTEGER,
            icmp_code INTEGER,
            client_pkts INTEGER,
            client_bytes INTEGER,
            server_pkts INTEGER,
            server_bytes INTEGER,
            raw_json TEXT,
            engine TEXT,
            event_ts_utc INTEGER,
            flow_id TEXT,
            community_id TEXT,
            severity INTEGER,
            rule_key TEXT,
            correlation_group_id TEXT,
            event_hash TEXT,
            uid INTEGER
        )
        """
    )


def _add_missing_columns(
    conn: sqlite3.Connection,
    table: str,
    definitions: dict[str, str],
) -> None:
    existing = _table_columns(conn, table)

    for column, definition in definitions.items():
        if column not in existing:
            conn.execute(
                f"ALTER TABLE {table} "
                f"ADD COLUMN {column} {definition}"
            )


def _create_manual_correlation_guards(conn: sqlite3.Connection) -> None:
    """Permit only groups explicitly created by the manual correlation UI."""
    conn.execute(
        """
        CREATE TRIGGER IF NOT EXISTS trg_manual_group_insert
        BEFORE INSERT ON alerts
        WHEN NEW.correlation_group_id IS NOT NULL
          AND TRIM(NEW.correlation_group_id) != ''
          AND SUBSTR(NEW.correlation_group_id, 1, 7) != 'manual:'
        BEGIN
            SELECT RAISE(ABORT, 'Only manual correlation groups are allowed');
        END
        """
    )
    conn.execute(
        """
        CREATE TRIGGER IF NOT EXISTS trg_manual_group_update
        BEFORE UPDATE OF correlation_group_id ON alerts
        WHEN NEW.correlation_group_id IS NOT NULL
          AND TRIM(NEW.correlation_group_id) != ''
          AND SUBSTR(NEW.correlation_group_id, 1, 7) != 'manual:'
        BEGIN
            SELECT RAISE(ABORT, 'Only manual correlation groups are allowed');
        END
        """
    )


def _create_indexes(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_alerts_community_id
        ON alerts(community_id)
        """
    )

    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_alerts_event_ts_utc
        ON alerts(event_ts_utc)
        """
    )

    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_alerts_engine_event_ts
        ON alerts(engine, event_ts_utc)
        """
    )

    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_alerts_rule_key
        ON alerts(rule_key)
        """
    )

    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_alerts_flow_id
        ON alerts(flow_id)
        """
    )

    conn.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS ux_alerts_event_hash
        ON alerts(event_hash)
        """
    )

    conn.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS ux_alerts_uid
        ON alerts(uid)
        """
    )

    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_alerts_correlation_group_id
        ON alerts(
            correlation_group_id,
            community_id,
            engine,
            event_ts_utc
        )
        """
    )

    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_packets_event_ts_utc
        ON packets(event_ts_utc)
        """
    )


# The Alert Explorer's filters, each with the engine and time after it: a
# filter's alerts are counted, and come newest first, from its index alone,
# without reading the alerts (which are large) one by one. The expressions
# are the ones ids.dashboard_data's filters use.
FILTER_INDEXES = {
    "idx_alerts_severity": "MIN(4, MAX(1, COALESCE(severity, priority, 4))), engine, event_ts_utc",
    "idx_alerts_protocol": "lower(protocol), engine, event_ts_utc",
    "idx_alerts_class": "lower(classification), engine, event_ts_utc",
    "idx_alerts_service": "lower(service), engine, event_ts_utc",
    "idx_alerts_sid": "sid, gid, rev, engine, event_ts_utc",
    "idx_alerts_src_addr": "src_addr, engine, event_ts_utc",
    "idx_alerts_dst_addr": "dst_addr, engine, event_ts_utc",
    "idx_alerts_src_port": "src_port, engine, event_ts_utc",
    "idx_alerts_dst_port": "dst_port, engine, event_ts_utc",
}


def _create_filter_indexes(conn: sqlite3.Connection) -> None:
    for name, columns in FILTER_INDEXES.items():
        conn.execute(f"CREATE INDEX IF NOT EXISTS {name} ON alerts({columns})")


def ensure_schema(conn: sqlite3.Connection, uid_mark: Path | None = None) -> None:
    """Creates or updates the tables and indexes, and gives the alerts
    stored before UIDs theirs (ids/uids.py, ``uid_mark`` its mark file)."""
    _create_tables(conn)

    _add_missing_columns(
        conn,
        "alerts",
        ALERT_BASE_COLUMNS,
    )

    _add_missing_columns(
        conn,
        "alerts",
        ALERT_PHASE1_COLUMNS,
    )

    _add_missing_columns(
        conn,
        "packets",
        PACKET_BASE_COLUMNS,
    )

    _add_missing_columns(
        conn,
        "packets",
        PACKET_PHASE1_COLUMNS,
    )

    _create_indexes(conn)
    _create_filter_indexes(conn)
    # UIDs for the alerts stored before them (after the indexes, which
    # assign_uids looks them up through).
    assign_uids(conn, uid_mark)
    _create_manual_correlation_guards(conn)

    conn.commit()
