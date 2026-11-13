"""The hourly test alert (ids.test_alert): a ping, then each engine's alert."""

import json
import sqlite3

import pytest

from ids.config import test_alert_target as configured_target
from ids.dashboard_data import status
from ids.schema import ensure_schema
from ids.test_alert import read_result, result_path, run_test

SOURCE = "192.168.50.142"
TARGET = "192.168.50.1"
SENT_S = 1_794_569_180.0


def _database(path, rows):
    connection = sqlite3.connect(path)
    ensure_schema(connection)
    connection.executemany(
        "INSERT INTO alerts (engine, gid, sid, src_addr, dst_addr, event_ts_utc, event_hash) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        [(*row, f"hash{index}") for index, row in enumerate(rows)],
    )
    connection.commit()
    connection.close()


class Clock:
    """Starts at the ping and moves on as the test sleeps."""

    def __init__(self):
        self.now = SENT_S

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


def _run(tmp_path, db_path, pings):
    clock = Clock()
    result = run_test(
        db_path, ("snort", "suricata"), TARGET, "ens38", tmp_path / "test_alert.json",
        wait_seconds=10, poll_seconds=2, clock=clock, sleep=clock.sleep,
        pinger=lambda target, interface: pings.append((target, interface)) or True,
        source=SOURCE,
    )
    return result


def test_both_engines_alerting_on_the_ping_is_a_pass(tmp_path):
    db_path = tmp_path / "ids_live.db"
    sent_ms = int(SENT_S * 1000)
    _database(db_path, [
        ("snort", 1, 366, SOURCE, TARGET, sent_ms + 3),
        ("snort", 1, 384, SOURCE, TARGET, sent_ms + 3),
        ("suricata", 1, 2100366, SOURCE, TARGET, sent_ms + 4),
        # The router's reply, and an older test: neither counts.
        ("suricata", 1, 2100408, TARGET, SOURCE, sent_ms + 5),
        ("snort", 1, 366, SOURCE, TARGET, sent_ms - 3_600_000),
    ])
    pings = []

    result = _run(tmp_path, db_path, pings)

    assert pings == [(TARGET, "ens38")]
    assert result["ok"] is True
    assert result["engines"]["snort"] == {"rule": "1:366", "time_ms": sent_ms + 3, "stored_after_s": 0.0}
    assert result["engines"]["suricata"]["rule"] == "1:2100366"
    # Kept for the dashboard.
    assert read_result(tmp_path / "test_alert.json") == result


def test_an_engine_without_its_alert_fails_the_test_after_the_wait(tmp_path):
    db_path = tmp_path / "ids_live.db"
    _database(db_path, [("snort", 1, 384, SOURCE, TARGET, int(SENT_S * 1000) + 3)])

    result = _run(tmp_path, db_path, [])

    assert result["ok"] is False
    assert result["engines"]["snort"]["rule"] == "1:384"
    assert result["engines"]["suricata"] is None


def test_the_result_sits_beside_the_collectors_state_and_reaches_the_status(tmp_path):
    db_path = tmp_path / "ids_live.db"
    _database(db_path, [])
    state = tmp_path / ".runtime" / "ids_collector_state.json"
    assert result_path(state) == tmp_path / ".runtime" / "test_alert.json"
    result_path(state).parent.mkdir()
    result_path(state).write_text(json.dumps({"sent_ms": 1, "ok": True}))

    assert status(db_path, None, test_alert_file=result_path(state))["test_alert"] == {"sent_ms": 1, "ok": True}
    assert status(db_path, None)["test_alert"] is None
    assert read_result(tmp_path / "missing.json") is None


def test_the_target_is_an_ipv4_address_or_none(monkeypatch):
    monkeypatch.setenv("IDS_TEST_ALERT_TARGET", " 192.168.50.1 ")
    assert configured_target() == "192.168.50.1"
    monkeypatch.setenv("IDS_TEST_ALERT_TARGET", "")
    assert configured_target() is None
    monkeypatch.setenv("IDS_TEST_ALERT_TARGET", "router")
    with pytest.raises(ValueError, match="IPv4"):
        configured_target()
