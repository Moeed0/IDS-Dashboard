"""
The hourly test alert: proof that capture, both engines' rules and the
collector work, end to end.

One ping goes out of the capture card to a machine on the lab network
(IDS_TEST_ALERT_TARGET, the router here). Linux's ping carries the bytes
0x10 to 0x1F, which each engine's own rules flag as a Unix ping: Snort's
1:366 "PROTOCOL-ICMP PING Unix" and 1:384 "PROTOCOL-ICMP PING", Suricata's
(ET Open) 1:2100366 "GPL ICMP PING *NIX" and 1:2100384 "GPL ICMP PING". The
echo request alone sets them off, so the target need not answer, only
exist (the ping waits for its address on the network). The test then waits
for the collector to store each engine's alert, and keeps the result in
.runtime/test_alert.json for the dashboard.

The ping's alerts are ordinary stored alerts (about 9 an hour: these and a
few others the same packets match), from this machine to the target.
"""

from __future__ import annotations

import json
import socket
import sqlite3
import subprocess
import time
from collections.abc import Callable, Sequence
from contextlib import closing
from pathlib import Path
from typing import Any

# The rules each engine's alert on the test ping may come from: (gid, sid).
PING_RULES: dict[str, tuple[tuple[int, int], ...]] = {
    "snort": ((1, 366), (1, 384)),
    "suricata": ((1, 2100366), (1, 2100384)),
}
RESULT_NAME = "test_alert.json"
# How long the engines and the collector get to store the ping's alerts.
WAIT_SECONDS = 90
# Alerts this much before the ping was sent still count: the engines stamp
# a packet with its capture time, which may run a little behind the clock
# read before the ping.
EARLY_MS = 5_000


def result_path(state_file: Path | str) -> Path:
    """Where the result is kept: beside the collector's state file."""
    return Path(state_file).with_name(RESULT_NAME)


def source_address(target: str) -> str:
    """This machine's address towards ``target``: the one its packets carry.
    (A UDP socket's connect only looks the route up; nothing is sent.)"""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.connect((target, 9))
        return probe.getsockname()[0]


def send_ping(target: str, interface: str) -> bool:
    """One ping to ``target`` out of ``interface``; whether it was answered
    (the test doesn't need an answer)."""
    done = subprocess.run(
        ["ping", "-c", "1", "-W", "2", "-I", interface, target],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return done.returncode == 0


def found_alerts(
    db_path: Path | str, engines: Sequence[str], source: str, target: str, since_ms: int,
) -> dict[str, dict[str, Any]]:
    """For each of the ``engines`` that stored one, its first alert on a
    test ping from ``source`` to ``target`` since ``since_ms``: its rule
    and time."""
    found: dict[str, dict[str, Any]] = {}
    with closing(sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=30)) as connection:
        for engine in engines:
            rules = PING_RULES.get(engine, ())
            if not rules:
                continue
            sids = ", ".join(str(sid) for _, sid in rules)
            row = connection.execute(
                f"""
                SELECT gid, sid, event_ts_utc FROM alerts
                WHERE sid IN ({sids}) AND gid = 1 AND engine = ?
                    AND event_ts_utc >= ? AND src_addr = ? AND dst_addr = ?
                ORDER BY event_ts_utc LIMIT 1
                """,
                (engine, since_ms, source, target),
            ).fetchone()
            if row is not None:
                found[engine] = {"rule": f"{row[0]}:{row[1]}", "time_ms": row[2]}
    return found


def run_test(
    db_path: Path | str,
    engines: Sequence[str],
    target: str,
    interface: str,
    result_file: Path | str,
    *,
    wait_seconds: float = WAIT_SECONDS,
    poll_seconds: float = 1,
    clock: Callable[[], float] = time.time,
    sleep: Callable[[float], None] = time.sleep,
    pinger: Callable[[str, str], bool] = send_ping,
    source: str | None = None,
) -> dict[str, Any]:
    """Sends the test ping and waits until each of the ``engines`` has its
    alert stored, or ``wait_seconds`` pass. Writes and returns the result:
    when it was sent, whether the target answered, and for each engine its
    alert (rule, time, and how many seconds after the ping it was stored)
    or None. ``ok`` is true when every engine's alert came."""
    source = source or source_address(target)
    sent_s = clock()
    answered = pinger(target, interface)
    sent_ms = int(sent_s * 1000)
    seen: dict[str, dict[str, Any]] = {}
    while True:
        for engine, alert in found_alerts(
            db_path, engines, source, target, sent_ms - EARLY_MS,
        ).items():
            if engine not in seen:
                seen[engine] = {**alert, "stored_after_s": round(clock() - sent_s, 1)}
        if len(seen) == len(engines) or clock() - sent_s >= wait_seconds:
            break
        sleep(poll_seconds)
    result = {
        "sent_ms": sent_ms,
        "source": source,
        "target": target,
        "answered": answered,
        "wait_seconds": wait_seconds,
        "engines": {engine: seen.get(engine) for engine in engines},
        "ok": all(engine in seen for engine in engines),
    }
    path = Path(result_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)
    return result


def read_result(result_file: Path | str | None) -> dict[str, Any] | None:
    """The last test's result; None when there is none (or it can't be
    read)."""
    if result_file is None:
        return None
    try:
        found = json.loads(Path(result_file).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return found if isinstance(found, dict) else None
