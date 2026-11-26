"""Snort's own record of each TLS connection, to check alerts against.

Snort's extractor (deploy/snort/snort.lua) writes a JSON line for every TLS
connection it sees: the client and server, the site the client asked for
(SNI), the TLS version, cipher and curve, and the certificate's subject and
issuer (TLS 1.2 only: TLS 1.3 encrypts the certificate). The collector
stores each line here (``connection``, ``record_connections``), and the
dashboard finds the one on an alert's connection (``on_flow``) to check the
site Suricata named, or to name the site when Suricata's alert has no TLS
details (a Snort alert, a lone reset, a stream event).

Snort gives no client fingerprint (JA3 or JA4) and, without a QUIC
inspector, no QUIC connections: those stay Suricata's
(ids/tls_fingerprints.py).
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Mapping
from typing import Any

from ids.tls_fingerprints import address

TABLES = (
    """
    CREATE TABLE IF NOT EXISTS snort_tls (
        time_ms INTEGER NOT NULL,
        client TEXT NOT NULL,
        client_port INTEGER,
        server TEXT NOT NULL,
        server_port INTEGER,
        site TEXT,
        version TEXT,
        cipher TEXT,
        curve TEXT,
        subject TEXT,
        issuer TEXT,
        record TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_snort_tls_flow ON snort_tls(server, server_port, client, client_port, time_ms)",
    "CREATE INDEX IF NOT EXISTS idx_snort_tls_time ON snort_tls(time_ms)",
)
# How long before an alert its connection's TLS handshake may have been
# (a connection can stay open for hours), and how long after (the alert
# can come from a packet before the handshake was complete).
BEFORE_MS = 24 * 3600 * 1000
AFTER_MS = 60 * 1000
# Kept a day longer than the oldest stored alert, for its connection.
KEEP_BEFORE_ALERTS_MS = BEFORE_MS
_FIELDS = ("site", "version", "cipher", "curve", "subject", "issuer")


def create_tables(conn: sqlite3.Connection) -> None:
    for statement in TABLES:
        conn.execute(statement)


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _port(value: Any) -> int | None:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 0 <= port <= 65535 else None


def _time_ms(value: Any) -> int | None:
    """The extractor's ``ts``: microseconds (time = 'unix_us'), or seconds
    with a fraction (its default, 'unix')."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return int(value // 1000) if isinstance(value, int) and value > 10**14 else int(value * 1000)


def connection(event: Mapping[str, Any]) -> dict[str, Any] | None:
    """One extractor line as stored, or None for a line that isn't a TLS
    connection's."""
    client = address(event.get("id.orig_h"))
    server = address(event.get("id.resp_h"))
    time_ms = _time_ms(event.get("ts"))
    if client is None or server is None or time_ms is None:
        return None
    site = _text(event.get("server_name"))
    return {
        "time_ms": time_ms,
        "client": client,
        "client_port": _port(event.get("id.orig_p")),
        "server": server,
        "server_port": _port(event.get("id.resp_p")),
        "site": site.lower().rstrip(".") if site else None,
        "version": _text(event.get("version")),
        "cipher": _text(event.get("cipher")),
        "curve": _text(event.get("curve")),
        "subject": _text(event.get("subject")),
        "issuer": _text(event.get("issuer")),
        "record": json.dumps(dict(event), sort_keys=True),
    }


def record_connections(conn: sqlite3.Connection, connections: Iterable[Mapping[str, Any]]) -> int:
    """Adds the connections to ``snort_tls`` (the caller commits); how many."""
    rows = [
        (
            item["time_ms"], item["client"], item["client_port"], item["server"], item["server_port"],
            *(item[name] for name in _FIELDS), item["record"],
        )
        for item in connections
    ]
    conn.executemany(f"INSERT INTO snort_tls VALUES ({', '.join('?' * 12)})", rows)
    return len(rows)


def prune(conn: sqlite3.Connection) -> int:
    """Removes the connections from before any stored alert's (the caller
    commits); how many."""
    oldest = conn.execute("SELECT MIN(event_ts_utc) FROM alerts").fetchone()[0]
    if oldest is None:
        return 0
    return conn.execute(
        "DELETE FROM snort_tls WHERE time_ms < ?", (int(oldest) - KEEP_BEFORE_ALERTS_MS,)
    ).rowcount


def on_flow(
    conn: sqlite3.Connection,
    source: Any,
    source_port: Any,
    destination: Any,
    destination_port: Any,
    time_ms: Any,
) -> dict[str, Any] | None:
    """Snort's record of the TLS connection an alert was on: the one with
    the alert's addresses and ports, either way round, nearest before the
    alert (up to a day), or else the first in the minute after it; None
    when Snort saw none."""
    ends = [(address(source), _port(source_port)), (address(destination), _port(destination_port))]
    if None in (ends[0][0], ends[1][0], ends[0][1], ends[1][1]) or time_ms is None:
        return None
    if not conn.execute(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'snort_tls'"
    ).fetchone()[0]:
        return None
    row = conn.execute(
        f"""
        SELECT time_ms, client, client_port, server, server_port, {', '.join(_FIELDS)}, record
        FROM snort_tls
        WHERE ((server = ? AND server_port = ? AND client = ? AND client_port = ?)
            OR (server = ? AND server_port = ? AND client = ? AND client_port = ?))
          AND time_ms BETWEEN ? AND ?
        ORDER BY time_ms > ?, ABS(time_ms - ?)
        LIMIT 1
        """,
        (
            *ends[1], *ends[0], *ends[0], *ends[1],
            int(time_ms) - BEFORE_MS, int(time_ms) + AFTER_MS, int(time_ms), int(time_ms),
        ),
    ).fetchone()
    if row is None:
        return None
    found = dict(zip(("time_ms", "client", "client_port", "server", "server_port", *_FIELDS), row))
    try:
        found["record"] = json.loads(row[-1])
    except ValueError:
        found["record"] = row[-1]
    return found


def checked(
    names: Mapping[str, Any] | None, snort: Mapping[str, Any] | None, intel: Any,
) -> dict[str, Any] | None:
    """``names`` (ids/tls_fingerprints.py ``connection_names``, from a
    Suricata alert's TLS details) checked against ``snort``, Snort's record
    of the same connection (``on_flow``); ``intel`` names the services
    (tls_fingerprints.Intel). When both name the same site, ``seen_by`` is
    both engines; when they differ, Snort's site is ``snort_site`` (with
    its service); when only Snort names one, the site is Snort's. None
    when neither names a site and there were no names."""
    site = (names or {}).get("site")
    snort_site = (snort or {}).get("site")
    if site:
        if not snort_site:
            return dict(names or {})
        if snort_site == site.lower().rstrip("."):
            return {**(names or {}), "seen_by": ["suricata", "snort"]}
        return {
            **(names or {}),
            "seen_by": ["suricata"],
            "snort_site": snort_site,
            "snort_service": ", ".join(intel.services(snort_site)) or None,
        }
    if snort_site:
        return {
            "fingerprint": None,
            "program": None,
            **(names or {}),
            "site": snort_site,
            "service": ", ".join(intel.services(snort_site)) or None,
            "seen_by": ["snort"],
        }
    return dict(names) if names else None


def details(native: Mapping[str, Any] | None, snort: Mapping[str, Any] | None) -> dict[str, Any]:
    """How the connection is encrypted (``encryption``: version, cipher,
    curve) and the server's certificate (``certificate``: subject, issuer),
    each from whichever engine has it: a Suricata alert's ``tls`` details
    (``native``, which give no cipher) or Snort's record (``snort``)."""
    tls = (native or {}).get("tls") if isinstance((native or {}).get("tls"), Mapping) else {}
    snort = snort or {}
    encryption = {
        "version": _text(tls.get("version")) or snort.get("version"),
        "cipher": snort.get("cipher"),
        "curve": snort.get("curve"),
    }
    certificate = {
        "subject": _text(tls.get("subject")) or snort.get("subject"),
        "issuer": _text(tls.get("issuerdn")) or snort.get("issuer"),
    }
    found: dict[str, Any] = {}
    if any(encryption.values()):
        found["encryption"] = encryption
    if any(certificate.values()):
        found["certificate"] = certificate
    return found
