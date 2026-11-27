"""Our own TLS client fingerprints, to check Suricata's.

Suricata works out each TLS client's JA3 and JA4 from its Client Hello
(ids/tls_fingerprints.py). This module works them out again, separately,
from the packets themselves: Suricata keeps the packets of every flow it
alerted on (pcap-log, deploy/apply-suricata-settings.sh), and ``hellos``
reads those files, finds each Client Hello sent over TCP (put back together
when it spans several segments) and computes its JA3 and JA4 here, with
nothing but the Python standard library. The collector stores them
(``record_hellos``) and the dashboard compares them with the fingerprints
on the same connection's Suricata alerts (``on_flow``, ``compared``).

QUIC's Client Hello travels encrypted (with keys any listener can derive,
but that takes AES and HKDF the standard library lacks), so QUIC
fingerprints are not checked.

JA3: https://github.com/salesforce/ja3; JA4: FoxIO's JA4 specification
(https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md).
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import struct
from collections.abc import Iterable, Iterator, Mapping
from pathlib import Path
from typing import Any, BinaryIO

from ids.tls_fingerprints import address

TABLES = (
    """
    CREATE TABLE IF NOT EXISTS tls_hellos (
        time_ms INTEGER NOT NULL,
        client TEXT NOT NULL,
        client_port INTEGER NOT NULL,
        server TEXT NOT NULL,
        server_port INTEGER NOT NULL,
        site TEXT,
        ja3 TEXT NOT NULL,
        ja3_string TEXT NOT NULL,
        ja4 TEXT NOT NULL,
        ja4_r TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_tls_hellos_flow ON tls_hellos(server, server_port, client, client_port, time_ms)",
    "CREATE INDEX IF NOT EXISTS idx_tls_hellos_time ON tls_hellos(time_ms)",
    # How far each of Suricata's pcap files has been read.
    """
    CREATE TABLE IF NOT EXISTS tls_hello_files (
        path TEXT PRIMARY KEY,
        offset INTEGER NOT NULL
    )
    """,
)
# Read at most this much of the pcap files at a time, so the collector
# keeps up with the engines' logs while it catches up.
POLL_BYTES = 64 * 1024 * 1024
# How long before an alert its connection's Client Hello may have been,
# and how long after (as ids/snort_tls.py).
BEFORE_MS = 24 * 3600 * 1000
AFTER_MS = 60 * 1000
# Kept a day longer than the oldest stored alert, for its connection.
KEEP_BEFORE_ALERTS_MS = BEFORE_MS
# A Client Hello longer than this isn't put back together (they are 0.5-2 KB;
# TLS allows 16 KB a record).
MAX_HELLO = 16 * 1024 + 5
# A flow whose Client Hello is still incomplete after this many segments is
# given up on.
MAX_PARTS = 16
# How many flows' Client Hellos are remembered, to tell a copy written the
# other way round (a source of 443 to the client's port, as Suricata's
# pcap files sometimes hold) from a new one.
MAX_DONE = 50_000

# GREASE values (RFC 8701): 0x0a0a, 0x1a1a ... 0xfafa, left out of both.
_GREASE = {(value << 8) | value for value in range(0x0A, 0x100, 0x10)}
_VERSIONS = {
    0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3", 0x0002: "s2",
    0xFEFF: "d1", 0xFEFD: "d2", 0xFEFC: "d3",
}
_SNI, _GROUPS, _POINT_FORMATS, _SIGNATURES, _ALPN, _VERSIONS_EXT = 0x0000, 0x000A, 0x000B, 0x000D, 0x0010, 0x002B


def create_tables(conn: sqlite3.Connection) -> None:
    for statement in TABLES:
        conn.execute(statement)


class _Reader:
    """Reads a Client Hello's fields, failing with ValueError when short."""

    def __init__(self, data: bytes) -> None:
        self.data, self.at = data, 0

    def take(self, size: int) -> bytes:
        if size < 0 or self.at + size > len(self.data):
            raise ValueError("short")
        part = self.data[self.at:self.at + size]
        self.at += size
        return part

    def number(self, size: int) -> int:
        return int.from_bytes(self.take(size), "big")

    def block(self, length_size: int) -> bytes:
        return self.take(self.number(length_size))


def _numbers(data: bytes, size: int = 2) -> list[int]:
    return [int.from_bytes(data[i:i + size], "big") for i in range(0, len(data) - size + 1, size)]


def parse_client_hello(record: bytes) -> dict[str, Any] | None:
    """The fields of a TLS record holding a Client Hello (from its 5-byte
    record header on), or None when it isn't one."""
    try:
        reader = _Reader(record)
        if reader.number(1) != 0x16:
            return None
        reader.take(2)
        body = _Reader(reader.block(2))
        if body.number(1) != 0x01:
            return None
        hello = _Reader(body.take(body.number(3)))
        version = hello.number(2)
        hello.take(32)
        hello.block(1)
        ciphers = _numbers(hello.block(2))
        hello.block(1)
        extensions: list[tuple[int, bytes]] = []
        if hello.at < len(hello.data):
            listed = _Reader(hello.block(2))
            while listed.at < len(listed.data):
                kind = listed.number(2)
                extensions.append((kind, listed.block(2)))
    except ValueError:
        return None
    found: dict[str, Any] = {
        "version": version, "ciphers": ciphers, "extensions": [kind for kind, _ in extensions],
        "groups": [], "point_formats": [], "signatures": [], "alpn": [], "versions": [], "site": None,
    }
    for kind, data in extensions:
        try:
            part = _Reader(data)
            if kind == _SNI:
                names = _Reader(part.block(2))
                while names.at < len(names.data):
                    name_type, name = names.number(1), names.block(2)
                    if name_type == 0:
                        found["site"] = name.decode("ascii", "replace").lower().rstrip(".")
                        break
            elif kind == _GROUPS:
                found["groups"] = _numbers(part.block(2))
            elif kind == _POINT_FORMATS:
                found["point_formats"] = list(part.block(1))
            elif kind == _SIGNATURES:
                found["signatures"] = _numbers(part.block(2))
            elif kind == _ALPN:
                names = _Reader(part.block(2))
                while names.at < len(names.data):
                    found["alpn"].append(names.block(1))
            elif kind == _VERSIONS_EXT:
                found["versions"] = _numbers(part.block(1))
        except ValueError:
            continue
    return found


def ja3(hello: Mapping[str, Any]) -> tuple[str, str]:
    """The JA3 string and its MD5: the version, ciphers, extensions, groups
    and point formats in the order sent, in decimal, GREASE left out."""
    def joined(values: Iterable[int]) -> str:
        return "-".join(str(value) for value in values if value not in _GREASE)

    text = ",".join((
        str(hello["version"]), joined(hello["ciphers"]), joined(hello["extensions"]),
        joined(hello["groups"]), joined(hello["point_formats"]),
    ))
    return text, hashlib.md5(text.encode()).hexdigest()


def _alpn_code(alpn: list[bytes]) -> str:
    if not alpn or not alpn[0]:
        return "00"
    first = alpn[0]
    start, end = chr(first[0]), chr(first[-1])
    if start.isascii() and start.isalnum() and end.isascii() and end.isalnum():
        return start + end
    return f"{first[0]:02x}"[0] + f"{first[-1]:02x}"[-1]


def _hash12(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:12] if text else "000000000000"


def ja4(hello: Mapping[str, Any], protocol: str = "t") -> tuple[str, str]:
    """The JA4 and its raw form (JA4_r): protocol, version, SNI or not,
    cipher and extension counts and ALPN; the sorted ciphers' hash; the
    sorted extensions' (without SNI and ALPN) and the signature
    algorithms' hash."""
    ciphers = [value for value in hello["ciphers"] if value not in _GREASE]
    extensions = [value for value in hello["extensions"] if value not in _GREASE]
    # The highest version offered that is one (Facebook's apps also offer
    # 0xfb1a, their own), else the Client Hello's own.
    versions = [value for value in hello["versions"] if value in _VERSIONS]
    version = _VERSIONS.get(max(versions) if versions else hello["version"], "00")
    head = (
        f"{protocol}{version}{'d' if _SNI in extensions else 'i'}"
        f"{min(len(ciphers), 99):02d}{min(len(extensions), 99):02d}{_alpn_code(hello['alpn'])}"
    )
    cipher_text = ",".join(f"{value:04x}" for value in sorted(ciphers))
    extension_text = ",".join(f"{value:04x}" for value in sorted(extensions) if value not in (_SNI, _ALPN))
    signatures = ",".join(f"{value:04x}" for value in hello["signatures"] if value not in _GREASE)
    if signatures:
        extension_text = f"{extension_text}_{signatures}"
    return (
        f"{head}_{_hash12(cipher_text)}_{_hash12(extension_text)}",
        f"{head}_{cipher_text}_{extension_text}",
    )


# Reading Suricata's pcap files.

_PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000), b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000), b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}
_ETHERNET, _LINUX_SLL, _RAW = 1, 113, 101


def _packets(stream: BinaryIO, start: int) -> Iterator[tuple[int, int, bytes]]:
    """(time in ms, offset after the packet, frame) for each whole packet
    of a pcap file from ``start`` (0: its beginning); stops at a packet not
    yet written whole."""
    header = stream.read(24)
    if len(header) < 24 or header[:4] not in _PCAP_MAGIC:
        return
    order, per_second = _PCAP_MAGIC[header[:4]]
    link = struct.unpack(order + "I", header[20:24])[0] & 0x0FFFFFFF
    stream.seek(max(start, 24))
    while True:
        record = stream.read(16)
        if len(record) < 16:
            return
        seconds, fraction, captured, _ = struct.unpack(order + "IIII", record)
        frame = stream.read(captured)
        if len(frame) < captured:
            return
        yield seconds * 1000 + fraction * 1000 // per_second, stream.tell(), _payload_frame(link, frame)


def _payload_frame(link: int, frame: bytes) -> bytes:
    """The IP packet in a frame of the file's link type, or b""."""
    if link == _RAW:
        return frame
    if link == _LINUX_SLL:
        kind, at = frame[14:16], 16
    elif link == _ETHERNET:
        kind, at = frame[12:14], 14
    else:
        return b""
    while kind in (b"\x81\x00", b"\x88\xa8") and len(frame) >= at + 4:
        kind, at = frame[at + 2:at + 4], at + 4
    return frame[at:] if kind in (b"\x08\x00", b"\x86\xdd") else b""


def _tcp(packet: bytes) -> tuple[str, str, int, int, int, bytes] | None:
    """(source, destination, source port, destination port, sequence
    number, payload) of a TCP packet, or None."""
    if not packet:
        return None
    version = packet[0] >> 4
    if version == 4 and len(packet) >= 20:
        header = (packet[0] & 0x0F) * 4
        total = int.from_bytes(packet[2:4], "big")
        fragment = int.from_bytes(packet[6:8], "big") & 0x3FFF
        if packet[9] != 6 or fragment:
            return None
        source, destination = packet[12:16], packet[16:20]
        segment = packet[header:total or len(packet)]
    elif version == 6 and len(packet) >= 40:
        next_header, at = packet[6], 40
        # Hop-by-hop, routing and destination options come before TCP.
        while next_header in (0, 43, 60) and len(packet) >= at + 8:
            next_header, at = packet[at], at + (packet[at + 1] + 1) * 8
        if next_header != 6:
            return None
        source, destination = packet[8:24], packet[24:40]
        segment = packet[at:40 + int.from_bytes(packet[4:6], "big")]
    else:
        return None
    if len(segment) < 20:
        return None
    offset = (segment[12] >> 4) * 4
    return (
        address(_ip_text(source)) or "", address(_ip_text(destination)) or "",
        int.from_bytes(segment[0:2], "big"), int.from_bytes(segment[2:4], "big"),
        int.from_bytes(segment[4:8], "big"), segment[offset:],
    )


def _ip_text(raw: bytes) -> str:
    import ipaddress

    return str(ipaddress.ip_address(raw))


def _starts_hello(payload: bytes) -> bool:
    return len(payload) >= 6 and payload[0] == 0x16 and payload[1] == 0x03 and payload[5] == 0x01


class HelloFinder:
    """Puts each TCP flow's Client Hello back together from its segments,
    as the packets come, and gives the hellos it completes."""

    def __init__(self) -> None:
        # Flow -> (time of its first segment, the next sequence number,
        # the bytes so far, the segments so far).
        self.pending: dict[tuple[str, int, str, int], tuple[int, int, bytes, int]] = {}
        # The flows whose Client Hello was read, the oldest first.
        self.done: dict[tuple[str, int, str, int], None] = {}

    def add(self, time_ms: int, packet: bytes) -> dict[str, Any] | None:
        parts = _tcp(packet)
        if parts is None:
            return None
        source, destination, source_port, destination_port, sequence, payload = parts
        if not payload or not source or not destination:
            return None
        flow = (source, source_port, destination, destination_port)
        if (destination, destination_port, source, source_port) in self.done:
            # The client's Client Hello again, with the addresses swapped.
            return None
        waiting = self.pending.get(flow)
        if waiting is None:
            if not _starts_hello(payload):
                return None
            waiting = (time_ms, sequence, b"", 0)
        first, expected, data, count = waiting
        if sequence != expected:
            # A segment sent again, or out of order: wait for the next one.
            if (sequence - expected) & 0xFFFFFFFF > 0x7FFFFFFF:
                return None
            del self.pending[flow]
            return None
        data += payload
        expected = (expected + len(payload)) & 0xFFFFFFFF
        count += 1
        needed = 5 + int.from_bytes(data[3:5], "big") if len(data) >= 5 else MAX_HELLO
        if len(data) < needed:
            if needed > MAX_HELLO or count >= MAX_PARTS:
                self.pending.pop(flow, None)
            else:
                self.pending[flow] = (first, expected, data, count)
            return None
        self.pending.pop(flow, None)
        hello = parse_client_hello(data[:needed])
        if hello is None:
            return None
        self.done[flow] = None
        if len(self.done) > MAX_DONE:
            del self.done[next(iter(self.done))]
        text, md5 = ja3(hello)
        fingerprint, raw = ja4(hello)
        return {
            "time_ms": first, "client": source, "client_port": source_port,
            "server": destination, "server_port": destination_port, "site": hello["site"],
            "ja3": md5, "ja3_string": text, "ja4": fingerprint, "ja4_r": raw,
        }


def hellos(
    path: Path | str, start: int = 0, finder: HelloFinder | None = None, budget: int | None = None,
) -> tuple[list[dict[str, Any]], int]:
    """The Client Hellos in a pcap file from byte ``start`` (0: the
    beginning), reading about ``budget`` bytes at most, and the byte to
    read on from next time."""
    finder = finder or HelloFinder()
    found: list[dict[str, Any]] = []
    end = max(start, 24)
    with open(path, "rb") as stream:
        for time_ms, end, packet in _packets(stream, start):
            hello = finder.add(time_ms, packet)
            if hello:
                found.append(hello)
            if budget is not None and end - start >= budget:
                break
    return found, end


def pcap_files(base: Path | str) -> list[Path]:
    """Suricata's pcap files, oldest first: ``log.pcap.<seconds>`` beside
    ``base`` (its pcap-log filename), or ``base`` itself."""
    base = Path(base)
    found = []
    for path in base.parent.glob(base.name + ".*"):
        suffix = path.name[len(base.name) + 1:]
        if suffix.isdigit():
            found.append((int(suffix), path))
    found.sort()
    files = [path for _, path in found]
    return files or ([base] if base.is_file() else [])


class PcapReader:
    """Reads the Client Hellos Suricata's pcap files gain, for the
    collector: ``poll`` stores the new ones with how far each file has been
    read, in one transaction."""

    def __init__(self, base: Path | str) -> None:
        self.base = Path(base)
        self.finder = HelloFinder()

    def poll(self, conn: sqlite3.Connection) -> int:
        """Reads on in the files (up to POLL_BYTES), stores the Client
        Hellos found and commits; how many."""
        files = pcap_files(self.base)
        read = dict(conn.execute("SELECT path, offset FROM tls_hello_files").fetchall())
        found: list[dict[str, Any]] = []
        budget = POLL_BYTES
        for path in files:
            if budget <= 0:
                break
            start = int(read.get(str(path), 0))
            size = path.stat().st_size
            if size < start:
                # The file was started again: from its beginning.
                start = 0
            if size <= max(start, 24):
                continue
            items, end = hellos(path, start, self.finder, budget)
            budget -= end - max(start, 24)
            found += items
            conn.execute(
                "INSERT INTO tls_hello_files (path, offset) VALUES (?, ?) "
                "ON CONFLICT(path) DO UPDATE SET offset = excluded.offset",
                (str(path), end),
            )
        # The files Suricata has removed (it keeps the last few).
        kept = {str(path) for path in files}
        conn.executemany(
            "DELETE FROM tls_hello_files WHERE path = ?", [(path,) for path in read if path not in kept]
        )
        record_hellos(conn, found)
        conn.commit()
        return len(found)


_COLUMNS = ("time_ms", "client", "client_port", "server", "server_port", "site", "ja3", "ja3_string", "ja4", "ja4_r")


def record_hellos(conn: sqlite3.Connection, items: Iterable[Mapping[str, Any]]) -> int:
    """Adds Client Hellos to ``tls_hellos`` (the caller commits); how many."""
    rows = [tuple(item[name] for name in _COLUMNS) for item in items]
    conn.executemany(f"INSERT INTO tls_hellos VALUES ({', '.join('?' * len(_COLUMNS))})", rows)
    return len(rows)


def prune(conn: sqlite3.Connection) -> int:
    """Removes the Client Hellos from before any stored alert's (the
    caller commits); how many."""
    oldest = conn.execute("SELECT MIN(event_ts_utc) FROM alerts").fetchone()[0]
    if oldest is None:
        return 0
    return conn.execute(
        "DELETE FROM tls_hellos WHERE time_ms < ?", (int(oldest) - KEEP_BEFORE_ALERTS_MS,)
    ).rowcount


def _port(value: Any) -> int | None:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 0 <= port <= 65535 else None


def on_flow(
    conn: sqlite3.Connection, source: Any, source_port: Any, destination: Any, destination_port: Any, time_ms: Any,
) -> dict[str, Any] | None:
    """The Client Hello of the connection an alert was on, worked out here
    from the packet: the one with the alert's addresses and ports, either
    way round, nearest before the alert (up to a day), or else the first in
    the minute after it; None when none was read."""
    ends = [(address(source), _port(source_port)), (address(destination), _port(destination_port))]
    if None in (ends[0][0], ends[1][0], ends[0][1], ends[1][1]) or time_ms is None:
        return None
    if not conn.execute(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'tls_hellos'"
    ).fetchone()[0]:
        return None
    row = conn.execute(
        f"""
        SELECT {', '.join(_COLUMNS)}
        FROM tls_hellos
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
    return dict(zip(_COLUMNS, row)) if row else None


# A JA4 with no ciphers: what Suricata puts on an alert raised before the
# Client Hello was all there (t00i000000_e3b0c44298fc_...), as no client
# sends a Client Hello without ciphers.
_NO_CIPHERS = "_e3b0c44298fc_"


def _text(value: Any) -> str | None:
    text = str(value).strip() if value is not None else ""
    return text or None


def compared(
    native: Mapping[str, Any] | None, hello: Mapping[str, Any] | None,
) -> tuple[Mapping[str, Any] | None, dict[str, Any] | None]:
    """A Suricata alert's own TLS details (``native``, None for a Snort
    alert) checked against the Client Hello read from the packet
    (``hello``, ``on_flow``). The check (None without a Client Hello):

    - ``same``: Suricata's JA4 and JA3 are the ones worked out here;
    - ``differs``: Suricata gave others (``suricata_ja4``, ``suricata_ja3``);
    - ``added``: the alert had none, or an incomplete one (raised before
      the Client Hello was all there), and gets the packet's.

    With ``added``, the details returned carry the packet's fingerprints,
    so the program is named by them (the site stays the engines' own: the
    packet's is ``site`` in the check); otherwise they are ``native`` as it
    was."""
    if not hello:
        return native, None
    tls = native.get("tls") if isinstance(native, Mapping) and isinstance(native.get("tls"), Mapping) else None
    theirs4 = _text((tls or {}).get("ja4"))
    ja3_part = (tls or {}).get("ja3")
    theirs3 = _text(ja3_part.get("hash")) if isinstance(ja3_part, Mapping) else None
    check: dict[str, Any] = {
        "ja4": hello["ja4"], "ja3": hello["ja3"], "ja4_r": hello["ja4_r"], "ja3_string": hello["ja3_string"],
        "site": hello["site"],
    }
    complete4 = theirs4 if theirs4 and _NO_CIPHERS not in theirs4 else None
    if complete4 or theirs3:
        same = (complete4 in (None, hello["ja4"])) and (theirs3 in (None, hello["ja3"]))
        check["result"] = "same" if same else "differs"
        if not same:
            check["suricata_ja4"], check["suricata_ja3"] = theirs4, theirs3
        return native, check
    check["result"] = "added"
    if theirs4:
        check["suricata_ja4"] = theirs4
    filled = dict(tls or {})
    filled["ja4"] = hello["ja4"]
    filled["ja3"] = {"hash": hello["ja3"], "string": hello["ja3_string"]}
    return {**(native or {}), "tls": filled}, check
