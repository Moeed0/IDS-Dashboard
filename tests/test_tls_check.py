from __future__ import annotations

import sqlite3
import struct

from ids.db import insert_alert_batch
from ids.live_normalizer import normalize_suricata
from ids.tls_check import (
    HelloFinder,
    PcapReader,
    compared,
    hellos,
    ja3,
    ja4,
    on_flow,
    parse_client_hello,
    pcap_files,
    prune,
)
from ids.tls_fingerprints import fingerprint_list, record_handshakes
from test_tls_fingerprints import _database

# FoxIO's JA4 example (Chrome): t13d1516h2_8daaf6152771_e5627efa2ab1.
CIPHERS = [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013, 0xC014, 0x009C,
           0x009D, 0x002F, 0x0035]
EXTENSIONS = [0x0000, 0x0017, 0xFF01, 0x000A, 0x000B, 0x0023, 0x0010, 0x0005, 0x000D, 0x0012, 0x0033, 0x002D,
              0x002B, 0x001B, 0x0015, 0x4469]
SIGNATURES = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]
GROUPS = [0x001D, 0x0017, 0x0018]
GREASE = 0x3A3A


def _u16(value: int) -> bytes:
    return value.to_bytes(2, "big")


def _block(data: bytes, size: int = 2) -> bytes:
    return len(data).to_bytes(size, "big") + data


def client_hello(site: str = "www.example.com", padding: int = 0) -> bytes:
    """A TLS record holding a Client Hello as Chrome sends one, GREASE
    first, with ``padding`` bytes more (to span several segments)."""
    bodies = {
        0x0000: _block(b"\x00" + _block(site.encode())),
        0x000A: _block(b"".join(_u16(group) for group in [GREASE, *GROUPS])),
        0x000B: _block(b"\x00", 1),
        0x000D: _block(b"".join(_u16(value) for value in SIGNATURES)),
        0x0010: _block(_block(b"h2", 1) + _block(b"http/1.1", 1)),
        0x002B: _block(b"".join(_u16(value) for value in [GREASE, 0x0304, 0x0303]), 1),
        0x0015: b"\x00" * padding,
    }
    extensions = b"".join(
        _u16(kind) + _block(bodies.get(kind, b"")) for kind in [GREASE, *EXTENSIONS]
    )
    hello = (
        _u16(0x0303) + b"\x11" * 32 + _block(b"\x22" * 32, 1)
        + _block(b"".join(_u16(value) for value in [GREASE, *CIPHERS])) + _block(b"\x00", 1)
        + _block(extensions)
    )
    handshake = b"\x01" + len(hello).to_bytes(3, "big") + hello
    return b"\x16\x03\x01" + _block(handshake)


def test_ja3_and_ja4_of_a_client_hello():
    hello = parse_client_hello(client_hello())

    assert hello["site"] == "www.example.com"
    assert [name.decode() for name in hello["alpn"]] == ["h2", "http/1.1"]
    fingerprint, raw = ja4(hello)
    assert fingerprint == "t13d1516h2_8daaf6152771_e5627efa2ab1"
    assert raw.startswith("t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_")
    text, md5 = ja3(hello)
    # The order sent, in decimal, GREASE left out.
    assert text == (
        "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,"
        "0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21-17513,29-23-24,0"
    )
    assert len(md5) == 32
    # Facebook's apps also offer their own version (0xfb1a): TLS 1.3 still.
    hello["versions"] = [0x0304, 0xFB1A]
    assert ja4(hello)[0].startswith("t13")
    # No SNI, no ALPN.
    hello.update(extensions=[kind for kind in hello["extensions"] if kind not in (0x0000, 0x0010)], alpn=[])
    assert ja4(hello)[0].startswith("t13i151400_8daaf6152771_")
    assert parse_client_hello(b"\x17\x03\x03\x00\x02ab") is None
    assert parse_client_hello(client_hello()[:40]) is None


def _frame(source: str, destination: str, source_port: int, destination_port: int, sequence: int,
           payload: bytes) -> bytes:
    tcp = struct.pack(">HHIIBBHHH", source_port, destination_port, sequence, 0, 5 << 4, 0x18, 65535, 0, 0)
    ip = struct.pack(
        ">BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp) + len(payload), 0, 0, 64, 6, 0,
        bytes(int(part) for part in source.split(".")), bytes(int(part) for part in destination.split(".")),
    )
    return b"\x00" * 12 + b"\x08\x00" + ip + tcp + payload


def _pcap(frames: list[tuple[float, bytes]]) -> bytes:
    data = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for time, frame in frames:
        data += struct.pack("<IIII", int(time), int(round(time % 1 * 1_000_000)), len(frame), len(frame)) + frame
    return data


CLIENT, SERVER = "192.168.50.165", "142.250.181.142"


def _hello_frames(time: float, client_port: int, padding: int = 1500) -> list[tuple[float, bytes]]:
    """A Client Hello sent in two segments, the second also sent again."""
    record = client_hello("www.youtube.com", padding)
    first, second = record[:1400], record[1400:]
    return [
        (time, _frame(CLIENT, SERVER, client_port, 443, 1000, first)),
        (time + 0.01, _frame(SERVER, CLIENT, 443, client_port, 5000, b"")),
        (time + 0.02, _frame(CLIENT, SERVER, client_port, 443, 1000 + len(first), second)),
        (time + 0.03, _frame(CLIENT, SERVER, client_port, 443, 1000 + len(first), second)),
    ]


def test_client_hellos_are_read_from_a_pcap_file_put_back_together(tmp_path):
    path = tmp_path / "log.pcap.1795767215"
    data = _pcap(_hello_frames(1795767228.5, 43508) + [(1795767229.0, _frame(CLIENT, SERVER, 1, 80, 1, b"GET /"))])
    path.write_bytes(data[:-20])

    # The last packet isn't all written yet: read up to it, then on from there.
    finder = HelloFinder()
    found, end = hellos(path, 0, finder)
    assert [(item["client_port"], item["site"], item["ja4"], item["time_ms"]) for item in found] == [
        (43508, "www.youtube.com", "t13d1516h2_8daaf6152771_e5627efa2ab1", 1795767228500),
    ]
    assert end < len(data) - 20
    path.write_bytes(data)
    assert hellos(path, end, finder) == ([], len(data))

    # The same Client Hello written again with the addresses swapped: not a
    # Client Hello from the server.
    record = client_hello("www.youtube.com")
    swapped = tmp_path / "log.pcap.1795767300"
    swapped.write_bytes(_pcap([
        (1795767300.0, _frame(CLIENT, SERVER, 43600, 443, 1, record)),
        (1795767300.2, _frame(SERVER, CLIENT, 443, 43600, 1, record)),
    ]))
    assert [(item["client"], item["client_port"]) for item in hellos(swapped)[0]] == [(CLIENT, 43600)]


def test_the_collector_reads_on_in_suricata_s_pcap_files(tmp_path):
    conn = sqlite3.connect(_database(tmp_path))
    older, newer = tmp_path / "log.pcap.1795767215", tmp_path / "log.pcap.1795769999"
    older.write_bytes(_pcap(_hello_frames(1795767228.5, 43508)))
    newer.write_bytes(_pcap(_hello_frames(1795770000.0, 50344)[:2]))
    (tmp_path / "log.pcap.notes").write_text("not Suricata's")
    assert pcap_files(tmp_path / "log.pcap") == [older, newer]

    reader = PcapReader(tmp_path / "log.pcap")
    assert reader.poll(conn) == 1
    # Its second segment comes in the next poll.
    newer.write_bytes(_pcap(_hello_frames(1795770000.0, 50344)))
    assert reader.poll(conn) == 1
    assert reader.poll(conn) == 0
    # Suricata removes the older file: so is its place.
    older.unlink()
    reader.poll(conn)
    assert [row[0] for row in conn.execute("SELECT path FROM tls_hello_files")] == [str(newer)]

    hello = on_flow(conn, SERVER, 443, CLIENT, 43508, 1795767228500 + 3600 * 1000)
    assert (hello["site"], hello["ja4"]) == ("www.youtube.com", "t13d1516h2_8daaf6152771_e5627efa2ab1")
    assert on_flow(conn, SERVER, 443, CLIENT, 43509, 1795767228500) is None

    # Kept back to a day before the oldest alert.
    reset = {
        "timestamp": "2026-11-27T15:00:00.000000+0500", "event_type": "alert", "src_ip": CLIENT,
        "src_port": 50344, "dest_ip": SERVER, "dest_port": 443, "proto": "TCP",
        "alert": {"gid": 1, "signature_id": 2210041, "rev": 3, "signature": "SURICATA STREAM RST recv but no session"},
    }
    insert_alert_batch(conn, [normalize_suricata(reset)], tmp_path / "uid-mark")
    conn.execute("UPDATE alerts SET event_ts_utc = ?", (1795767228500 + 86400 * 1000 + 1,))
    assert prune(conn) == 1
    conn.close()


def test_suricata_s_fingerprints_are_checked_against_the_packet(tmp_path):
    hello = {
        "ja4": "t13d1516h2_8daaf6152771_e5627efa2ab1", "ja3": "aa" * 16, "ja4_r": "raw", "ja3_string": "771,...",
        "site": "www.youtube.com",
    }
    native = {"tls": {"sni": "www.youtube.com", "ja4": hello["ja4"], "ja3": {"hash": hello["ja3"]}}}

    assert compared(native, hello) == (native, hello | {"result": "same"})
    other = {"tls": {"ja4": "t13d1517h2_8daaf6152771_b0da82dd1658", "ja3": {"hash": hello["ja3"]}}}
    assert compared(other, hello)[1] | {} == hello | {
        "result": "differs", "suricata_ja4": "t13d1517h2_8daaf6152771_b0da82dd1658", "suricata_ja3": hello["ja3"],
    }
    # An alert raised before the Client Hello was all there: the packet's.
    early = {"tls": {"version": "TLSv1", "ja4": "t00i000000_e3b0c44298fc_d2e2adf7177b"}}
    filled, check = compared(early, hello)
    assert (check["result"], check["suricata_ja4"]) == ("added", "t00i000000_e3b0c44298fc_d2e2adf7177b")
    assert filled["tls"] == {"version": "TLSv1", "ja4": hello["ja4"], "ja3": {"hash": hello["ja3"], "string": "771,..."}}
    # A Snort alert, or none read from the packet.
    assert compared(None, hello)[1]["result"] == "added"
    assert compared(native, None) == (native, None)


def test_the_fingerprint_page_shows_what_the_packets_confirm(tmp_path):
    db = _database(tmp_path)
    conn = sqlite3.connect(db)
    (tmp_path / "log.pcap.1795767215").write_bytes(
        _pcap(_hello_frames(1795767228.5, 43508) + _hello_frames(1795767230.0, 43510))
    )
    PcapReader(tmp_path / "log.pcap").poll(conn)
    record_handshakes(conn, [{
        "device": CLIENT, "fingerprint": "t13d1516h2_8daaf6152771_e5627efa2ab1",
        "ja4": "t13d1516h2_8daaf6152771_e5627efa2ab1", "ja3": None, "ja3s": None, "protocol": "tls",
        "site": "www.youtube.com", "alpn": "h2", "time_ms": 1795767228500, "server": SERVER,
    }])
    conn.execute("UPDATE tls_hellos SET ja4 = 't13d1517h2_8daaf6152771_b0da82dd1658' WHERE client_port = 43510")
    conn.commit()
    conn.close()

    listed = fingerprint_list(db)
    assert [(row["device"], row["checked"]) for row in listed["fingerprints"]] == [(CLIENT, 1)]
    assert [(item["device"], item["ja4"], item["connections"]) for item in listed["packet_only"]] == [
        (CLIENT, "t13d1517h2_8daaf6152771_b0da82dd1658", 1),
    ]


def test_an_alert_raised_before_its_client_hello_gets_the_packet_s_fingerprint(monkeypatch, tmp_path):
    from ids.config import get_settings
    from ids.dashboard_data import alert_detail

    db = _database(tmp_path)
    monkeypatch.setenv("IDS_DB_FILE", str(db))
    conn = sqlite3.connect(db)
    (tmp_path / "log.pcap.1795767215").write_bytes(_pcap(_hello_frames(1795767228.5, 43508)))
    PcapReader(tmp_path / "log.pcap").poll(conn)
    early = {
        "timestamp": "2026-11-27T12:22:36.091030+0500", "event_type": "alert", "src_ip": CLIENT,
        "src_port": 43508, "dest_ip": SERVER, "dest_port": 443, "proto": "TCP", "app_proto": "tls",
        "alert": {"gid": 1, "signature_id": 2027389, "rev": 3, "signature": "ET INFO TLSv1.0 Used in Session"},
        "tls": {"version": "TLSv1", "ja4": "t00i000000_e3b0c44298fc_d2e2adf7177b"},
    }
    insert_alert_batch(conn, [normalize_suricata(early)], tmp_path / "uid-mark")
    conn.execute("UPDATE alerts SET event_ts_utc = ?", (1795767228600,))
    conn.commit()
    alert_id = conn.execute("SELECT id FROM alerts").fetchone()[0]
    conn.close()

    detail = alert_detail(get_settings().db_file, alert_id, rule_intelligence=None, engines=("suricata",))
    check = detail["connection"]["packet_check"]
    assert (check["result"], check["ja4"], check["suricata_ja4"]) == (
        "added", "t13d1516h2_8daaf6152771_e5627efa2ab1", "t00i000000_e3b0c44298fc_d2e2adf7177b",
    )
    assert detail["connection"]["fingerprint"] == "t13d1516h2_8daaf6152771_e5627efa2ab1"
