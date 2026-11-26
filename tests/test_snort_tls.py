from __future__ import annotations

import json
import sqlite3

from ids.config import get_settings
from ids.db import insert_alert_batch
from ids.live_normalizer import normalize_live_event, normalize_suricata
from ids.snort_tls import checked, connection, details, on_flow, prune, record_connections
from ids.tailer import PersistentJsonTailer
from ids.tls_fingerprints import Intel
from live_dual_collector import PendingBatch, build_tailers, flush_pending, handle_line, sources
from test_tls_fingerprints import _database, _intel_db

# Two lines as Snort's extractor writes them (deploy/snort/snort.lua).
TLS13 = (
    '{ "ts": 1795692540661904, "id.orig_h": "192.168.50.165", "id.resp_h": "157.240.236.19", '
    '"id.orig_p": 40454, "id.resp_p": 443, "version": "TLS 1.3", "server_name": "i.instagram.com", '
    '"cipher": "TLS_AES_128_GCM_SHA256" }'
)
TLS12 = (
    '{ "ts": 1795692821677120, "id.orig_h": "192.168.50.165", "id.resp_h": "54.116.63.6", '
    '"id.orig_p": 39606, "id.resp_p": 443, "version": "TLS 1.2", "server_name": "www.youtube.com", '
    '"subject": "CN=*.youtube.com", "issuer": "CN=Amazon RSA 2048 S18,O=Amazon,C=US", '
    '"cipher": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "curve": "secp256r1" }'
)


def test_an_extractor_line_is_one_tls_connection():
    found = connection(json.loads(TLS12))

    assert {key: found[key] for key in found if key != "record"} == {
        "time_ms": 1795692821677, "client": "192.168.50.165", "client_port": 39606,
        "server": "54.116.63.6", "server_port": 443, "site": "www.youtube.com", "version": "TLS 1.2",
        "cipher": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "curve": "secp256r1",
        "subject": "CN=*.youtube.com", "issuer": "CN=Amazon RSA 2048 S18,O=Amazon,C=US",
    }
    assert json.loads(found["record"]) == json.loads(TLS12)
    # Seconds with a fraction (the extractor's default time), and IPv6 written one way.
    ipv6 = connection({"ts": 1795692821.5, "id.orig_h": "2a03:2880:f12f:0083:face:b00c:0000:25de",
                       "id.resp_h": "192.168.50.165", "server_name": "WWW.Example.com."})
    assert (ipv6["time_ms"], ipv6["client"], ipv6["site"], ipv6["cipher"]) == (
        1795692821500, "2a03:2880:f12f:83:face:b00c:0:25de", "www.example.com", None,
    )
    # No addresses or time: not a connection.
    assert connection({"ts": 1795692821677120, "id.orig_h": "192.168.50.165"}) is None
    assert connection({"id.orig_h": "192.168.50.165", "id.resp_h": "54.116.63.6"}) is None


def test_an_alert_finds_snort_s_record_of_its_connection_either_way_round(tmp_path):
    conn = sqlite3.connect(_database(tmp_path))
    record_connections(conn, [connection(json.loads(TLS13)), connection(json.loads(TLS12))])
    later = connection(json.loads(TLS12) | {"ts": 1795692900000000, "server_name": "m.youtube.com"})
    record_connections(conn, [later])

    # The server's reply, an hour after the handshake.
    reply = on_flow(conn, "157.240.236.19", 443, "192.168.50.165", 40454, 1795692540661 + 3600 * 1000)
    assert reply["site"] == "i.instagram.com"
    assert reply["record"] == json.loads(TLS13)
    # The newest handshake on those ports before the alert, or else the first in the minute after.
    assert on_flow(conn, "192.168.50.165", 39606, "54.116.63.6", 443, 1795692850000)["site"] == "www.youtube.com"
    assert on_flow(conn, "192.168.50.165", 39606, "54.116.63.6", 443, 1795692950000)["site"] == "m.youtube.com"
    assert on_flow(conn, "192.168.50.165", 39606, "54.116.63.6", 443, 1795692800000)["site"] == "www.youtube.com"
    # Another port, a day too late, or no ports: none.
    assert on_flow(conn, "192.168.50.165", 40455, "157.240.236.19", 443, 1795692540661) is None
    assert on_flow(conn, "192.168.50.165", 40454, "157.240.236.19", 443, 1795692540661 + 25 * 3600 * 1000) is None
    assert on_flow(conn, "192.168.50.165", None, "157.240.236.19", None, 1795692540661) is None

    # Kept back to a day before the oldest alert.
    reset = {
        "timestamp": "2026-11-26T15:00:00.000000+0500", "event_type": "alert", "src_ip": "192.168.50.165",
        "src_port": 39606, "dest_ip": "54.116.63.6", "dest_port": 443, "proto": "TCP",
        "alert": {"gid": 1, "signature_id": 2210041, "rev": 3, "signature": "SURICATA STREAM RST recv but no session"},
    }
    insert_alert_batch(conn, [normalize_suricata(reset)], tmp_path / "uid-mark")
    conn.execute("UPDATE alerts SET event_ts_utc = ?", (1795692540661 + 86400 * 1000 + 1,))
    assert prune(conn) == 1
    assert [row[0] for row in conn.execute("SELECT site FROM snort_tls ORDER BY time_ms")] == [
        "www.youtube.com", "m.youtube.com",
    ]
    conn.close()


def test_the_site_is_checked_against_snort_s_record(tmp_path):
    intel = Intel(_intel_db(tmp_path))
    names = {"fingerprint": "t13d1516h2_8daaf6152771_02713d6af862", "program": None,
             "site": "www.youtube.com", "service": "YouTube"}
    snort = connection(json.loads(TLS12))

    # The same site: named by both engines, once.
    assert checked(names, snort, intel) == names | {"seen_by": ["suricata", "snort"]}
    # Another site: Snort's beside it.
    other = checked(names, snort | {"site": "i.instagram.com"}, intel)
    assert (other["site"], other["seen_by"], other["snort_site"], other["snort_service"]) == (
        "www.youtube.com", ["suricata"], "i.instagram.com", "Instagram",
    )
    # No TLS details on the alert (a Snort alert, a reset): Snort's site.
    assert checked(None, snort, intel) == {
        "fingerprint": None, "program": None, "site": "www.youtube.com", "service": "YouTube", "seen_by": ["snort"],
    }
    # Snort saw no such connection: as Suricata named it.
    assert checked(names, None, intel) == names
    assert checked(None, None, intel) is None
    intel.close()

    # The cipher and curve are Snort's; the version and certificate the alert's own when it has them.
    native = {"tls": {"version": "TLS 1.2", "subject": "CN=www.youtube.com", "issuerdn": "CN=GTS CA 1C3"}}
    assert details(native, snort) == {
        "encryption": {"version": "TLS 1.2", "cipher": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "curve": "secp256r1"},
        "certificate": {"subject": "CN=www.youtube.com", "issuer": "CN=GTS CA 1C3"},
    }
    tls13 = connection(json.loads(TLS13))
    assert details(None, tls13) == {
        "encryption": {"version": "TLS 1.3", "cipher": "TLS_AES_128_GCM_SHA256", "curve": None},
    }
    assert details(None, None) == {}


def test_the_collector_stores_snort_s_tls_log_and_a_snort_alert_is_named_by_it(monkeypatch, tmp_path):
    from ids.dashboard_data import alert_detail, alerts

    tls_log = tmp_path / "extractor_tls.json"
    tls_log.write_text(TLS12 + "\nnot json\n" + TLS13 + "\n")
    monkeypatch.setenv("IDS_DB_FILE", str(_database(tmp_path)))
    monkeypatch.setenv("IDS_STATE_FILE", str(tmp_path / "state.json"))
    monkeypatch.setenv("IDS_SNORT_TLS_FILE", str(tls_log))
    settings = get_settings()

    assert sources(settings)["snort_tls"] == tls_log.resolve()
    assert list(build_tailers(settings)) == ["snort", "suricata", "snort_tls"]
    tailers = {"snort_tls": PersistentJsonTailer(tls_log, settings.state_file, "snort_tls", start_at_end=False)}
    pending = PendingBatch()
    tailers["snort_tls"].poll(lambda line, inode, offset: handle_line("snort_tls", line, inode, offset, pending))
    assert (len(pending.snort_tls), pending.rows) == (2, [])
    flush_pending(settings, pending, tailers)

    # A Snort alert on the YouTube connection, from the server.
    alert = {
        "timestamp": "11/26-16:33:45.000000", "pkt_num": 9, "proto": "TCP", "pkt_gen": "raw", "pkt_len": 60,
        "dir": "S2C", "src_addr": "54.116.63.6", "src_port": 443, "dst_addr": "192.168.50.165",
        "dst_port": 39606, "msg": "(stream_tcp) TCP timestamp is missing", "rule": "129:14:2", "gid": 129,
        "sid": 14, "rev": 2, "action": "allow", "class": "none", "priority": 3,
    }
    conn = sqlite3.connect(settings.db_file)
    insert_alert_batch(conn, [normalize_live_event("snort", alert)], tmp_path / "uid-mark")
    conn.execute("UPDATE alerts SET event_ts_utc = ?", (1795692825000,))
    conn.commit()
    conn.close()
    intel_db = _intel_db(tmp_path)

    row = alerts(settings.db_file, engines=("snort",), intel_db=intel_db)["rows"][0]
    # Named for sure, not "?": Snort recorded this connection's site.
    assert row["names"] == "YouTube"
    detail = alert_detail(settings.db_file, row["id"], rule_intelligence=None, engines=("snort",), intel_db=intel_db)
    assert detail["connection"] == {
        "fingerprint": None, "program": None, "site": "www.youtube.com", "service": "YouTube",
        "seen_by": ["snort"],
        "encryption": {"version": "TLS 1.2", "cipher": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "curve": "secp256r1"},
        "certificate": {"subject": "CN=*.youtube.com", "issuer": "CN=Amazon RSA 2048 S18,O=Amazon,C=US"},
    }
    # Snort's record of the connection is the last raw record, as it wrote it.
    assert detail["raw"][-1] == {"id": -1, "engine": "snort", "uid": None, "source": "snort_tls",
                                 "record": json.loads(TLS12)}
    assert [raw.get("source") for raw in detail["raw"]] == [None, "snort_tls"]
