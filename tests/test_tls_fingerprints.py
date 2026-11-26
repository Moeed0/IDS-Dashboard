from __future__ import annotations

import io
import json
import re
import shutil
import sqlite3
import tarfile
from datetime import datetime
from pathlib import Path

import pytest

from dashboard_api import create_app
from ids.combined_detections import PKT, build_combined_detections
from ids.config import get_settings
from ids.db import connect_database
from ids.live_normalizer import normalize_suricata
from ids.schema import ensure_schema
from ids.tailer import PersistentJsonTailer
from ids.tls_fingerprints import (
    Intel,
    connection_names,
    names_by_address,
    server_sites,
    short_name,
    fingerprint_list,
    fingerprints_in,
    handshake,
    labels,
    record_handshakes,
    set_label,
)
from live_dual_collector import PendingBatch, flush_pending, handle_line

REPO_ROOT = Path(__file__).resolve().parents[1]
# Suricata 8.0.3's own records of four TLS handshakes (a test capture, with
# ja3-fingerprints and ja4-fingerprints: yes and tls-fingerprints.rules):
# 192.168.50.120 twice with the same program (the second time with its
# extensions in another order), 192.168.50.121 with another program and
# then with .120's.
FIXTURE = REPO_ROOT / "tests" / "fixtures" / "suricata_tls_eve.json"
RULES = REPO_ROOT / "deploy" / "suricata" / "tls-fingerprints" / "tls-fingerprints.rules"
CHROME_LIKE = "t13d3013h2_1d37bd780c83_ecd0401ec68b"
OTHER = "t13d301200_1d37bd780c83_ecd0401ec68b"


def _events(kind=None):
    events = [json.loads(line) for line in FIXTURE.read_text().splitlines()]
    return [event for event in events if kind is None or event["event_type"] == kind]


def _database(tmp_path):
    path = tmp_path / "ids_live.db"
    conn = connect_database(path)
    ensure_schema(conn)
    conn.close()
    return path


def test_a_tls_record_gives_its_device_and_fingerprints():
    shake = handshake(_events("tls")[0])

    assert shake == {
        "device": "192.168.50.120",
        "fingerprint": CHROME_LIKE,
        "ja4": CHROME_LIKE,
        "ja3": "8ecf4858a704c8936042f20a8bedee04",
        "ja3s": "895252f3ce80cebf7a8837be83ec8e16",
        "protocol": "tls",
        "site": "www.example.com",
        "alpn": "h2,http/1.1",
        "server": "93.184.216.34",
        "time_ms": shake["time_ms"],
    }
    assert shake["time_ms"] == int(datetime(2026, 11, 25, 15, 30, 48, 274393, tzinfo=PKT).timestamp() * 1000)


def test_other_records_and_records_without_a_fingerprint_give_none():
    assert handshake(_events("alert")[0]) is None
    assert handshake({"event_type": "dns", "dns": {}}) is None
    tls = _events("tls")[0]
    tls["tls"] = {"sni": "www.example.com"}
    assert handshake(tls) is None


def test_a_record_without_a_ja4_is_kept_by_its_ja3_and_a_server_side_record_by_its_client():
    tls = _events("tls")[0]
    del tls["tls"]["ja4"]
    assert handshake(tls)["fingerprint"] == "ja3:8ecf4858a704c8936042f20a8bedee04"

    quic = {
        "timestamp": "2026-11-25T15:30:48.000000+0500",
        "event_type": "quic",
        "direction": "to_client",
        "src_ip": "142.250.1.1",
        "dest_ip": "192.168.50.120",
        "quic": {"sni": "www.youtube.com", "ja4": "q13d0310h3_55b375c5d22e_cd85d2d88918"},
    }
    shake = handshake(quic)
    assert (shake["device"], shake["protocol"], shake["site"]) == ("192.168.50.120", "quic", "www.youtube.com")


def test_each_device_and_fingerprint_is_one_row_with_its_connections_and_sites(tmp_path):
    path = _database(tmp_path)
    conn = sqlite3.connect(path)
    shakes = [handshake(event) for event in _events("tls")]
    assert record_handshakes(conn, shakes) == 4
    conn.commit()
    conn.close()

    listed = {(row["device"], row["fingerprint"]): row for row in fingerprint_list(path)["fingerprints"]}

    assert set(listed) == {
        ("192.168.50.120", CHROME_LIKE),
        ("192.168.50.121", OTHER),
        ("192.168.50.121", CHROME_LIKE),
    }
    first = listed[("192.168.50.120", CHROME_LIKE)]
    # The same program twice: one row. Its extensions in another order the
    # second time gave another JA3, not another JA4.
    assert first["connections"] == 2
    assert len(first["ja3"]) == 2
    assert first["sites"] == ["www.example.com"]
    assert first["protocols"] == ["tls"]
    assert first["devices"] == 2
    assert first["first_seen_ms"] < first["last_seen_ms"]
    assert listed[("192.168.50.121", OTHER)]["devices"] == 1
    # The newest first.
    seen = [row["last_seen_ms"] for row in fingerprint_list(path)["fingerprints"]]
    assert seen == sorted(seen, reverse=True)


def test_a_fingerprint_is_named_and_the_name_taken_away(tmp_path):
    path = _database(tmp_path)
    set_label(path, CHROME_LIKE, " Chrome ", "the lab laptop", now_ms=1)
    set_label(path, "8ECF4858A704C8936042F20A8BEDEE04", "Python", now_ms=2)

    assert labels(path) == {
        CHROME_LIKE: {"app": "Chrome", "note": "the lab laptop"},
        "ja3:8ecf4858a704c8936042f20a8bedee04": {"app": "Python", "note": None},
    }

    set_label(path, CHROME_LIKE, "", now_ms=3)
    assert CHROME_LIKE not in labels(path)
    with pytest.raises(ValueError):
        set_label(path, "", "Chrome", now_ms=4)
    with pytest.raises(ValueError):
        set_label(path, CHROME_LIKE, "x" * 101, now_ms=4)


def test_a_database_from_before_the_fingerprints_has_none(tmp_path):
    path = tmp_path / "old.db"
    sqlite3.connect(path).execute("CREATE TABLE alerts (id INTEGER)").connection.close()

    assert fingerprint_list(path) == {"fingerprints": []}
    assert labels(path) == {}


def test_the_collector_stores_the_handshakes_beside_the_alerts(tmp_path, monkeypatch):
    eve = tmp_path / "eve.json"
    shutil.copy2(FIXTURE, eve)
    monkeypatch.setenv("IDS_DB_FILE", str(tmp_path / "ids.db"))
    monkeypatch.setenv("IDS_STATE_FILE", str(tmp_path / "state.json"))
    monkeypatch.setenv("IDS_SURICATA_EVE_FILE", str(eve))
    monkeypatch.setenv("IDS_ENGINES", "suricata")
    settings = get_settings()
    conn = connect_database(settings.db_file)
    ensure_schema(conn)
    conn.close()
    tailers = {"suricata": PersistentJsonTailer(eve, settings.state_file, "suricata", start_at_end=False)}
    pending = PendingBatch()

    tailers["suricata"].poll(lambda line, inode, offset: handle_line("suricata", line, inode, offset, pending))
    assert len(pending.handshakes) == 4
    written = flush_pending(settings, pending, tailers)

    assert written["suricata"] == 6
    assert pending.handshakes == []
    rows = fingerprint_list(settings.db_file)["fingerprints"]
    assert sum(row["connections"] for row in rows) == 4


def test_the_combined_json_names_the_fingerprints_its_alerts_carry():
    rows = [
        {"id": number, "engine": "suricata", "raw_json": json.dumps(event)}
        | {key: value for key, value in normalize_suricata(event).items() if key == "event_ts_utc"}
        for number, event in enumerate(_events("alert"), start=1)
    ]
    start = datetime(2026, 11, 25, 15, 30, tzinfo=PKT)
    end = datetime(2026, 11, 25, 15, 35, tzinfo=PKT)
    named = {
        CHROME_LIKE: {"app": "Chrome", "note": None},
        "ja3:284deaeae14ea5ddc96c5d7e59855422": {"app": "Python", "note": "a test script"},
        "t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb": {"app": "Not in the file", "note": None},
    }

    document = build_combined_detections(rows, window_start=start, window_end=end, fingerprint_labels=named)

    assert document["schema_version"] == "14.3"
    assert document["tls_fingerprints"] == {
        CHROME_LIKE: {"app": "Chrome"},
        "ja3:284deaeae14ea5ddc96c5d7e59855422": {"app": "Python", "note": "a test script"},
    }
    # Without names, no section.
    assert "tls_fingerprints" not in build_combined_detections(rows, window_start=start, window_end=end)


def test_fingerprints_in_reads_tls_and_quic_records():
    alert = _events("alert")[0]
    assert fingerprints_in(alert) == [
        CHROME_LIKE,
        "ja3:8ecf4858a704c8936042f20a8bedee04",
        "ja3s:895252f3ce80cebf7a8837be83ec8e16",
    ]
    assert fingerprints_in({"quic": {"ja4": "q13d0310h3_55b375c5d22e_cd85d2d88918"}}) == [
        "q13d0310h3_55b375c5d22e_cd85d2d88918"
    ]


def test_the_api_lists_the_fingerprints_and_names_one(tmp_path):
    from test_dashboard_api import _get

    path = _database(tmp_path)
    conn = sqlite3.connect(path)
    record_handshakes(conn, [handshake(event) for event in _events("tls")])
    conn.commit()
    conn.close()
    app = create_app(db_path=path, ids_sources={}, token=None, rule_intelligence=None, web_dist=None)

    status, _, body = _get(app, "/tls-fingerprints/label", token=None, method="POST", fingerprint=CHROME_LIKE, app="Chrome")
    assert status == 200
    status, _, body = _get(app, "/tls-fingerprints", token=None)
    assert status == 200
    rows = json.loads(body)["fingerprints"]
    assert {row["app"] for row in rows if row["fingerprint"] == CHROME_LIKE} == {"Chrome"}
    status, _, body = _get(app, "/tls-fingerprints/label", token=None, method="POST", fingerprint="", app="x")
    assert status == 400


def test_the_rules_have_their_own_sids_and_every_known_bad_list_is_valid():
    rules = [line for line in RULES.read_text().splitlines() if line.startswith("alert ")]
    sids = [int(re.search(r"\bsid:(\d+);", rule).group(1)) for rule in rules]

    assert len(sids) == len(set(sids))
    assert all(1000101 <= sid <= 1000199 for sid in sids)
    assert all('msg:"LOCAL ' in rule for rule in rules)
    for kind, shape in (
        ("ja4", r"^[tqd][0-9a-z]{2}[di][0-9]{4}[0-9a-z]{2}_[0-9a-f]{12}_[0-9a-f]{12}$"),
        ("ja3", r"^[0-9a-f]{32}$"),
        ("ja3s", r"^[0-9a-f]{32}$"),
    ):
        listed = RULES.parent / f"known-bad-{kind}.txt"
        for line in listed.read_text().splitlines():
            value = line.split("#", 1)[0].strip()
            assert not value or re.match(shape, value), f"{listed.name}: {line}"


# A few of domain-list-community's lists, as its archive has them.
SITE_LISTS = {
    "youtube": "# All .youtube domains\nyoutube\n\nggpht.com\ngooglevideo.com\nyoutube.com\nytimg.com\n",
    "google": "include:youtube\ngoogle.com\ngstatic.com\nfull:www.gstatic.com\n",
    "connectivity-check": "full:www.gstatic.com\nkeyword:check\nregexp:^x$\n",
    "google-play": "play.google.com @ads\n",
    "example": "domain:example.com\n",
    "instagram": "instagram.com\n",
    "category-ads-all": "include:youtube\ndoubleclick.net @ads\n",
    "geolocation-!cn": "include:google\n",
}


def _site_list(tmp_path):
    path = tmp_path / "domain-list-community.tar.gz"
    with tarfile.open(path, "w:gz") as archive:
        for name, text in SITE_LISTS.items():
            data = text.encode()
            member = tarfile.TarInfo(f"domain-list-community-master/data/{name}")
            member.size = len(data)
            member.mtime = 1795600000
            archive.addfile(member, io.BytesIO(data))
        # Not a list: a file outside data/.
        readme = tarfile.TarInfo("domain-list-community-master/README.md")
        readme.size = 3
        archive.addfile(readme, io.BytesIO(b"hi\n"))
    return path


# A few of iptoasn.com's ranges, as its file has them.
IP_OWNERS = (
    "1.0.1.0\t1.0.3.255\t0\tNone\tNot routed\n"
    "57.144.0.0\t57.144.255.255\t32934\tUS\tFACEBOOK - Facebook, Inc.\n"
    "98.98.128.0\t98.98.191.255\t21859\tUS\tZEN-ECN - Zenlayer Inc\n"
    "162.62.0.0\t162.62.127.255\t132203\tCN\tTENCENT-NET-AP-CN - Tencent Building, Kejizhongyi Avenue\n"
    "2a03:2880::\t2a03:2880:ffff:ffff:ffff:ffff:ffff:ffff\t32934\tUS\tFACEBOOK - Facebook, Inc.\n"
    "not an address\tx\t1\tUS\tbroken\n"
)


def _ip_owners(tmp_path):
    import gzip

    path = tmp_path / "ip2asn-combined.tsv.gz"
    with gzip.open(path, "wt") as handle:
        handle.write(IP_OWNERS)
    return path


def _intel_db(tmp_path):
    from scripts.import_offline_intelligence import add_tls_fingerprints
    from test_intel_lookup import FOXIO_MAPPING, SSLBL_JA3, _intel

    db = _intel(tmp_path)
    (tmp_path / "foxio.csv").write_text(FOXIO_MAPPING)
    (tmp_path / "sslbl.csv").write_text(SSLBL_JA3)
    counts = add_tls_fingerprints(
        db, tmp_path / "foxio.csv", tmp_path / "sslbl.csv", _site_list(tmp_path), _ip_owners(tmp_path)
    )["counts"]
    # youtube 5, google 3, connectivity-check 1, google-play 1, example 1, instagram 1;
    # the category and geolocation lists, include:, keyword: and regexp: left out.
    # The not-routed range and the broken line left out.
    assert counts == {"tls_fingerprint_intel": 7, "site_services": 12, "ip_owners": 4}
    return db


def test_each_site_is_named_by_the_service_of_the_longest_name_the_list_has(tmp_path):
    intel = Intel(_intel_db(tmp_path))

    assert intel.services("WWW.YouTube.com.") == ["Youtube"]
    assert intel.services("rr3---sn-a5mekn6s.googlevideo.com") == ["Youtube"]
    assert intel.services("anything.youtube") == ["Youtube"]
    # play.google.com is Google Play's, not Google's; the rest of google.com is Google's.
    assert intel.services("play.google.com") == ["Google Play"]
    assert intel.services("mail.google.com") == ["Google"]
    # A name two lists give in full: both.
    assert intel.services("www.gstatic.com") == ["Connectivity Check", "Google"]
    # full: is that name only; the rest of gstatic.com is Google's by domain.
    assert intel.services("fonts.gstatic.com") == ["Google"]
    assert intel.services("ads.doubleclick.net") == []
    assert intel.services("") == []
    intel.close()


def test_the_list_names_each_program_and_each_service_once(tmp_path):
    path = _database(tmp_path)
    conn = sqlite3.connect(path)
    shakes = [handshake(event) for event in _events("tls")]
    for shake, site in zip(shakes, ("www.youtube.com", "mail.google.com", "i.ytimg.com", "lab.local")):
        shake["site"] = site
    record_handshakes(conn, shakes)
    conn.commit()
    conn.close()
    intel_db = _intel_db(tmp_path)

    listed = {(row["device"], row["fingerprint"]): row for row in fingerprint_list(path, intel_db)["fingerprints"]}

    first = listed[("192.168.50.120", CHROME_LIKE)]
    # FoxIO lists the JA4 (as Python): its name, before the BitRAT JA3 seen with it.
    assert first["known_app"] == {"name": "Python", "source": "FoxIO's JA4+ mapping", "malware": False}
    # Two sites, one service: named once.
    assert first["services"] == [{"name": "Youtube", "sites": ["i.ytimg.com", "www.youtube.com"]}]
    other = listed[("192.168.50.121", OTHER)]
    # In neither list.
    assert other["known_app"] is None
    # A JA4 FoxIO doesn't list, with a JA3 abuse.ch does: the malware's name.
    assert Intel(intel_db).program("t13d0000h2_000000000000_000000000000", ["8ecf4858a704c8936042f20a8bedee04"]) == {
        "name": "BitRAT", "source": "abuse.ch's SSL Blacklist", "malware": True,
    }
    assert other["services"] == [{"name": "Google", "sites": ["mail.google.com"]}]
    # A site of no known service comes under none.
    assert listed[("192.168.50.121", CHROME_LIKE)]["services"] == [{"name": None, "sites": ["lab.local"]}]
    # Without the database: no names, the sites under none.
    plain = {(row["device"], row["fingerprint"]): row for row in fingerprint_list(path)["fingerprints"]}
    assert plain[("192.168.50.120", CHROME_LIKE)]["known_app"] is None
    assert plain[("192.168.50.120", CHROME_LIKE)]["services"] == [
        {"name": None, "sites": ["i.ytimg.com", "www.youtube.com"]}
    ]


def test_a_site_two_services_list_goes_under_one_already_there(tmp_path):
    intel = Intel(_intel_db(tmp_path))

    # Google has other sites: www.gstatic.com joins it, and Google is written once.
    assert intel.grouped(["www.gstatic.com", "mail.google.com", "lab.local"]) == [
        {"name": "Google", "sites": ["www.gstatic.com", "mail.google.com"]},
        {"name": None, "sites": ["lab.local"]},
    ]
    # Alone, it is under both names.
    assert intel.grouped(["www.gstatic.com"]) == [{"name": "Connectivity Check, Google", "sites": ["www.gstatic.com"]}]
    intel.close()


def test_an_alert_on_a_tls_connection_names_its_program_and_service(tmp_path):
    intel = Intel(_intel_db(tmp_path))
    alert = _events("alert")[0]
    alert["tls"]["sni"] = "i.ytimg.com"

    assert connection_names(alert, labels={}, intel=intel) == {
        "fingerprint": CHROME_LIKE,
        "program": {"name": "Python", "source": "FoxIO's JA4+ mapping", "malware": False},
        "site": "i.ytimg.com",
        "service": "Youtube",
    }
    # A name given in the lab comes first.
    named = connection_names(alert, labels={CHROME_LIKE: {"app": "Chrome", "note": None}}, intel=intel)
    assert named["program"] == {"name": "Chrome", "source": "named in the lab", "malware": False}
    # Without a site, or a fingerprint anyone knows.
    alert["tls"] = {"ja4": "t00i000000_e3b0c44298fc_d2e2adf7177b", "version": "TLSv1"}
    assert connection_names(alert, labels={}, intel=intel) == {
        "fingerprint": "t00i000000_e3b0c44298fc_d2e2adf7177b", "program": None, "site": None, "service": None,
    }
    # Not a TLS or QUIC connection.
    assert connection_names({"event_type": "alert", "dns": {}}, labels={}, intel=intel) is None
    intel.close()


def test_a_short_name_writes_each_name_once():
    program = {"name": "Chromium Browser", "source": "x", "malware": False}
    assert short_name({"program": program, "service": "Youtube", "site": "i.ytimg.com"}) == "Chromium Browser · Youtube"
    assert short_name({"program": None, "service": None, "site": "i.golootlo.pk"}) == "i.golootlo.pk"
    assert short_name({"program": {**program, "name": "WhatsApp"}, "service": "Whatsapp", "site": "w.whatsapp.net"}) == "WhatsApp"
    assert short_name({"program": None, "service": None, "site": None}) is None
    assert short_name(None) is None


def test_the_alert_list_names_each_encrypted_connection(tmp_path, monkeypatch):
    from ids.dashboard_data import alerts

    eve = tmp_path / "eve.json"
    shutil.copy2(FIXTURE, eve)
    monkeypatch.setenv("IDS_DB_FILE", str(tmp_path / "ids.db"))
    monkeypatch.setenv("IDS_STATE_FILE", str(tmp_path / "state.json"))
    monkeypatch.setenv("IDS_SURICATA_EVE_FILE", str(eve))
    monkeypatch.setenv("IDS_ENGINES", "suricata")
    settings = get_settings()
    conn = connect_database(settings.db_file)
    ensure_schema(conn)
    conn.close()
    tailers = {"suricata": PersistentJsonTailer(eve, settings.state_file, "suricata", start_at_end=False)}
    pending = PendingBatch()
    tailers["suricata"].poll(lambda line, inode, offset: handle_line("suricata", line, inode, offset, pending))
    flush_pending(settings, pending, tailers)

    rows = alerts(settings.db_file, engines=("suricata",), intel_db=_intel_db(tmp_path))["rows"]

    names = {row.get("names") for row in rows}
    # FoxIO lists .120's JA4 as Python; www.example.com is Example's, api.example.org no one's.
    assert "Python · Example" in names
    assert all(row.get("names") for row in rows if row["service"] in ("tls", "quic"))
    # Without the database, no names but the sites.
    plain = alerts(settings.db_file, engines=("suricata",))["rows"]
    assert {row.get("names") for row in plain} <= {"www.example.com", "api.example.org", None}


def test_an_alert_without_tls_details_is_named_by_its_servers_address(tmp_path):
    from ids.dashboard_data import alert_detail, alerts

    path = _database(tmp_path)
    conn = sqlite3.connect(path)
    shakes = [handshake(event) for event in _events("tls")]
    for shake, site in zip(shakes, ("test-gateway.instagram.com", "i.ytimg.com", "graph.instagram.com", "www.youtube.com")):
        shake["site"] = site
    # Two of them to an IPv6 server; test-gateway reached twice.
    shakes[1]["server"] = shakes[3]["server"] = "2a03:2880:f12f:83:face:b00c:0:25de"
    shakes.append(dict(shakes[0]))
    record_handshakes(conn, shakes)
    # A lone reset to 93.184.216.34, and a stream event from the IPv6 server: no TLS details.
    reset = {
        "timestamp": "2026-11-25T15:31:00.000000+0500", "event_type": "alert", "src_ip": "192.168.50.120",
        "src_port": 40736, "dest_ip": "93.184.216.34", "dest_port": 443, "proto": "TCP",
        "alert": {"gid": 1, "signature_id": 2210041, "rev": 3, "signature": "SURICATA STREAM RST recv but no session"},
    }
    stream = reset | {
        "src_ip": "2a03:2880:f12f:0083:face:b00c:0000:25de", "dest_ip": "192.168.50.120", "direction": "to_client",
        "alert": {"gid": 1, "signature_id": 2210045, "rev": 3, "signature": "SURICATA STREAM Packet with invalid ack"},
    }
    from ids.db import insert_alert_batch

    insert_alert_batch(conn, [normalize_suricata(reset), normalize_suricata(stream)], tmp_path / "uid-mark")
    conn.commit()
    sites = server_sites(conn, ["93.184.216.34", "2a03:2880:f12f:0083:face:b00c:0000:25de", "10.0.0.1"])
    conn.close()
    intel_db = _intel_db(tmp_path)

    # Each address written one way; the site most reached first.
    assert sites == {
        "93.184.216.34": ["test-gateway.instagram.com", "graph.instagram.com"],
        "2a03:2880:f12f:83:face:b00c:0:25de": ["www.youtube.com", "i.ytimg.com"],
    }
    names = {row["message"]: row.get("names") for row in alerts(path, engines=("suricata",), intel_db=intel_db)["rows"]}
    # Instagram's sites only: named once, as probable.
    assert names["SURICATA STREAM RST recv but no session"] == "Instagram?"
    assert names["SURICATA STREAM Packet with invalid ack"] == "Youtube?"
    reset_id = next(row["id"] for row in alerts(path, engines=("suricata",))["rows"] if row["sid"] == 2210041)
    assert alert_detail(path, reset_id, rule_intelligence=None, intel_db=intel_db)["connection"] == {
        "fingerprint": None, "program": None, "site": "test-gateway.instagram.com", "service": "Instagram",
        "server": "93.184.216.34", "by_address": True,
    }
    # A private address no handshake went to names nothing.
    assert names_by_address(["10.0.0.1"], sites, Intel(intel_db)) is None


def test_an_address_no_handshake_went_to_is_named_by_its_owner(tmp_path):
    from ids.tls_fingerprints import owner_name

    intel = Intel(_intel_db(tmp_path))

    assert intel.owner("162.62.62.152") == {
        "name": "Tencent Building", "asn": 132203, "country": "CN",
        "description": "TENCENT-NET-AP-CN - Tencent Building, Kejizhongyi Avenue",
    }
    assert intel.owner("2a03:2880:f12f:0083:face:b00c:0000:25de")["name"] == "Facebook"
    # Between ranges, not routed, private, or not an address: no owner.
    for value in ("98.98.192.1", "1.0.2.1", "192.168.50.165", "x"):
        assert intel.owner(value) is None
    # The device's private address is passed over for the server's.
    names = names_by_address(["98.98.143.158", "192.168.50.165"], {}, intel)
    assert names["owner"]["name"] == "Zenlayer"
    assert (names["server"], names["site"], names["by_address"]) == ("98.98.143.158", None, True)
    assert short_name(names) == "Zenlayer network?"
    # A site seen at the address comes before its owner.
    assert short_name(names_by_address(["57.144.1.1"], {"57.144.1.1": ["graph.instagram.com"]}, intel)) == "Instagram?"
    assert owner_name("GOOGLE - Google LLC") == "Google"
    assert owner_name("AKAMAI-AS - Akamai Technologies, Inc.") == "Akamai Technologies"
    assert owner_name("NTC-AS") == "NTC-AS"
    intel.close()
