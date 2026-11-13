import base64
import json
import sqlite3
from datetime import datetime

from ids.extended_alert_intelligence import (
    ACTION_KEV_PRIORITY,
    ACTION_REVIEW_LOGS,
    CHECK_AFFECTED_PRODUCT,
    CHECK_CONTEXT,
    CHECK_FALSE_POSITIVES,
    MEANING_CVE_CAVEAT,
    MEANING_NOTE_CAVEAT,
)
from ids.combined_detections import (
    PKT,
    both_engine_alerts,
    build_combined_detections,
    combined_filename,
    complete_window_end,
    ids_output,
    load_window_rows,
    newest_event_times,
    packet_counts,
    rebuild_ids_output,
    serialize_combined_detections,
    snort_packet_time_us,
    window_bounds,
)


# Shellshock probe from the lab, as stored by both engines (15 Oct 2026).
def _snort_native(**changes):
    native = {
        "action": "allow",
        "class": "Attempted Administrator Privilege Gain",
        "client_bytes": 351,
        "client_pkts": 3,
        "dir": "C2S",
        "dst_addr": "192.168.50.114",
        "dst_port": 80,
        "eth_dst": "00:0c:29:aa:bb:cc",
        "eth_src": "00:0c:29:dd:ee:ff",
        "flowstart_time": 1792061642,
        "gid": 1,
        "iface": "ens38",
        "msg": "OS-OTHER Bash CGI environment variable injection attempt",
        "pkt_gen": "stream_tcp",
        "pkt_len": 109,
        "pkt_num": 29745,
        "priority": 1,
        "proto": "TCP",
        "rev": 5,
        "rule": "1:31978:5",
        "server_bytes": 140,
        "server_pkts": 2,
        "service": "http",
        "sid": 31978,
        "src_addr": "192.168.50.141",
        "src_port": 36788,
        "timestamp": "10/15-15:54:02.661821",
        "vlan": 0,
    }
    native.update(changes)
    return native


def _suricata_native(**changes):
    native = {
        "alert": {
            "action": "allowed",
            "category": "Attempted Administrator Privilege Gain",
            "gid": 1,
            "metadata": {
                "confidence": ["Medium"],
                "created_at": ["2014_09_25"],
                "cve": ["CVE_2014_6271"],
                "tag": ["Description_Generated_By_Proofpoint_Nexus", "CISA_KEV"],
            },
            "rev": 7,
            "severity": 1,
            "signature": "ET WEB_SERVER Possible CVE-2014-6271 Attempt in Headers",
            "signature_id": 2019232,
        },
        "app_proto": "http",
        "community_id": "1:VtLM8w9QQw/rxKkhooBa20VkAO0=",
        "dest_ip": "192.168.50.114",
        "dest_port": 80,
        "direction": "to_server",
        "event_type": "alert",
        "flow": {
            "bytes_toclient": 659,
            "bytes_toserver": 417,
            "dest_ip": "192.168.50.114",
            "dest_port": 80,
            "pkts_toclient": 3,
            "pkts_toserver": 4,
            "src_ip": "192.168.50.141",
            "src_port": 36788,
            "start": "2026-10-15T15:54:02.659143+0500",
        },
        "flow_id": 579200695037415,
        "http": {
            "hostname": "192.168.50.114",
            "http_method": "GET",
            "http_refer": "http://192.168.50.114/index.html",
            "http_user_agent": "() { :; }; /bin/bash -c id",
            "url": "/cgi-bin/test-cgi",
            "status": 404,
            "http_content_type": "",
        },
        "in_iface": "ens38",
        "pkt_src": "wire/pcap",
        "proto": "TCP",
        "src_ip": "192.168.50.141",
        "src_port": 36788,
        "suricata_version": "8.0.3",
        "timestamp": "2026-10-15T15:54:02.681047+0500",
        "tx_id": 0,
    }
    native.update(changes)
    return native


def _snort_row(native=None, event_ts_utc=1792061642662):
    native = native or _snort_native()
    return {
        "engine": "snort",
        "event_ts_utc": event_ts_utc,
        "msg": native["msg"],
        "raw_json": json.dumps(native),
    }


def _suricata_row(native=None, event_ts_utc=1792061642681):
    native = native or _suricata_native()
    return {
        "engine": "suricata",
        "event_ts_utc": event_ts_utc,
        "msg": native["alert"]["signature"],
        "raw_json": json.dumps(native),
    }


def _igmp_row(clock="15:50:00.000100", event_ts_utc=1792061400000):
    native = _snort_native(
        msg="POLICY-OTHER IGMP membership query attempt",
        proto="IP", src_addr="0.0.0.0", dst_addr="224.0.0.1",
        dir="C2S", sid=51037, rev=1, rule="1:51037:1", pkt_gen="raw",
        service="unknown", flowstart_time=1792061400,
        timestamp=f"10/15-{clock}",
    )
    for key in ("src_port", "dst_port"):
        native.pop(key)
    return _snort_row(native, event_ts_utc=event_ts_utc)


def _windows_update_row(client_port, clock, event_ts_utc):
    native = {
        "alert": {
            "action": "allowed",
            "category": "Not Suspicious Traffic",
            "gid": 1,
            "rev": 2,
            "severity": 3,
            "signature": "ET INFO Windows Update P2P Activity",
            "signature_id": 2027766,
        },
        "dest_ip": "192.168.50.124",
        "dest_port": 7680,
        "direction": "to_server",
        "event_type": "alert",
        "flow": {
            "bytes_toclient": 66,
            "bytes_toserver": 255,
            "dest_ip": "192.168.50.124",
            "dest_port": 7680,
            "pkts_toclient": 1,
            "pkts_toserver": 3,
            "src_ip": "192.168.50.122",
            "src_port": client_port,
            "start": f"2026-10-15T{clock}.000100+0500",
        },
        "pkt_src": "wire/pcap",
        "proto": "TCP",
        "src_ip": "192.168.50.122",
        "src_port": client_port,
        "timestamp": f"2026-10-15T{clock}.000300+0500",
    }
    return _suricata_row(native, event_ts_utc=event_ts_utc)


WINDOW_START = datetime(2026, 10, 15, 15, 45, tzinfo=PKT)
WINDOW_END = datetime(2026, 10, 15, 16, 0, tzinfo=PKT)


def _intelligence(engine, gid, sid, message):
    cves = {
        31978: ["CVE-2014-6271", "CVE-2014-7169"],
        2019232: ["CVE-2014-6271"],
    }.get(sid, [])
    return {
        "identifiers": {"cves": cves, "mitre_attack": []},
        "risk_context": {"known_exploited": bool(cves)},
        "explanation": {
            "why_triggered": "It alerts when the HTTP headers contain `() {`."
        },
        "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2014-6271"}],
    }


def _packets(document, *engines):
    """Packets in document order; with engines given, only the packets
    exactly those engines alerted on."""
    return [
        packet for packet in document["packets"]
        if not engines
        or {engine for engine in ("snort", "suricata") if engine in packet} == set(engines)
    ]


def _full_output(document, packet, engine, entry, rule):
    """One alert's whole IDS output: the rule's part, the flow's part, the
    engine's own part, the fields the rule's name and rule text give and the
    packet's fields under the engine's own names."""
    return rebuild_ids_output(document, packet, engine, entry, rule)


def _alerts(document, engine=None):
    """(packet, engine, entry, rule) for every alert, in document order."""
    return [
        (packet, name, entry, rule)
        for packet in document["packets"]
        for name in ("snort", "suricata")
        if engine in (None, name)
        for entry in packet.get(name, [])
        for rule in entry.get("rules", [])
    ]


def _without_output(rule):
    return {key: value for key, value in rule.items() if key != "ids_output"}


def _walk(value):
    """Every dict key and string in a document."""
    if isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _walk(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk(item)
    elif isinstance(value, str):
        yield value


def _build(rows, **kwargs):
    return build_combined_detections(
        rows,
        window_start=WINDOW_START,
        window_end=WINDOW_END,
        length_label="15 minutes",
        generated_at=WINDOW_END,
        **kwargs,
    )


def test_a_packet_both_engines_alerted_on_is_one_entry():
    suricata = _suricata_native(timestamp="2026-10-15T15:54:02.661821+0500")

    document = _build([_suricata_row(suricata), _snort_row()], rule_intelligence=_intelligence)

    packet, = document["packets"]
    # What the packet is, once; then each engine's part.
    assert {key: packet[key] for key in packet if key not in ("snort", "suricata")} == {
        "packet": 1,
        "time": "2026-10-15T15:54:02.661821+05:00",
        "protocol": "TCP",
        "src": "192.168.50.141:36788",
        "dst": "192.168.50.114:80",
        "matched_by": "time_and_addresses",
    }
    snort, = packet["snort"]
    suricata, = packet["suricata"]
    assert snort["rules"] == ["snort:31978"]
    assert suricata["rules"] == ["suricata:2019232"]
    # Both stamped the packet at the packet's time.
    assert "time" not in snort
    assert "time" not in suricata
    # The packet's addresses, ports and protocol are not repeated per engine.
    for field in ("src_addr", "dst_addr", "src_port", "dst_port", "proto"):
        assert field not in snort["ids_output"]
    for field in ("src_ip", "dest_ip", "src_port", "dest_port", "proto"):
        assert field not in suricata["ids_output"]


def test_packet_counts_are_the_counts_of_the_combined_document():
    rows = [
        # The Shellshock request both engines alerted on.
        _suricata_row(_suricata_native(timestamp="2026-10-15T15:54:02.661821+0500")),
        _snort_row(),
        # Suricata's alert on the next packet, and Snort's on an IGMP query.
        _suricata_row(),
        _igmp_row(),
        # Before the window.
        _igmp_row("15:40:00.000100", 1792060800000),
    ]

    document = _build(rows)
    counts = packet_counts(rows, window_start=WINDOW_START, window_end=WINDOW_END)

    assert counts == {
        "alerts": {"snort": 2, "suricata": 2},
        "packets": 3,
        "both": 1,
        "snort_only": 1,
        "suricata_only": 1,
    }
    packets = document["packets"]
    assert counts["alerts"] == document["alerts"]
    assert counts["packets"] == len(packets)
    assert counts["both"] == sum("snort" in p and "suricata" in p for p in packets)
    assert counts["snort_only"] == sum("suricata" not in p for p in packets)
    assert counts["suricata_only"] == sum("snort" not in p for p in packets)


def test_the_rules_both_engines_fired_on_one_packet_are_counted_in_pairs():
    rows = [
        _suricata_row(_suricata_native(timestamp="2026-10-15T15:54:02.661821+0500")),
        _snort_row(),
        _suricata_row(),
        _igmp_row(),
    ]

    counts = packet_counts(rows, window_start=WINDOW_START, window_end=WINDOW_END, rule_pairs=10)

    # Only the Shellshock request both engines alerted on.
    assert counts["pairs"] == [{
        "snort": {
            "gid": 1, "sid": 31978, "rev": 5,
            "message": "OS-OTHER Bash CGI environment variable injection attempt",
        },
        "suricata": {
            "gid": 1, "sid": 2019232, "rev": 7,
            "message": "ET WEB_SERVER Possible CVE-2014-6271 Attempt in Headers",
        },
        "packets": 1,
    }]


def test_both_engine_alerts_are_the_rows_on_a_packet_both_engines_alerted_on():
    rows = [
        _suricata_row(_suricata_native(timestamp="2026-10-15T15:54:02.661821+0500")),
        _snort_row(),
        # Suricata's alert on the next packet, and Snort's on an IGMP query.
        _suricata_row(),
        _igmp_row(),
    ]

    assert both_engine_alerts({**row, "id": number} for number, row in enumerate(rows, 1)) == {1, 2}


def test_alerts_on_different_packets_of_a_connection_are_separate_entries():
    # Snort alerted on the request it put together, Suricata 19 ms later.
    document = _build([_suricata_row(), _snort_row()])

    first, second = document["packets"]
    assert (first["packet"], first["time"]) == (1, "2026-10-15T15:54:02.661821+05:00")
    assert (second["packet"], second["time"]) == (2, "2026-10-15T15:54:02.681047+05:00")
    # Each shows only the engine that alerted on it.
    assert "snort" in first and "suricata" not in first
    assert "suricata" in second and "snort" not in second
    assert "matched_by" not in first and "matched_by" not in second


def test_live_stamps_a_few_microseconds_apart_are_the_same_packet():
    # Live, each engine stamps the packet itself.
    suricata = _suricata_native(timestamp="2026-10-15T15:54:02.661824+0500")

    document = _build([_snort_row(), _suricata_row(suricata)])

    packet, = document["packets"]
    assert packet["time"] == "2026-10-15T15:54:02.661821+05:00"
    assert "time" not in packet["snort"][0]
    # Suricata's own stamp, 3 µs later, is kept.
    assert packet["suricata"][0]["time"] == "2026-10-15T15:54:02.661824+05:00"


def _icmp_unreachable_rows():
    """A router's ICMP Network Unreachable reply to the PC, as both engines
    stored it on 28 Oct (moved to 15 Oct). Snort's flow starts with the
    router's reply, so it says C2S; Suricata's flow starts with the PC's
    packet, so it says to_client. Suricata stamped it 1 µs earlier."""
    snort = _snort_native(
        msg="PROTOCOL-ICMP Destination Unreachable Network Unreachable",
        sid=401, rev=9, rule="1:401:9", priority=3, proto="ICMP",
        src_addr="192.168.50.1", dst_addr="192.168.50.122", dir="C2S",
        icmp_type=3, icmp_code=0, pkt_gen="raw", pkt_len=80, service="unknown",
        flowstart_time=1792061915, timestamp="10/15-15:58:36.810289",
        **{"class": "Misc activity"},
    )
    for key in ("src_port", "dst_port"):
        snort.pop(key)
    suricata = {
        "alert": {
            "action": "allowed", "category": "Misc activity", "gid": 1, "rev": 7,
            "severity": 3,
            "signature": "GPL ICMP Destination Unreachable Network Unreachable",
            "signature_id": 2100401,
        },
        "community_id": "1:54dPmBA06SzZ/y6kmo8hNuL51LA=",
        "dest_ip": "192.168.50.122",
        "direction": "to_client",
        "event_type": "alert",
        "flow": {
            "bytes_toclient": 94, "bytes_toserver": 132,
            "dest_ip": "192.168.50.1", "pkts_toclient": 1, "pkts_toserver": 2,
            "src_ip": "192.168.50.122", "start": "2026-10-15T15:58:35.805255+0500",
        },
        "icmp_code": 0,
        "icmp_type": 3,
        "proto": "ICMP",
        "src_ip": "192.168.50.1",
        "timestamp": "2026-10-15T15:58:36.810288+0500",
    }
    return [
        _snort_row(snort, event_ts_utc=1792061916810),
        _suricata_row(suricata, event_ts_utc=1792061916810),
    ]


def test_same_packet_is_found_when_the_engines_label_its_direction_differently():
    document = _build(_icmp_unreachable_rows())

    # Both name the router as the packet's source and the PC as its
    # destination, so it is one packet whatever direction each engine says.
    packet, = document["packets"]
    assert packet["time"] == "2026-10-15T15:58:36.810288+05:00"
    assert (packet["protocol"], packet["src"], packet["dst"]) == (
        "ICMP", "192.168.50.1", "192.168.50.122",
    )
    assert (packet["icmp_type"], packet["icmp_code"]) == (3, 0)
    assert packet["matched_by"] == "time_and_addresses"
    snort, = packet["snort"]
    suricata, = packet["suricata"]
    assert snort["time"] == "2026-10-15T15:58:36.810289+05:00"
    assert snort["ids_output"]["dir"] == "C2S"
    assert suricata["ids_output"]["direction"] == "to_client"
    # Suricata's own Community ID belongs to the flow it filed the reply under
    # (started by the PC); it stays in Suricata's part as Suricata wrote it.
    assert suricata["ids_output"]["community_id"] == "1:54dPmBA06SzZ/y6kmo8hNuL51LA="


def test_packets_in_opposite_directions_are_not_the_same_packet():
    # The server's packet lands 30 µs after the client's: close in time, but
    # a different packet.
    reply = _suricata_native(
        src_ip="192.168.50.114", src_port=80,
        dest_ip="192.168.50.141", dest_port=36788,
        direction="to_client",
        timestamp="2026-10-15T15:54:02.661851+0500",
    )

    document = _build([_snort_row(), _suricata_row(reply)])

    assert len(_packets(document, "snort")) == 1
    reply_packet, = _packets(document, "suricata")
    assert (reply_packet["src"], reply_packet["dst"]) == (
        "192.168.50.114:80", "192.168.50.141:36788",
    )


def _ethernet_tcp_packet(ip_id, seq, ack, vlan=False):
    """Base64 of an Ethernet/IPv4/TCP packet from the PC to the web server, as
    Suricata writes it in eve's alert ``packet``."""
    ethernet = bytes(12) + (b"\x81\x00\x00\x05" if vlan else b"") + b"\x08\x00"
    ip = (
        bytes([0x45, 0]) + (52).to_bytes(2, "big") + ip_id.to_bytes(2, "big")
        + b"\x40\x00\x40\x06\x00\x00"
        + bytes([192, 168, 50, 141]) + bytes([192, 168, 50, 114])
    )
    tcp = (
        (36788).to_bytes(2, "big") + (80).to_bytes(2, "big")
        + seq.to_bytes(4, "big") + ack.to_bytes(4, "big") + b"\x50\x18" + bytes(6)
    )
    return base64.b64encode(ethernet + ip + tcp).decode()


def _raw_snort(**changes):
    """The Shellshock request packet itself (not a reassembled segment), with
    the header values Snort writes."""
    return _snort_native(
        pkt_gen="raw", pkt_num=29744, ip_id=4242, tcp_seq=1000, tcp_ack=2000,
        **changes,
    )


def _suricata_with_packet(packet, clock="15:54:02.661824"):
    return _suricata_native(
        timestamp=f"2026-10-15T{clock}+0500",
        packet=packet, packet_info={"linktype": 1},
    )


def test_header_values_confirm_the_same_packet():
    document = _build([
        _snort_row(_raw_snort()),
        _suricata_row(_suricata_with_packet(_ethernet_tcp_packet(4242, 1000, 2000, vlan=True))),
    ])

    packet, = document["packets"]
    assert packet["matched_by"] == "headers"
    # The raw packet is evidence for matching, not output.
    suricata = packet["suricata"][0]["ids_output"]
    assert "packet" not in suricata
    assert "packet_info" not in suricata


def test_different_header_values_are_different_packets_even_when_close_in_time():
    # 3 µs apart with the same addresses, but another IP ID and sequence
    # number: the next packet of the burst.
    document = _build([
        _snort_row(_raw_snort()),
        _suricata_row(_suricata_with_packet(_ethernet_tcp_packet(4243, 1052, 2000))),
    ])

    first, second = document["packets"]
    assert "snort" in first and "suricata" not in first
    assert "suricata" in second and "snort" not in second


def test_several_rules_on_one_packet_are_one_entry_per_engine():
    packet = _ethernet_tcp_packet(4242, 1000, 2000)
    second_rule = _suricata_with_packet(packet)
    second_rule["alert"] = {**second_rule["alert"], "signature_id": 2022028, "signature": "ET second rule"}
    later = _snort_native(timestamp="10/15-15:54:02.700000")

    document = _build([
        _snort_row(_raw_snort()),
        _suricata_row(_suricata_with_packet(packet)),
        _suricata_row(second_rule),
        _snort_row(later, event_ts_utc=1792061642700),
    ])

    first, second = document["packets"]
    snort, = first["snort"]
    suricata, = first["suricata"]
    assert snort["rules"] == ["snort:31978"]
    # Suricata's two alerts on this packet differ only in the rule.
    assert suricata["rules"] == ["suricata:2019232", "suricata:2022028"]
    assert second["snort"][0]["rules"] == ["snort:31978"]
    assert "suricata" not in second


def test_one_engines_alerts_on_one_packet_with_different_output_stay_apart():
    other_request = _suricata_native(timestamp="2026-10-15T15:54:02.681047+0500")
    other_request["http"] = {**other_request["http"], "url": "/cgi-bin/status"}
    other_request["alert"] = {**other_request["alert"], "signature_id": 2022028}

    document = _build([_suricata_row(), _suricata_row(other_request)])

    packet, = document["packets"]
    first, second = packet["suricata"]
    assert first["ids_output"]["http"]["url"] == "/cgi-bin/test-cgi"
    assert second["ids_output"]["http"]["url"] == "/cgi-bin/status"


def test_snort_packet_numbers_that_start_again_are_different_packets():
    # Snort counts packets from 1 again after a restart.
    after_restart = _snort_native(timestamp="10/15-15:56:02.100000")

    document = _build([_snort_row(), _snort_row(after_restart, event_ts_utc=1792061762100)])

    assert [packet["time"] for packet in document["packets"]] == [
        "2026-10-15T15:54:02.661821+05:00", "2026-10-15T15:56:02.100000+05:00",
    ]


def test_ids_output_has_no_links_device_ids_internal_counters_or_empty_values():
    document = _build(
        [_snort_row(), _suricata_row()], rule_intelligence=_intelligence
    )

    def walk(value):
        assert value not in (None, "", [], {})
        if isinstance(value, str):
            assert "://" not in value
        elif isinstance(value, dict):
            assert "gid" not in value
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(document)

    (snort_packet, _, snort_entry, snort_rule), (suricata_packet, _, suricata_entry, suricata_rule) = (
        _alerts(document)
    )
    snort = _full_output(document, snort_packet, "snort", snort_entry, snort_rule)
    suricata = _full_output(document, suricata_packet, "suricata", suricata_entry, suricata_rule)
    for dropped in ("iface", "vlan", "eth_src", "eth_dst", "pkt_num", "timestamp"):
        assert dropped not in snort
    for dropped in (
        "in_iface", "flow_id", "event_type", "suricata_version", "tx_id", "timestamp",
        "ip_v", "pkt_src",
    ):
        assert dropped not in suricata
    # Each engine's own record is kept whole, addresses and ports included.
    assert (snort["src_addr"], snort["src_port"]) == ("192.168.50.141", 36788)
    assert (snort["dst_addr"], snort["dst_port"]) == ("192.168.50.114", 80)
    assert (snort["proto"], snort["service"]) == ("TCP", "http")
    assert snort["flowstart_time"] == 1792061642
    assert (suricata["src_ip"], suricata["dest_port"]) == ("192.168.50.141", 80)
    assert suricata["community_id"] == "1:VtLM8w9QQw/rxKkhooBa20VkAO0="
    assert suricata["app_proto"] == "http"
    assert suricata["flow"]["start"] == "2026-10-15T15:54:02.659143+0500"
    assert suricata["flow"]["bytes_toserver"] == 417
    assert snort["dir"] == "C2S"
    assert suricata["direction"] == "to_server"
    # The engines only watch traffic, so "allow" / "allowed" says nothing.
    assert "action" not in snort
    assert "action" not in suricata["alert"]
    # Every rule here has GID 1; Snort's gid:sid:rev field goes with it.
    assert "rule" not in snort
    assert (snort["sid"], snort["rev"]) == (31978, 5)
    assert snort["class"] == "Attempted Administrator Privilege Gain"
    assert snort["msg"] == "OS-OTHER Bash CGI environment variable injection attempt"
    assert snort["pkt_gen"] == "stream_tcp"
    assert suricata["alert"]["metadata"] == {
        "confidence": ["Medium"],
        "cve": ["CVE_2014_6271"],
        "tag": ["CISA_KEV"],
    }
    # The request path and the payload header are traffic evidence; the
    # web link in the Referer header is removed.
    assert suricata["http"]["url"] == "/cgi-bin/test-cgi"
    assert suricata["http"]["http_user_agent"] == "() { :; }; /bin/bash -c id"
    assert "http_refer" not in suricata["http"]
    assert "http_content_type" not in suricata["http"]

    # The rule's output fields and enrichment are in the file's rules, the
    # packet's fields with the packet; each engine's part keeps the rest. The
    # SID is in the rule's name, not repeated in its output.
    assert document["rules"] == {
        "snort:31978": {
            "ids_output": {
                "msg": "OS-OTHER Bash CGI environment variable injection attempt",
                "class": "Attempted Administrator Privilege Gain",
                "priority": 1,
                "rev": 5,
            },
            "why_triggered": "It alerts when the HTTP headers contain `() {`.",
            "cves": ["CVE-2014-6271", "CVE-2014-7169"],
        },
        "suricata:2019232": {
            "ids_output": {"alert": {
                "signature": "ET WEB_SERVER Possible CVE-2014-6271 Attempt in Headers",
                "category": "Attempted Administrator Privilege Gain",
                "severity": 1,
                "rev": 7,
                "metadata": {
                    "confidence": ["Medium"], "cve": ["CVE_2014_6271"], "tag": ["CISA_KEV"],
                },
            }},
            "why_triggered": "It alerts when the HTTP headers contain `() {`.",
            "cves": ["CVE-2014-6271"],
        },
    }
    assert snort_entry["ids_output"] == {
        "client_bytes": 351, "client_pkts": 3, "dir": "C2S", "flowstart_time": 1792061642,
        "pkt_gen": "stream_tcp", "pkt_len": 109, "server_bytes": 140, "server_pkts": 2,
        "service": "http",
    }
    assert set(suricata_entry["ids_output"]) == {
        "app_proto", "community_id", "direction", "flow", "http",
    }


def test_blocking_actions_are_kept_in_ids_output():
    snort = _snort_native(action="drop")
    suricata = _suricata_native()
    suricata["alert"] = {**suricata["alert"], "action": "blocked"}

    document = _build([_snort_row(snort), _suricata_row(suricata)])

    snort_packet, suricata_packet = document["packets"]
    assert snort_packet["snort"][0]["ids_output"]["action"] == "drop"
    assert suricata_packet["suricata"][0]["ids_output"]["alert"]["action"] == "blocked"


def test_alert_counts_leave_out_an_engine_that_raised_none():
    no_ip_layer = {
        "alert": {
            "gid": 1, "rev": 1, "severity": 3, "signature_id": 2200121,
            "signature": "SURICATA Ethertype unknown",
        },
        "event_type": "alert",
        "in_iface": "ens38",
        "pkt_src": "wire/pcap",
        "timestamp": "2026-10-15T15:51:00.000200+0500",
    }

    document = _build([
        _snort_row(),
        _suricata_row(),
        _igmp_row(),
        _suricata_row(no_ip_layer, event_ts_utc=1792061460000),
    ])

    # The file states only the alerts per engine, the rules and the packets
    # (no engine alerted on two packets of one connection, so there are no
    # flows); no sessions, summary, guidance or classification.
    assert list(document) == [
        "schema", "schema_version", "generated_at", "window", "alerts", "rules",
        "packets",
    ]
    assert document["schema_version"] == "9.3"
    assert document["alerts"] == {"snort": 2, "suricata": 2}
    assert not {
        "classification", "guidance", "summary", "routine", "sessions",
    } & set(_walk(document))

    igmp, no_ip_layer_packet, request, response = document["packets"]
    # Snort calls IGMP "IP".
    assert (igmp["protocol"], igmp["src"], igmp["dst"]) == ("IP", "0.0.0.0", "224.0.0.1")
    assert "suricata" not in igmp
    # Suricata named no protocol and no addresses for this frame.
    assert no_ip_layer_packet == {
        "packet": 2,
        "time": "2026-10-15T15:51:00.000200+05:00",
        "suricata": [{"rules": ["suricata:2200121"]}],
    }
    assert "suricata" not in request
    assert "snort" not in response


def test_non_ip_alerts_from_the_two_engines_are_not_combined():
    arp = _snort_native(
        msg="(arp_spoof) unicast ARP request", gid=112, sid=1, rev=1,
        rule="112:1:1", dir="UNK", pkt_gen="raw", timestamp="10/15-15:51:00.000100",
    )
    for key in ("src_addr", "dst_addr", "src_port", "dst_port", "proto", "flowstart_time"):
        arp.pop(key)
    unknown_ethertype = {
        "alert": {
            "gid": 1, "rev": 1, "severity": 3, "signature_id": 2200121,
            "signature": "SURICATA Ethertype unknown",
        },
        "event_type": "alert",
        "timestamp": "2026-10-15T15:51:00.000200+0500",
    }

    document = _build([
        _snort_row(arp, event_ts_utc=1792061460000),
        _suricata_row(unknown_ethertype, event_ts_utc=1792061460000),
    ])

    arp_packet, other = document["packets"]
    assert arp_packet["snort"][0]["rules"] == ["snort:112:1"]
    assert "suricata" not in arp_packet
    assert "snort" not in other


def _collapse_rows():
    stream_event = _suricata_native(
        alert={
            "action": "allowed",
            "category": "Generic Protocol Command Decode",
            "gid": 1,
            "rev": 1,
            "severity": 3,
            "signature": "SURICATA STREAM ESTABLISHED packet out of window",
            "signature_id": 2210020,
        },
        direction="to_client",
        timestamp="2026-10-15T15:54:02.690000+0500",
    )
    return [
        _snort_row(),
        _suricata_row(),
        _suricata_row(stream_event, event_ts_utc=1792061642690),
        _igmp_row(),
        _igmp_row("15:52:05.000200", 1792061525000),
        _windows_update_row(51001, "15:51:01", 1792061461000),
        _windows_update_row(51002, "15:51:41", 1792061501000),
        _windows_update_row(51003, "15:52:21", 1792061541000),
    ]


def test_every_alert_is_listed_oldest_first():
    document = _build(_collapse_rows())

    packets = document["packets"]
    assert [packet["packet"] for packet in packets] == [1, 2, 3, 4, 5, 6, 7, 8]
    assert [packet["time"] for packet in packets] == sorted(packet["time"] for packet in packets)
    assert [
        [rule for engine in ("snort", "suricata") for entry in packet.get(engine, []) for rule in entry["rules"]]
        for packet in packets
    ] == [
        ["snort:51037"],
        ["suricata:2027766"],
        ["suricata:2027766"],
        ["snort:51037"],
        ["suricata:2027766"],
        ["snort:31978"],
        ["suricata:2019232"],
        ["suricata:2210020"],
    ]
    # Each Windows Update connection uses a new client port.
    assert [packet["src"] for packet in _packets(document, "suricata")[:3]] == [
        "192.168.50.122:51001", "192.168.50.122:51002", "192.168.50.122:51003",
    ]
    # The format is described in docs/combined-json-format.md, not in every file.
    assert "options" not in document
    assert "about" not in document
    assert "timezone" not in document["window"]


def test_every_alert_can_be_rebuilt_exactly_from_the_file():
    rows = [
        *_icmp_unreachable_rows(),
        _igmp_row(), _suricata_igmp_row(),
        _snort_row(_raw_snort()),
        _suricata_row(_suricata_with_packet(_ethernet_tcp_packet(4242, 1000, 2000))),
        _snort_row(), _suricata_row(),
        *_collapse_rows()[2:],
    ]

    document = _build(rows, rule_intelligence=_intelligence)

    rebuilt = sorted(
        json.dumps(_full_output(document, packet, engine, entry, rule), sort_keys=True)
        for packet, engine, entry, rule in _alerts(document)
    )
    expected = sorted(
        json.dumps(ids_output(row["engine"], json.loads(row["raw_json"])), sort_keys=True)
        for row in rows
    )
    assert rebuilt == expected


def test_rule_enrichment_is_given_once_per_file():
    # The same rule fires again on a later packet of the same connection.
    again = _snort_native(timestamp="10/15-15:54:03.100000", pkt_len=120)

    document = _build(
        [_snort_row(), _snort_row(again, event_ts_utc=1792061643100)],
        rule_intelligence=_intelligence,
    )

    first, second = document["packets"]
    assert first["snort"][0]["rules"] == second["snort"][0]["rules"] == ["snort:31978"]
    assert list(document["rules"]) == ["snort:31978"]
    assert document["rules"]["snort:31978"]["cves"] == ["CVE-2014-6271", "CVE-2014-7169"]
    # What differs per alert stays with the alert; the rule's message and
    # class, and any other field the same on both alerts, are given once,
    # with the rule.
    assert first["snort"][0]["ids_output"] == {"pkt_len": 109}
    assert second["snort"][0]["ids_output"] == {"pkt_len": 120}
    rule_output = document["rules"]["snort:31978"]["ids_output"]
    assert rule_output["class"] == "Attempted Administrator Privilege Gain"
    assert rule_output["flowstart_time"] == 1792061642


def test_rule_names_keep_a_non_default_gid_and_split_revisions():
    builtin = _snort_native(
        gid=116, sid=408, rev=1, rule="116:408:1", msg="(ipv4) IPv4 option set",
        pkt_gen="raw", timestamp="10/15-15:54:02.700000",
    )
    newer = _snort_native(rev=6, rule="1:31978:6", timestamp="10/15-15:54:02.800000")

    document = _build(
        [
            _snort_row(),
            _snort_row(builtin, event_ts_utc=1792061642700),
            _snort_row(newer, event_ts_utc=1792061642800),
        ],
        rule_intelligence=_intelligence,
    )

    assert [packet["snort"][0]["rules"] for packet in document["packets"]] == [
        ["snort:31978:rev5"], ["snort:116:408"], ["snort:31978:rev6"],
    ]
    assert list(document["rules"]) == ["snort:116:408", "snort:31978:rev5", "snort:31978:rev6"]


def test_file_is_written_indented():
    document = _build([_snort_row()], rule_intelligence=_intelligence)

    text = serialize_combined_detections(document)

    # Two-space indentation, ending with a line break; the content is unchanged.
    assert text == json.dumps(document, ensure_ascii=False, indent=2) + "\n"
    assert text.startswith('{\n  "schema": ')
    assert json.loads(text) == document


SHELLSHOCK_ACTION = (
    "Check this destination first: CVE-2014-6271 scores 9.8 (CVSS v3.1)."
)


def _full_intelligence(engine, gid, sid, message):
    """Offline intelligence shaped like ids.offline_intelligence returns it."""
    shared = {
        "identifiers": {"cves": ["CVE-2014-6271"], "mitre_attack": []},
        "explanation": {
            "why_triggered": f"{engine} rule logic",
            "what_it_means": (
                "The rule is associated with 1 CVE: CVE-2014-6271. At least one "
                "of those CVEs is listed in CISA's Known Exploited "
                f"Vulnerabilities catalog. {MEANING_CVE_CAVEAT}"
            ),
            "what_to_check": [CHECK_AFFECTED_PRODUCT, CHECK_CONTEXT],
            "recommended_actions": [
                ACTION_KEV_PRIORITY, SHELLSHOCK_ACTION, ACTION_REVIEW_LOGS,
            ],
        },
        "vulnerabilities": {
            "CVE-2014-6271": {
                "nvd": {
                    "description": "GNU Bash through 4.3 runs trailing strings. "
                                   "See https://example.test/advisory",
                    "cvss": {
                        "version": "3.1", "base_score": 9.8,
                        "base_severity": "CRITICAL",
                        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    },
                    "references": [{"url": "https://nvd.nist.gov/x"}],
                },
                "epss": {"score": 0.99999, "percentile": 0.99993},
                "cisa_kev": {
                    "dateAdded": "2022-01-28",
                    "knownRansomwareCampaignUse": "Unknown",
                    "requiredAction": "Apply updates per vendor instructions.",
                },
            },
        },
    }
    if engine == "snort":
        shared["identifiers"]["mitre_attack"] = ["T1190"]
        shared["explanation"]["known_usage"] = "Attacks seen in the wild"
        shared["explanation"]["false_positives"] = "Rare."
        shared["explanation"]["what_to_check"] = [
            f"{CHECK_FALSE_POSITIVES}Rare.", CHECK_AFFECTED_PRODUCT, CHECK_CONTEXT,
        ]
        shared["mitre_enrichment"] = {"T1190": [{
            "technique_id": "T1190", "name": "Exploit Public-Facing Application",
            "tactics": ["initial-access"], "description": "See https://attack.test/x",
        }]}
    return shared


def test_enrichment_holds_cve_and_technique_details_without_general_sentences():
    document = _build(
        [_snort_row(), _suricata_row()], rule_intelligence=_full_intelligence
    )

    snort_rule = _without_output(document["rules"]["snort:31978"])
    suricata_rule = _without_output(document["rules"]["suricata:2019232"])
    # Both rules name the Shellshock CVE; its details are given once.
    assert document["cves"] == {
        "CVE-2014-6271": {
            "summary": "GNU Bash through 4.3 runs trailing strings. See",
            "cvss": {
                "score": 9.8, "version": "3.1", "severity": "CRITICAL",
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            },
            "epss": {"score": 0.99999, "percentile": 0.99993},
            "cisa_kev": {"date_added": "2022-01-28"},
        },
    }
    assert serialize_combined_detections(document).count("GNU Bash through 4.3") == 1
    assert document["attack_techniques"] == {
        "T1190": {"name": "Exploit Public-Facing Application", "tactics": ["initial-access"]},
    }
    # The recommended action only restated the CVE's score, given under cves.
    assert snort_rule == {
        "why_triggered": "snort rule logic",
        "known_usage": "Attacks seen in the wild",
        "false_positives": "Rare.",
        "cves": ["CVE-2014-6271"],
        "attack_techniques": ["T1190"],
    }
    # Sentences that hold for any alert or any rule with CVEs are left out,
    # and the "what it means" text only listed the CVE plus such a sentence.
    assert suricata_rule == {
        "why_triggered": "suricata rule logic",
        "cves": ["CVE-2014-6271"],
    }
    assert SHELLSHOCK_ACTION not in serialize_combined_detections(document)


# The two Shellshock rules as written in the local rule files.
SHELLSHOCK_RULE_TEXTS = {
    31978: (
        'alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS ( msg:"OS-OTHER Bash '
        'CGI environment variable injection attempt"; flow:to_server,established; '
        'http_header; content:"() {",fast_pattern,nocase; metadata:policy '
        'balanced-ips drop,policy max-detect-ips drop,policy security-ips drop,'
        'ruleset community; service:http; reference:cve,2014-6271; '
        'reference:cve,2014-6277; reference:cve,2014-6278; reference:cve,2014-7169; '
        'classtype:attempted-admin; sid:31978; rev:5; )'
    ),
    2019232: (
        'alert http any any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible '
        'CVE-2014-6271 Attempt in Headers"; flow:established,to_server; '
        'http.header; content:"|28 29 20 7b|"; fast_pattern; content:"bash|20 2d|c"; '
        'reference:url,blogs.akamai.com/2014/09/environment-bashing.html; '
        'classtype:attempted-admin; sid:2019232; rev:7; metadata:created_at '
        '2014_09_25, cve CVE_2014_6271, confidence Medium, signature_severity Major, '
        'tag CISA_KEV, tag Description_Generated_By_Proofpoint_Nexus, updated_at '
        '2021_11_03, reviewed_at 2024_03_06;)'
    ),
}


def test_rule_text_is_given_without_web_link_references_or_metadata():
    def intelligence(engine, gid, sid, message):
        return {
            "explanation": {"why_triggered": f"{engine} rule logic"},
            "base_intelligence": {"rule": {"rule_text": SHELLSHOCK_RULE_TEXTS[sid]}},
        }

    document = _build([_snort_row(), _suricata_row()], rule_intelligence=intelligence)

    snort_rule = _without_output(document["rules"]["snort:31978"])
    suricata_rule = _without_output(document["rules"]["suricata:2019232"])
    # Everything else stays as the rule file writes it. The CVE references
    # are the rule's cves.
    assert snort_rule == {
        "why_triggered": "snort rule logic",
        "rule_text": (
            'alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS ( msg:"OS-OTHER '
            'Bash CGI environment variable injection attempt"; '
            'flow:to_server,established; http_header; content:"() {",fast_pattern,'
            'nocase; service:http; classtype:attempted-admin; sid:31978; rev:5; )'
        ),
        "cves": ["CVE-2014-6271", "CVE-2014-6277", "CVE-2014-6278", "CVE-2014-7169"],
    }
    assert list(suricata_rule) == ["why_triggered", "rule_text", "cves"]
    assert suricata_rule["rule_text"] == (
        'alert http any any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible '
        'CVE-2014-6271 Attempt in Headers"; flow:established,to_server; '
        'http.header; content:"|28 29 20 7b|"; fast_pattern; content:"bash|20 2d|c"; '
        'classtype:attempted-admin; sid:2019232; rev:7;)'
    )
    # The message and revision the rule text gives are not repeated in the
    # rule's IDS output; the alert's full output still rebuilds.
    snort_output = document["rules"]["snort:31978"]["ids_output"]
    suricata_output = document["rules"]["suricata:2019232"]["ids_output"]["alert"]
    assert not {"msg", "rev", "sid"} & set(snort_output)
    assert not {"signature", "rev", "signature_id"} & set(suricata_output)
    for packet, engine, entry, rule in _alerts(document):
        native = (_snort_native() if engine == "snort" else _suricata_native())
        assert _full_output(document, packet, engine, entry, rule) == ids_output(engine, native)


# Talos documentation of Snort's FTP bad login rule, as the local copy holds it.
FTP_BAD_LOGIN_DOCUMENTATION = {
    "rule_explanation": (
        "This event is generated when a failed attempt to login to an FTP server\n"
        "is detected.\n\nImpact:\nUnknown. Multiple events may indicate an attempt to "
        "enumerate accounts\nand passwords using brute force methodology.\n\nDetails:\n"
        "This event is generated when a failed attempt to login to an FTP server\n"
        "is detected.\n\nMultiple events may indicate an attempt to enumerate accounts\n"
        "and passwords using brute force methodology.\n\nEase of Attack:\nSimple."
    ),
    "what_to_look_for": "This rule alerts on a failed FTP login. See https://example.test/ftp",
    "rule_vulnerability": "Brute Force\n \n\n Brute force attacks try many passwords.",
    "contributors": "Cisco Talos\nBrian Caswell \nNigel Houghton",
}


def test_rule_documentation_is_given_on_one_line_without_repeats():
    def intelligence(engine, gid, sid, message):
        if engine != "snort":
            return {}
        return {
            "explanation": {
                "why_triggered": "snort rule logic",
                # Built from the documentation's vulnerability type.
                "what_it_means": (
                    "Brute Force\n \n\n Brute force attacks try many passwords. "
                    f"{MEANING_NOTE_CAVEAT}"
                ),
            },
            "base_intelligence": {"documentation": FTP_BAD_LOGIN_DOCUMENTATION},
        }

    document = _build([_snort_row(), _suricata_row()], rule_intelligence=intelligence)

    # The details only repeat the description and impact; the vulnerability
    # type is given once, in the documentation.
    assert _without_output(document["rules"]["snort:31978"]) == {
        "why_triggered": "snort rule logic",
        "documentation": {
            "description": (
                "This event is generated when a failed attempt to login to an FTP "
                "server is detected."
            ),
            "impact": (
                "Unknown. Multiple events may indicate an attempt to enumerate "
                "accounts and passwords using brute force methodology."
            ),
            "ease_of_attack": "Simple.",
            "what_to_look_for": "This rule alerts on a failed FTP login. See",
            "vulnerability": {
                "type": "Brute Force",
                "description": "Brute force attacks try many passwords.",
            },
        },
    }
    assert "documentation" not in document["rules"]["suricata:2019232"]


def test_rule_documentation_written_on_one_line_is_split_into_its_parts():
    documentation = {"rule_explanation": (
        "This event is generated when an attacker makes an HTTP request that "
        "contains '/etc/passwd' in the URI. Impact: Information Gathering. Details: "
        "The passwd file holds login information for the host's users. "
        "Ease of Attack: Simple HTTP request."
    )}

    document = _build(
        [_snort_row()],
        rule_intelligence=lambda *rule: {"base_intelligence": {"documentation": documentation}},
    )

    assert document["rules"]["snort:31978"]["documentation"] == {
        "description": (
            "This event is generated when an attacker makes an HTTP request that "
            "contains '/etc/passwd' in the URI."
        ),
        "impact": "Information Gathering.",
        "details": "The passwd file holds login information for the host's users.",
        "ease_of_attack": "Simple HTTP request.",
    }


def test_rule_documentation_copied_from_nvd_is_left_to_the_cves():
    def intelligence(engine, gid, sid, message):
        result = _full_intelligence(engine, gid, sid, message)
        result["base_intelligence"] = {"documentation": {
            "rule_explanation": (
                "GNU Bash through 4.3 runs trailing strings. See "
                "https://example.test/advisory\n\nImpact:\nCVSS base score 10.0\n"
                "CVSS impact score 10.0\n\nDetails:\n\nEase of Attack:"
            ),
            "what_to_look_for": (
                "This rule alerts when attempts to exploit CVE-2014-6271 are detected"
            ),
            "rule_vulnerability": "N/A\n \n\n Not Applicable",
            "contributors": (
                "Talos research team.\n\nThis document was generated from data "
                "supplied by the national vulnerability database."
            ),
        }}
        return result

    document = _build([_snort_row(), _suricata_row()], rule_intelligence=intelligence)

    snort_rule = document["rules"]["snort:31978"]
    # The description and impact copy the CVE's NVD summary and CVSS scores;
    # "N/A" is no vulnerability type.
    assert snort_rule["documentation"] == {
        "what_to_look_for": (
            "This rule alerts when attempts to exploit CVE-2014-6271 are detected"
        ),
    }
    assert snort_rule["cves"] == ["CVE-2014-6271"]
    assert document["cves"]["CVE-2014-6271"]["summary"] == (
        "GNU Bash through 4.3 runs trailing strings. See"
    )


def test_alerts_on_the_same_packet_each_keep_their_full_output():
    policy = _snort_native(
        msg="POLICY-OTHER HTTP request by IPv4 address attempt", sid=50447,
        rev=1, rule="1:50447:1", priority=1,
        **{"class": "Potential Corporate Privacy Violation"},
    )

    document = _build([_snort_row(), _snort_row(policy)])

    packet, = document["packets"]
    entry, = packet["snort"]
    assert entry["rules"] == ["snort:31978", "snort:50447"]
    first, second = (
        _full_output(document, packet, "snort", entry, rule) for rule in entry["rules"]
    )
    assert first["pkt_len"] == second["pkt_len"] == 109
    assert first["msg"] == "OS-OTHER Bash CGI environment variable injection attempt"
    assert second["msg"] == "POLICY-OTHER HTTP request by IPv4 address attempt"
    assert second["src_addr"] == "192.168.50.141"


def test_low_value_defaults_are_left_out():
    dns_lookup = {
        "alert": {
            "action": "allowed", "category": "Misc activity", "gid": 1, "rev": 2,
            "severity": 3, "signature_id": 2060512,
            "signature": "ET REMOTE_ACCESS Anydesk Domain (boot .net .anydesk .com) in DNS Lookup",
            "metadata": {
                "affected_product": ["Any"], "deployment": ["Perimeter"],
                "former_category": ["INFO"], "confidence": ["High"],
            },
        },
        "app_proto": "failed",
        "dest_ip": "192.168.50.1", "dest_port": 53,
        "direction": "to_server",
        "dns": {
            "flags": "100", "id": 62255, "opcode": 0, "rd": True, "tx_id": 12,
            "version": 3, "type": "request", "rcode": "NOERROR",
            "queries": [{"rrname": "boot.net.anydesk.com", "rrtype": "A"}],
        },
        "event_type": "alert",
        "ip_v": 4,
        "pkt_src": "wire/pcap",
        "proto": "UDP",
        "src_ip": "192.168.50.122", "src_port": 50121,
        "timestamp": "2026-10-15T15:52:00.000500+0500",
    }

    document = _build([_suricata_row(dns_lookup, event_ts_utc=1792061520000)])

    (packet, engine, entry, rule), = _alerts(document)
    assert _full_output(document, packet, engine, entry, rule) == {
        "alert": {
            "category": "Misc activity",
            "metadata": {"confidence": ["High"]},
            "rev": 2,
            "severity": 3,
            "signature": "ET REMOTE_ACCESS Anydesk Domain (boot .net .anydesk .com) in DNS Lookup",
            "signature_id": 2060512,
        },
        "dest_ip": "192.168.50.1",
        "dest_port": 53,
        "direction": "to_server",
        "dns": {
            "type": "request", "rcode": "NOERROR",
            "queries": [{"rrname": "boot.net.anydesk.com", "rrtype": "A"}],
        },
        "proto": "UDP",
        "src_ip": "192.168.50.122",
        "src_port": 50121,
    }


# Suricata's view of the IGMP query in _igmp_row: it stamps the packet itself,
# a few microseconds after Snort, and names the protocol that Snort calls "IP".
def _suricata_igmp_row(clock="15:50:00.000104", src_ip="0.0.0.0", dest_ip="224.0.0.1"):
    native = {
        "alert": {
            "action": "allowed",
            "category": "Generic Protocol Command Decode",
            "gid": 1,
            "rev": 2,
            "severity": 3,
            "signature": "SURICATA IPv4 padding required",
            "signature_id": 2200007,
        },
        "dest_ip": dest_ip,
        "direction": "to_server",
        "event_type": "alert",
        "flow": {
            "dest_ip": dest_ip,
            "pkts_toserver": 1,
            "src_ip": src_ip,
            "start": "2026-10-15T15:50:00.000104+0500",
        },
        "proto": "IGMP",
        "src_ip": src_ip,
        "timestamp": f"2026-10-15T{clock}+0500",
    }
    return _suricata_row(native, event_ts_utc=1792061400000)


def test_snort_ip_alert_and_suricata_alert_on_the_same_packet_are_one_entry():
    document = _build([_igmp_row(), _suricata_igmp_row()])

    packet, = document["packets"]
    # Suricata names the protocol Snort calls "IP".
    assert (packet["protocol"], packet["src"], packet["dst"]) == ("IGMP", "0.0.0.0", "224.0.0.1")
    assert packet["matched_by"] == "time_and_addresses"
    # 4 µs apart; Snort's own name for the protocol stays in its part.
    assert packet["snort"][0]["ids_output"]["proto"] == "IP"
    assert "proto" not in packet["suricata"][0]["ids_output"]
    assert packet["suricata"][0]["time"] == "2026-10-15T15:50:00.000104+05:00"


def test_snort_ip_alert_without_a_suricata_alert_on_its_packet_stays_apart():
    document = _build([_igmp_row(), _suricata_igmp_row(clock="15:50:00.200000")])

    assert len(_packets(document, "snort")) == 1
    assert len(_packets(document, "suricata")) == 1


def test_snort_ip_alert_is_not_combined_with_a_packet_going_the_other_way():
    # 4 µs apart, but Suricata's packet runs from 224.0.0.1 to 0.0.0.0.
    document = _build([
        _igmp_row(), _suricata_igmp_row(src_ip="224.0.0.1", dest_ip="0.0.0.0"),
    ])

    assert len(_packets(document, "snort")) == 1
    assert len(_packets(document, "suricata")) == 1


def test_ipv6_addresses_have_one_spelling_across_engines():
    document = _build([
        _suricata_igmp_row(
            src_ip="fe80:0000:0000:0000:2d37:6cf4:f5c8:64f7",
            dest_ip="ff02:0000:0000:0000:0000:0000:0000:0016",
        ),
    ])

    packet, = document["packets"]
    assert (packet["src"], packet["dst"]) == ("fe80::2d37:6cf4:f5c8:64f7", "ff02::16")
    # Suricata's full spelling of the same addresses is not repeated.
    assert "src_ip" not in packet["suricata"][0]["ids_output"]


def test_rows_outside_the_window_are_left_out():
    document = build_combined_detections(
        [_snort_row(), _suricata_row()],
        window_start=datetime(2026, 10, 15, 15, 50, tzinfo=PKT),
        window_end=datetime(2026, 10, 15, 15, 54, 2, 670000, tzinfo=PKT),
    )

    assert document["alerts"] == {"snort": 1}
    assert document["window"]["length"] == "4 minutes"


def test_snort_packet_time_keeps_microseconds_across_a_rounded_second():
    assert snort_packet_time_us(
        "10/15-15:54:02.661821", 1792061642662
    ) == 1792061642661821
    # .9997 s rounds up to the next whole second in event_ts_utc.
    assert snort_packet_time_us(
        "10/15-15:54:02.999700", 1792061643000
    ) == 1792061642999700


def _store(db_path, rows):
    connection = sqlite3.connect(db_path)
    connection.execute(
        "CREATE TABLE IF NOT EXISTS alerts (id INTEGER PRIMARY KEY, engine TEXT, "
        "event_ts_utc INTEGER, msg TEXT, rule_key TEXT, raw_json TEXT)"
    )
    connection.executemany(
        "INSERT INTO alerts (engine, event_ts_utc, msg, rule_key, raw_json) "
        "VALUES (:engine, :event_ts_utc, :msg, :rule_key, :raw_json)",
        [{"rule_key": None, **row} for row in rows],
    )
    connection.commit()
    connection.close()


def test_load_window_rows_reads_only_the_window(tmp_path):
    db_path = tmp_path / "ids_live.db"
    _store(
        db_path,
        [
            {"engine": "snort", "event_ts_utc": 1792061642662, "msg": "in",
             "rule_key": "snort:1:1:1", "raw_json": "{}"},
            {"engine": "snort", "event_ts_utc": 1792060000000, "msg": "before",
             "rule_key": "snort:1:2:1", "raw_json": "{}"},
            {"engine": "suricata", "event_ts_utc": 1792062000000, "msg": "after",
             "rule_key": "suricata:1:3:1", "raw_json": "{}"},
        ],
    )

    rows = load_window_rows(
        db_path,
        datetime(2026, 10, 15, 15, 50, tzinfo=PKT),
        datetime(2026, 10, 15, 15, 55, tzinfo=PKT),
    )

    assert [row["msg"] for row in rows] == ["in"]
    assert newest_event_times(db_path) == {
        "snort": datetime(2026, 10, 15, 15, 54, 2, 662000, tzinfo=PKT),
        "suricata": datetime(2026, 10, 15, 16, 0, tzinfo=PKT),
    }


def test_window_ends_where_both_engines_alerts_are_stored():
    snort_newest = datetime(2026, 11, 2, 14, 54, 0, 651000, tzinfo=PKT)
    suricata_newest = datetime(2026, 11, 2, 14, 55, 53, 120000, tzinfo=PKT)

    # The last whole second before the older of the two newest alerts.
    assert complete_window_end(
        {"snort": snort_newest, "suricata": suricata_newest}
    ) == datetime(2026, 11, 2, 14, 54, tzinfo=PKT)
    # An alert on a whole second is left out too.
    assert complete_window_end(
        {"snort": datetime(2026, 11, 2, 14, 54, tzinfo=PKT), "suricata": suricata_newest}
    ) == datetime(2026, 11, 2, 14, 53, 59, tzinfo=PKT)
    # The stored time is rounded to the millisecond: 14:50:00.001 may be
    # 14:50:00.0005 or later, which is still after 14:50:00.
    assert complete_window_end(
        {"suricata": datetime(2026, 11, 2, 14, 50, 0, 1000, tzinfo=PKT)}
    ) == datetime(2026, 11, 2, 14, 50, tzinfo=PKT)
    assert complete_window_end({}) is None


def test_a_window_ending_where_both_engines_are_complete_has_no_one_sided_packet(tmp_path):
    db_path = tmp_path / "ids_live.db"

    def suricata_igmp(clock, event_ts_utc):
        return {**_suricata_igmp_row(clock=clock), "event_ts_utc": event_ts_utc}

    # Both engines stored their alerts on the IGMP queries at 15:50:00 and
    # 15:51:10. Snort's alert on the query at 15:52:30 is still waiting in
    # its batch; Suricata's is stored.
    _store(
        db_path,
        [
            _igmp_row(),
            _suricata_igmp_row(),
            _igmp_row("15:51:10.300100", 1792061470300),
            suricata_igmp("15:51:10.300104", 1792061470300),
            suricata_igmp("15:52:30.250104", 1792061550250),
        ],
    )

    newest = newest_event_times(db_path)
    end = complete_window_end(newest)
    start, end = window_bounds(end, "5 minutes")
    document = build_combined_detections(
        load_window_rows(db_path, start, end),
        window_start=start,
        window_end=end,
    )

    assert end == datetime(2026, 10, 15, 15, 51, 10, tzinfo=PKT)
    # The query at 15:51:10 is left for a later window with its second.
    assert [
        (packet["time"], "snort" in packet, "suricata" in packet)
        for packet in document["packets"]
    ] == [("2026-10-15T15:50:00.000100+05:00", True, True)]

    # A window ending after Snort's newest stored alert would show the
    # 15:52:30 query as Suricata's only.
    start, end = window_bounds(datetime(2026, 10, 15, 15, 53, tzinfo=PKT), "5 minutes")
    document = build_combined_detections(
        load_window_rows(db_path, start, end),
        window_start=start,
        window_end=end,
    )
    last = document["packets"][-1]
    assert (last["time"], "snort" in last, "suricata" in last) == (
        "2026-10-15T15:52:30.250104+05:00",
        False,
        True,
    )


def test_window_bounds_and_filename():
    start, end = window_bounds(WINDOW_END, "15 minutes")

    assert start == WINDOW_START
    assert end == WINDOW_END
    assert combined_filename(start, "15 minutes") == (
        "snort_suricata_combined_20261015_1545_15min.json"
    )
    assert combined_filename(start, "1 hour") == (
        "snort_suricata_combined_20261015_1545_1hour.json"
    )


def test_what_is_the_same_on_every_alert_of_a_connection_is_given_once():
    later = _suricata_native(
        alert={
            "action": "allowed",
            "category": "Generic Protocol Command Decode",
            "gid": 1,
            "rev": 1,
            "severity": 3,
            "signature": "SURICATA STREAM ESTABLISHED packet out of window",
            "signature_id": 2210020,
        },
        timestamp="2026-10-15T15:54:02.690000+0500",
    )
    packets_to_server = later["flow"]["pkts_toserver"] + 1
    later["flow"] = {**later["flow"], "pkts_toserver": packets_to_server}
    rows = [_suricata_row(), _suricata_row(later, event_ts_utc=1792061642690)]

    document = _build(rows)

    first, second = document["packets"]
    assert first["flow"] == second["flow"] == 1
    flow = document["flows"]["1"]["suricata"]
    assert flow["community_id"] == "1:VtLM8w9QQw/rxKkhooBa20VkAO0="
    assert flow["direction"] == "to_server"
    assert flow["flow"]["start"] == "2026-10-15T15:54:02.659143+0500"
    # Suricata's flow addresses and ports are the packet's: not repeated.
    assert not {"src_ip", "dest_ip", "src_port", "dest_port"} & set(flow["flow"])
    assert "community_id" not in first["suricata"][0].get("ids_output", {})
    assert second["suricata"][0]["ids_output"] == {"flow": {"pkts_toserver": packets_to_server}}
    rebuilt = sorted(
        json.dumps(_full_output(document, packet, engine, entry, rule), sort_keys=True)
        for packet, engine, entry, rule in _alerts(document)
    )
    assert rebuilt == sorted(
        json.dumps(ids_output("suricata", json.loads(row["raw_json"])), sort_keys=True)
        for row in rows
    )


def test_a_rule_name_and_generic_sentences_are_not_repeated_in_the_rule():
    builtin = _snort_native(
        gid=116, sid=408, rev=1, rule="116:408:1", msg="(ipv4) IPv4 option set",
        pkt_gen="raw", timestamp="10/15-15:54:02.700000",
    )

    def intelligence(engine, gid, sid, message):
        return {"explanation": {"why_triggered": (
            "A built-in Snort rule (116:408): Snort's ipv4 component raised this "
            "event while decoding or inspecting the traffic. Built-in rules have no "
            "rule text; the message names the check that failed."
        )}}

    document = _build([_snort_row(builtin, event_ts_utc=1792061642700)], rule_intelligence=intelligence)

    rule = document["rules"]["snort:116:408"]
    # GID and SID are in the name, and Snort's rule field is gid:sid:rev.
    assert not {"gid", "sid", "rule"} & set(rule["ids_output"])
    # No rule text gives the message and revision.
    assert (rule["ids_output"]["msg"], rule["ids_output"]["rev"]) == ("(ipv4) IPv4 option set", 1)
    assert rule["why_triggered"] == (
        "A built-in Snort rule: Snort's ipv4 component raised this event while "
        "decoding or inspecting the traffic."
    )
    packet, = document["packets"]
    entry, = packet["snort"]
    assert _full_output(document, packet, "snort", entry, "snort:116:408") == ids_output("snort", builtin)


def test_suricata_names_for_the_packets_protocol_and_addresses_are_not_repeated():
    row = _suricata_igmp_row(
        src_ip="fe80:0000:0000:0000:2d37:6cf4:f5c8:64f7",
        dest_ip="ff02:0000:0000:0000:0000:0000:0000:0016",
    )
    native = json.loads(row["raw_json"])
    native.update(proto="IPv6-ICMP", icmp_type=143, icmp_code=0)

    document = _build([_suricata_row(native, event_ts_utc=row["event_ts_utc"])])

    packet, = document["packets"]
    entry, = packet["suricata"]
    assert (packet["protocol"], packet["src"], packet["dst"]) == (
        "ICMPv6", "fe80::2d37:6cf4:f5c8:64f7", "ff02::16",
    )
    assert "proto" not in entry["ids_output"]
    assert not {"src_ip", "dest_ip"} & set(entry["ids_output"]["flow"])
    rebuilt = _full_output(document, packet, "suricata", entry, entry["rules"][0])
    assert rebuilt["proto"] == "IPv6-ICMP"
    assert (rebuilt["flow"]["src_ip"], rebuilt["flow"]["dest_ip"]) == (
        "fe80::2d37:6cf4:f5c8:64f7", "ff02::16",
    )


def _leaves(value, path=()):
    """(path, value) of every field; an entry with no output has none."""
    if isinstance(value, dict) and (value or not path):
        for key, item in value.items():
            yield from _leaves(item, path + (key,))
    else:
        yield path, json.dumps(value, sort_keys=True)


def test_nothing_is_written_once_per_alert_that_holds_for_a_whole_rule_or_connection():
    rows = [
        *_icmp_unreachable_rows(),
        _igmp_row(), _suricata_igmp_row(),
        _snort_row(_raw_snort()),
        _suricata_row(_suricata_with_packet(_ethernet_tcp_packet(4242, 1000, 2000))),
        _snort_row(), _suricata_row(),
        *_collapse_rows()[2:],
    ]

    document = _build(rows, rule_intelligence=_intelligence)

    groups = {}
    for packet, engine, entry, rule in _alerts(document):
        groups.setdefault(("rule", rule), []).append((packet["packet"], entry))
        if "flow" in packet:
            groups.setdefault(("flow", packet["flow"], engine), []).append((packet["packet"], entry))
    checked = 0
    for group, items in groups.items():
        if len({number for number, _ in items}) < 2:
            continue
        values = {}
        for _, entry in items:
            for path, value in _leaves(entry.get("ids_output", {})):
                values.setdefault(path, []).append(value)
        for path, seen in values.items():
            checked += 1
            assert not (len(seen) == len(items) and len(set(seen)) == 1), (group, path)
    assert checked


def _igmp_query(clock, event_ts_utc, pkt_num, client_pkts, *, gid=1, sid=51037, **changes):
    """Snort's alert of one rule on an IGMP query."""
    msg = {
        51037: "POLICY-OTHER IGMP membership query attempt",
        408: "(ipv4) IPv4 packet from 'current net' source address",
        444: "(ipv4) IPv4 option set",
    }[sid]
    row = _igmp_row(clock, event_ts_utc)
    native = json.loads(row["raw_json"])
    native.update(
        gid=gid, sid=sid, msg=msg, rule=f"{gid}:{sid}:1", pkt_num=pkt_num,
        client_pkts=client_pkts, client_bytes=60 * client_pkts, **{"tos": 192, **changes},
    )
    return _snort_row(native, event_ts_utc=event_ts_utc)


def test_several_rules_on_one_packet_stay_one_entry_when_one_rule_varies():
    def query(clock, event_ts_utc, pkt_num, client_pkts):
        return [
            _igmp_query(clock, event_ts_utc, pkt_num, client_pkts, gid=gid, sid=sid)
            for gid, sid in ((1, 51037), (116, 408), (116, 444))
        ]

    rows = [
        *query("15:50:00.000100", 1792061400000, 100, 3504),
        *query("15:52:05.000200", 1792061525000, 200, 3505),
        # 116:444 also fires on another device's IGMP report, from another
        # flow and with another TOS: its flow start and TOS vary.
        _igmp_query(
            "15:53:00.000300", 1792061580000, 300, 7, gid=116, sid=444,
            src_addr="192.168.50.122", dst_addr="224.0.0.252",
            flowstart_time=1792061000, tos=0,
        ),
    ]

    document = _build(rows)

    first, second, _ = document["packets"]
    for packet in (first, second):
        # The three alerts on one query are one entry: nothing in it twice.
        entry, = packet["snort"]
        assert sorted(entry["rules"]) == ["snort:116:408", "snort:116:444", "snort:51037"]
    # What 116:444 does not share with the other two stays with the packet;
    # the query's flow gives it once.
    assert document["flows"]["1"]["snort"]["flowstart_time"] == 1792061400
    assert first["snort"][0]["ids_output"] == {"client_bytes": 210240, "client_pkts": 3504}
    rebuilt = sorted(
        json.dumps(_full_output(document, packet, engine, entry, rule), sort_keys=True)
        for packet, engine, entry, rule in _alerts(document)
    )
    assert rebuilt == sorted(
        json.dumps(ids_output("snort", json.loads(row["raw_json"])), sort_keys=True)
        for row in rows
    )


def test_what_different_alerts_on_one_packet_share_is_given_once_with_the_packet():
    first = _suricata_native()
    second = _suricata_native(
        alert={
            **first["alert"],
            "signature": "ET WEB_SERVER Bash shell injection with target",
            "signature_id": 2044666,
            "target": {"ip": "192.168.50.114", "port": 80},
        },
    )
    rows = [_suricata_row(first), _suricata_row(second)]

    document = _build(rows)

    packet, = document["packets"]
    one, two = packet["suricata"]
    # The second alert names a target; everything else of the packet's output
    # is the same for both, and given once.
    assert "ids_output" not in one
    assert two["ids_output"] == {"alert": {"target": {"ip": "192.168.50.114", "port": 80}}}
    shared = packet["ids_output"]["suricata"]
    assert shared["community_id"] == "1:VtLM8w9QQw/rxKkhooBa20VkAO0="
    assert shared["http"]["url"] == "/cgi-bin/test-cgi"
    rebuilt = sorted(
        json.dumps(_full_output(document, packet, engine, entry, rule), sort_keys=True)
        for packet, engine, entry, rule in _alerts(document)
    )
    assert rebuilt == sorted(
        json.dumps(ids_output("suricata", json.loads(row["raw_json"])), sort_keys=True)
        for row in rows
    )


def test_snorts_payload_is_written_as_text_as_suricatas_is():
    from ids.combined_detections import ids_output, printable_payload

    assert printable_payload("R0VUIC8gSFRUUC8xLjENCgD/") == "GET / HTTP/1.1\r\n.."
    assert printable_payload("not base64!") == ""
    output = ids_output("snort", {"msg": "x", "b64_data": "R0VUIC8="})
    assert output == {"msg": "x", "payload_printable": "GET /"}
