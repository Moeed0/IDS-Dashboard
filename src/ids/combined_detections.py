"""Combine Snort and Suricata rule matches from one time window into one JSON.

Both engines inspect every packet as it arrives and raise an alert on the
packet where a rule matches (Snort sometimes on a reassembled TCP segment).
The file is a timeline of those packets, oldest first. A packet only one
engine alerted on carries only that engine's part. A packet both engines
alerted on is one entry with both parts, so what the packet is (time,
protocol, addresses, ports) is written once.

A Snort and a Suricata alert are on the same packet when they are at most
100 µs apart, name the same packet source and destination, and give the same
IP ID and TCP or ICMP sequence numbers wherever both engines give them (Snort
writes them; Suricata's are read from the raw packet in eve's alert
``packet``). Each packet pairs with at most one packet of the other engine,
the closest in time first. Alerts without IP addresses are never combined.

Every alert's IDS output is kept, split so nothing is written twice: fields
that are the same on every alert of a rule go to that rule in the file's
``rules`` (with the rule's enrichment), fields that describe the packet go to
the packet, and each engine's part keeps the rest. Values that carry no
information are left out: web links, empty values, interface and MAC
addresses, internal counters, the default GID 1, the pass-through action,
"not identified" defaults and sentences that hold for any alert.
docs/combined-json-format.md describes the format. The export reads the
database only; it creates no correlation groups.
"""

from __future__ import annotations

import base64
import binascii
import bisect
import ipaddress
import json
import math
import re
import sqlite3
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence
from zoneinfo import ZoneInfo

from ids.alert_classification import is_pass_through_action
from ids.community_id import community_id, protocol_number
from ids.config import KNOWN_ENGINES
from ids.extended_alert_intelligence import (
    ACTION_CONFIRM_EXPECTED,
    ACTION_KEV_PRIORITY,
    ACTION_REVIEW_LOGS,
    CHECK_AFFECTED_PRODUCT,
    CHECK_CONTEXT,
    CHECK_FALSE_POSITIVES,
    MEANING_CVE_CAVEAT,
    MEANING_NOTE_CAVEAT,
    MEANING_WITHOUT_CVES,
)
from ids.export_cleanup import drop_default_gid


SCHEMA_ID = "ids.combined-detections"
SCHEMA_VERSION = "9.4"

PKT = ZoneInfo("Asia/Karachi")

WINDOW_LENGTHS = {
    "5 minutes": timedelta(minutes=5),
    "10 minutes": timedelta(minutes=10),
    "15 minutes": timedelta(minutes=15),
    "30 minutes": timedelta(minutes=30),
    "1 hour": timedelta(hours=1),
    "3 hours": timedelta(hours=3),
    "6 hours": timedelta(hours=6),
    "12 hours": timedelta(hours=12),
    "1 day": timedelta(days=1),
    "7 days": timedelta(days=7),
}

# Fields left out of ids_output: capture interface, device identifiers,
# internal counters and IDs, and values restated as the detection time.
_DROPPED_FIELDS = {
    "snort": {
        "iface", "vlan", "eth_src", "eth_dst", "eth_type", "ip_id",
        "pkt_num", "timestamp", "b64_data",
    },
    "suricata": {
        "in_iface", "flow_id", "event_type", "suricata_version", "tx_id",
        "timestamp", "pcap_cnt", "packet", "packet_info", "payload", "host",
        "capture_file", "pcap_filename", "ip_v",
    },
}
# Values that only say "a normal captured packet" or "not identified".
_DEFAULT_VALUES = {
    "pkt_src": "wire/pcap",
    "app_proto": "failed",
    "service": "unknown",
}
# DNS bookkeeping: transaction IDs, header flags and the log format version.
_DROPPED_DNS_FIELDS = {"id", "tx_id", "version", "opcode", "flags", "rd"}
# Suricata rule metadata about rule maintenance and placement, not traffic.
_DROPPED_RULE_METADATA = {
    "created_at", "updated_at", "reviewed_at", "performance_impact",
    "deployment", "former_category",
}
_DROPPED_METADATA_VALUES = {"Description_Generated_By_Proofpoint_Nexus"}
_UNINFORMATIVE_METADATA = {"affected_product": ["Any"]}

_LINK_RE = re.compile(r"\b[a-z][a-z0-9+.-]*://\S+", re.IGNORECASE)
# One option of a Snort or Suricata rule ("name:value;" or "name;").
_RULE_OPTION_RE = re.compile(
    r'\s*([A-Za-z_][\w.-]*)\s*(?::\s*((?:"(?:[^"\\]|\\.)*"|[^;])*))?;'
)
_OFFSET_RE = re.compile(r"([+-]\d{2})(\d{2})$")
_PROTOCOL_NAMES = {
    1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 58: "ICMPv6", 132: "SCTP",
}
_ENGINE_ORDER = {"snort": 0, "suricata": 1}
# On live traffic each engine stamps a packet itself: alerts on the same packet
# land 0-50 µs apart, while different packets are rarely this close.
_SAME_PACKET_TOLERANCE_US = 100

# Sentences that hold for any alert, or for every rule of a kind; they say
# nothing about the alert at hand.
_GENERIC_SENTENCES = {
    CHECK_CONTEXT,
    ACTION_REVIEW_LOGS,
    MEANING_WITHOUT_CVES,
    ACTION_CONFIRM_EXPECTED,
    MEANING_CVE_CAVEAT,
    CHECK_AFFECTED_PRODUCT,
    ACTION_KEV_PRIORITY,
    MEANING_NOTE_CAVEAT,
}
# Recommended actions built only from a rule's CVE scores, which the file's
# ``cves`` gives.
_CVE_SCORE_ACTIONS = (
    "Check this destination first:",
    "Check the destination during routine triage:",
    "Treat the associated CVEs as context:",
    "Check the affected product/version and apply",
)
# Said of every Snort built-in rule, with its GID and SID, which the rule's
# name gives; the format guide says it once.
_BUILTIN_RULE_NOTE = " Built-in rules have no rule text; the message names the check that failed."
_BUILTIN_RULE_NUMBER_RE = re.compile(r"^(A built-in Snort rule) \(\d+:\d+\):")
# The engines' names for a protocol the packet names otherwise.
_PROTOCOL_ALIASES = {"suricata": {"IPv6-ICMP": "ICMPv6"}}
_RULE_TEXT_OPTION_RES = {
    "msg": re.compile(r'\bmsg\s*:\s*"((?:[^"\\]|\\.)*)"'),
    "rev": re.compile(r"\brev\s*:\s*(\d+)\s*;"),
}
# Where each engine writes the rule's GID, SID, revision and message.
_RULE_ID_PATHS = {
    "snort": {"gid": ("gid",), "sid": ("sid",), "rev": ("rev",), "msg": ("msg",)},
    "suricata": {
        "gid": ("alert", "gid"), "sid": ("alert", "signature_id"),
        "rev": ("alert", "rev"), "msg": ("alert", "signature"),
    },
}


@dataclass
class _Match:
    engine: str
    time_us: int
    rule_key: str
    native: dict[str, Any]
    protocol: str | None
    # The packet's source and destination as (address, port); the port is
    # None when the engine gives none (ICMP, IGMP).
    source: tuple[Any, Any] | None
    destination: tuple[Any, Any] | None
    # ICMP type and code, when the engine gives them.
    icmp: tuple[Any, Any] | None
    # Source and destination with ICMP type and code in place of ports: what
    # the two engines must agree on to be on one packet.
    packet: tuple[tuple[Any, Any], tuple[Any, Any]] | None
    # Header values that identify the packet itself (IP ID, TCP sequence and
    # acknowledgement numbers, ICMP identifier and sequence).
    header: dict[str, int]
    community_id: str | None


def is_empty(value: Any) -> bool:
    return value is None or value == "" or value == [] or value == {}


def prune_empty(value: Any) -> Any:
    """Drop None, empty strings, empty lists and empty dicts at every level."""
    if isinstance(value, dict):
        cleaned = {key: prune_empty(item) for key, item in value.items()}
        return {key: item for key, item in cleaned.items() if not is_empty(item)}
    if isinstance(value, list):
        cleaned = [prune_empty(item) for item in value]
        return [item for item in cleaned if not is_empty(item)]
    return value


def strip_links(value: Any) -> Any:
    """Remove web links (anything with a scheme://) from every string."""
    if isinstance(value, dict):
        return {key: strip_links(item) for key, item in value.items()}
    if isinstance(value, list):
        return [strip_links(item) for item in value]
    if isinstance(value, str):
        return _LINK_RE.sub("", value).strip()
    return value


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _epoch_us(moment: datetime) -> int:
    return (moment - datetime(1970, 1, 1, tzinfo=timezone.utc)) // timedelta(
        microseconds=1
    )


def _parse_iso_us(value: Any) -> int | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = _OFFSET_RE.sub(r"\1:\2", value.strip().replace("Z", "+00:00"))
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return _epoch_us(parsed)


def snort_packet_time_us(stamp: Any, event_ts_utc: Any) -> int | None:
    """Packet time of a Snort alert in epoch microseconds.

    Snort writes ``MM/DD-HH:MM:SS.ffffff`` in local time without a year. The
    stored ``event_ts_utc`` (milliseconds) gives the whole seconds and Snort's
    own fraction gives the microseconds.
    """
    if event_ts_utc is None:
        return None
    try:
        fallback_us = int(round(float(event_ts_utc) * 1000))
    except (TypeError, ValueError):
        return None
    match = re.search(r"\.(\d{1,6})$", str(stamp or ""))
    if not match:
        return fallback_us
    fraction_us = int(match.group(1).ljust(6, "0"))
    candidate = (fallback_us // 1_000_000) * 1_000_000 + fraction_us
    # event_ts_utc is rounded to milliseconds, which can cross a second.
    if candidate - fallback_us > 500_000:
        candidate -= 1_000_000
    elif fallback_us - candidate > 500_000:
        candidate += 1_000_000
    return candidate


def _iso(time_us: int, *, whole_seconds: bool = False) -> str:
    moment = datetime.fromtimestamp(time_us // 1_000_000, tz=PKT).replace(
        microsecond=time_us % 1_000_000
    )
    return moment.isoformat(timespec="seconds" if whole_seconds else "microseconds")


def _endpoint(address: Any, port: Any) -> str | None:
    if not address:
        return None
    if port is None:
        return str(address)
    if ":" in str(address):
        return f"[{address}]:{port}"
    return f"{address}:{port}"


def _protocol(name: Any, address: Any) -> tuple[str | None, int | None]:
    """Protocol label and number; Snort reports ICMPv6 as ICMP and IGMP as IP."""
    text = str(name or "").strip()
    if not text:
        return None, None
    if text.upper() == "IP":
        return "IP", None
    try:
        number = protocol_number(text)
    except ValueError:
        return text, None
    if number == 1 and ":" in str(address or ""):
        number = 58
    return _PROTOCOL_NAMES.get(number, text), number


def _address(value: Any) -> Any:
    """One spelling per address: Suricata writes IPv6 in full, Snort shortened."""
    if not value:
        return value
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError:
        return value


def _network(engine: str, native: Mapping[str, Any]) -> dict[str, Any]:
    if engine == "snort":
        source, destination = native.get("src_addr"), native.get("dst_addr")
        source_port, destination_port = native.get("src_port"), native.get("dst_port")
    else:
        source, destination = native.get("src_ip"), native.get("dest_ip")
        source_port, destination_port = native.get("src_port"), native.get("dest_port")
    source, destination = _address(source), _address(destination)
    icmp = (
        (native.get("icmp_type"), native.get("icmp_code"))
        if "icmp_type" in native else None
    )
    # ICMP type and code take the place of ports in the Community ID and in
    # the same-packet check.
    key_ports = (
        icmp if source_port is None and icmp is not None
        else (source_port, destination_port)
    )

    label, number = _protocol(native.get("proto"), source)
    flow_key = None
    if number is not None and source and destination:
        try:
            flow_key = community_id(
                source, key_ports[0], destination, key_ports[1], number
            )
        except (ValueError, TypeError):
            flow_key = None

    addressed = bool(source and destination)
    return {
        "protocol": label,
        "source": (source, source_port) if addressed else None,
        "destination": (destination, destination_port) if addressed else None,
        "icmp": icmp,
        "packet": (
            ((source, key_ports[0]), (destination, key_ports[1]))
            if addressed else None
        ),
        "community_id": flow_key,
    }


_HEADER_FIELDS = ("ip_id", "tcp_seq", "tcp_ack", "icmp_id", "icmp_seq")
_LINKTYPE_ETHERNET = 1
_LINKTYPES_RAW_IP = {12, 101}
_VLAN_ETHERTYPES = {0x8100, 0x88A8}
# IPv6 extension headers whose length is in 8-byte units after the first 8.
_IPV6_EXTENSIONS = {0, 43, 60}
_IPV6_FRAGMENT = 44


def _decode_header(data: bytes, linktype: Any) -> dict[str, int]:
    """IP ID, TCP sequence/acknowledgement and ICMP identifier/sequence of a
    raw packet (Suricata's eve ``packet``), the same values Snort writes."""
    offset = 0
    if linktype == _LINKTYPE_ETHERNET:
        offset = 14
        ethertype = int.from_bytes(data[12:14], "big") if len(data) >= 14 else None
        while ethertype in _VLAN_ETHERTYPES and len(data) >= offset + 4:
            ethertype = int.from_bytes(data[offset + 2:offset + 4], "big")
            offset += 4
        if ethertype not in {0x0800, 0x86DD}:
            return {}
    elif linktype not in _LINKTYPES_RAW_IP:
        return {}
    if len(data) < offset + 20:
        return {}

    header: dict[str, int] = {}
    version = data[offset] >> 4
    if version == 4:
        length = (data[offset] & 0x0F) * 4
        header["ip_id"] = int.from_bytes(data[offset + 4:offset + 6], "big")
        protocol = data[offset + 9]
        if int.from_bytes(data[offset + 6:offset + 8], "big") & 0x1FFF:
            return header  # a later fragment has no transport header
        offset += length
    elif version == 6 and len(data) >= offset + 40:
        protocol = data[offset + 6]
        offset += 40
        while len(data) >= offset + 8:
            if protocol in _IPV6_EXTENSIONS:
                protocol, offset = data[offset], offset + (data[offset + 1] + 1) * 8
            elif protocol == _IPV6_FRAGMENT:
                if int.from_bytes(data[offset + 2:offset + 4], "big") & 0xFFF8:
                    return header
                protocol, offset = data[offset], offset + 8
            else:
                break
    else:
        return {}

    if protocol == 6 and len(data) >= offset + 12:
        header["tcp_seq"] = int.from_bytes(data[offset + 4:offset + 8], "big")
        header["tcp_ack"] = int.from_bytes(data[offset + 8:offset + 12], "big")
    elif protocol in {1, 58} and len(data) >= offset + 8:
        header["icmp_id"] = int.from_bytes(data[offset + 4:offset + 6], "big")
        header["icmp_seq"] = int.from_bytes(data[offset + 6:offset + 8], "big")
    return header


def _packet_header(engine: str, native: Mapping[str, Any]) -> dict[str, int]:
    """Snort writes the header values itself (not for a reassembled TCP
    segment); Suricata writes the raw packet when eve's alert ``packet``
    option is on."""
    if engine == "snort":
        return {
            name: native[name]
            for name in _HEADER_FIELDS
            if isinstance(native.get(name), int) and not isinstance(native[name], bool)
        }
    packet = native.get("packet")
    if not isinstance(packet, str) or not packet:
        return {}
    try:
        data = base64.b64decode(packet, validate=True)
    except (ValueError, binascii.Error):
        return {}
    return _decode_header(data, _dict(native.get("packet_info")).get("linktype"))


def _rule_key(engine: str, row: Mapping[str, Any], native: Mapping[str, Any]) -> str:
    if row.get("rule_key"):
        return str(row["rule_key"])
    if engine == "snort":
        parts = (native.get("gid"), native.get("sid"), native.get("rev"))
    else:
        alert = _dict(native.get("alert"))
        parts = (alert.get("gid"), alert.get("signature_id"), alert.get("rev"))
    return ":".join([engine, *(str(part) for part in parts if part is not None)])


def _message(engine: str, row: Mapping[str, Any], native: Mapping[str, Any]) -> str:
    return str(
        row.get("msg")
        or (native.get("msg") if engine == "snort" else None)
        or _dict(native.get("alert")).get("signature")
        or ""
    )


def ids_output(engine: str, native: Mapping[str, Any]) -> dict[str, Any]:
    """The engine's own alert fields, without links, noise or empty values."""
    dropped = _DROPPED_FIELDS.get(engine, set())
    output = {
        key: value for key, value in native.items()
        if key not in dropped and _DEFAULT_VALUES.get(key) != value
    }
    # Snort writes the action at the top level, Suricata inside "alert".
    if is_pass_through_action(output.get("action")):
        del output["action"]
    alert = _dict(output.get("alert"))
    if alert:
        alert = {
            key: value for key, value in alert.items()
            if not (key == "action" and is_pass_through_action(value))
        }
        metadata = _dict(alert.get("metadata"))
        if metadata:
            alert["metadata"] = {
                key: (
                    [item for item in values if item not in _DROPPED_METADATA_VALUES]
                    if isinstance(values, list) else values
                )
                for key, values in metadata.items()
                if key not in _DROPPED_RULE_METADATA
                and _UNINFORMATIVE_METADATA.get(key) != values
            }
        output["alert"] = alert
    dns = _dict(output.get("dns"))
    if dns:
        output["dns"] = {
            key: value for key, value in dns.items()
            if key not in _DROPPED_DNS_FIELDS
        }
    # Snort's payload (b64_data) as text, as Suricata's payload_printable (9.3).
    if engine == "snort" and native.get("b64_data"):
        output["payload_printable"] = printable_payload(native["b64_data"])
    return prune_empty(drop_default_gid(strip_links(output)))


def printable_payload(encoded: Any) -> str:
    """Base64 bytes as text, the way Suricata writes payload_printable:
    printable ASCII, tabs and line breaks kept, every other byte a dot. ""
    when it isn't Base64."""
    try:
        raw = base64.b64decode(str(encoded), validate=True)
    except (ValueError, TypeError):
        return ""
    return "".join(
        chr(byte) if 32 <= byte < 127 or byte in (9, 10, 13) else "." for byte in raw
    )


# Fields of the IDS output that describe the rule. Each is given once, in the
# file's ``rules``, when it has the same value on every alert of that rule.
_RULE_FIELDS = {
    "snort": [("msg",), ("class",), ("priority",), ("gid",), ("sid",), ("rev",), ("rule",)],
    "suricata": [
        ("alert", "signature"), ("alert", "category"), ("alert", "severity"),
        ("alert", "gid"), ("alert", "signature_id"), ("alert", "rev"),
        ("alert", "metadata"),
    ],
}
# Fields of the IDS output that say what the packet is, by the packet's own
# field they repeat. Each is given once, with the packet, when it says the same.
_PACKET_FIELDS = {
    "snort": {
        "proto": "protocol", "src_addr": "src_address", "src_port": "src_port",
        "dst_addr": "dst_address", "dst_port": "dst_port",
        "icmp_type": "icmp_type", "icmp_code": "icmp_code",
    },
    "suricata": {
        "proto": "protocol", "src_ip": "src_address", "src_port": "src_port",
        "dest_ip": "dst_address", "dest_port": "dst_port",
        "icmp_type": "icmp_type", "icmp_code": "icmp_code",
    },
}
_MISSING = object()


def _get_path(value: Mapping[str, Any], path: tuple[str, ...]) -> Any:
    for key in path:
        if not isinstance(value, dict) or key not in value:
            return _MISSING
        value = value[key]
    return value


def _take_common(
    outputs: list[dict[str, Any]], paths: list[tuple[str, ...]]
) -> dict[str, Any]:
    """Remove the fields at ``paths`` that have one value on every output and
    return them, nested as in the output."""
    common: dict[str, Any] = {}
    if not outputs:
        return common
    for path in paths:
        values = [_get_path(output, path) for output in outputs]
        if _MISSING in values or any(value != values[0] for value in values[1:]):
            continue
        target = common
        for key in path[:-1]:
            target = target.setdefault(key, {})
        target[path[-1]] = values[0]
        for output in outputs:
            parent = output
            for key in path[:-1]:
                parent = parent[key]
            del parent[path[-1]]
    return common


def _native(row: Mapping[str, Any]) -> dict[str, Any]:
    native = row.get("native_event")
    if isinstance(native, dict):
        return native
    raw = row.get("raw_json")
    if isinstance(raw, str) and raw.strip():
        try:
            parsed = json.loads(raw)
        except ValueError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _to_match(row: Mapping[str, Any]) -> _Match | None:
    engine = str(row.get("engine") or "").strip().lower()
    if engine not in _ENGINE_ORDER:
        return None
    native = _native(row)
    if engine == "snort":
        time_us = snort_packet_time_us(native.get("timestamp"), row.get("event_ts_utc"))
    else:
        time_us = _parse_iso_us(native.get("timestamp"))
        if time_us is None and row.get("event_ts_utc") is not None:
            time_us = int(round(float(row["event_ts_utc"]) * 1000))
    if time_us is None:
        return None
    return _Match(
        engine=engine,
        time_us=time_us,
        rule_key=_rule_key(engine, row, native),
        native=native,
        header=_packet_header(engine, native),
        **_network(engine, native),
    )


def _same_endpoints(snort: _Match, suricata: _Match) -> bool:
    """Both engines name the same packet source and destination. A port (or
    ICMP type and code) is compared only when both engines report it."""
    for (snort_address, snort_port), (suricata_address, suricata_port) in zip(
        snort.packet, suricata.packet
    ):
        if snort_address != suricata_address:
            return False
        if None not in (snort_port, suricata_port) and snort_port != suricata_port:
            return False
    return True


def _shared_header(snort: _Match, suricata: _Match) -> list[str]:
    """Header values both engines give for their alert packet."""
    return [name for name in _HEADER_FIELDS if name in snort.header and name in suricata.header]


def _same_packet(snort: _Match, suricata: _Match) -> bool:
    """Alerts on one packet: at most _SAME_PACKET_TOLERANCE_US apart, with the
    same packet source and destination, and the same IP ID and TCP or ICMP
    sequence numbers wherever both engines give them. Alerts without IP
    addresses are never on the same packet: nothing ties one engine's to the
    other's (Snort's ARP checks and Suricata's unknown-Ethertype events see
    different frames). The engines' direction labels are not compared: each
    labels direction against its own idea of which side started the flow, and
    for ICMP they disagree."""
    if not (snort.packet and suricata.packet):
        return False
    if abs(snort.time_us - suricata.time_us) > _SAME_PACKET_TOLERANCE_US:
        return False
    if any(snort.header[name] != suricata.header[name] for name in _shared_header(snort, suricata)):
        return False
    return _same_endpoints(snort, suricata)


def _engine_packet_key(match: _Match) -> tuple[Any, ...]:
    """Alerts of one engine on one packet share this key: Snort's packet
    number and time (the number starts again when Snort restarts), or
    Suricata's packet time and raw packet."""
    if match.engine == "snort" and match.native.get("pkt_num") is not None:
        return (
            "pkt_num", match.native["pkt_num"], match.native.get("pkt_gen"), match.time_us,
        )
    return ("time", match.time_us, match.native.get("packet") or match.packet)


@dataclass
class _Packet:
    snort: list[_Match]
    suricata: list[_Match]

    @property
    def matches(self) -> list[_Match]:
        return [*self.snort, *self.suricata]


def _packets(matches: list[_Match]) -> list[_Packet]:
    """The packets the alerts are on, oldest first. A Snort packet and a
    Suricata packet are one packet when their first alerts pass _same_packet;
    each packet pairs with at most one of the other engine's, the closest in
    time first."""
    by_engine: dict[str, dict[tuple[Any, ...], list[_Match]]] = {"snort": {}, "suricata": {}}
    for match in sorted(matches, key=lambda match: match.time_us):
        by_engine[match.engine].setdefault(_engine_packet_key(match), []).append(match)
    snort_packets = list(by_engine["snort"].values())
    suricata_packets = list(by_engine["suricata"].values())

    suricata_times = [alerts[0].time_us for alerts in suricata_packets]
    pairs = []
    for i, left in enumerate(snort_packets):
        j = bisect.bisect_left(suricata_times, left[0].time_us - _SAME_PACKET_TOLERANCE_US)
        while j < len(suricata_times) and suricata_times[j] <= left[0].time_us + _SAME_PACKET_TOLERANCE_US:
            if _same_packet(left[0], suricata_packets[j][0]):
                pairs.append((abs(left[0].time_us - suricata_times[j]), i, j))
            j += 1
    # Closest pairs first.
    pairs.sort()
    packets: list[_Packet] = []
    used_snort: set[int] = set()
    used_suricata: set[int] = set()
    for _, i, j in pairs:
        if i not in used_snort and j not in used_suricata:
            used_snort.add(i)
            used_suricata.add(j)
            packets.append(_Packet(snort_packets[i], suricata_packets[j]))
    packets += [_Packet(alerts, []) for i, alerts in enumerate(snort_packets) if i not in used_snort]
    packets += [_Packet([], alerts) for j, alerts in enumerate(suricata_packets) if j not in used_suricata]
    packets.sort(key=lambda packet: (
        min(match.time_us for match in packet.matches), 0 if packet.snort else 1,
    ))
    return packets


_CVE_RE = re.compile(r"CVE[-_](\d{4})[-_](\d{4,})", re.IGNORECASE)


def _strings(value: Any) -> Iterable[str]:
    if isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)
    elif isinstance(value, str):
        yield value


def _cves_in(value: Any) -> set[str]:
    """CVE IDs written anywhere in a value (Suricata writes CVE_2014_6271)."""
    return {
        f"CVE-{year}-{number}"
        for text in _strings(value)
        for year, number in _CVE_RE.findall(text)
    }


def _cve_details(record: Mapping[str, Any]) -> dict[str, Any]:
    """Summary, CVSS, EPSS and CISA KEV status of one CVE."""
    nvd = _dict(record.get("nvd"))
    cvss = _dict(nvd.get("cvss"))
    epss = _dict(record.get("epss"))
    kev = _dict(record.get("cisa_kev"))
    details = {
        "summary": nvd.get("description"),
        "cvss": {
            "score": cvss.get("base_score"),
            "version": cvss.get("version"),
            "severity": cvss.get("base_severity"),
            "vector": cvss.get("vector"),
        } if cvss.get("base_score") is not None else None,
        "epss": {
            "score": epss.get("score"),
            "percentile": epss.get("percentile"),
        } if epss.get("score") is not None else None,
        "cisa_kev": {
            "date_added": kev.get("dateAdded"),
            "known_ransomware_use": (
                True
                if str(kev.get("knownRansomwareCampaignUse")).lower() == "known"
                else None
            ),
        } if kev else None,
    }
    return prune_empty(strip_links(details))


def _technique_details(records: Any) -> dict[str, Any]:
    """Name and tactics of one ATT&CK technique."""
    record = _dict(records[0] if isinstance(records, list) and records else records)
    return prune_empty({
        "name": record.get("name"),
        "tactics": list(record.get("tactics") or []),
    })


def _reference_cves(text: Any) -> set[str]:
    """The CVEs a rule's ``reference:cve,...`` options name."""
    return {
        f"CVE-{value[4:].strip()}"
        for name, value in _rule_options(text)
        if name == "reference" and value.lower().startswith("cve,")
    }


def _rule_options(text: Any) -> list[tuple[str, str]]:
    text = str(text or "")
    start, end = text.find("("), text.rfind(")")
    if start < 0 or end <= start:
        return []
    return [
        (match.group(1).lower(), str(match.group(2) or "").strip())
        for match in _RULE_OPTION_RE.finditer(text[start + 1:end])
    ]


def _rule_text(text: Any) -> str | None:
    """The rule as written in its rule file, without its web-link and CVE
    references (the file has no web links, and the rule's cves give its
    CVEs) and its metadata, which is rule upkeep or policy information or
    repeats Suricata's own alert metadata."""
    text = str(text or "").strip()
    start, end = text.find("("), text.rfind(")")
    if start < 0 or end <= start:
        return text or None
    body = text[start + 1:end]
    dropped = [
        match.span()
        for match in _RULE_OPTION_RE.finditer(body)
        if match.group(1).lower() == "metadata"
        or (
            match.group(1).lower() == "reference"
            and str(match.group(2) or "").strip().lower().startswith(("url", "cve,"))
        )
    ]
    for begin, finish in reversed(dropped):
        body = body[:begin] + body[finish:]
    return text[: start + 1] + body + text[end:]


def _one_line(text: Any) -> str:
    return " ".join(str(text or "").split())


# Section labels in a rule's published description (Talos rule documentation).
_DOC_SECTION_RE = re.compile(r"(?:^|\s)(Impact|Details|Ease of Attack):(?=\s|$)")
_DOC_SECTIONS = {"Impact": "impact", "Details": "details", "Ease of Attack": "ease_of_attack"}
_SENTENCE_END_RE = re.compile(r"(?<=[.!?])\s+")


def _documentation(documentation: Mapping[str, Any]) -> dict[str, Any]:
    """The rule's published documentation (Talos documents many Snort rules),
    each part on one line: its description, impact, details, ease of attack,
    what to look for and the type of vulnerability the rule covers."""
    pieces = _DOC_SECTION_RE.split(str(documentation.get("rule_explanation") or ""))
    parts: dict[str, Any] = {"description": pieces[0]}
    for label, body in zip(pieces[1::2], pieces[2::2]):
        parts[_DOC_SECTIONS[label]] = body
    parts["what_to_look_for"] = documentation.get("what_to_look_for")
    # Written as the vulnerability type, a blank line and a description of it.
    kind, _, about = str(documentation.get("rule_vulnerability") or "").strip().partition("\n")
    if _one_line(kind).upper() != "N/A":
        parts["vulnerability"] = {"type": kind, "description": about}
    return prune_empty({
        key: (
            {name: _one_line(strip_links(str(text))) for name, text in value.items()}
            if isinstance(value, dict)
            else _one_line(strip_links(str(value or "")))
        )
        for key, value in parts.items()
    })


def _rule_facts(
    intelligence: Mapping[str, Any] | None,
    native: Mapping[str, Any],
) -> dict[str, Any]:
    """What is known about one rule: offline intelligence plus the CVEs the
    engine itself wrote into the alert."""
    intelligence = _dict(intelligence)
    identifiers = _dict(intelligence.get("identifiers"))
    explanation = _dict(intelligence.get("explanation"))
    base = _dict(intelligence.get("base_intelligence"))
    documentation = _dict(base.get("documentation"))
    return {
        "cves": sorted(
            set(identifiers.get("cves") or [])
            | _cves_in([native.get("alert"), native.get("msg")])
            | _reference_cves(_dict(base.get("rule")).get("rule_text"))
        ),
        "attack_techniques": list(identifiers.get("mitre_attack") or []),
        "why_triggered": explanation.get("why_triggered"),
        "rule_text": _rule_text(_dict(base.get("rule")).get("rule_text")),
        "documentation": _documentation(documentation),
        # Talos generates the documentation of many CVE rules from NVD data.
        "documentation_from_nvd": "national vulnerability database"
        in _one_line(documentation.get("contributors")).lower(),
        "vulnerability_note": _one_line(documentation.get("rule_vulnerability")),
        "what_it_means": str(explanation.get("what_it_means") or ""),
        "known_usage": explanation.get("known_usage"),
        "false_positives": explanation.get("false_positives"),
        "what_to_check": [str(item) for item in explanation.get("what_to_check") or []],
        "recommended_actions": [
            str(item) for item in explanation.get("recommended_actions") or []
        ],
        "cve_details": {
            cve: _cve_details(_dict(record))
            for cve, record in _dict(intelligence.get("vulnerabilities")).items()
        },
        "technique_details": {
            technique: _technique_details(records)
            for technique, records in _dict(intelligence.get("mitre_enrichment")).items()
        },
    }


def _rule_section(facts: Mapping[str, Any]) -> dict[str, Any]:
    """Everything known about the rule, given with every alert it raised."""
    meaning = facts.get("what_it_means") or ""
    if meaning.startswith("The rule is associated with") or meaning in _GENERIC_SENTENCES:
        # Only lists the rule's CVEs (given below) plus a general caveat.
        meaning = ""
    elif meaning.endswith(MEANING_NOTE_CAVEAT):
        meaning = meaning[: -len(MEANING_NOTE_CAVEAT)].strip()
    if meaning and _one_line(meaning) == facts.get("vulnerability_note"):
        # The vulnerability type from the documentation, given there.
        meaning = ""

    def specific(items: Iterable[str]) -> list[str]:
        # The false-positive check only points at false_positives.
        return [
            item for item in items
            if item not in _GENERIC_SENTENCES
            and not item.startswith(CHECK_FALSE_POSITIVES)
        ]

    cve_details = facts.get("cve_details", {})
    documentation = dict(facts.get("documentation", {}))
    description = documentation.get("description", "")
    told = set(_SENTENCE_END_RE.split(description)) | set(
        _SENTENCE_END_RE.split(documentation.get("impact", ""))
    )
    if set(_SENTENCE_END_RE.split(documentation.get("details", ""))) <= told:
        # Details that only repeat the description and impact.
        documentation.pop("details", None)
    if documentation.get("what_to_look_for") == description:
        documentation.pop("what_to_look_for")
    summaries = {_one_line(details.get("summary")) for details in cve_details.values()} - {""}
    if summaries and (facts.get("documentation_from_nvd") or description in summaries):
        # A copy of a CVE's NVD summary and CVSS scores, given under cves.
        documentation.pop("description", None)
        if documentation.get("impact", "").startswith("CVSS "):
            documentation.pop("impact")
    why_triggered = str(facts.get("why_triggered") or "")
    why_triggered = _BUILTIN_RULE_NUMBER_RE.sub(
        r"\1:", why_triggered.replace(_BUILTIN_RULE_NOTE, "")
    )
    section = strip_links({
        "why_triggered": why_triggered,
        "what_it_means": meaning,
        "known_usage": facts.get("known_usage"),
        "false_positives": facts.get("false_positives"),
        "what_to_check": specific(facts.get("what_to_check", [])),
        "recommended_actions": [
            item for item in specific(facts.get("recommended_actions", []))
            if not item.startswith(_CVE_SCORE_ACTIONS)
        ],
        # Their details are given once, in the file's cves and
        # attack_techniques.
        "cves": list(facts.get("cves", [])),
        "attack_techniques": list(facts.get("attack_techniques", [])),
    })
    # The rule text skips strip_links: its web-link references are already
    # removed, and a link inside a content match is detection logic.
    return prune_empty({
        "why_triggered": section.pop("why_triggered", None),
        "rule_text": facts.get("rule_text"),
        "documentation": documentation,
        **section,
    })


def _alert_counts(matches: Iterable[_Match]) -> dict[str, int]:
    """Alerts per engine; an engine that raised none is left out."""
    counts = Counter(match.engine for match in matches)
    return {engine: counts[engine] for engine in _ENGINE_ORDER if counts[engine]}


def _rule_ids(rule_keys: Iterable[str]) -> dict[str, str]:
    """Short, readable rule names for the file: ``engine:sid``, with the GID
    when it is not the default 1 (``snort:116:408``). A rule that fired with
    two revisions in one window gets its revision too (``snort:31978:rev5``)."""
    names: dict[str, str] = {}
    for key in rule_keys:
        engine, *numbers = key.split(":")
        if len(numbers) >= 2 and numbers[0] == "1":
            numbers = numbers[1:]
        names[key] = ":".join([engine, *numbers[:-1]]) if len(numbers) >= 2 else key
    counts = Counter(names.values())
    return {
        key: f"{name}:rev{key.rsplit(':', 1)[-1]}" if counts[name] > 1 else name
        for key, name in names.items()
    }


def _same_as_packet(engine: str, field: str, value: Any, fact: Any) -> bool:
    if fact is None:
        return False
    if field in {"src_addr", "dst_addr", "src_ip", "dest_ip"}:
        # Suricata writes IPv6 in full, Snort and the packet in short form.
        return _address(value) == fact
    if field == "proto":
        # Suricata calls ICMPv6 "IPv6-ICMP". Snort calls IGMP "IP", which
        # names less than the packet does: kept.
        aliases = {
            name.upper(): alias
            for name, alias in _PROTOCOL_ALIASES.get(engine, {}).items()
        }
        return aliases.get(str(value).upper(), str(value)).upper() == str(fact).upper()
    return value == fact


def _packet_facts(packet: _Packet) -> dict[str, Any]:
    """What the packet is: protocol, addresses, ports, ICMP type and code."""
    matches = packet.matches
    # Snort reports IGMP as "IP", without a Community ID: the description of
    # an engine that gives a full protocol wins.
    anchor = next(
        (match for match in matches if match.community_id),
        next((match for match in matches if match.source), matches[0]),
    )
    icmp = next((match.icmp for match in matches if match.icmp), None)
    return {
        "protocol": anchor.protocol,
        "src_address": anchor.source[0] if anchor.source else None,
        "src_port": anchor.source[1] if anchor.source else None,
        "dst_address": anchor.destination[0] if anchor.destination else None,
        "dst_port": anchor.destination[1] if anchor.destination else None,
        "icmp_type": icmp[0] if icmp else None,
        "icmp_code": icmp[1] if icmp else None,
    }


def _flow_endpoints(output: Mapping[str, Any]) -> dict[str, str] | None:
    """The packet fact each of Suricata's flow addresses and ports repeats:
    the flow's source is the packet's source when the packet goes to the
    server, and its destination when the packet goes to the client."""
    direction = output.get("direction")
    if direction not in ("to_server", "to_client"):
        return None
    source, destination = ("src", "dst") if direction == "to_server" else ("dst", "src")
    return {
        "src_ip": f"{source}_address", "src_port": f"{source}_port",
        "dest_ip": f"{destination}_address", "dest_port": f"{destination}_port",
    }


def _without_packet_fields(
    engine: str, output: Mapping[str, Any], facts: Mapping[str, Any]
) -> dict[str, Any]:
    """The output without the fields that say what the packet is, which the
    packet gives once."""
    fields = _PACKET_FIELDS[engine]
    kept = {
        field: value for field, value in output.items()
        if not (
            field in fields
            and _same_as_packet(engine, field, value, facts[fields[field]])
        )
    }
    flow = _dict(kept.get("flow"))
    endpoints = _flow_endpoints(kept) if engine == "suricata" and flow else None
    if endpoints:
        kept["flow"] = {
            field: value for field, value in flow.items()
            if not (
                field in endpoints
                and _same_as_packet(engine, field, value, facts[endpoints[field]])
            )
        }
    return kept


def _flow_key(facts: Mapping[str, Any]) -> tuple[Any, ...] | None:
    """One connection: the same protocol between the same two endpoints,
    either way."""
    if not (facts["src_address"] and facts["dst_address"]):
        return None
    return (
        facts["protocol"],
        frozenset({
            (facts["src_address"], facts["src_port"]),
            (facts["dst_address"], facts["dst_port"]),
        }),
    )


def _leaf_paths(value: Mapping[str, Any], prefix: tuple[str, ...] = ()) -> list[tuple[str, ...]]:
    paths: list[tuple[str, ...]] = []
    for key, item in value.items():
        if isinstance(item, dict) and item:
            paths += _leaf_paths(item, prefix + (key,))
        else:
            paths.append(prefix + (key,))
    return paths


def _merged(*parts: Mapping[str, Any]) -> dict[str, Any]:
    """Deep-merged copy; later parts add to earlier ones."""
    merged: dict[str, Any] = {}
    for part in parts:
        for key, value in part.items():
            if isinstance(value, dict):
                merged[key] = _merged(_dict(merged.get(key)), value)
            else:
                merged[key] = value
    return merged


def _rule_wide(
    by_rule: Mapping[str, list[_Match]],
    packets: list[_Packet],
    outputs: Mapping[int, dict[str, Any]],
    packet_of: Mapping[int, int],
) -> dict[str, list[tuple[str, ...]]]:
    """The fields each rule takes from its alerts beyond those that describe
    it: those with one value on every alert of a rule that fired on more than
    one packet.

    An engine's alerts on one packet with the same output are one entry,
    which names all their rules. A field leaves such an entry only when every
    one of its rules takes it; otherwise the entry would split in two, and
    the fields left in both would be written twice. A rule that fired on one
    packet takes what the other rules of its entry take."""
    groups: dict[tuple[Any, ...], set[str]] = {}
    for index, packet in enumerate(packets):
        for match in packet.matches:
            entry = (
                index, match.engine, match.time_us,
                json.dumps(outputs[id(match)], sort_keys=True, default=str),
            )
            groups.setdefault(entry, set()).add(match.rule_key)

    # None: the rule fired on one packet, and takes what its entries allow.
    taken: dict[str, set[tuple[str, ...]] | None] = {}
    for key, rule_matches in by_rule.items():
        if len({packet_of[id(match)] for match in rule_matches}) < 2:
            taken[key] = None
            continue
        first = outputs[id(rule_matches[0])]
        taken[key] = {
            path for path in _leaf_paths(first)
            if all(
                _get_path(outputs[id(match)], path) == _get_path(first, path)
                for match in rule_matches[1:]
            )
        }

    def agree() -> None:
        # Every rule of an entry takes the same fields, the ones all of them
        # can take; repeated until no rule loses one.
        changed = True
        while changed:
            changed = False
            for rule_keys in groups.values():
                sets = [taken[key] for key in rule_keys if taken[key] is not None]
                if not sets:
                    continue
                shared = set.intersection(*sets)
                for key in rule_keys:
                    if taken[key] is not None and taken[key] != shared:
                        taken[key] = set(shared)
                        changed = True

    agree()
    for key in by_rule:
        if taken[key] is None:
            allowed = [
                set.intersection(*[taken[other] for other in rule_keys if taken[other] is not None])
                if any(taken[other] is not None for other in rule_keys) else set()
                for rule_keys in groups.values()
                if key in rule_keys
            ]
            taken[key] = set.intersection(*allowed) if allowed else set()
    agree()
    return {key: sorted(paths) for key, paths in taken.items()}


def _int(value: Any) -> Any:
    return int(value) if isinstance(value, str) and value.isdigit() else value


def _rule_name_ids(name: str) -> dict[str, Any]:
    """The GID (when not 1), SID and revision (when given) in a rule's name,
    such as ``snort:116:408`` or ``snort:31978:rev5``."""
    _, *parts = name.split(":")
    rev = int(parts.pop()[3:]) if parts and parts[-1].startswith("rev") else None
    gid, sid = (parts[0], parts[1]) if len(parts) == 2 else (None, parts[0] if parts else None)
    return {"gid": _int(gid), "sid": _int(sid), "rev": rev}


def _rule_text_option(text: Any, option: str) -> Any:
    match = _RULE_TEXT_OPTION_RES[option].search(str(text or ""))
    if not match:
        return None
    value = match.group(1)
    return int(value) if option == "rev" else re.sub(r"\\(.)", r"\1", value)


def _stated_rule_ids(name: str, rule_text: Any) -> dict[str, Any]:
    """The GID, SID, revision and message a rule's name and rule text give."""
    named = _rule_name_ids(name)
    return {
        "gid": named["gid"],
        "sid": named["sid"],
        "rev": named["rev"] if named["rev"] is not None else _rule_text_option(rule_text, "rev"),
        "msg": _rule_text_option(rule_text, "msg"),
    }


def _without_stated_rule_ids(engine: str, name: str, entry: Mapping[str, Any]) -> dict[str, Any]:
    """The rule's entry without the IDS output fields its name and rule text
    give (GID, SID, revision, message); Snort's ``rule`` field (gid:sid:rev)
    goes with them."""
    output = _merged(_dict(entry.get("ids_output")))
    if engine == "snort" and "gid" in output and output.get("rule") == (
        f"{output['gid']}:{output.get('sid')}:{output.get('rev')}"
    ):
        del output["rule"]
    stated = _stated_rule_ids(name, entry.get("rule_text"))
    for field, path in _RULE_ID_PATHS[engine].items():
        if stated[field] is not None and _get_path(output, path) == stated[field]:
            parent = output
            for key in path[:-1]:
                parent = parent[key]
            del parent[path[-1]]
    cleaned = prune_empty({**entry, "ids_output": output})
    # A rule entry is kept whole when nothing else would be left of it.
    return cleaned or dict(entry)


def _endpoint_parts(endpoint: Any) -> tuple[Any, Any]:
    if not endpoint:
        return None, None
    text = str(endpoint)
    if text.startswith("["):
        address, port = text[1:].split("]:")
        return address, int(port)
    if text.count(":") == 1:
        address, port = text.split(":")
        return address, int(port)
    return text, None


def rebuild_ids_output(
    document: Mapping[str, Any],
    packet: Mapping[str, Any],
    engine: str,
    entry: Mapping[str, Any],
    rule: str,
) -> dict[str, Any]:
    """One alert's whole IDS output from the file: its rule's part, its
    flow's part, its packet's shared part and its own part, then the fields
    its rule's name and rule text give and the fields that say what the
    packet is. Addresses come back in one spelling (IPv6 shortened)."""
    rule_entry = _dict(_dict(document.get("rules")).get(rule))
    flow = _dict(_dict(document.get("flows")).get(str(packet.get("flow"))))
    output = _merged(
        _dict(rule_entry.get("ids_output")),
        _dict(flow.get(engine)),
        _dict(_dict(packet.get("ids_output")).get(engine)),
        _dict(entry.get("ids_output")),
    )
    stated = _stated_rule_ids(rule, rule_entry.get("rule_text"))
    for field, path in _RULE_ID_PATHS[engine].items():
        if stated[field] is not None and _get_path(output, path) is _MISSING:
            parent = output
            for key in path[:-1]:
                parent = parent.setdefault(key, {})
            parent[path[-1]] = stated[field]
    if engine == "snort" and "gid" in output and "rule" not in output:
        output["rule"] = f"{output['gid']}:{output.get('sid')}:{output.get('rev')}"

    src_address, src_port = _endpoint_parts(packet.get("src"))
    dst_address, dst_port = _endpoint_parts(packet.get("dst"))
    facts = {
        "protocol": packet.get("protocol"),
        "src_address": src_address, "src_port": src_port,
        "dst_address": dst_address, "dst_port": dst_port,
        "icmp_type": packet.get("icmp_type"), "icmp_code": packet.get("icmp_code"),
    }
    spelling = {
        alias.upper(): name for name, alias in _PROTOCOL_ALIASES.get(engine, {}).items()
    }
    for field, fact in _PACKET_FIELDS[engine].items():
        if field not in output and facts[fact] is not None:
            value = facts[fact]
            output[field] = spelling.get(str(value).upper(), value) if field == "proto" else value
    flow_output = output.get("flow")
    endpoints = _flow_endpoints(output) if engine == "suricata" and isinstance(flow_output, dict) else None
    for field, fact in (endpoints or {}).items():
        if field not in flow_output and facts[fact] is not None:
            flow_output[field] = facts[fact]
    return output


def _packet_document(
    number: int,
    packet: _Packet,
    facts: Mapping[str, Any],
    flow: int | None,
    outputs: Mapping[int, dict[str, Any]],
    rule_ids: Mapping[str, str],
) -> dict[str, Any]:
    """One packet: what it is, its flow when the file's flows hold
    something about it, how the two engines' alerts were matched when both
    alerted, and each engine's part. An engine's alerts on the packet whose
    output is the same apart from the rule (several rules on one packet) are
    written once, with all their rules."""
    time_us = min(match.time_us for match in packet.matches)
    document: dict[str, Any] = {
        "packet": number,
        "time": _iso(time_us),
        # Left out when no engine names one (Suricata's unknown-Ethertype
        # events).
        "protocol": facts["protocol"],
        "src": _endpoint(facts["src_address"], facts["src_port"]) if facts["src_address"] else None,
        "dst": _endpoint(facts["dst_address"], facts["dst_port"]) if facts["dst_address"] else None,
        "icmp_type": facts["icmp_type"],
        "icmp_code": facts["icmp_code"],
        "flow": flow,
        # How the two engines' alerts were found to be on this packet.
        "matched_by": (
            (
                "headers" if _shared_header(packet.snort[0], packet.suricata[0])
                else "time_and_addresses"
            )
            if packet.snort and packet.suricata else None
        ),
        # Per engine with more than one entry: the output its entries share.
        "ids_output": {},
    }
    for engine in _ENGINE_ORDER:
        entries: dict[tuple[Any, ...], dict[str, Any]] = {}
        for match in getattr(packet, engine):
            output = outputs[id(match)]
            entry = entries.setdefault(
                (match.time_us, json.dumps(output, sort_keys=True, default=str)),
                {
                    # The engine's own stamp, when it differs from the packet's.
                    "time": _iso(match.time_us) if match.time_us != time_us else None,
                    "rules": [],
                    "ids_output": output,
                },
            )
            if match.rule_key in rule_ids:
                entry["rules"].append(rule_ids[match.rule_key])
        document[engine] = list(entries.values())
        if len(document[engine]) > 1:
            # Alerts on the packet whose outputs differ are separate entries;
            # what they have in common is given once, with the packet.
            entry_outputs = [entry["ids_output"] for entry in document[engine]]
            document["ids_output"][engine] = _take_common(
                entry_outputs, _leaf_paths(entry_outputs[0])
            )
    return document


def _window_matches(
    rows: Iterable[Mapping[str, Any]],
    window_start: datetime,
    window_end: datetime,
) -> list[_Match]:
    """The rows' alerts whose packet time is inside the window."""
    start_us, end_us = _epoch_us(window_start), _epoch_us(window_end)
    return [
        match for match in (_to_match(row) for row in rows)
        if match is not None and start_us <= match.time_us <= end_us
    ]


def packet_counts(
    rows: Iterable[Mapping[str, Any]],
    *,
    window_start: datetime,
    window_end: datetime,
    rule_pairs: int = 0,
) -> dict[str, Any]:
    """The counts the combined document for this window gives, without
    building it: alerts per engine (an engine that raised none is left out),
    the packets they are on, and how many of those packets both engines,
    only Snort or only Suricata alerted on. With ``rule_pairs``, also that
    many ``pairs``: a Snort rule and a Suricata rule that fired on one
    packet, with how many packets, the most first."""
    packets = _packets(_window_matches(rows, window_start, window_end))
    counts: dict[str, Any] = {
        "alerts": _alert_counts(
            match for packet in packets for match in packet.matches
        ),
        "packets": len(packets),
        "both": sum(bool(packet.snort and packet.suricata) for packet in packets),
        "snort_only": sum(bool(packet.snort and not packet.suricata) for packet in packets),
        "suricata_only": sum(bool(packet.suricata and not packet.snort) for packet in packets),
    }
    if rule_pairs:
        counts["pairs"] = _rule_pairs(packets)[:rule_pairs]
    return counts


def _rule_pairs(packets: list[_Packet]) -> list[dict[str, Any]]:
    """Each Snort rule and Suricata rule that fired on one packet, with how
    many packets they did: the most first. A packet with two rules of an
    engine counts for each of them."""
    pairs: Counter[tuple[str, str]] = Counter()
    rules: dict[str, dict[str, Any]] = {}
    for packet in packets:
        if not (packet.snort and packet.suricata):
            continue
        for match in packet.matches:
            if match.rule_key not in rules:
                numbers = [int(part) if part.isdigit() else None for part in match.rule_key.split(":")[1:4]]
                gid, sid, rev = [*numbers, None, None, None][:3]
                rules[match.rule_key] = {
                    "gid": gid,
                    "sid": sid,
                    "rev": rev,
                    "message": _message(match.engine, {}, match.native).strip(),
                }
        pairs.update(
            (snort, suricata)
            for snort in sorted({match.rule_key for match in packet.snort})
            for suricata in sorted({match.rule_key for match in packet.suricata})
        )
    return [
        {"snort": rules[snort], "suricata": rules[suricata], "packets": count}
        for (snort, suricata), count in sorted(pairs.items(), key=lambda item: (-item[1], item[0]))
    ]


def both_engine_alerts(rows: Iterable[Mapping[str, Any]]) -> set[Any]:
    """The ``id`` of each row whose packet both engines alerted on, matched
    as in the combined document. The rows must hold the other engine's
    alerts near each row asked about: those within a millisecond of it."""
    matches = [(row["id"], match) for row in rows if (match := _to_match(row)) is not None]
    on_both = {
        id(match)
        for packet in _packets([match for _, match in matches])
        if packet.snort and packet.suricata
        for match in packet.matches
    }
    return {row_id for row_id, match in matches if id(match) in on_both}


def alert_packets(rows: Iterable[Mapping[str, Any]]) -> dict[Any, tuple[Any, bool]]:
    """For each row's ``id``: the packet its alert is on, named by the lowest
    id of that packet's alerts, and whether both engines alerted on it,
    matched as in the combined document. Nothing is stored: the same rows
    give the same packets. The rows must hold the other alerts near each row
    asked about: those within a millisecond of it."""
    matches = [(row["id"], match) for row in rows if (match := _to_match(row)) is not None]
    ids = {id(match): row_id for row_id, match in matches}
    found = {}
    for packet in _packets([match for _, match in matches]):
        name = min(ids[id(match)] for match in packet.matches)
        both = bool(packet.snort and packet.suricata)
        for match in packet.matches:
            found[ids[id(match)]] = (name, both)
    return found


def build_combined_detections(
    rows: Iterable[Mapping[str, Any]],
    *,
    window_start: datetime,
    window_end: datetime,
    length_label: str | None = None,
    rule_intelligence: Callable[[str, Any, Any, str], Mapping[str, Any] | None] | None = None,
    generated_at: datetime | None = None,
    trim_to_window: bool = True,
) -> dict[str, Any]:
    """Build the combined Snort + Suricata document for one time window.

    ``rows`` are alert rows with ``engine``, ``event_ts_utc`` and the native
    event (``raw_json`` text or a ``native_event`` dict). ``rule_intelligence``
    is called once per rule with (engine, gid, sid, message) and returns the
    offline intelligence for that rule. With ``trim_to_window`` false every
    row is kept: the caller chose them (the window then only says when).

    The document is a timeline of the packets the alerts are on, oldest
    first; a packet both engines alerted on is one entry with both engines'
    parts. Every alert is listed.
    """
    if trim_to_window:
        matches = _window_matches(rows, window_start, window_end)
    else:
        matches = [match for match in map(_to_match, rows) if match is not None]
    packets = _packets(matches)

    rule_facts: dict[str, dict[str, Any]] = {}
    for match in matches:
        if match.rule_key in rule_facts:
            continue
        intelligence = None
        if rule_intelligence is not None:
            if match.engine == "snort":
                gid, sid = match.native.get("gid"), match.native.get("sid")
            else:
                alert = _dict(match.native.get("alert"))
                gid, sid = alert.get("gid"), alert.get("signature_id")
            intelligence = rule_intelligence(
                match.engine, gid, sid, _message(match.engine, {}, match.native)
            )
        rule_facts[match.rule_key] = _rule_facts(intelligence, match.native)

    # Each alert's IDS output, without the fields that say what its packet
    # is: the packet gives them once.
    facts = [_packet_facts(packet) for packet in packets]
    outputs: dict[int, dict[str, Any]] = {}
    packet_of: dict[int, int] = {}
    for index, packet in enumerate(packets):
        for match in packet.matches:
            outputs[id(match)] = _without_packet_fields(
                match.engine, ids_output(match.engine, match.native), facts[index]
            )
            packet_of[id(match)] = index

    # A field with one value on every alert of a rule is given once, in the
    # rule's entry: the fields that describe the rule always, and the other
    # fields _rule_wide picks.
    by_rule: dict[str, list[_Match]] = {}
    for match in matches:
        by_rule.setdefault(match.rule_key, []).append(match)
    common = {
        key: _take_common(
            [outputs[id(match)] for match in rule_matches],
            _RULE_FIELDS[rule_matches[0].engine],
        )
        for key, rule_matches in by_rule.items()
    }
    outputs = {key: prune_empty(output) for key, output in outputs.items()}
    for key, paths in _rule_wide(by_rule, packets, outputs, packet_of).items():
        if paths:
            common[key] = _merged(
                common[key],
                _take_common([outputs[id(match)] for match in by_rule[key]], paths),
            )
    outputs = {key: prune_empty(output) for key, output in outputs.items()}
    rule_entries = {
        key: prune_empty({"ids_output": common[key], **_rule_section(rule_facts[key])})
        for key in by_rule
    }
    # An alert names its rule only when the file holds something about it.
    rule_ids = {
        key: name
        for key, name in _rule_ids(rule_entries).items()
        if rule_entries[key]
    }

    # A field with one value on every alert of an engine on one connection is
    # given once, in the file's flows, when the engine alerted on more than
    # one packet of it.
    by_flow: dict[tuple[Any, ...], list[int]] = {}
    for index, packet_facts in enumerate(facts):
        flow_key = _flow_key(packet_facts)
        if flow_key is not None:
            by_flow.setdefault(flow_key, []).append(index)
    flow_parts: dict[tuple[Any, ...], dict[str, Any]] = {}
    for flow_key, indexes in by_flow.items():
        parts = {}
        for engine in _ENGINE_ORDER:
            engine_matches = [
                match for index in indexes for match in getattr(packets[index], engine)
            ]
            if len({packet_of[id(match)] for match in engine_matches}) > 1:
                engine_outputs = [outputs[id(match)] for match in engine_matches]
                parts[engine] = _take_common(engine_outputs, _leaf_paths(engine_outputs[0]))
        parts = prune_empty(parts)
        if parts:
            flow_parts[flow_key] = parts
    outputs = {key: prune_empty(output) for key, output in outputs.items()}
    flow_numbers: dict[tuple[Any, ...], int] = {}
    for packet_facts in facts:
        flow_key = _flow_key(packet_facts)
        if flow_key in flow_parts and flow_key not in flow_numbers:
            flow_numbers[flow_key] = len(flow_numbers) + 1

    # Each CVE and ATT&CK technique once, however many rules name it.
    named = [rule_facts[key] for key in rule_ids]
    cves = {
        cve: details
        for rule in named
        for cve in rule.get("cves", [])
        if (details := rule.get("cve_details", {}).get(cve))
    }
    techniques = {
        technique: details
        for rule in named
        for technique in rule.get("attack_techniques", [])
        if (details := rule.get("technique_details", {}).get(technique))
    }

    length = length_label or _length_label(window_end - window_start)
    created = generated_at or datetime.now(tz=PKT)

    document = {
        "schema": SCHEMA_ID,
        "schema_version": SCHEMA_VERSION,
        "generated_at": created.astimezone(PKT).isoformat(timespec="seconds"),
        "window": {
            "start": window_start.astimezone(PKT).isoformat(timespec="seconds"),
            "end": window_end.astimezone(PKT).isoformat(timespec="seconds"),
            "length": length,
        },
        "alerts": _alert_counts(matches),
        # Each rule once for the whole file, by the name its alerts give: the
        # IDS output fields it gives on every alert, and its enrichment.
        "rules": {
            name: _without_stated_rule_ids(by_rule[key][0].engine, name, rule_entries[key])
            for key, name in sorted(rule_ids.items(), key=lambda item: item[1])
        },
        "cves": dict(sorted(cves.items())),
        "attack_techniques": dict(sorted(techniques.items())),
        "flows": {
            str(number): flow_parts[flow_key] for flow_key, number in flow_numbers.items()
        },
        "packets": [
            _packet_document(
                number, packet, facts[index],
                flow_numbers.get(_flow_key(facts[index])), outputs, rule_ids,
            )
            for index, (number, packet) in enumerate(enumerate(packets, start=1))
        ],
    }
    return prune_empty(document)


def _length_label(length: timedelta) -> str:
    for label, value in WINDOW_LENGTHS.items():
        if value == length:
            return label
    minutes = int(length.total_seconds() // 60)
    return f"{minutes} minutes"


def window_bounds(end: datetime, length_label: str) -> tuple[datetime, datetime]:
    """Start and end of a window that ends at ``end`` and lasts ``length_label``."""
    if end.tzinfo is None:
        end = end.replace(tzinfo=PKT)
    return end - WINDOW_LENGTHS[length_label], end


def load_window_rows(
    db_path: Path | str,
    window_start: datetime,
    window_end: datetime,
    engines: Sequence[str] = KNOWN_ENGINES,
) -> list[dict[str, Any]]:
    """Read-only query of every stored rule match of the ``engines`` inside
    the window.

    ``event_ts_utc`` is in milliseconds; one extra millisecond on each side
    covers its rounding, and the builder applies the exact bounds.
    """
    start_ms = math.floor(_epoch_us(window_start) / 1000) - 1
    end_ms = math.ceil(_epoch_us(window_end) / 1000) + 1
    connection = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5)
    try:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            f"""
            SELECT id, engine, event_ts_utc, msg, rule_key, raw_json
            FROM alerts
            WHERE event_ts_utc BETWEEN ? AND ?
              AND engine IN ({", ".join("?" for _ in engines)})
            ORDER BY event_ts_utc, id
            """,
            (start_ms, end_ms, *engines),
        ).fetchall()
    finally:
        connection.close()
    return [dict(row) for row in rows]


def newest_event_times(
    db_path: Path | str, engines: Sequence[str] = KNOWN_ENGINES,
) -> dict[str, datetime]:
    """Time of each engine's newest stored rule match, in PKT, for the
    ``engines`` this machine runs: an engine it no longer runs must not hold
    the windows back at its last alert. An engine with no stored match is
    left out."""
    connection = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5)
    try:
        rows = connection.execute(
            f"""
            SELECT engine, MAX(event_ts_utc)
            FROM alerts
            WHERE engine IN ({", ".join("?" for _ in engines)})
            GROUP BY engine
            """,
            tuple(engines),
        ).fetchall()
    finally:
        connection.close()
    return {
        engine: datetime.fromtimestamp(float(value) / 1000, tz=PKT)
        for engine, value in rows
        if value is not None
    }


def complete_window_end(newest: Mapping[str, datetime]) -> datetime | None:
    """Latest window end up to which every engine's rule matches are stored:
    the last whole second before the oldest of the engines' newest stored
    matches (``newest_event_times``).

    One engine's newest alerts can be stored after the other's: while it or
    the collector restarts, or with Snort's default pcap DAQ, which on a
    quiet network held its alerts for minutes by reading packets 64 at a
    time (the lab's Snort reads them with afpacket, which writes each alert
    within a second). A window running into that time would show packets
    both engines alerted on as one engine's only. Each engine stores its
    alerts in time order (Suricata's worker threads a fraction of a second
    apart at most), so the alerts before the older newest match are stored.
    The second of that match is left for a later window: one packet's
    alerts can be stored a moment apart.
    """
    if not newest:
        return None
    # The stored times are rounded to the millisecond; one millisecond less
    # keeps the end before the match's exact time.
    return (min(newest.values()) - timedelta(milliseconds=1)).replace(microsecond=0)


def serialize_combined_detections(document: Mapping[str, Any]) -> str:
    """JSON indented with two spaces, so that it is laid out the same in
    every editor and browser (compact JSON is one long line in most of
    them); about 1.8 times the compact size."""
    return json.dumps(document, ensure_ascii=False, indent=2) + "\n"


def combined_filename(window_start: datetime, length_label: str) -> str:
    slug = re.sub(r"[^0-9a-z]+", "", length_label.lower().replace("minutes", "min"))
    return (
        f"snort_suricata_combined_"
        f"{window_start.astimezone(PKT):%Y%m%d_%H%M}_{slug}.json"
    )
