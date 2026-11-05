from __future__ import annotations

import base64
import hashlib
import ipaddress
import struct


COMMUNITY_ID_VERSION = 1
DEFAULT_SEED = 0


_PROTOCOL_NUMBERS = {
    "ICMP": 1,
    "TCP": 6,
    "UDP": 17,
    "IGMP": 2,
    "ICMPV6": 58,
    "ICMP6": 58,
    "IPV6-ICMP": 58,
    "SCTP": 132,
}

# Only these protocols hash port values (ICMP types/codes stand in for ports).
_PORT_PROTOCOLS = {1, 6, 17, 58, 132}

# ICMP message types with a reply counterpart; all other types are one-way.
_ICMP_COUNTERPARTS = {
    8: 0, 0: 8, 13: 14, 14: 13, 15: 16, 16: 15, 10: 9, 9: 10, 17: 18, 18: 17,
}
_ICMPV6_COUNTERPARTS = {
    128: 129, 129: 128, 130: 131, 131: 130, 133: 134, 134: 133,
    135: 136, 136: 135, 139: 140, 140: 139, 144: 145, 145: 144,
}


def protocol_number(
    protocol: str | int | None,
) -> int:
    if isinstance(protocol, int):
        if 0 <= protocol <= 255:
            return protocol

        raise ValueError(
            f"Protocol number out of range: {protocol}"
        )

    if protocol is None:
        raise ValueError(
            "Protocol is required"
        )

    value = str(protocol).strip().upper()

    if value in _PROTOCOL_NUMBERS:
        return _PROTOCOL_NUMBERS[value]

    try:
        number = int(value)
    except ValueError as exc:
        raise ValueError(
            f"Unsupported protocol: {protocol!r}"
        ) from exc

    if not 0 <= number <= 255:
        raise ValueError(
            f"Protocol number out of range: {number}"
        )

    return number


def _address_bytes(
    ip: str,
) -> bytes:
    return ipaddress.ip_address(ip).packed


def _canonical_flow(
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
) -> tuple[bytes, bytes, int, int]:
    """
    Return the flow endpoints in canonical order.

    Ordering is based on the IP addresses first. When the IPs are equal,
    ports provide the tie-breaker.
    """
    src = _address_bytes(src_ip)
    dst = _address_bytes(dst_ip)

    if not 0 <= src_port <= 65535:
        raise ValueError(
            f"Source port out of range: {src_port}"
        )

    if not 0 <= dst_port <= 65535:
        raise ValueError(
            f"Destination port out of range: {dst_port}"
        )

    if src < dst:
        return (
            src,
            dst,
            src_port,
            dst_port,
        )

    if src > dst:
        return (
            dst,
            src,
            dst_port,
            src_port,
        )

    # Same IP: use ports to make the ordering deterministic.
    if src_port <= dst_port:
        return (
            src,
            dst,
            src_port,
            dst_port,
        )

    return (
        dst,
        src,
        dst_port,
        src_port,
    )


def community_id(
    src_ip: str,
    src_port: int | None,
    dst_ip: str,
    dst_port: int | None,
    protocol: str | int,
    *,
    seed: int = DEFAULT_SEED,
) -> str:
    """
    Calculate Community ID version 1.

    Input layout:

        2-byte seed
        source address
        destination address
        1-byte protocol
        1-byte zero padding
        2-byte source port
        2-byte destination port

    The endpoint order is canonicalized so reversing the packet direction
    produces the same Community ID.

    For ICMP and ICMPv6, pass the message type as src_port and the code as
    dst_port. As in the specification, a request/reply type is hashed with
    its counterpart type so both directions match, and other types are
    one-way (kept in the given order). Protocols without ports, such as
    IGMP, hash the addresses and protocol only.
    """
    if not 0 <= seed <= 65535:
        raise ValueError(
            f"Seed out of range: {seed}"
        )

    proto = protocol_number(protocol)

    src_port = (
        0
        if src_port is None
        else int(src_port)
    )

    dst_port = (
        0
        if dst_port is None
        else int(dst_port)
    )

    one_way = False
    if proto in (1, 58):
        counterparts = (
            _ICMP_COUNTERPARTS if proto == 1 else _ICMPV6_COUNTERPARTS
        )
        if src_port in counterparts:
            dst_port = counterparts[src_port]
        else:
            one_way = True

    has_ports = proto in _PORT_PROTOCOLS
    if not has_ports:
        src_port = dst_port = 0

    if one_way:
        (
            source_address,
            destination_address,
            source_port,
            destination_port,
        ) = (
            _address_bytes(src_ip),
            _address_bytes(dst_ip),
            src_port,
            dst_port,
        )
    else:
        (
            source_address,
            destination_address,
            source_port,
            destination_port,
        ) = _canonical_flow(
            src_ip,
            src_port,
            dst_ip,
            dst_port,
        )

    payload = (
        struct.pack(
            "!H",
            seed,
        )
        + source_address
        + destination_address
        + struct.pack(
            "!B",
            proto,
        )
        + b"\x00"
    )
    if has_ports:
        payload += struct.pack(
            "!HH",
            source_port,
            destination_port,
        )

    digest = hashlib.sha1(
        payload
    ).digest()

    encoded = base64.b64encode(
        digest
    ).decode("ascii")

    return (
        f"{COMMUNITY_ID_VERSION}:{encoded}"
    )
