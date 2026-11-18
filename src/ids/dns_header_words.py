"""What the bytes a DNS rule tests mean, read as the DNS header (RFC 1035,
section 4.1.1).

A UDP rule on port 53 that looks at fixed places at the start of the
payload (a regular expression anchored with ^, or a content match with an
offset) is testing the DNS header: bytes 1-2 are the transaction ID,
bytes 3-4 the flags and response code, bytes 5-12 four counts. Rule
2001119's /^..[\\x81-\\x87]\\x85/ reads: any ID; a response to a standard
query with at least one of AA, TC or RD set; recursion available, response
code 5 (Refused).
"""

from __future__ import annotations

import re
import warnings
from typing import Any

try:  # The parser behind re, in Python 3.11 and later.
    from re import _constants as _codes, _parser
except ImportError:  # pragma: no cover
    _codes = _parser = None

HEADER_BYTES = 12
_ALL = frozenset(range(256))

OPCODES = {
    0: ("a standard query", "QUERY"),
    1: ("an inverse query", "IQUERY"),
    2: ("a server status request", "STATUS"),
    4: ("a zone change notice", "NOTIFY"),
    5: ("a dynamic update", "UPDATE"),
    6: ("a DNS stateful operation", "DSO"),
}
RCODES = {
    0: "0, NoError (no error)",
    1: "1, FormErr (the server could not read the query)",
    2: "2, ServFail (the server failed to answer)",
    3: "3, NXDomain (the name does not exist)",
    4: "4, NotImp (the server does not support this kind of query)",
    5: "5, Refused (the server refused to answer)",
    6: "6, YXDomain (a name exists that should not)",
    7: "7, YXRRSet (a record set exists that should not)",
    8: "8, NXRRSet (a record set that should exist does not)",
    9: "9, NotAuth (the server is not authoritative for the zone)",
    10: "10, NotZone (the name is not in the zone)",
}
_HIGH_FLAGS = (
    (0x04, "AA (authoritative answer)"),
    (0x02, "TC (truncated)"),
    (0x01, "RD (recursion desired)"),
)
_LOW_FLAGS = (
    (0x80, "RA (recursion available)"),
    (0x20, "AD (authenticated data)"),
    (0x10, "CD (checking disabled)"),
)
_COUNTS = {4: "question count", 6: "answer count", 8: "authority record count", 10: "additional record count"}

_OPTION_RE = re.compile(r'\s*([A-Za-z_][\w.-]*)\s*(?::\s*((?:"(?:[^"\\]|\\.)*"|[^;])*))?;')
_HEADER_RE = re.compile(r"^\s*\w+\s+(\S+)\s+\S+\s+(\S+)\s+(?:->|<>)\s+\S+\s+(\S+)\s*\(")
# Options after which a content or pcre no longer looks at the payload itself.
_BUFFERS = re.compile(r"^(?:http|tls|dns|file|ja3|ssh|smb|krb5|sip|dce|ftp|smtp|pkt_data$|raw_data$|base64_data$|js_data$|app-layer)")


def _hex_content(value: str) -> list[int] | None:
    """A content value's bytes (|01 00|abc), or None if it is not readable."""
    match = re.match(r'^"((?:[^"\\]|\\.)*)"', value.strip())
    if not match:
        return None
    text, out, index = match.group(1), [], 0
    while index < len(text):
        char = text[index]
        if char == "|":
            end = text.find("|", index + 1)
            if end < 0:
                return None
            try:
                out.extend(bytes.fromhex("".join(text[index + 1:end].split())))
            except ValueError:
                return None
            index = end + 1
            continue
        if char == "\\" and index + 1 < len(text):
            index += 1
            char = text[index]
        out.append(ord(char))
        index += 1
    return out


_ANY_BUT_NEWLINE = _ALL - {0x0A}


def _item_set(op: Any, value: Any, dotall: bool = False) -> frozenset[int] | None:
    """The bytes one single-byte regular-expression item matches; "." is
    any byte but 0x0a unless the s modifier is given."""
    if op is _codes.LITERAL:
        return frozenset({value})
    if op is _codes.NOT_LITERAL:
        return _ALL - {value}
    if op is _codes.ANY:
        return _ALL if dotall else _ANY_BUT_NEWLINE
    if op is _codes.IN:
        chosen: set[int] = set()
        negate = False
        for kind, item in value:
            if kind is _codes.NEGATE:
                negate = True
            elif kind is _codes.LITERAL:
                chosen.add(item)
            elif kind is _codes.RANGE:
                chosen.update(range(item[0], item[1] + 1))
            else:
                return None
        return frozenset(_ALL - chosen if negate else chosen)
    return None


def _pcre_start(value: str) -> dict[int, frozenset[int]]:
    """The bytes a ^-anchored payload regular expression allows at each of
    the first places it fixes."""
    match = re.match(r'^"/(.*)/([A-Za-z]*)"$', value.strip(), re.S)
    if not match or _parser is None:
        return {}
    pattern, flags = match.groups()
    if set(flags) - set("sAGOB"):  # case, buffers, R (relative), m, x
        return {}
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            parsed = list(_parser.parse(pattern.encode("latin-1"), 0))
    except Exception:
        return {}
    if "A" not in flags:
        if not parsed or parsed[0] != (_codes.AT, _codes.AT_BEGINNING):
            return {}
        parsed = parsed[1:]
    places: dict[int, frozenset[int]] = {}
    offset = 0
    for op, value in parsed:
        repeat, item = 1, (op, value)
        if op in (_codes.MAX_REPEAT, _codes.MIN_REPEAT):
            low, high, inner = value
            if low != high or len(inner) != 1:
                break
            repeat, item = low, list(inner)[0]
        allowed = _item_set(*item, dotall="s" in flags)
        if allowed is None:
            break
        for _ in range(repeat):
            places[offset] = allowed
            offset += 1
        if offset >= HEADER_BYTES:
            break
    return places


def _number(options: str, name: str) -> int | None:
    match = re.search(rf"(?:^|[\s,;]){name}[\s:]+(\d+)", options)
    return int(match.group(1)) if match else None


def header_places(rule_text: str) -> dict[int, frozenset[int]]:
    """For a UDP rule on port 53: the DNS header places (0 to 11) its
    payload matches fix, and the bytes each allows."""
    header = _HEADER_RE.match(rule_text or "")
    # Port 53 itself, not a list that has it: [53,443,9000] is often not DNS.
    if not header or header.group(1).lower() != "udp" or "53" not in (header.group(2), header.group(3)):
        return {}
    start, end = rule_text.find("("), rule_text.rfind(")")
    options = [(m.group(1).lower(), (m.group(2) or "").strip()) for m in _OPTION_RE.finditer(rule_text[start + 1:end])]
    places: dict[int, frozenset[int]] = {}
    for index, (name, value) in enumerate(options):
        if _BUFFERS.match(name) and not value:
            break  # a sticky buffer: what follows is not the payload
        if name == "content" and not value.startswith("!"):
            data = _hex_content(value)
            # Its modifiers: in the value (Snort 3) or the options after it.
            tail = value
            for later, later_value in options[index + 1:]:
                if later in ("content", "pcre"):
                    break
                tail += f"; {later} {later_value}"
            if data is None or re.search(r"\b(distance|within|nocase)\b", tail):
                continue
            offset = _number(tail, "offset")
            if _number(tail, "depth") != len(data):
                continue  # it may sit anywhere in a longer stretch
            for position, code in enumerate(data, start=offset or 0):
                if position < HEADER_BYTES:
                    places[position] = frozenset({code})
        elif name == "pcre" and not value.startswith("!"):
            for position, allowed in _pcre_start(value).items():
                places.setdefault(position, allowed)
    return places


def _bytes_seen(allowed: frozenset[int]) -> str:
    values = sorted(allowed)
    if len(values) == 1:
        return f"0x{values[0]:02x}"
    if values == list(range(values[0], values[-1] + 1)):
        return f"0x{values[0]:02x} to 0x{values[-1]:02x}"
    return ", ".join(f"0x{value:02x}" for value in values)


def _flags(allowed: frozenset[int], flags: tuple[tuple[int, str], ...]) -> list[str]:
    """Each flag set in every allowed value, clear in every one, or the
    combinations the values leave."""
    words, varying = [], []
    for bit, name in flags:
        states = {bool(value & bit) for value in allowed}
        if states == {True}:
            words.append(f"{name} set")
        elif states == {False}:
            words.append(f"{name} not set")
        else:
            varying.append((bit, name))
    if varying:
        mask = sum(bit for bit, _ in varying)
        combos = {value & mask for value in allowed}
        names = [name for _, name in varying]
        listed = ", ".join(names[:-1]) + f" or {names[-1]}" if len(names) > 1 else names[0]
        if len(combos) == 2 ** len(varying):
            words.append(f"{listed} set or not")
        elif 0 not in combos and len(combos) == 2 ** len(varying) - 1:
            words.append(f"at least one of {listed} set")
        else:
            words.append(f"{listed} in the combinations those values give")
    return words


def _high_byte(allowed: frozenset[int]) -> str:
    parts = []
    kinds = {bool(value & 0x80) for value in allowed}
    if kinds == {True}:
        parts.append("a response (QR=1)")
    elif kinds == {False}:
        parts.append("a query (QR=0),")
    opcodes = sorted({(value >> 3) & 0x0F for value in allowed})
    if len(opcodes) == 1:
        prefix = "to " if kinds == {True} else ""
        words, name = OPCODES.get(opcodes[0], (f"opcode {opcodes[0]}", ""))
        parts.append(f"{prefix}{words} (opcode {opcodes[0]}{', ' + name if name else ''})")
    text = " ".join(parts)
    flags = _flags(allowed, _HIGH_FLAGS)
    return text + (", with " + ", ".join(flags) if flags else "")


def _low_byte(allowed: frozenset[int]) -> str:
    parts = _flags(allowed, _LOW_FLAGS)
    zs = {bool(value & 0x40) for value in allowed}
    if zs == {True}:
        parts.append("the reserved Z bit set (it should be 0)")
    codes = sorted({value & 0x0F for value in allowed})
    if len(codes) == 1:
        parts.append(f"response code {RCODES.get(codes[0], str(codes[0]))}")
    else:
        parts.append("response code " + ", ".join(str(code) for code in codes))
    return ", ".join(parts)


def dns_header_words(rule_text: str) -> str | None:
    """The DNS meaning of the header bytes the rule tests, in words; None
    if the rule fixes none."""
    places = {
        position: allowed for position, allowed in header_places(rule_text).items()
        if allowed not in (_ALL, _ANY_BUT_NEWLINE) or position < 2
    }
    if not any(allowed not in (_ALL, _ANY_BUT_NEWLINE) for allowed in places.values()):
        return None
    said = []
    if 0 in places or 1 in places:
        first, second = places.get(0, _ALL), places.get(1, _ALL)
        if first == _ALL and second == _ALL:
            said.append("bytes 1-2, the transaction ID, can be anything")
        elif first == _ANY_BUT_NEWLINE and second == _ANY_BUT_NEWLINE:
            said.append("bytes 1-2, the transaction ID, can be any value without a 0x0a byte")
        elif len(first) == 1 and len(second) == 1:
            said.append(f"bytes 1-2 are transaction ID {next(iter(first)) * 256 + next(iter(second))}")
    if 2 in places and places[2] != _ALL:
        said.append(f"byte 3 ({_bytes_seen(places[2])}) means {_high_byte(places[2])}")
    if 3 in places and places[3] != _ALL:
        said.append(f"byte 4 ({_bytes_seen(places[3])}) means {_low_byte(places[3])}")
    for position, name in _COUNTS.items():
        high, low = places.get(position), places.get(position + 1)
        if high and low and len(high) == 1 and len(low) == 1:
            article = "an" if name[0] in "aeiou" else "a"
            count = next(iter(high)) * 256 + next(iter(low))
            said.append(f"bytes {position + 1}-{position + 2} mean {article} {name} of {count}")
    if len(said) <= (1 if said and said[0].startswith("bytes 1-2, the") else 0):
        return None
    return "Read as the DNS header (RFC 1035): " + "; ".join(said) + "."
