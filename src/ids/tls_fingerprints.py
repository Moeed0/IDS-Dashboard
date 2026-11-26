"""The TLS fingerprints each device has used, from Suricata's records.

Before a connection is encrypted the client says, in plain text, which TLS
versions, ciphers and extensions it supports. JA4 and JA3 turn that list into
a short code: one per program (a browser, an app, a script), never what is
sent inside. Suricata writes them in its ``tls`` and ``quic`` records
(ja3-fingerprints and ja4-fingerprints: yes); the collector stores each
handshake's here (``handshake``, ``record_handshakes``):

- ``tls_fingerprints``: one row per device and client fingerprint, when it
  was first and last seen, how many connections used it, and the sites
  (SNI), server fingerprints (JA3S), JA3s and ALPNs seen with it;
- ``tls_fingerprint_labels``: the app a person has said a fingerprint is
  (``set_label``), which the dashboard and the combined JSON show with it;
- ``tls_servers``: the sites (SNI) each server address was reached as, so
  that an alert with no TLS details of its own (a lone reset, a stream
  event, an IP rule) is named by its server's address (``names_by_address``),
  as probable: one address can serve several sites. An address no handshake
  went to is named by the network that owns it (iptoasn.com, ``ip_owners``
  in the threat-intel database): who runs the server, not the app.

Without a person's name, ``fingerprint_list`` names what it can from the
threat-intel database (data/intel/intel.db, scripts/download_intel_sources.py
--fingerprints-only), with nothing fetched from the internet: the program,
from FoxIO's JA4+ mapping or abuse.ch's SSL Blacklist of malware JA3s
(``tls_fingerprint_intel``), and the service each site name (SNI) belongs
to, from domain-list-community (``site_services``): www.youtube.com and
i.ytimg.com are both YouTube's. Each name is given once.

A device is the address that opened the connection. A fingerprint is the
JA4, or ``ja3:<hash>`` when Suricata gave no JA4: Chrome and Firefox send
their TLS extensions in a new order on every connection, which changes their
JA3 every time but not their JA4.

The alerts (new on the network, new for a device, known-bad) are
Suricata's own: deploy/suricata/tls-fingerprints/tls-fingerprints.rules.
"""

from __future__ import annotations

import ipaddress
import json
import re
import sqlite3
from collections.abc import Iterable, Mapping
from contextlib import closing
from pathlib import Path
from typing import Any

from ids.time_utils import parse_suricata_timestamp, to_epoch_ms

# How many of each kept with a fingerprint, the newest last.
MAX_SITES = 20
MAX_JA3 = 10
MAX_JA3S = 10
MAX_ALPN = 5
MAX_LABEL = 100
MAX_NOTE = 500
# The legal-form words an address owner's name ends in, left out of it.
_OWNER_SUFFIX_RE = re.compile(
    r"[\s,]+(inc|llc|l\.l\.c|ltd|limited|corporation|corp|co|company|gmbh|s\.?a|b\.?v|ag|plc|pte|pvt|private|srl|s\.?r\.?l|oy|ab|as|kg|sarl|sas|spa|jsc|ojsc|llp|lp)\.?$",
    re.IGNORECASE,
)
# The intel database's sources of program names, as the page names them.
PROGRAM_SOURCES = {
    "foxio_ja4plus_mapping": "FoxIO's JA4+ mapping",
    "sslbl_ja3": "abuse.ch's SSL Blacklist",
}

TABLES = (
    """
    CREATE TABLE IF NOT EXISTS tls_fingerprints (
        device TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        ja4 TEXT,
        protocols TEXT NOT NULL DEFAULT '[]',
        first_seen INTEGER NOT NULL,
        last_seen INTEGER NOT NULL,
        connections INTEGER NOT NULL DEFAULT 0,
        sites TEXT NOT NULL DEFAULT '[]',
        ja3 TEXT NOT NULL DEFAULT '[]',
        ja3s TEXT NOT NULL DEFAULT '[]',
        alpn TEXT NOT NULL DEFAULT '[]',
        PRIMARY KEY (device, fingerprint)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS tls_fingerprint_labels (
        fingerprint TEXT PRIMARY KEY,
        app TEXT NOT NULL,
        note TEXT,
        updated_ms INTEGER NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_tls_fingerprints_last_seen ON tls_fingerprints(last_seen)",
    """
    CREATE TABLE IF NOT EXISTS tls_servers (
        server TEXT NOT NULL,
        site TEXT NOT NULL,
        first_seen INTEGER NOT NULL,
        last_seen INTEGER NOT NULL,
        connections INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (server, site)
    )
    """,
)


def create_tables(conn: sqlite3.Connection) -> None:
    for statement in TABLES:
        conn.execute(statement)


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def address(value: Any) -> str | None:
    """An IP address written one way (Suricata writes IPv6 in full, others
    shortened); None for anything else."""
    try:
        return ipaddress.ip_address(str(value).strip()).compressed
    except ValueError:
        return None


def handshake(event: Mapping[str, Any]) -> dict[str, Any] | None:
    """The fingerprints of one Suricata ``tls`` or ``quic`` record, or None
    for any other record and for a record with no client fingerprint."""
    kind = event.get("event_type")
    if kind not in ("tls", "quic"):
        return None
    record = event.get(kind)
    if not isinstance(record, Mapping):
        return None
    ja3 = record.get("ja3") if isinstance(record.get("ja3"), Mapping) else {}
    ja3s = record.get("ja3s") if isinstance(record.get("ja3s"), Mapping) else {}
    ja4 = _text(record.get("ja4"))
    ja3_hash = _text(ja3.get("hash"))
    if not ja4 and not ja3_hash:
        return None
    try:
        time_ms = to_epoch_ms(parse_suricata_timestamp(str(event.get("timestamp"))))
    except (TypeError, ValueError, OSError, OverflowError):
        return None
    device = _text(event.get("src_ip"))
    server = event.get("dest_ip")
    # Suricata names the side that sent the record; the client opened it.
    if event.get("direction") == "to_client":
        device, server = _text(event.get("dest_ip")), event.get("src_ip")
    if not device:
        return None
    alpn = record.get("client_alpns")
    return {
        "device": device,
        "fingerprint": ja4 or f"ja3:{ja3_hash}",
        "ja4": ja4,
        "ja3": ja3_hash,
        "ja3s": _text(ja3s.get("hash")),
        "protocol": kind,
        "site": _text(record.get("sni")),
        "alpn": ",".join(str(item) for item in alpn) if isinstance(alpn, list) and alpn else None,
        "server": address(server),
        "time_ms": time_ms,
    }


def _added(values: list[Any], value: Any, limit: int) -> list[Any]:
    """``values`` with ``value`` moved to the end (the newest), at most
    ``limit`` long."""
    if value is None:
        return values
    values = [item for item in values if item != value] + [value]
    return values[-limit:]


def _list(text: Any) -> list[Any]:
    try:
        value = json.loads(text or "[]")
    except ValueError:
        return []
    return value if isinstance(value, list) else []


def record_handshakes(conn: sqlite3.Connection, handshakes: Iterable[Mapping[str, Any]]) -> int:
    """Adds the handshakes to ``tls_fingerprints`` (the caller commits); how
    many it added."""
    count = 0
    for shake in handshakes:
        key = (shake["device"], shake["fingerprint"])
        row = conn.execute(
            """
            SELECT protocols, first_seen, last_seen, connections, sites, ja3, ja3s, alpn
            FROM tls_fingerprints WHERE device = ? AND fingerprint = ?
            """,
            key,
        ).fetchone()
        if row is None:
            row = ("[]", shake["time_ms"], shake["time_ms"], 0, "[]", "[]", "[]", "[]")
        protocols, first, last, connections, sites, ja3, ja3s, alpn = row
        conn.execute(
            """
            INSERT OR REPLACE INTO tls_fingerprints (
                device, fingerprint, ja4, protocols, first_seen, last_seen,
                connections, sites, ja3, ja3s, alpn
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                *key,
                shake.get("ja4"),
                json.dumps(sorted(set(_list(protocols)) | {shake["protocol"]})),
                min(first, shake["time_ms"]),
                max(last, shake["time_ms"]),
                connections + 1,
                json.dumps(_added(_list(sites), shake.get("site"), MAX_SITES)),
                json.dumps(_added(_list(ja3), shake.get("ja3"), MAX_JA3)),
                json.dumps(_added(_list(ja3s), shake.get("ja3s"), MAX_JA3S)),
                json.dumps(_added(_list(alpn), shake.get("alpn"), MAX_ALPN)),
            ),
        )
        if shake.get("server") and shake.get("site"):
            conn.execute(
                """
                INSERT INTO tls_servers (server, site, first_seen, last_seen, connections)
                VALUES (?, ?, ?, ?, 1)
                ON CONFLICT (server, site) DO UPDATE SET
                    first_seen = MIN(first_seen, excluded.first_seen),
                    last_seen = MAX(last_seen, excluded.last_seen),
                    connections = connections + 1
                """,
                (shake["server"], shake["site"].lower(), shake["time_ms"], shake["time_ms"]),
            )
        count += 1
    return count


def server_sites(conn: sqlite3.Connection, addresses: Iterable[Any]) -> dict[str, list[str]]:
    """The sites each of the addresses was reached as in a handshake, the
    most connections first; an address no handshake went to is left out."""
    wanted = sorted({found for found in (address(value) for value in addresses) if found})
    if not wanted or not conn.execute(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'tls_servers'"
    ).fetchone()[0]:
        return {}
    sites: dict[str, list[str]] = {}
    for server, site in conn.execute(
        f"SELECT server, site FROM tls_servers WHERE server IN ({', '.join('?' for _ in wanted)}) "
        "ORDER BY server, connections DESC, last_seen DESC",
        wanted,
    ):
        sites.setdefault(server, []).append(site)
    return sites


def owner_name(description: str) -> str:
    """An address owner's name, short: "FACEBOOK - Facebook, Inc." gives
    "Facebook", "ZEN-ECN - Zenlayer Inc" "Zenlayer"; the AS's handle when
    it has no other name."""
    handle, _, name = description.partition(" - ")
    name = (name or handle).split(",")[0].strip()
    while True:
        shorter = _OWNER_SUFFIX_RE.sub("", name).strip()
        if shorter == name or not shorter:
            return name
        name = shorter


def names_by_address(
    addresses: Iterable[Any], sites: Mapping[str, list[str]], intel: "Intel",
) -> dict[str, Any] | None:
    """An alert named by the first of its addresses (the destination, then
    the source) a handshake went to: the site most reached there and the
    services of all its sites, each once, as probable (``by_address``); or
    else by the network that owns its first public address (``owner``)."""
    addresses = list(addresses)
    for value in addresses:
        server = address(value)
        if server in sites:
            seen = sites[server]
            return {
                "fingerprint": None,
                "program": None,
                "site": seen[0],
                "service": ", ".join(_unique(
                    name for site in seen for name in intel.services(site)
                )) or None,
                "server": server,
                "by_address": True,
            }
    for value in addresses:
        owner = intel.owner(value)
        if owner:
            return {
                "fingerprint": None,
                "program": None,
                "site": None,
                "service": None,
                "server": address(value),
                "by_address": True,
                "owner": owner,
            }
    return None


def _connect(db_path: Path | str) -> sqlite3.Connection:
    return sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5)


def _has_tables(conn: sqlite3.Connection) -> bool:
    return conn.execute(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'tls_fingerprints'"
    ).fetchone()[0] > 0


def labels(db_path: Path | str) -> dict[str, dict[str, Any]]:
    """Every fingerprint a person has named: {fingerprint: {app, note}}."""
    with closing(_connect(db_path)) as conn:
        if not _has_tables(conn):
            return {}
        return {
            fingerprint: {"app": app, "note": note}
            for fingerprint, app, note in conn.execute(
                "SELECT fingerprint, app, note FROM tls_fingerprint_labels"
            )
        }


def _unique(names: Iterable[str | None]) -> list[str]:
    """The names, each once (whatever its case), in their order."""
    seen: set[str] = set()
    kept = []
    for name in names:
        if name and name.strip() and name.strip().lower() not in seen:
            seen.add(name.strip().lower())
            kept.append(name.strip())
    return kept


class Intel:
    """Names from the threat-intel database, each looked up once; nothing
    when it is missing or older than its tables."""

    def __init__(self, intel_db: Path | str | None) -> None:
        self.conn: sqlite3.Connection | None = None
        self.tables: set[str] = set()
        if intel_db is not None and Path(intel_db).is_file():
            try:
                self.conn = sqlite3.connect(f"file:{intel_db}?mode=ro", uri=True, timeout=5)
                self.tables = {
                    name for (name,) in self.conn.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table' "
                        "AND name IN ('tls_fingerprint_intel', 'site_services', 'ip_owners')"
                    )
                }
            except sqlite3.Error:
                self.close()
        self._programs: dict[str, dict[str, Any] | None] = {}
        self._services: dict[str, list[str]] = {}
        self._owners: dict[str, dict[str, Any] | None] = {}

    def close(self) -> None:
        if self.conn is not None:
            self.conn.close()
        self.conn = None
        self.tables = set()

    def program(self, fingerprint: str, ja3: Iterable[str] = ()) -> dict[str, Any] | None:
        """The program the fingerprint (or one of the JA3s seen with it)
        is, by the first source that lists it: {name, source, malware}."""
        if self.conn is None or "tls_fingerprint_intel" not in self.tables:
            return None
        for key in _unique([fingerprint.removeprefix("ja3:"), *ja3]):
            key = key.lower()
            if key not in self._programs:
                rows = self.conn.execute(
                    "SELECT COALESCE(application, library), source FROM tls_fingerprint_intel "
                    "WHERE fingerprint = ? AND kind IN ('ja4', 'ja3') ORDER BY rowid",
                    (key,),
                ).fetchall()
                names = _unique(name for name, _ in rows)
                self._programs[key] = {
                    "name": ", ".join(names),
                    "source": PROGRAM_SOURCES.get(rows[0][1], rows[0][1]),
                    "malware": rows[0][1] == "sslbl_ja3",
                } if names else None
            if self._programs[key]:
                return self._programs[key]
        return None

    def services(self, site: str) -> list[str]:
        """The service a site name belongs to, by the longest name the list
        has for it (the name itself, or a name it is under); two when two
        services list that name; none when the list doesn't have it."""
        site = site.lower().strip().strip(".")
        if self.conn is None or "site_services" not in self.tables or not site:
            return []
        if site not in self._services:
            labels = site.split(".")
            names = [".".join(labels[index:]) for index in range(len(labels))]
            rows = [
                (domain, service)
                for domain, match, service in self.conn.execute(
                    f"SELECT domain, match, service FROM site_services "
                    f"WHERE domain IN ({', '.join('?' for _ in names)})",
                    names,
                )
                if match == "domain" or domain == site
            ]
            longest = max((len(domain) for domain, _ in rows), default=0)
            self._services[site] = sorted(
                _unique(service for domain, service in rows if len(domain) == longest)
            )
        return self._services[site]

    def owner(self, value: Any) -> dict[str, Any] | None:
        """The network that owns a public address: {name, asn, country,
        description}; None for a private or unknown one."""
        try:
            found = ipaddress.ip_address(str(value).strip())
        except ValueError:
            return None
        if self.conn is None or "ip_owners" not in self.tables or not found.is_global:
            return None
        key = f"{found.version}{int(found):032x}"
        if key not in self._owners:
            row = self.conn.execute(
                "SELECT range_end, asn, country, description FROM ip_owners "
                "WHERE range_start <= ? ORDER BY range_start DESC LIMIT 1",
                (key,),
            ).fetchone()
            self._owners[key] = {
                "name": owner_name(row[3]),
                "asn": row[1],
                "country": row[2],
                "description": row[3],
            } if row and row[0] >= key and row[0][0] == key[0] else None
        return self._owners[key]

    def grouped(self, sites: Iterable[str]) -> list[dict[str, Any]]:
        """The sites under their service, each service once, in the order
        the sites come; the sites of no known service last, under none. A
        site two services list goes under one of them already there
        (www.gstatic.com under Google when Google has other sites), and
        under both names only when neither is."""
        sites = list(sites)
        groups: dict[str | None, dict[str, Any]] = {}
        shared = []
        for site in sites:
            services = self.services(site)
            if len(services) > 1:
                shared.append((site, services))
                continue
            name = services[0] if services else None
            groups.setdefault(name.lower() if name else None, {"name": name, "sites": []})["sites"].append(site)
        for site, services in shared:
            key = next((name.lower() for name in services if name.lower() in groups), None)
            if key is None:
                name = ", ".join(services)
                key = name.lower()
                groups.setdefault(key, {"name": name, "sites": []})
            groups[key]["sites"].append(site)
        # Each group's sites in the order they came.
        for group in groups.values():
            group["sites"].sort(key=sites.index)
        unnamed = groups.pop(None, None)
        return [*groups.values(), *([unnamed] if unnamed else [])]


def fingerprint_list(db_path: Path | str, intel_db: Path | str | None = None) -> dict[str, Any]:
    """Every device's client fingerprints, the newest first, each with the
    app it was named as (``labels``) and, from the threat-intel database
    ``intel_db``, the program it is known as (``known_app``) and its sites
    under the service they belong to (``services``)."""
    with closing(_connect(db_path)) as conn:
        if not _has_tables(conn):
            return {"fingerprints": []}
        rows = conn.execute(
            """
            SELECT f.device, f.fingerprint, f.ja4, f.protocols, f.first_seen,
                   f.last_seen, f.connections, f.sites, f.ja3, f.ja3s, f.alpn,
                   l.app, l.note,
                   (SELECT COUNT(*) FROM tls_fingerprints AS o
                    WHERE o.fingerprint = f.fingerprint) AS devices
            FROM tls_fingerprints AS f
            LEFT JOIN tls_fingerprint_labels AS l ON l.fingerprint = f.fingerprint
            ORDER BY f.last_seen DESC
            """
        ).fetchall()
    intel = Intel(intel_db)
    try:
        return {"fingerprints": [_with_names(row, intel) for row in _rows(rows)]}
    finally:
        intel.close()


def _with_names(row: dict[str, Any], intel: Intel) -> dict[str, Any]:
    return {
        **row,
        "known_app": intel.program(row["fingerprint"], row["ja3"]),
        "services": intel.grouped(row["sites"]),
    }


def _rows(rows: list[tuple[Any, ...]]) -> list[dict[str, Any]]:
    return [
            {
                "device": device,
                "fingerprint": fingerprint,
                "ja4": ja4,
                "protocols": _list(protocols),
                "first_seen_ms": first,
                "last_seen_ms": last,
                "connections": connections,
                "sites": _list(sites)[::-1],
                "ja3": _list(ja3)[::-1],
                "ja3s": _list(ja3s)[::-1],
                "alpn": _list(alpn)[::-1],
                "app": app,
                "note": note,
                "devices": devices,
            }
            for (
                device, fingerprint, ja4, protocols, first, last, connections,
                sites, ja3, ja3s, alpn, app, note, devices,
            ) in rows
    ]


def set_label(
    db_path: Path | str,
    fingerprint: str,
    app: str | None,
    note: str | None = None,
    *,
    now_ms: int,
) -> None:
    """Names the program a fingerprint (a JA4, ``ja3:<hash>`` or a JA3
    hash) is; an empty ``app`` takes the name away."""
    fingerprint = (fingerprint or "").strip()
    if not fingerprint or len(fingerprint) > 200:
        raise ValueError("a fingerprint is needed (a JA4, or ja3:<hash>)")
    # A bare JA3 hash is kept the way the table names JA3s.
    if len(fingerprint) == 32 and all(char in "0123456789abcdef" for char in fingerprint.lower()):
        fingerprint = f"ja3:{fingerprint.lower()}"
    app = (app or "").strip()
    note = (note or "").strip() or None
    if len(app) > MAX_LABEL:
        raise ValueError(f"the app's name is at most {MAX_LABEL} characters")
    if note and len(note) > MAX_NOTE:
        raise ValueError(f"the note is at most {MAX_NOTE} characters")
    with closing(sqlite3.connect(db_path, timeout=5)) as conn:
        create_tables(conn)
        if app:
            conn.execute(
                "INSERT OR REPLACE INTO tls_fingerprint_labels (fingerprint, app, note, updated_ms) "
                "VALUES (?, ?, ?, ?)",
                (fingerprint, app, note, now_ms),
            )
        else:
            conn.execute("DELETE FROM tls_fingerprint_labels WHERE fingerprint = ?", (fingerprint,))
        conn.commit()


def fingerprints_in(native: Mapping[str, Any]) -> list[str]:
    """The fingerprints a Suricata record or alert carries, the way
    ``tls_fingerprint_labels`` keys them: its JA4, its JA3 as ``ja3:<hash>``
    and its JA3S as ``ja3s:<hash>``."""
    found = []
    for kind in ("tls", "quic"):
        record = native.get(kind)
        if not isinstance(record, Mapping):
            continue
        if _text(record.get("ja4")):
            found.append(_text(record.get("ja4")))
        for name in ("ja3", "ja3s"):
            part = record.get(name)
            if isinstance(part, Mapping) and _text(part.get("hash")):
                found.append(f"{name}:{_text(part.get('hash'))}")
    return found


def connection_names(
    native: Mapping[str, Any],
    *,
    labels: Mapping[str, Mapping[str, Any]],
    intel: Intel,
) -> dict[str, Any] | None:
    """What a Suricata record or alert on a TLS or QUIC connection names:
    its client fingerprint, the program that is (a name given in the lab
    first, then the threat-intel database's) and the site (SNI) with the
    service it belongs to; None for a record of no such connection."""
    record = next(
        (native[kind] for kind in ("tls", "quic") if isinstance(native.get(kind), Mapping)), None
    )
    if record is None:
        return None
    client = [value for value in fingerprints_in(native) if not value.startswith("ja3s:")]
    program = next(
        (
            {"name": labels[value]["app"], "source": "named in the lab", "malware": False}
            for value in client
            if value in labels and labels[value].get("app")
        ),
        None,
    )
    if program is None and client:
        program = intel.program(
            client[0], [value.removeprefix("ja3:") for value in client if value.startswith("ja3:")]
        )
    site = _text(record.get("sni"))
    return {
        "fingerprint": client[0] if client else None,
        "program": program,
        "site": site,
        "service": ", ".join(intel.services(site)) or None if site else None,
    }


def short_name(names: Mapping[str, Any] | None) -> str | None:
    """``connection_names`` as a few words for a list: the program and the
    service ("Chromium Browser · Youtube"), the site when its service is
    unknown, each name once, with "?" when named by its server's address
    ("Tencent network?" by its owner); None when it names nothing."""
    if not names:
        return None
    if names.get("owner") and not names.get("site"):
        return f"{names['owner']['name']} network?"
    program = (names.get("program") or {}).get("name")
    text = " · ".join(_unique([program, names.get("service") or names.get("site")]))
    return (text + "?" if names.get("by_address") else text) or None


def names_something(names: Mapping[str, Any] | None) -> bool:
    """Whether ``connection_names`` gave a program or a site."""
    return bool(names and (names.get("program") or names.get("site")))
