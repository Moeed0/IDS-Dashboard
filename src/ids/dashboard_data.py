"""The data behind each dashboard screen, without any UI.

Each function reads the live database read-only and returns plain JSON values
(dicts, lists, strings, numbers and None; times as epoch milliseconds, UTC),
so the React page and a React Native app, through an HTTP API, can show the
same data.
"""

from __future__ import annotations

import ipaddress
import json
import math
import re
import shutil
import sqlite3
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from contextlib import closing
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from functools import lru_cache
from pathlib import Path
from typing import Any

from ids.alert_archive import TooManyAlerts, archived_alerts
from ids.capture_stats import snort_last_hour, suricata_last_hour
from ids.db_backup import backup_summary
from ids.combined_detections import (
    PKT,
    WINDOW_LENGTHS,
    alert_packets,
    build_combined_detections,
    combined_filename,
    complete_window_end,
    load_window_rows,
    newest_event_times,
    packet_counts,
    serialize_combined_detections,
    window_bounds,
)
from ids.config import KNOWN_ENGINES
from ids.ids_config import read_network_variables
from ids.test_alert import read_result
from ids.uids import uid_text
from ids.uptime import off_during

PROJECT_ROOT = Path(__file__).resolve().parents[2]
LAB_PHASES_FILE = PROJECT_ROOT / "config" / "lab_phases.json"

# Every engine the screens know. Each function takes the ones this machine
# runs (IDS_ENGINES) and leaves the others out.
ENGINES = KNOWN_ENGINES
LAST_HOUR = timedelta(hours=1)
LAST_DAY = timedelta(hours=24)
# Minutes between the points of the last 24 hours' chart.
CHART_STEPS = (5, 10, 15)
DEFAULT_CHART_STEP = 15
# The live chart, which moves with the clock: the last 15 minutes in steps
# of 30 seconds.
LIVE_WINDOW = timedelta(minutes=15)
LIVE_STEP = timedelta(seconds=30)
# The top rules cover one of the export's window lengths.
DEFAULT_TOP_RULES_LENGTH = "1 day"
TOP_RULES = 10
# The Alert Explorer's pairs of a Snort rule and a Suricata rule on one packet.
RULE_PAIRS = 10
# Where the status looks for Snort, Suricata and the collector.
PROC_DIR = Path("/proc")
# Time ranges of the alert list; None lists every stored alert.
TIME_RANGES = {
    "Last 5 minutes": timedelta(minutes=5),
    "Last 10 minutes": timedelta(minutes=10),
    "Last 15 minutes": timedelta(minutes=15),
    "Last 30 minutes": timedelta(minutes=30),
    "Last hour": timedelta(hours=1),
    "Last 24 hours": timedelta(hours=24),
    "Last 7 days": timedelta(days=7),
    "Last 30 days": timedelta(days=30),
    "All stored": None,
}
PAGE_SIZES = (10, 25, 50, 100, 250)
# The most alerts one combined export holds: building one takes about 8 KB
# of memory an alert, so 150,000 take about 1.2 GB.
EXPORT_MAX_ALERTS = 150_000
# The columns an export reads, from the database or the archive.
EXPORT_FIELDS = ("id", "engine", "event_ts_utc", "msg", "rule_key", "raw_json")
# Each engine's packets and drops over the last hour, from its statistics.
CAPTURE_READERS = {"snort": snort_last_hour, "suricata": suricata_last_hour}


def _ms(moment: datetime) -> int:
    return int(moment.timestamp() * 1000)


def _moment(epoch_ms: int | float) -> datetime:
    return datetime.fromtimestamp(float(epoch_ms) / 1000, tz=PKT)


def _connect(db_path: Path | str) -> sqlite3.Connection:
    return sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5)


def rule_name(gid: Any, sid: Any) -> str:
    """The SID, with the GID first when it is not 1, as the combined export
    names rules."""
    return f"{gid}:{sid}" if gid not in (None, 1) else str(sid)


def _endpoint(address: Any, port: Any) -> str | None:
    if not address:
        return None
    try:
        address = str(ipaddress.ip_address(str(address)))
    except ValueError:
        address = str(address)
    if port is None:
        return address
    return f"[{address}]:{port}" if ":" in address else f"{address}:{port}"


# Values that only say "not identified", as the combined export leaves them out.
_UNKNOWN_VALUES = {"", "none", "unknown", "failed"}


def _known(value: Any) -> Any:
    return None if str(value or "").strip().lower() in _UNKNOWN_VALUES else value


def _lab_attacker_ips() -> set[str]:
    """The lab attackers' addresses (config/lab_phases.json), read again
    only when the file changes: the status says when one is outside
    HOME_NET."""
    try:
        changed = LAB_PHASES_FILE.stat().st_mtime_ns
    except OSError:
        return set()
    return set(_attackers_in(LAB_PHASES_FILE, changed))


@lru_cache(maxsize=4)
def _attackers_in(path: Path, changed: int) -> frozenset[str]:
    try:
        phases = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return frozenset()
    return frozenset(
        str(phase.get("attacker_ip"))
        for phase in phases.values()
        if isinstance(phase, dict) and phase.get("attacker_ip")
    )


def _inside(ip: str, networks: str | None) -> bool:
    """True when ip falls in a [a/b, c/d] style address group."""
    for part in str(networks or "").strip("[]").split(","):
        part = part.strip()
        if not part or part.startswith(("!", "$")) or part == "any":
            continue
        try:
            if ipaddress.ip_address(ip) in ipaddress.ip_network(part, strict=False):
                return True
        except ValueError:
            continue
    return False


def overview(
    db_path: Path | str,
    ids_sources: Mapping[str, Any],
    *,
    alert_retention: int | None = None,
    step_minutes: int = DEFAULT_CHART_STEP,
    top_rules_length: str = DEFAULT_TOP_RULES_LENGTH,
    engines: Sequence[str] = ENGINES,
    off_periods: Sequence[tuple[int, int]] = (),
) -> dict[str, Any]:
    """The Overview screen.

    For each of the ``engines`` this machine runs what ``_engines`` gives.
    Then the last hour's alerts and packets, matched as in the combined
    export, the last 24 hours in steps of ``step_minutes`` (one of
    CHART_STEPS), and each engine's most frequent rules over the last
    ``top_rules_length`` (a window length of the export).

    All of them end at ``complete_end_ms``, the latest complete time: up to
    there every engine's alerts are stored. The last 24 hours cover whole
    steps. The last hour and the last 24 hours give the parts of
    ``off_periods`` (when the machine was off) inside them as ``off``.
    """
    if step_minutes not in CHART_STEPS:
        raise ValueError(f"step_minutes must be one of {CHART_STEPS}")
    if top_rules_length not in WINDOW_LENGTHS:
        raise ValueError(f"top_rules_length must be one of {list(WINDOW_LENGTHS)}")
    newest = newest_event_times(db_path, engines)
    end = complete_window_end(newest)
    with closing(_connect(db_path)) as connection:
        engine_info = _engines(connection, ids_sources, newest, engines)
        last_day = _last_day(connection, end, step_minutes, engines) if end is not None else None
        top_rules = (
            _top_rules(connection, end, top_rules_length, engines) if end is not None else None
        )

    if last_day is not None:
        last_day["off"] = off_during(list(off_periods), last_day["start_ms"], last_day["end_ms"])

    last_hour = None
    if end is not None:
        start = end - LAST_HOUR
        last_hour = {
            "start_ms": _ms(start),
            "end_ms": _ms(end),
            "off": off_during(list(off_periods), _ms(start), _ms(end)),
            **packet_counts(
                load_window_rows(db_path, start, end, engines),
                window_start=start,
                window_end=end,
            ),
        }

    return {
        "complete_end_ms": _ms(end) if end is not None else None,
        "alert_retention": alert_retention,
        "engines": engine_info,
        "last_hour": last_hour,
        "last_day": last_day,
        "top_rules": top_rules,
    }


def _engines(
    connection: sqlite3.Connection,
    ids_sources: Mapping[str, Any],
    newest: Mapping[str, datetime],
    engines: Sequence[str],
) -> dict[str, Any]:
    """For each engine: its newest stored alert, how many alerts are stored
    and since when, its rule count and HOME_NET, and the lab attackers its
    EXTERNAL_NET keeps its rules from matching."""
    stored = {
        engine: (count, oldest)
        for engine, count, oldest in connection.execute(
            """
            SELECT engine, COUNT(*), MIN(event_ts_utc)
            FROM alerts
            WHERE engine IN ('snort', 'suricata')
            GROUP BY engine
            """
        )
    }
    attackers = _lab_attacker_ips()
    info = {}
    for engine in engines:
        config = ids_sources.get(engine) or {}
        network = read_network_variables(engine, config.get("config_file"))
        count, oldest = stored.get(engine, (0, None))
        info[engine] = {
            "newest_ms": _ms(newest[engine]) if engine in newest else None,
            "alerts": count,
            "oldest_ms": oldest,
            "rules": config.get("engine_rule_count"),
            "home_net": network.get("home_net"),
            "external_net": network.get("external_net"),
            "unmatched_lab_attackers": sorted(
                ip for ip in attackers
                if network.get("external_excludes_home")
                and _inside(ip, network.get("home_net"))
            ),
        }
    return info


def _alerts_per_step(
    connection: sqlite3.Connection, start_ms: int, end_ms: int, step_ms: int,
) -> dict[tuple[str, int], int]:
    """Each engine's alerts from ``start_ms`` (a multiple of ``step_ms``) up
    to ``end_ms``, by engine and step start; a step without alerts is left
    out."""
    return {
        (engine, step): count
        for engine, step, count in connection.execute(
            """
            SELECT engine, event_ts_utc / :step * :step AS step_start, COUNT(*)
            FROM alerts
            WHERE engine IN ('snort', 'suricata')
              AND event_ts_utc >= :start AND event_ts_utc < :end
            GROUP BY engine, step_start
            """,
            {"start": start_ms, "end": end_ms, "step": step_ms},
        )
    }


def _last_day(
    connection: sqlite3.Connection, end: datetime, step_minutes: int, engines: Sequence[str],
) -> dict[str, Any]:
    step_ms = step_minutes * 60 * 1000
    end_ms = _ms(end) // step_ms * step_ms
    start_ms = end_ms - int(LAST_DAY.total_seconds() * 1000)
    per_step = _alerts_per_step(connection, start_ms, end_ms, step_ms)
    steps = range(start_ms, end_ms, step_ms)
    return {
        "start_ms": start_ms,
        "end_ms": end_ms,
        "step_ms": step_ms,
        # Alerts per step, oldest first; a step without alerts is 0.
        "alerts": {
            engine: [per_step.get((engine, step), 0) for step in steps]
            for engine in engines
        },
    }


def _top_rules(
    connection: sqlite3.Connection, end: datetime, length: str, engines: Sequence[str],
) -> dict[str, Any]:
    """Each engine's most frequent rules over the ``length`` before ``end``."""
    end_ms = _ms(end)
    start_ms = end_ms - int(WINDOW_LENGTHS[length].total_seconds() * 1000)
    # A rule that fired with two revisions is listed once for each.
    rules = connection.execute(
        """
        SELECT engine, gid, sid, rev, MAX(msg), COUNT(*) AS alerts
        FROM alerts
        WHERE engine IN ('snort', 'suricata')
          AND event_ts_utc >= :start AND event_ts_utc < :end
        GROUP BY engine, gid, sid, rev
        ORDER BY alerts DESC, engine, gid, sid, rev
        """,
        {"start": start_ms, "end": end_ms},
    ).fetchall()
    return {
        "length": length,
        "start_ms": start_ms,
        "end_ms": end_ms,
        "rules": {
            engine: [
                {
                    "rule": rule_name(gid, sid),
                    "gid": gid,
                    "sid": sid,
                    "rev": rev,
                    "message": str(message or "").strip(),
                    "alerts": count,
                }
                for rule_engine, gid, sid, rev, message, count in rules
                if rule_engine == engine
            ][:TOP_RULES]
            for engine in engines
        },
    }


# What the alert search looks in: the message, the rule as the screens show
# it (gid:sid:rev), the class, the protocol, the service, the app, both
# endpoints and the PKT time.
_SEARCHED = " || ' ' || ".join(
    f"COALESCE({expression}, '')"
    for expression in (
        "msg",
        "gid || ':' || sid || COALESCE(':' || rev, '')",
        "classification",
        "protocol",
        "service",
        "app",
        "src_addr || ':' || src_port",
        "dst_addr || ':' || dst_port",
        "strftime('%Y-%m-%d %H:%M:%S', event_ts_utc / 1000, 'unixepoch', '+5 hours')",
    )
)


# An alert's severity as the lists show it: 1 (the most severe) to 4.
_SEVERITY = "MIN(4, MAX(1, COALESCE(severity, priority, 4)))"
# The most alerts "last N" takes: as many as one export holds.
MAX_LAST = EXPORT_MAX_ALERTS
# The Alert Explorer's quick choices for "last N" (any number can be typed).
LAST_CHOICES = (5, 10, 20)


@dataclass(frozen=True)
class AlertFilter:
    """Which stored alerts the Alert Explorer's lists, download and send take:
    every alert of the engines when nothing is set.

    ``engine`` takes one engine's alerts; ``since_ms`` and ``until_ms`` a
    time range; ``search`` what the search box finds; ``severities`` (1 to
    4) any of those; ``protocol``, ``classification``, ``service`` and
    ``app`` (the application OpenAppID named, Snort's alerts only) that
    value, in any case; ``rule`` (gid, sid, rev; None for any) that rule;
    ``source`` and ``destination`` an address or network (parse_network);
    ``port`` that port on either side. ``last`` takes only the newest that many of them, and with ``each`` that
    many of each engine (a download of the side-by-side lists)."""

    engine: str | None = None
    since_ms: int | None = None
    until_ms: int | None = None
    search: str = ""
    severities: tuple[int, ...] = ()
    protocol: str = ""
    classification: str = ""
    service: str = ""
    app: str = ""
    rule: tuple[int | None, int | None, int | None] | None = None
    source: str = ""
    destination: str = ""
    port: int | None = None
    last: int | None = None
    each: bool = False


def parse_rule(text: str) -> tuple[int | None, int | None, int | None] | None:
    """(gid, sid, rev) from a rule as the lists show it: SID, GID:SID or
    GID:SID:Rev; None when empty. ValueError otherwise."""
    text = text.strip()
    if not text:
        return None
    parts = text.split(":")
    if len(parts) > 3 or not all(part.isdigit() for part in parts):
        raise ValueError("rule must be a SID, GID:SID or GID:SID:Rev, like 2001119 or 116:444")
    numbers = [int(part) for part in parts]
    if len(numbers) == 1:
        return None, numbers[0], None
    return numbers[0], numbers[1], numbers[2] if len(numbers) == 3 else None


def parse_network(text: str, name: str = "address") -> str:
    """The network an address filter matches, written out (192.168.50.0/24):
    from an address (192.168.50.122, fe80::1), a network (192.168.50.0/24)
    or an IPv4 address's first parts ending in a dot or .* (192.168.50.);
    "" when empty. ValueError, naming the filter ``name``, otherwise."""
    text = text.strip()
    if not text:
        return ""
    partial = re.fullmatch(r"(\d{1,3}(?:\.\d{1,3}){0,2})\.\*?", text)
    if partial:
        parts = partial.group(1).split(".")
        text = ".".join(parts + ["0"] * (4 - len(parts))) + f"/{8 * len(parts)}"
    try:
        return str(ipaddress.ip_network(text, strict=False))
    except ValueError:
        raise ValueError(
            f"{name} must be an address or a network, like 192.168.50.122, "
            "192.168.50.0/24 or 192.168.50."
        ) from None


@lru_cache(maxsize=65_536)
def _in_network(address: str | None, network: str) -> int:
    """1 when ``address`` (as stored: IPv6 may be written out in full) is in
    ``network``: SQLite's in_network() for the address filters."""
    if not address:
        return 0
    try:
        return int(ipaddress.ip_address(address) in ipaddress.ip_network(network))
    except ValueError:
        return 0


def _connect_filtering(db_path: Path | str) -> sqlite3.Connection:
    connection = _connect(db_path)
    connection.create_function("in_network", 2, _in_network, deterministic=True)
    return connection


def _filter_sql(chosen: AlertFilter, engines: Sequence[str]) -> tuple[str, dict[str, Any]]:
    """The WHERE clause that takes the alerts ``chosen`` takes (all but
    ``last``), and its parameters; on a _connect_filtering connection."""
    conditions: list[str] = []
    parameters: dict[str, Any] = {}

    def any_of(expression: str, key: str, values: Sequence[Any]) -> None:
        names = {f"{key}{index}": value for index, value in enumerate(values)}
        conditions.append(f"{expression} IN ({', '.join(f':{name}' for name in names)})")
        parameters.update(names)

    if chosen.engine:
        any_of("engine", "engine", [chosen.engine])
    elif set(engines) != set(KNOWN_ENGINES):
        # Only this machine's engines. With every engine there is nothing to
        # leave out, and the condition would lead SQLite to read the alerts
        # one by one through the engine index instead of a filter's own.
        any_of("engine", "engine", list(engines))
    if chosen.since_ms is not None:
        conditions.append("event_ts_utc >= :since")
        parameters["since"] = int(chosen.since_ms)
    if chosen.until_ms is not None:
        conditions.append("event_ts_utc <= :until")
        parameters["until"] = int(chosen.until_ms)
    if chosen.search.strip():
        conditions.append(f"instr(lower({_SEARCHED}), :search) > 0")
        parameters["search"] = chosen.search.strip().lower()
    if chosen.severities:
        any_of(_SEVERITY, "severity", sorted({int(level) for level in chosen.severities}))
    for column, value in (
        ("protocol", chosen.protocol),
        ("classification", chosen.classification),
        ("service", chosen.service),
        ("app", chosen.app),
    ):
        if value.strip():
            conditions.append(f"lower({column}) = :{column}")
            parameters[column] = value.strip().lower()
    for column, value in zip(("gid", "sid", "rev"), chosen.rule or ()):
        if value is not None:
            conditions.append(f"{column} = :rule_{column}")
            parameters[f"rule_{column}"] = value
    for column, value in (("src_addr", chosen.source), ("dst_addr", chosen.destination)):
        if value:
            conditions.append(f"in_network({column}, :{column})")
            parameters[column] = value
    if chosen.port is not None:
        conditions.append("(src_port = :port OR dst_port = :port)")
        parameters["port"] = int(chosen.port)
    return (f"WHERE {' AND '.join(conditions)}" if conditions else ""), parameters


def alerts(
    db_path: Path | str,
    *,
    engine: str | None = None,
    since_ms: int | None = None,
    search: str = "",
    page: int = 1,
    page_size: int = 25,
    engines: Sequence[str] = ENGINES,
    filters: AlertFilter | None = None,
) -> dict[str, Any]:
    """One page of stored alerts of the ``engines``, newest first, with how
    many there are (``total``) and how many match before ``last`` keeps the
    newest (``matching``).

    ``filters`` chooses the alerts (AlertFilter); without it ``engine``
    limits the list to one engine, ``since_ms`` to alerts from then on, and
    ``search`` to alerts whose message, rule, class, protocol, service,
    endpoints or PKT time contain it (any case). A page past the last is the
    last page. Each row names its packet (``packet``: the UID of the first
    stored alert on it, the same in every list) and says whether both
    engines alerted on it (``both``), matched as in the combined export. A
    page's rows are grouped by packet: the packets in the order of their
    newest row, each packet's rows together, Snort's first.
    """
    chosen = filters if filters is not None else AlertFilter(
        engine=engine, since_ms=since_ms, search=search,
    )
    where, parameters = _filter_sql(chosen, engines)
    page_size = max(1, int(page_size))
    with closing(_connect_filtering(db_path)) as connection:
        matching = connection.execute(
            f"SELECT COUNT(*) FROM alerts {where}", parameters
        ).fetchone()[0]
        total = matching if chosen.last is None else min(matching, chosen.last)
        pages = max(1, math.ceil(total / page_size))
        page = min(max(1, int(page)), pages)
        offset = (page - 1) * page_size
        rows = connection.execute(
            f"""
            SELECT {_LISTED}
            FROM alerts
            {where}
            ORDER BY event_ts_utc DESC, id DESC
            LIMIT :limit OFFSET :offset
            """,
            # The last page of "last N" stops at the Nth.
            {**parameters, "limit": max(0, min(page_size, total - offset)), "offset": offset},
        ).fetchall()
        packets = _alert_packets(connection, rows, engines)
        # A packet is named by its first stored alert's UID, which may be
        # another engine's alert, not on this page.
        uids = {row[0]: row[15] for row in rows}
        named = sorted({packet for packet, _ in packets.values()} - uids.keys())
        if named:
            uids.update(connection.execute(
                f"SELECT id, uid FROM alerts WHERE id IN ({', '.join('?' for _ in named)})", named
            ).fetchall())
    # Each packet's rows together, where its first row stands.
    first_row: dict[Any, int] = {}
    for index, row in enumerate(rows):
        first_row.setdefault(packets.get(row[0], (row[0], False))[0], index)
    rows = sorted(
        rows,
        key=lambda row: (
            first_row[packets.get(row[0], (row[0], False))[0]],
            ENGINES.index(row[1]) if row[1] in ENGINES else len(ENGINES),
            row[2] or 0,
            row[0],
        ),
    )
    return {
        "total": total,
        "matching": matching,
        "page": page,
        "pages": pages,
        "page_size": page_size,
        "rows": [
            _listed(
                row,
                uids.get(packets.get(row[0], (row[0], False))[0]),
                packets.get(row[0], (row[0], False))[1],
            )
            for row in rows
        ],
    }


# The columns of an alert as the lists show it (_listed).
_LISTED = (
    "id, engine, event_ts_utc, gid, sid, rev, msg, classification, "
    "COALESCE(severity, priority), protocol, service, "
    "src_addr, src_port, dst_addr, dst_port, uid, app"
)


def _listed(row: Sequence[Any], packet_uid: Any, both: bool) -> dict[str, Any]:
    """One alert as the lists show it, from its _LISTED columns, its
    packet's UID and whether both engines alerted on that packet."""
    (
        record_id, engine, event_ts_utc, gid, sid, rev, message, classification,
        severity, protocol, service, src_addr, src_port, dst_addr, dst_port, uid, app,
    ) = row
    return {
        "id": record_id,
        "engine": engine,
        "time_ms": event_ts_utc,
        "rule": rule_name(gid, sid),
        "gid": gid,
        "sid": sid,
        "rev": rev,
        "message": str(message or "").strip(),
        "class": _known(classification),
        # 1 is the most severe, 4 the least.
        "severity": max(1, min(4, int(severity))) if severity is not None else 4,
        "protocol": protocol,
        "service": _known(service),
        # The application OpenAppID named (Snort's alerts); None when none.
        "app": _known(app),
        "src": _endpoint(src_addr, src_port),
        "dst": _endpoint(dst_addr, dst_port),
        "uid": uid_text(uid),
        "packet": uid_text(packet_uid),
        "both": both,
    }


def rule_pairs(db_path: Path | str, *, engines: Sequence[str] = ENGINES) -> dict[str, Any]:
    """The Alert Explorer's "Both engines: rule pairs": over the last hour up
    to the latest complete time (as the Overview's "Both engines" counts), up
    to RULE_PAIRS of a Snort rule and a Suricata rule that fired on one
    packet, with how many packets, the most first. The times are null before
    any alert is stored; with one engine there are no pairs."""
    end = complete_window_end(newest_event_times(db_path, engines))
    if end is None:
        return {"start_ms": None, "end_ms": None, "pairs": []}
    start = end - LAST_HOUR
    pairs = []
    if len(engines) > 1:
        pairs = packet_counts(
            load_window_rows(db_path, start, end, engines),
            window_start=start,
            window_end=end,
            rule_pairs=RULE_PAIRS,
        )["pairs"]
    return {"start_ms": _ms(start), "end_ms": _ms(end), "pairs": pairs}


def _alert_packets(
    connection: sqlite3.Connection, rows: Sequence[Sequence[Any]], engines: Sequence[str]
) -> dict[Any, tuple[Any, bool]]:
    """The packet of each listed alert (id, engine and time first) and
    whether both engines alerted on it, matched among the alerts stored
    within a millisecond of each: the stored times are in milliseconds, the
    engines' packet times in their JSON to the microsecond."""
    ranges: list[list[int]] = []
    for time_ms in sorted({row[2] for row in rows if row[2] is not None}):
        if ranges and time_ms - 1 <= ranges[-1][1]:
            ranges[-1][1] = time_ms + 1
        else:
            ranges.append([time_ms - 1, time_ms + 1])
    if not ranges:
        return {}
    # One range of the time index each (an engine IN (...) here would make
    # SQLite read every alert of each engine instead).
    near = connection.execute(
        "SELECT id, engine, event_ts_utc, msg, rule_key, raw_json FROM alerts WHERE "
        + " OR ".join("event_ts_utc BETWEEN ? AND ?" for _ in ranges),
        [bound for time_range in ranges for bound in time_range],
    ).fetchall()
    columns = ("id", "engine", "event_ts_utc", "msg", "rule_key", "raw_json")
    return alert_packets(dict(zip(columns, row)) for row in near if row[1] in engines)


def _running(proc_dir: Path, engines: Sequence[str] = ENGINES) -> dict[str, bool] | None:
    """Which of the ``engines`` and live_dual_collector.py run on this
    machine, from each process's command line; None when there is no /proc
    to read."""
    try:
        processes = [entry for entry in proc_dir.iterdir() if entry.name.isdigit()]
    except OSError:
        return None
    running = {**{engine: False for engine in engines}, "collector": False}
    for process in processes:
        try:
            arguments = (process / "cmdline").read_bytes().split(b"\0")
        except OSError:
            # Ended meanwhile, or not ours to read.
            continue
        program = Path(arguments[0].decode("utf-8", "replace")).name
        if program in engines:
            running[program] = True
        elif program.startswith("python") and any(
            argument.endswith(b"live_dual_collector.py") for argument in arguments[1:]
        ):
            running["collector"] = True
    return running


def status(
    db_path: Path | str,
    state_file: Path | str | None,
    ids_sources: Mapping[str, Any] | None = None,
    *,
    alert_retention: int | None = None,
    proc_dir: Path = PROC_DIR,
    engines: Sequence[str] = ENGINES,
    stats_files: Mapping[str, Path | str] | None = None,
    archive_dir: Path | str | None = None,
    backup_dir: Path | str | None = None,
    test_alert_file: Path | str | None = None,
) -> dict[str, Any]:
    """Whether the IDS is working now, for the status panel on every
    screen: which of the ``engines`` and the collector run, when the
    collector last saved its place in their logs (it does each time it
    stores alerts), the latest complete time, for each engine what
    ``_engines`` gives, and from each engine's statistics file in
    ``stats_files`` its packets and drops over the last hour (``capture``;
    null when the file can't be read), what ``storage`` says, and the last
    hourly test alert's result (``test_alert``, ids.test_alert; null when
    there is none)."""
    try:
        saved_ms = int(Path(state_file).stat().st_mtime * 1000) if state_file else None
    except OSError:
        saved_ms = None
    newest = newest_event_times(db_path, engines)
    end = complete_window_end(newest)
    with closing(_connect(db_path)) as connection:
        engine_info = _engines(connection, ids_sources or {}, newest, engines)
    now_ms = _ms(datetime.now(tz=PKT))
    return {
        "checked_ms": now_ms,
        "running": _running(proc_dir, engines),
        "collector_saved_ms": saved_ms,
        "complete_end_ms": _ms(end) if end is not None else None,
        "alert_retention": alert_retention,
        "engines": engine_info,
        "capture": {
            engine: CAPTURE_READERS[engine](path, now_ms)
            for engine, path in (stats_files or {}).items()
            if engine in engines
        },
        "storage": storage(db_path, archive_dir, backup_dir),
        "test_alert": read_result(test_alert_file),
    }


def _folder_bytes(folder: Path | str | None) -> int:
    total = 0
    for path in Path(folder).rglob("*") if folder else ():
        try:
            total += path.stat().st_size if path.is_file() else 0
        except OSError:
            # Removed meanwhile (packed into a zip, say).
            continue
    return total


def storage(
    db_path: Path | str, archive_dir: Path | str | None, backup_dir: Path | str | None,
) -> dict[str, Any]:
    """The disk the database is on (free and total bytes), and how much the
    database and the alert archive take. ``backups`` is how many nightly
    backups there are, their size and when the newest was made (null
    without one); it is null when backups are off."""
    disk = shutil.disk_usage(Path(db_path).resolve().parent)
    database = sum(
        path.stat().st_size
        for path in (Path(db_path), Path(f"{db_path}-wal"))
        if path.exists()
    )
    return {
        "disk_free": disk.free,
        "disk_total": disk.total,
        "database": database,
        "archive": _folder_bytes(archive_dir),
        "backups": backup_summary(backup_dir) if backup_dir else None,
    }


def live(
    db_path: Path | str,
    *,
    now: datetime | None = None,
    engines: Sequence[str] = ENGINES,
    off_periods: Sequence[tuple[int, int]] = (),
) -> dict[str, Any]:
    """The Overview's live chart, which moves with the clock: each engine's
    alerts per LIVE_STEP over the last LIVE_WINDOW up to ``now``.

    The steps start at whole half minutes (11:15:00, 11:15:30, …), so a
    step's count stays the same from one request to the next while the
    chart moves; the first one starts before the window. Each engine's
    counts run up to its own latest complete time, not both engines' as on
    the rest of the Overview: both lines run nearly up to now while the
    engines and the collector keep up, and one whose alerts are stored
    late (while it restarts, say) stops earlier until it catches up.
    """
    now_ms = _ms(now or datetime.now(tz=PKT))
    step_ms = int(LIVE_STEP.total_seconds() * 1000)
    window_ms = int(LIVE_WINDOW.total_seconds() * 1000)
    start_ms = (now_ms - window_ms) // step_ms * step_ms
    newest = newest_event_times(db_path, engines)
    with closing(_connect(db_path)) as connection:
        per_step = _alerts_per_step(connection, start_ms, now_ms, step_ms)
    counts = {}
    for engine in engines:
        complete = complete_window_end({engine: newest[engine]}) if engine in newest else None
        # Only whole steps: the one holding the newest alert may get more.
        end_ms = min(_ms(complete), now_ms) // step_ms * step_ms if complete else start_ms
        counts[engine] = [per_step.get((engine, step), 0) for step in range(start_ms, end_ms, step_ms)]
    return {
        "checked_ms": now_ms,
        "window_ms": window_ms,
        "start_ms": start_ms,
        "step_ms": step_ms,
        # Alerts per step from start_ms, oldest first; an engine's list is
        # shorter when its alerts are stored up to an earlier time.
        "alerts": counts,
        # When the machine was off in the window.
        "off": off_during(list(off_periods), start_ms, now_ms),
    }


def export_window(
    db_path: Path | str,
    length_label: str,
    chosen_end_ms: int | None = None,
    *,
    engines: Sequence[str] = ENGINES,
    max_alerts: int = EXPORT_MAX_ALERTS,
    archive_dir: Path | str | None = None,
) -> dict[str, Any] | None:
    """Where a combined export of this length starts and ends: at the
    chosen end, or the latest complete time of the ``engines`` when none is
    chosen or the chosen end is later (``moved_back``); how many of its
    alerts the database holds, the most one export holds, and whether its
    start is older than the database's oldest alert, so the alerts before
    that come from the archive. None when no alert is stored."""
    complete = complete_window_end(newest_event_times(db_path, engines))
    if complete is None:
        return None
    chosen = _moment(chosen_end_ms) if chosen_end_ms is not None else None
    start, end = window_bounds(
        complete if chosen is None else min(chosen, complete), length_label
    )
    start_ms, end_ms = _ms(start), _ms(end)
    with closing(_connect(db_path)) as connection:
        stored = _window_count(connection, start_ms, end_ms, engines)
        oldest = connection.execute("SELECT MIN(event_ts_utc) FROM alerts").fetchone()[0]
    return {
        "start_ms": start_ms,
        "end_ms": end_ms,
        "complete_end_ms": _ms(complete),
        "moved_back": chosen is not None and chosen > complete,
        "stored_alerts": stored,
        "max_alerts": max_alerts,
        "from_archive": archive_dir is not None and oldest is not None and start_ms < oldest,
    }


def _window_count(
    connection: sqlite3.Connection, start_ms: int, end_ms: int, engines: Sequence[str],
) -> int:
    """The stored alerts of the ``engines`` that an export of this window
    reads (a millisecond more on each side, as load_window_rows does)."""
    return connection.execute(
        f"""
        SELECT COUNT(*) FROM alerts
        WHERE event_ts_utc BETWEEN ? AND ?
          AND engine IN ({", ".join("?" for _ in engines)})
        """,
        (start_ms - 1, end_ms + 1, *engines),
    ).fetchone()[0]


@lru_cache(maxsize=4096)
def offline_rule_intelligence(engine: str, gid: Any, sid: Any, message: str) -> dict[str, Any]:
    """Offline intelligence for one rule from the local data, kept for the
    next export; {} when there is none."""
    # Loaded on the first export: the other screens do not need it.
    from ids.offline_intelligence import get_offline_live_intelligence

    try:
        intelligence, _ = get_offline_live_intelligence(
            {"engine": engine, "gid": gid, "sid": sid, "msg": message}
        )
    except Exception:
        return {}
    return intelligence if isinstance(intelligence, dict) else {}


def combined_export(
    db_path: Path | str,
    start_ms: int,
    end_ms: int,
    length_label: str,
    *,
    rule_intelligence: Callable[[str, Any, Any, str], Mapping[str, Any] | None]
    | None = offline_rule_intelligence,
    engines: Sequence[str] = ENGINES,
    archive_dir: Path | str | None = None,
    max_alerts: int = EXPORT_MAX_ALERTS,
) -> dict[str, Any]:
    """The combined JSON of the ``engines`` for one window (see
    docs/combined-json-format.md): its file name and text, and the counts the
    screen shows. The window's alerts come from the database, and the ones
    that have left it from the archive in ``archive_dir``. A window with more
    than ``max_alerts`` raises TooManyAlerts before it is built, as building
    it could take more memory than the machine has."""
    start, end = _moment(start_ms), _moment(end_ms)
    with closing(_connect(db_path)) as connection:
        stored = _window_count(connection, start_ms, end_ms, engines)
        oldest = connection.execute("SELECT MIN(event_ts_utc) FROM alerts").fetchone()[0]
    if stored > max_alerts:
        raise TooManyAlerts(stored, max_alerts)
    rows = load_window_rows(db_path, start, end, engines)
    if archive_dir is not None and (oldest is None or start_ms < oldest):
        known = {row["id"] for row in rows}
        try:
            archived = archived_alerts(
                archive_dir, start_ms, end_ms, engines,
                limit=max_alerts - stored, fields=EXPORT_FIELDS,
            )
        except TooManyAlerts:
            # Said of the whole window, not of its archived part.
            raise TooManyAlerts(None, max_alerts) from None
        rows = sorted(
            [*rows, *(alert for alert in archived if alert["id"] not in known)],
            key=lambda row: (row["event_ts_utc"], row["id"]),
        )
    document = build_combined_detections(
        rows,
        window_start=start,
        window_end=end,
        length_label=length_label,
        rule_intelligence=rule_intelligence,
    )
    packets = document.get("packets", [])
    return {
        "filename": combined_filename(start, length_label),
        "json": serialize_combined_detections(document),
        "alerts": document.get("alerts", {}),
        "packets": len(packets),
        "both_engine_packets": sum(
            "snort" in packet and "suricata" in packet for packet in packets
        ),
    }


def filter_values(db_path: Path | str, *, engines: Sequence[str] = ENGINES) -> dict[str, list[str]]:
    """The protocols, classes, services and apps the stored alerts of the
    ``engines`` have, the most common first: the Alert Explorer's filter
    choices."""
    with closing(_connect(db_path)) as connection:
        rows = connection.execute(
            f"""
            SELECT protocol, classification, service, app, COUNT(*) FROM alerts
            WHERE engine IN ({", ".join("?" for _ in engines)})
            GROUP BY protocol, classification, service, app
            """,
            tuple(engines),
        ).fetchall()
    found: dict[str, Counter[str]] = {
        "protocols": Counter(), "classes": Counter(), "services": Counter(), "apps": Counter(),
    }
    for protocol, classification, service, app, number in rows:
        for key, value in (
            ("protocols", protocol), ("classes", classification), ("services", service), ("apps", app),
        ):
            if _known(value) is not None:
                found[key][str(value)] += number
    return {key: [value for value, _ in values.most_common()] for key, values in found.items()}


def _cut(
    db_path: Path | str, chosen: AlertFilter, engines: Sequence[str],
) -> tuple[AlertFilter, int | None]:
    """``chosen`` up to the latest complete time when it takes more than one
    engine's alerts (see complete_window_end), and that time; one engine's
    alerts need no waiting for the other's (None)."""
    taken = [chosen.engine] if chosen.engine else list(engines)
    if len(taken) < 2:
        return chosen, None
    complete = complete_window_end(newest_event_times(db_path, taken))
    if complete is None:
        return chosen, None
    complete_ms = _ms(complete)
    until = complete_ms if chosen.until_ms is None else min(chosen.until_ms, complete_ms)
    return replace(chosen, until_ms=until), complete_ms


def _selection_groups(chosen: AlertFilter, engines: Sequence[str]) -> list[AlertFilter]:
    """``chosen`` as filters whose newest ``last`` are taken one by one:
    one per engine for the last N of each."""
    if chosen.last is not None and chosen.each and not chosen.engine:
        return [replace(chosen, engine=engine) for engine in engines]
    return [chosen]


def _selection_counts(
    connection: sqlite3.Connection, chosen: AlertFilter, engines: Sequence[str],
) -> dict[str, tuple[int, int, int]]:
    """For each engine, how many alerts ``chosen`` takes, and the first and
    last one's time."""
    counts = {}
    for group in _selection_groups(chosen, engines):
        where, parameters = _filter_sql(group, engines)
        # Sorted only to keep the newest: counting needs no order.
        limit = "ORDER BY event_ts_utc DESC, id DESC LIMIT :last" if group.last is not None else ""
        for engine, number, first, last in connection.execute(
            f"""
            SELECT engine, COUNT(*), MIN(event_ts_utc), MAX(event_ts_utc) FROM (
                SELECT engine, event_ts_utc FROM alerts {where} {limit}
            ) GROUP BY engine
            """,
            {**parameters, "last": group.last},
        ):
            counts[engine] = (number, first, last)
    return counts


def _selected_rows(
    connection: sqlite3.Connection, chosen: AlertFilter, engines: Sequence[str],
) -> list[dict[str, Any]]:
    """The alerts ``chosen`` takes, as an export reads them, oldest first."""
    found: dict[int, dict[str, Any]] = {}
    for group in _selection_groups(chosen, engines):
        where, parameters = _filter_sql(group, engines)
        limit = "LIMIT :last" if group.last is not None else ""
        for row in connection.execute(
            f"""
            SELECT {", ".join(EXPORT_FIELDS)} FROM alerts {where}
            ORDER BY event_ts_utc DESC, id DESC {limit}
            """,
            {**parameters, "last": group.last},
        ):
            alert = dict(zip(EXPORT_FIELDS, row))
            found[alert["id"]] = alert
    return sorted(found.values(), key=lambda alert: (alert["event_ts_utc"] or 0, alert["id"]))


def selection(
    db_path: Path | str,
    chosen: AlertFilter,
    *,
    engines: Sequence[str] = ENGINES,
    max_alerts: int = EXPORT_MAX_ALERTS,
) -> dict[str, Any]:
    """What a download or send of the alerts ``chosen`` takes would hold,
    before it is built: how many alerts of each engine (``alerts``; an
    engine with none left out) and in all, the first and last one's time
    (null without alerts), the latest complete time it stops at with more
    than one engine (``complete_end_ms``, else null), and the most one file
    holds."""
    cut, complete_ms = _cut(db_path, chosen, engines)
    with closing(_connect_filtering(db_path)) as connection:
        counts = _selection_counts(connection, cut, engines)
    return {
        "alerts": {engine: counts[engine][0] for engine in engines if engine in counts},
        "total": sum(number for number, _, _ in counts.values()),
        "first_ms": min((first for _, first, _ in counts.values()), default=None),
        "last_ms": max((last for _, _, last in counts.values()), default=None),
        "complete_end_ms": complete_ms,
        "max_alerts": max_alerts,
    }


def _span_label(span_ms: int) -> str:
    """A window's length in words: its WINDOW_LENGTHS name when it has one."""
    seconds = max(0, round(span_ms / 1000))
    for label, length in WINDOW_LENGTHS.items():
        if length.total_seconds() == seconds:
            return label
    for unit, size, below in (("second", 1, 120), ("minute", 60, 7_200), ("hour", 3_600, 172_800)):
        if seconds < below:
            break
    else:
        unit, size = "day", 86_400
    number = round(seconds / size)
    return f"{number} {unit}{'' if number == 1 else 's'}"


def selection_export(
    db_path: Path | str,
    chosen: AlertFilter,
    *,
    rule_intelligence: Callable[[str, Any, Any, str], Mapping[str, Any] | None]
    | None = offline_rule_intelligence,
    engines: Sequence[str] = ENGINES,
    max_alerts: int = EXPORT_MAX_ALERTS,
) -> dict[str, Any] | None:
    """The combined JSON (see docs/combined-json-format.md) of the alerts
    ``chosen`` takes, as the Alert Explorer's lists show them (from the
    database): its file name and text, its window and the counts the screen
    shows. None when no alert matches. Its window is the time range chosen,
    up to the latest complete time with more than one engine, or with
    ``last`` or no range the alerts' own span, in whole seconds. More than
    ``max_alerts`` raises TooManyAlerts before it is built."""
    cut, _ = _cut(db_path, chosen, engines)
    with closing(_connect_filtering(db_path)) as connection:
        total = sum(number for number, _, _ in _selection_counts(connection, cut, engines).values())
        if total > max_alerts:
            raise TooManyAlerts(total, max_alerts)
        rows = _selected_rows(connection, cut, engines)
    if not rows:
        return None
    ranged = cut.last is None
    start_ms = cut.since_ms if ranged and cut.since_ms is not None else rows[0]["event_ts_utc"]
    end_ms = cut.until_ms if ranged and cut.until_ms is not None else rows[-1]["event_ts_utc"]
    start_ms = start_ms // 1000 * 1000
    end_ms = -(-end_ms // 1000) * 1000
    label = _span_label(end_ms - start_ms)
    start, end = _moment(start_ms), _moment(end_ms)
    # The rows are the chosen ones already: none is left out for its time.
    document = build_combined_detections(
        rows,
        window_start=start,
        window_end=end,
        length_label=label,
        rule_intelligence=rule_intelligence,
        trim_to_window=False,
    )
    taken = [chosen.engine] if chosen.engine else list(engines)
    slug = (
        f"last{chosen.last}{'each' if len(_selection_groups(chosen, engines)) > 1 else ''}"
        if chosen.last is not None
        else re.sub(r"[^0-9a-z]+", "", label.lower().replace("minutes", "min"))
    )
    packets = document.get("packets", [])
    return {
        "filename": f"{'_'.join(taken)}_combined_{start:%Y%m%d_%H%M}_{slug}.json",
        "json": serialize_combined_detections(document),
        "start_ms": start_ms,
        "end_ms": end_ms,
        "alerts": document.get("alerts", {}),
        "packets": len(packets),
        "both_engine_packets": sum(
            "snort" in packet and "suricata" in packet for packet in packets
        ),
    }


def alert_detail(
    db_path: Path | str,
    alert_id: int,
    *,
    rule_intelligence: Callable[[str, Any, Any, str], Mapping[str, Any] | None]
    | None = offline_rule_intelligence,
    engines: Sequence[str] = ENGINES,
) -> dict[str, Any] | None:
    """Everything about one stored alert, for the Alert Explorer's side
    panel; None when no alert of the ``engines`` has that id. ``alert`` is
    the alert as the lists show it, ``same_packet`` the other alerts on its
    packet (both engines'), and ``rules``, ``cves``, ``attack_techniques``,
    ``flows`` and ``packets`` what the combined JSON gives for that one
    packet (see docs/combined-json-format.md): each rule with its text and
    enrichment, and each engine's own output."""
    with closing(_connect(db_path)) as connection:
        found = connection.execute(
            "SELECT event_ts_utc, engine FROM alerts WHERE id = ?", (int(alert_id),)
        ).fetchone()
        if found is None or found[1] not in engines:
            return None
        time_ms = found[0]
        near = [
            dict(zip(EXPORT_FIELDS, row))
            for row in connection.execute(
                f"SELECT {', '.join(EXPORT_FIELDS)} FROM alerts WHERE "
                + ("event_ts_utc BETWEEN ? AND ?" if time_ms is not None else "id = ?"),
                (time_ms - 1, time_ms + 1) if time_ms is not None else (int(alert_id),),
            )
            if row[1] in engines
        ]
        packets = alert_packets(near)
        packet, both = packets.get(alert_id, (alert_id, False))
        together = sorted(
            {alert_id, packet, *(other for other, (name, _) in packets.items() if name == packet)}
        )
        listed = {
            row[0]: row
            for row in connection.execute(
                f"SELECT {_LISTED} FROM alerts WHERE id IN ({', '.join('?' for _ in together)})",
                together,
            )
        }
    packet_uid = listed[packet][15] if packet in listed else listed[alert_id][15]
    rows = sorted(
        (row for row in near if row["id"] in listed),
        key=lambda row: (row["event_ts_utc"] or 0, row["id"]),
    )
    moment = _moment(time_ms if time_ms is not None else 0)
    document = build_combined_detections(
        rows,
        window_start=moment,
        window_end=moment,
        rule_intelligence=rule_intelligence,
        trim_to_window=False,
    )
    return {
        "alert": _listed(listed[alert_id], packet_uid, both),
        "same_packet": [
            _listed(listed[other], packet_uid, both)
            for other in together
            if other != alert_id and other in listed
        ],
        **{
            key: document[key]
            for key in ("rules", "cves", "attack_techniques", "flows", "packets")
            if key in document
        },
    }
