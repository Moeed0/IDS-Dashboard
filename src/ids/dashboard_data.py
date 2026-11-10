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
import sqlite3
from collections.abc import Callable, Mapping, Sequence
from contextlib import closing
from datetime import datetime, timedelta
from functools import lru_cache
from pathlib import Path
from typing import Any

from ids.alert_archive import TooManyAlerts, archived_alerts
from ids.capture_stats import snort_last_hour, suricata_last_hour
from ids.combined_detections import (
    PKT,
    WINDOW_LENGTHS,
    both_engine_alerts,
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
    try:
        phases = json.loads(LAB_PHASES_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return set()
    return {
        str(phase.get("attacker_ip"))
        for phase in phases.values()
        if isinstance(phase, dict) and phase.get("attacker_ip")
    }


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
# it (gid:sid:rev), the class, the protocol, the service, both endpoints and
# the PKT time.
_SEARCHED = " || ' ' || ".join(
    f"COALESCE({expression}, '')"
    for expression in (
        "msg",
        "gid || ':' || sid || COALESCE(':' || rev, '')",
        "classification",
        "protocol",
        "service",
        "src_addr || ':' || src_port",
        "dst_addr || ':' || dst_port",
        "strftime('%Y-%m-%d %H:%M:%S', event_ts_utc / 1000, 'unixepoch', '+5 hours')",
    )
)


def alerts(
    db_path: Path | str,
    *,
    engine: str | None = None,
    since_ms: int | None = None,
    search: str = "",
    page: int = 1,
    page_size: int = 25,
    engines: Sequence[str] = ENGINES,
) -> dict[str, Any]:
    """One page of stored alerts of the ``engines``, newest first, with how
    many match.

    ``engine`` limits the list to one engine, ``since_ms`` to alerts from
    then on, and ``search`` to alerts whose message, rule, class, protocol,
    service, endpoints or PKT time contain it (any case). A page past the
    last is the last page. Each row says whether both engines alerted on
    its packet (``both``), matched as in the combined export.
    """
    conditions, parameters = [], {}
    if engine:
        conditions.append("engine = :engine")
        parameters["engine"] = engine
    else:
        names = {f"engine{index}": name for index, name in enumerate(engines)}
        conditions.append(f"engine IN ({', '.join(f':{key}' for key in names)})")
        parameters.update(names)
    if since_ms is not None:
        conditions.append("event_ts_utc >= :since")
        parameters["since"] = int(since_ms)
    if search.strip():
        conditions.append(f"instr(lower({_SEARCHED}), :search) > 0")
        parameters["search"] = search.strip().lower()
    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    page_size = max(1, int(page_size))
    with closing(_connect(db_path)) as connection:
        total = connection.execute(
            f"SELECT COUNT(*) FROM alerts {where}", parameters
        ).fetchone()[0]
        pages = max(1, math.ceil(total / page_size))
        page = min(max(1, int(page)), pages)
        rows = connection.execute(
            f"""
            SELECT id, engine, event_ts_utc, gid, sid, rev, msg, classification,
                   COALESCE(severity, priority), protocol, service,
                   src_addr, src_port, dst_addr, dst_port
            FROM alerts
            {where}
            ORDER BY event_ts_utc DESC, id DESC
            LIMIT :limit OFFSET :offset
            """,
            {**parameters, "limit": page_size, "offset": (page - 1) * page_size},
        ).fetchall()
        both = _both_engine_ids(connection, rows, engines) if len(engines) > 1 else set()
    return {
        "total": total,
        "page": page,
        "pages": pages,
        "page_size": page_size,
        "rows": [
            {
                "id": record_id,
                "engine": row_engine,
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
                "src": _endpoint(src_addr, src_port),
                "dst": _endpoint(dst_addr, dst_port),
                "both": record_id in both,
            }
            for (
                record_id, row_engine, event_ts_utc, gid, sid, rev, message, classification,
                severity, protocol, service, src_addr, src_port, dst_addr, dst_port,
            ) in rows
        ],
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


def _both_engine_ids(
    connection: sqlite3.Connection, rows: Sequence[Sequence[Any]], engines: Sequence[str]
) -> set[int]:
    """The ids of the listed alerts (id, engine and time first) whose packet both
    engines alerted on, matched among the alerts stored within a millisecond
    of each: the stored times are in milliseconds, the engines' packet
    times in their JSON to the microsecond."""
    ranges: list[list[int]] = []
    for time_ms in sorted({row[2] for row in rows if row[2] is not None}):
        if ranges and time_ms - 1 <= ranges[-1][1]:
            ranges[-1][1] = time_ms + 1
        else:
            ranges.append([time_ms - 1, time_ms + 1])
    if not ranges:
        return set()
    # One range of the time index each (an engine IN (...) here would make
    # SQLite read every alert of each engine instead).
    near = connection.execute(
        "SELECT id, engine, event_ts_utc, msg, rule_key, raw_json FROM alerts WHERE "
        + " OR ".join("event_ts_utc BETWEEN ? AND ?" for _ in ranges),
        [bound for time_range in ranges for bound in time_range],
    ).fetchall()
    columns = ("id", "engine", "event_ts_utc", "msg", "rule_key", "raw_json")
    return both_engine_alerts(dict(zip(columns, row)) for row in near if row[1] in engines)


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
) -> dict[str, Any]:
    """Whether the IDS is working now, for the status panel on every
    screen: which of the ``engines`` and the collector run, when the
    collector last saved its place in their logs (it does each time it
    stores alerts), the latest complete time, for each engine what
    ``_engines`` gives, and from each engine's statistics file in
    ``stats_files`` its packets and drops over the last hour (``capture``;
    null when the file can't be read)."""
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
