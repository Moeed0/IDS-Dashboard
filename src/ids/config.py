from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]
ENV_FILE = PROJECT_ROOT / ".env"
# The engines this project reads, in the order the screens show them.
KNOWN_ENGINES = ("snort", "suricata")


def _read_project_env() -> dict[str, str]:
    """
    Read a small .env file without adding a third-party dependency.

    Existing process environment variables always take precedence.
    """
    if not ENV_FILE.is_file():
        return {}

    values: dict[str, str] = {}

    for raw_line in ENV_FILE.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()

        if not line or line.startswith("#"):
            continue

        if line.startswith("export "):
            line = line[7:].strip()

        if "=" not in line:
            continue

        name, value = line.split("=", 1)
        name = name.strip()
        value = value.strip()

        if not name:
            continue

        if len(value) >= 2 and value[0] == value[-1]:
            if value[0] in {"'", '"'}:
                value = value[1:-1]

        values[name] = value

    return values


def _value_from_env(name: str, default: str) -> str:
    """
    Process environment wins over the project .env file.
    """
    project_env = _read_project_env()
    return os.environ.get(name, project_env.get(name, default))


def _path_from_env(name: str, default: str) -> Path:
    value = _value_from_env(name, default)
    path = Path(value).expanduser()

    if not path.is_absolute():
        path = PROJECT_ROOT / path

    return path.resolve()


def _int_from_env(name: str, default: int, minimum: int = 0) -> int:
    raw = _value_from_env(name, str(default))

    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(
            f"{name} must be an integer, got {raw!r}"
        ) from exc

    if value < minimum:
        raise ValueError(
            f"{name} must be >= {minimum}, got {value}"
        )

    return value


def _engines_from_env() -> tuple[str, ...]:
    """IDS_ENGINES: the engines this machine runs, such as "snort,suricata"
    or "suricata" alone, in KNOWN_ENGINES order."""
    raw = _value_from_env("IDS_ENGINES", ",".join(KNOWN_ENGINES))
    chosen = {name.strip().lower() for name in raw.split(",") if name.strip()}
    unknown = chosen.difference(KNOWN_ENGINES)

    if unknown:
        raise ValueError(
            f"IDS_ENGINES: unknown engine {', '.join(sorted(unknown))}; "
            f"use {' or '.join(KNOWN_ENGINES)}, or both"
        )

    if not chosen:
        raise ValueError("IDS_ENGINES cannot be empty")

    return tuple(engine for engine in KNOWN_ENGINES if engine in chosen)


def get_api_token() -> str:
    """
    The token the dashboard API asks for (IDS_API_TOKEN); "" when none is
    set. Kept out of Settings so it is never printed with them.
    """
    return _value_from_env("IDS_API_TOKEN", "").strip()


def api_token_required() -> bool:
    """
    False when IDS_API_REQUIRE_TOKEN is false (or no, off, 0): the dashboard
    API then lets every request in without a token, for testing on a
    trusted network.
    """
    value = _value_from_env("IDS_API_REQUIRE_TOKEN", "true").strip().lower()
    return value not in {"false", "no", "off", "0"}


@dataclass(frozen=True)
class Settings:
    db_file: Path
    state_file: Path
    snort_alert_file: Path
    suricata_eve_file: Path
    interface: str
    alert_retention: int
    packet_retention: int
    batch_size: int
    batch_flush_ms: int
    retention_interval_seconds: int
    # The alerts past alert_retention go to this folder, in zips of
    # alert_archive_zip_days days kept for alert_archive_days; with 0 days
    # they are deleted instead.
    alert_archive_dir: Path
    alert_archive_days: int
    alert_archive_zip_days: int
    # The statistics the engines write every minute, for their dropped
    # packets: Snort's perf_monitor CSV and Suricata's stats.log.
    snort_perf_file: Path
    suricata_stats_file: Path
    # The most alerts one combined export holds (memory: about 8 KB each).
    export_max_alerts: int
    # The nightly gzipped copies of the database, and how many stay (0: none).
    backup_dir: Path
    backup_keep: int
    # The engines this machine runs (IDS_ENGINES), in KNOWN_ENGINES order.
    engines: tuple[str, ...]
    # Each engine's rules (one file, or a folder of .rules files) and its
    # config file.
    snort_rules: Path
    snort_config: Path
    suricata_rules: Path
    suricata_config: Path
    # How many rules each engine loaded, as the last rule update saw it.
    rule_counts_file: Path
    # The basic rules both engines share (deploy/rules/local.rules), which
    # the rule index adds to each engine's own; None (IDS_LOCAL_RULES empty)
    # on a machine whose engines load none.
    local_rules: Path | None


def get_settings() -> Settings:
    interface = _value_from_env(
        "IDS_INTERFACE",
        "ens38",
    ).strip()

    if not interface:
        raise ValueError("IDS_INTERFACE cannot be empty")

    return Settings(
        db_file=_path_from_env(
            "IDS_DB_FILE",
            "ids_live.db",
        ),
        state_file=_path_from_env(
            "IDS_STATE_FILE",
            "ids_collector_state.json",
        ),
        snort_alert_file=_path_from_env(
            "IDS_SNORT_ALERT_FILE",
            "/var/log/snort/alert_json.txt",
        ),
        suricata_eve_file=_path_from_env(
            "IDS_SURICATA_EVE_FILE",
            "/var/log/suricata/eve.json",
        ),
        interface=interface,
        alert_retention=_int_from_env(
            "IDS_ALERT_RETENTION",
            10000,
            minimum=1,
        ),
        packet_retention=_int_from_env(
            "IDS_PACKET_RETENTION",
            5000,
            minimum=1,
        ),
        batch_size=_int_from_env(
            "IDS_BATCH_SIZE",
            100,
            minimum=1,
        ),
        batch_flush_ms=_int_from_env(
            "IDS_BATCH_FLUSH_MS",
            250,
            minimum=1,
        ),
        retention_interval_seconds=_int_from_env(
            "IDS_RETENTION_INTERVAL_SECONDS",
            60,
            minimum=1,
        ),
        alert_archive_dir=_path_from_env(
            "IDS_ALERT_ARCHIVE_DIR",
            "alert-archive",
        ),
        alert_archive_days=_int_from_env(
            "IDS_ALERT_ARCHIVE_DAYS",
            30,
            minimum=0,
        ),
        alert_archive_zip_days=_int_from_env(
            "IDS_ALERT_ARCHIVE_ZIP_DAYS",
            10,
            minimum=1,
        ),
        snort_perf_file=_path_from_env(
            "IDS_SNORT_PERF_FILE",
            "/var/log/snort/perf_monitor_base.csv",
        ),
        suricata_stats_file=_path_from_env(
            "IDS_SURICATA_STATS_FILE",
            "/var/log/suricata/stats.log",
        ),
        export_max_alerts=_int_from_env(
            "IDS_EXPORT_MAX_ALERTS",
            150000,
            minimum=1,
        ),
        backup_dir=_path_from_env(
            "IDS_BACKUP_DIR",
            "backups",
        ),
        backup_keep=_int_from_env(
            "IDS_BACKUP_KEEP",
            3,
            minimum=0,
        ),
        engines=_engines_from_env(),
        snort_rules=_path_from_env(
            "IDS_SNORT_RULES",
            "/usr/local/etc/snort/rules",
        ),
        snort_config=_path_from_env(
            "IDS_SNORT_CONFIG",
            "/usr/local/etc/snort/snort.lua",
        ),
        suricata_rules=_path_from_env(
            "IDS_SURICATA_RULES",
            "/var/lib/suricata/rules/suricata.rules",
        ),
        suricata_config=_path_from_env(
            "IDS_SURICATA_CONFIG",
            "/etc/suricata/suricata.yaml",
        ),
        rule_counts_file=_path_from_env(
            "IDS_RULE_COUNTS_FILE",
            ".runtime/engine_rule_counts.json",
        ),
        local_rules=(
            _path_from_env("IDS_LOCAL_RULES", "deploy/rules/local.rules")
            if _value_from_env("IDS_LOCAL_RULES", "deploy/rules/local.rules").strip()
            else None
        ),
    )


def read_rule_counts(path: Path | str) -> dict[str, int]:
    """How many rules each engine loaded, from IDS_RULE_COUNTS_FILE
    ({"snort": 48757, "suricata": 69309}); {} while there is no such file."""
    try:
        counts = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}

    if not isinstance(counts, dict):
        return {}

    return {
        engine: value
        for engine, value in counts.items()
        if engine in KNOWN_ENGINES
        and isinstance(value, int)
        and not isinstance(value, bool)
    }


def write_rule_counts(path: Path | str, counts: Mapping[str, int]) -> None:
    """Save how many rules each engine loaded, replacing the file at once so
    that a reader never sees half of it."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    written = path.with_name(f"{path.name}.new")
    written.write_text(
        json.dumps(
            {engine: int(counts[engine]) for engine in KNOWN_ENGINES if engine in counts},
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    written.replace(path)


def engine_sources(settings: Settings) -> dict[str, dict[str, Any]]:
    """For each engine this machine runs: its rules, the local rules both
    engines share, its config file and how many rules it loaded (None until
    a rule update saves the count)."""
    counts = read_rule_counts(settings.rule_counts_file)
    paths = {
        "snort": (settings.snort_rules, settings.snort_config),
        "suricata": (settings.suricata_rules, settings.suricata_config),
    }
    return {
        engine: {
            "rules": str(paths[engine][0]),
            "local_rules": str(settings.local_rules) if settings.local_rules else None,
            "config_file": str(paths[engine][1]),
            "engine_rule_count": counts.get(engine),
        }
        for engine in settings.engines
    }
