"""
How many packets each engine received and dropped over the last hour, from
the statistics the engines write every minute: Snort's perf_monitor CSV
(counts for each minute) and Suricata's stats.log (totals since it
started). A dropped packet is one the engine never looked at, so the alerts
it would have raised are missing.
"""

from __future__ import annotations

import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any

HOUR_MS = 60 * 60 * 1000
# More than an hour of either file: a Snort row is about 2 KB, a Suricata
# block about 1 KB.
TAIL_BYTES = 512 * 1024

_SURICATA_DATE = re.compile(
    r"^Date: (\d+/\d+/\d+ -- \d+:\d+:\d+) \(uptime: (\d+)d, (\d+)h (\d+)m (\d+)s\)"
)


def _tail_lines(path: Path) -> list[str]:
    """The file's last lines, without one cut at the start."""
    with open(path, "rb") as file:
        size = file.seek(0, os.SEEK_END)
        file.seek(max(0, size - TAIL_BYTES))
        lines = file.read().decode("utf-8", "replace").splitlines()
    return lines[1:] if size > TAIL_BYTES else lines


def snort_last_hour(path: Path | str, now_ms: int) -> dict[str, Any] | None:
    """Snort's packets and drops over its rows of the last hour; None when
    the file is missing or has no such columns."""
    try:
        with open(path, encoding="utf-8", errors="replace") as file:
            header = file.readline()
        lines = _tail_lines(Path(path))
    except OSError:
        return None

    packets = dropped = minutes = 0
    columns: dict[str, int] = {}
    counted = False

    for line in [header, *lines]:
        fields = line.strip().split(",")

        # Snort writes the column names again when it starts.
        if line.startswith("#"):
            columns = {name.lstrip("#"): index for index, name in enumerate(fields)}
            counted = counted or {"daq.received", "daq.dropped"} <= columns.keys()
            continue

        if "daq.received" not in columns or "daq.dropped" not in columns:
            continue

        try:
            at_ms = int(fields[columns["timestamp"]]) * 1000
            received = int(fields[columns["daq.received"]])
            lost = int(fields[columns["daq.dropped"]])
        except (KeyError, IndexError, ValueError):
            continue

        if at_ms > now_ms - HOUR_MS:
            packets += received
            dropped += lost
            minutes += 1

    if not counted:
        return None

    return {"packets": packets, "dropped": dropped, "minutes": minutes}


def suricata_last_hour(path: Path | str, now_ms: int) -> dict[str, Any] | None:
    """Suricata's packets and drops over the last hour (since it started,
    when that is later); None when the file is missing or has no blocks.
    stats.log leaves out counters that are 0, so a missing drop count is 0."""
    try:
        lines = _tail_lines(Path(path))
    except OSError:
        return None

    blocks: list[dict[str, int]] = []

    for line in lines:
        found = _SURICATA_DATE.match(line)

        if found:
            days, hours, minutes, seconds = (int(part) for part in found.groups()[1:])
            blocks.append({
                "at_ms": int(datetime.strptime(found[1], "%m/%d/%Y -- %H:%M:%S").timestamp() * 1000),
                "uptime_ms": ((days * 24 + hours) * 60 + minutes) * 60_000 + seconds * 1000,
                "packets": 0,
                "dropped": 0,
            })
            continue

        name, _, rest = line.partition("|")
        key = {"capture.kernel_packets": "packets", "capture.kernel_drops": "dropped"}.get(name.strip())

        if blocks and key and rest.partition("|")[0].strip() == "Total":
            try:
                blocks[-1][key] = int(rest.rpartition("|")[2])
            except ValueError:
                pass

    if not blocks:
        return None

    latest = blocks[-1]
    started_ms = latest["at_ms"] - latest["uptime_ms"]
    # The oldest block of this run in the last hour (its start, worked out
    # from whole seconds, within 2 s of the latest's); with none, since it
    # started.
    since = next(
        (
            block for block in blocks
            if block["at_ms"] >= latest["at_ms"] - HOUR_MS
            and abs(block["at_ms"] - block["uptime_ms"] - started_ms) <= 2000
            and block is not latest
        ),
        None,
    )

    if since is None or latest["uptime_ms"] <= HOUR_MS:
        return {
            "packets": latest["packets"],
            "dropped": latest["dropped"],
            "minutes": min(60, latest["uptime_ms"] // 60_000),
        }

    return {
        "packets": latest["packets"] - since["packets"],
        "dropped": latest["dropped"] - since["dropped"],
        "minutes": (latest["at_ms"] - since["at_ms"]) // 60_000,
    }
