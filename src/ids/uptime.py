"""
When this machine was off, from the boots the system journal lists: the
time from one boot's last entry to the next boot's first. While it is off
the engines see no packets, so the screens show those times as off rather
than as times without alerts.

A suspended machine stays in one boot, so a suspension is not found.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Callable


def machine_off_periods(
    run: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> list[tuple[int, int]]:
    """Each time the machine was off, as (from_ms, to_ms), oldest first; []
    when the journal can't be read (another init system, or a user without
    the right to read it)."""
    try:
        listed = run(
            ["journalctl", "--list-boots", "--output=json", "--no-pager"],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        ).stdout
        # The journal gives microseconds.
        boots = sorted(
            (int(boot["first_entry"]) // 1000, int(boot["last_entry"]) // 1000)
            for boot in json.loads(listed)
        )
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError):
        return []

    return [
        (earlier_last, later_first)
        for (_, earlier_last), (later_first, _) in zip(boots, boots[1:])
        if later_first > earlier_last
    ]


def off_during(
    periods: list[tuple[int, int]], start_ms: int, end_ms: int,
) -> list[list[int]]:
    """Each of ``periods`` that overlaps ``start_ms`` to ``end_ms``, whole,
    so a screen can say when it began and ended."""
    return [
        [off_from, off_to]
        for off_from, off_to in periods
        if off_to > start_ms and off_from < end_ms
    ]
