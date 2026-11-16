"""
What an engine's action on an alert says, for the combined JSON
(ids/combined_detections.py), which leaves out actions that carry nothing.
"""

from __future__ import annotations

from typing import Any


# What passive engines report for every packet: they watch a copy of the
# traffic and block nothing. Only a blocking action carries information.
PASS_THROUGH_ACTIONS = frozenset({
    "allow",
    "allowed",
})


def is_pass_through_action(action: Any) -> bool:
    return str(action or "").strip().lower() in PASS_THROUGH_ACTIONS
