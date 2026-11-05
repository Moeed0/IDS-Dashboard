"""Remove fields that repeat in every exported record without adding information.

Every stored Snort and Suricata event uses generator ID (GID) 1, the ID of
ordinary text rules, so the GID repeats in each record and says nothing.
JSON exports leave it out. A GID other than 1 (Snort's built-in decoder and
inspector events) identifies the rule and is kept.
"""

from __future__ import annotations

from typing import Any


DEFAULT_GID = 1


def _is_default_gid(value: Any) -> bool:
    return not isinstance(value, bool) and str(value).strip() == str(DEFAULT_GID)


def drop_default_gid(value: Any) -> Any:
    """Return a copy without default GIDs, at every level.

    Snort's ``rule`` field ("gid:sid:rev") is dropped with the GID when it
    only repeats the ``sid`` and ``rev`` next to it.
    """
    if isinstance(value, list):
        return [drop_default_gid(item) for item in value]
    if not isinstance(value, dict):
        return value
    cleaned = {key: drop_default_gid(item) for key, item in value.items()}
    if "gid" in cleaned and _is_default_gid(cleaned["gid"]):
        del cleaned["gid"]
        repeated = f"{DEFAULT_GID}:{cleaned.get('sid')}:{cleaned.get('rev')}"
        if cleaned.get("rule") == repeated:
            del cleaned["rule"]
    return cleaned
