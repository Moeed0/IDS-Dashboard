"""The rules ticked as false positives in the dashboard, to turn off.

The dashboard keeps them in a small JSON file (IDS_RULES_OFF_FILE):
{"rules": [{"engine", "gid", "sid", "rule", "message", "added_ms"}]}. Root's
ids-rules-off (deploy/rules-off/ids-rules-off.py, started by
ids-rules-off.path whenever the file is saved) suppresses them in their
engine and writes how that went to IDS_RULES_OFF_STATUS, which ``listing``
gives with them.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

ENGINES = ("snort", "suricata")
# As ids-rules-off takes at most.
MAX_RULES = 1000
MAX_MESSAGE = 300


def _read(path: Path | str) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def rules(path: Path | str) -> list[dict[str, Any]]:
    """The rules ticked, in the order they were."""
    listed = _read(path)
    found = listed.get("rules") if isinstance(listed, dict) else None
    return [rule for rule in found if isinstance(rule, dict)] if isinstance(found, list) else []


def _number(value: Any, name: str) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{name} must be a whole number") from None
    if not 0 < number < 2**32:
        raise ValueError(f"{name} is out of range")
    return number


def set_rule(
    path: Path | str, engine: str, gid: Any, sid: Any, off: bool, *, message: str = "", now_ms: int,
) -> list[dict[str, Any]]:
    """Ticks a rule (``off``) or unticks it, saving the list in one go (a
    reader never sees half of it); the list."""
    if engine not in ENGINES:
        raise ValueError(f"engine must be one of {', '.join(ENGINES)}")
    gid, sid = _number(gid, "gid"), _number(sid, "sid")
    listed = [rule for rule in rules(path) if (rule.get("engine"), rule.get("gid"), rule.get("sid")) != (engine, gid, sid)]
    if off:
        if len(listed) >= MAX_RULES:
            raise ValueError(f"at most {MAX_RULES} rules can be turned off here")
        listed.append({
            "engine": engine, "gid": gid, "sid": sid, "rule": f"{gid}:{sid}",
            "message": str(message or "").strip()[:MAX_MESSAGE], "added_ms": now_ms,
        })
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.saving")
    temporary.write_text(json.dumps({"rules": listed}, indent=2) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o644)
    os.replace(temporary, path)
    return listed


def listing(path: Path | str, status_path: Path | str) -> dict[str, Any]:
    """The rules ticked, and how root's ids-rules-off last applied the
    list (``applied``: when, its rules, each engine's "reloaded",
    "unchanged" or "error: …"; None before it ever ran, or when it isn't
    installed)."""
    status = _read(status_path)
    return {"rules": rules(path), "applied": status if isinstance(status, dict) else None}
