"""Read the network variables each IDS engine is configured with.

Rules written as ``$EXTERNAL_NET -> $HOME_NET`` only fire when the traffic
source falls outside HOME_NET, so these values decide which rules can match
lab traffic. The files are read as text; nothing is modified.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

DEFAULT_CONFIG_FILES = {
    "snort": "/usr/local/etc/snort/snort.lua",
    "suricata": "/etc/suricata/suricata.yaml",
}

_SNORT_VAR_RE = re.compile(r"^\s*(HOME_NET|EXTERNAL_NET)\s*=\s*['\"]([^'\"]*)['\"]", re.M)
_SURICATA_VAR_RE = re.compile(r"^\s*(HOME_NET|EXTERNAL_NET):\s*['\"]?([^'\"\n#]+?)['\"]?\s*(?:#.*)?$", re.M)


def parse_network_variables(engine: str, text: str) -> dict[str, str]:
    """Return the active (uncommented) HOME_NET and EXTERNAL_NET values."""
    pattern = _SNORT_VAR_RE if engine == "snort" else _SURICATA_VAR_RE
    values: dict[str, str] = {}
    for name, value in pattern.findall(text):
        # The first active assignment wins; later lines are usually examples.
        values.setdefault(name, value.strip())
    return values


def external_net_excludes_home(variables: dict[str, str]) -> bool:
    """True when EXTERNAL_NET is defined as everything outside HOME_NET."""
    external = variables.get("EXTERNAL_NET", "").replace(" ", "")
    return external in {"!$HOME_NET", "![$HOME_NET]"}


def read_network_variables(engine: str, config_file: str | None = None) -> dict[str, Any]:
    path = Path(config_file or DEFAULT_CONFIG_FILES.get(engine, ""))
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return {"config_file": str(path), "error": type(exc).__name__}
    variables = parse_network_variables(engine, text)
    return {
        "config_file": str(path),
        "home_net": variables.get("HOME_NET"),
        "external_net": variables.get("EXTERNAL_NET"),
        "external_excludes_home": external_net_excludes_home(variables),
    }
