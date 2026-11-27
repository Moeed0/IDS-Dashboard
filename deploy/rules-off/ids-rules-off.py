#!/usr/bin/python3 -I
"""Turns off the rules ticked as false positives in the IDS dashboard.

Run as root by ids-rules-off.service, which ids-rules-off.path starts each
time the dashboard saves its list (deploy/install-rules-off.sh installs
this script as /usr/local/sbin/ids-rules-off, owned by root):

    ids-rules-off <the dashboard's list> <status file>

The list is only read as data: {"rules": [{"engine": "snort" or "suricata",
"gid": n, "sid": n, ...}]}, anything else is refused. Each engine's rules
are suppressed, so it no longer raises them and everything else stays the
same:

- Suricata: "suppress gen_id <gid>, sig_id <sid>" lines in its threshold
  file (/etc/suricata/threshold.config, between this script's marker
  lines), loaded with a rules reload (systemctl reload suricata), which
  keeps capturing meanwhile;
- Snort: the file /usr/local/etc/snort/suppress_dashboard.lua, which
  deploy/snort/snort.lua adds to its suppress list, loaded by a reload of
  its config (SIGHUP), which keeps capturing meanwhile.

An engine whose rules didn't change isn't touched. The status file (in a
folder only root writes) says when the list was applied and how each engine
took it, for the dashboard to show.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

SURICATA_THRESHOLDS = Path("/etc/suricata/threshold.config")
SURICATA_LOG = Path("/var/log/suricata/suricata.log")
SNORT_FILE = Path("/usr/local/etc/snort/suppress_dashboard.lua")
BEGIN = "# BEGIN ids-dashboard: rules turned off from the dashboard (ids-rules-off; don't edit)"
END = "# END ids-dashboard"
MAX_LIST_BYTES = 1024 * 1024
MAX_RULES = 1000
# How long an engine gets to load its rules again.
RELOAD_SECONDS = 240


def rules_in(path: Path) -> list[tuple[str, int, int]]:
    """The (engine, gid, sid) of each rule in the dashboard's list, sorted,
    or ValueError when the list isn't one."""
    with open(path, "rb") as stream:
        data = stream.read(MAX_LIST_BYTES + 1)
    if len(data) > MAX_LIST_BYTES:
        raise ValueError("the list is too long")
    try:
        listed = json.loads(data.decode("utf-8"))
    except ValueError:
        raise ValueError("the list isn't JSON") from None
    if not isinstance(listed, dict) or not isinstance(listed.get("rules"), list):
        raise ValueError("the list has no rules")
    if len(listed["rules"]) > MAX_RULES:
        raise ValueError(f"the list has more than {MAX_RULES} rules")
    found = set()
    for rule in listed["rules"]:
        if not isinstance(rule, dict) or rule.get("engine") not in ("snort", "suricata"):
            raise ValueError("a rule without its engine")
        gid, sid = rule.get("gid"), rule.get("sid")
        if not all(type(value) is int and 0 < value < 2**32 for value in (gid, sid)):
            raise ValueError("a rule without a whole GID and SID")
        found.add((rule["engine"], gid, sid))
    return sorted(found)


def suricata_text(current: str, rules: list[tuple[int, int]]) -> str:
    """The threshold file with this script's part holding ``rules``."""
    lines = current.splitlines()
    if BEGIN in lines and END in lines[lines.index(BEGIN):]:
        start = lines.index(BEGIN)
        lines = lines[:start] + lines[lines.index(END, start) + 1:]
    while lines and not lines[-1].strip():
        lines.pop()
    part = [BEGIN, *(f"suppress gen_id {gid}, sig_id {sid}" for gid, sid in rules), END] if rules else []
    return "\n".join(lines + ([""] if lines and part else []) + part) + "\n"


def snort_text(rules: list[tuple[int, int]]) -> str:
    entries = "".join(f"    {{ gid = {gid}, sid = {sid} }},\n" for gid, sid in rules)
    return f"-- Written by ids-rules-off: the rules turned off from the dashboard.\nreturn {{\n{entries}}}\n"


def write(path: Path, text: str) -> bool:
    """Writes ``text`` to ``path`` (root's file) when it differs; whether it did."""
    try:
        if path.read_text() == text:
            return False
    except FileNotFoundError:
        pass
    temporary = path.with_name(f".{path.name}.ids-rules-off")
    temporary.write_text(text)
    os.chmod(temporary, 0o644)
    os.replace(temporary, path)
    return True


def _lines(path: Path) -> int:
    try:
        with open(path, "rb") as stream:
            return sum(1 for _ in stream)
    except OSError:
        return 0


def reload_suricata(count: int) -> str:
    """Reloads Suricata's rules and waits for its log to say it read the
    threshold file with ``count`` entries."""
    before = _lines(SURICATA_LOG)
    result = subprocess.run(["systemctl", "reload", "suricata"], capture_output=True, text=True)
    if result.returncode:
        return f"error: systemctl reload suricata: {(result.stderr or result.stdout).strip()[:200]}"
    deadline = time.monotonic() + RELOAD_SECONDS
    while time.monotonic() < deadline:
        time.sleep(3)
        try:
            with open(SURICATA_LOG, errors="replace") as stream:
                new = stream.readlines()[before:]
        except OSError:
            continue
        for line in new:
            if "Threshold config parsed" in line:
                found = line.rsplit(":", 1)[-1].strip()
                return "reloaded" if found.startswith(f"{count} rule") else f"error: Suricata read {found}"
    return "error: Suricata didn't finish reloading its rules within 4 minutes"


def snort_service() -> str | None:
    result = subprocess.run(
        ["systemctl", "list-units", "--type=service", "--state=active", "--no-legend", "--plain", "snort*"],
        capture_output=True, text=True,
    )
    names = [line.split()[0] for line in result.stdout.splitlines() if line.strip()]
    return names[0] if names else None


def reload_outcome(log: str) -> str | None:
    """What Snort's log since its reload signal says: "reloaded" once it
    has the new config ("Reload ended"), an error when it refused it, or
    None while it is still at it."""
    text = log.lower()
    if "reload failed" in text:
        return "error: Snort didn't take the new config and keeps the old one"
    if "reload in progress" in text:
        return "error: Snort was still busy with an earlier reload"
    if "reload ended" in text:
        return "reloaded"
    return None


def _journal(service: str, since: str) -> str:
    return subprocess.run(
        ["journalctl", "-u", service, "--since", since, "-o", "cat", "--no-pager"],
        capture_output=True, text=True,
    ).stdout


def _wait_until_capturing(service: str) -> bool:
    """Waits for Snort to have started capturing since it last started (a
    reload signal while it is still loading its rules isn't taken)."""
    started = subprocess.run(
        ["systemctl", "show", service, "-p", "ActiveEnterTimestamp", "--value"], capture_output=True, text=True,
    ).stdout.strip()
    since = " ".join(started.split()[1:3]) if started else ""
    deadline = time.monotonic() + RELOAD_SECONDS
    while since and time.monotonic() < deadline:
        if "commencing packet processing" in _journal(service, since).lower():
            return True
        time.sleep(3)
    return not since


def reload_snort() -> str:
    """Has Snort reload its config (SIGHUP), once it is capturing, and
    waits for it to say how that went."""
    service = snort_service()
    if service is None:
        return "error: no Snort service is running"
    if not _wait_until_capturing(service):
        return "error: Snort didn't finish starting within 4 minutes"
    since = time.strftime("%Y-%m-%d %H:%M:%S")
    result = subprocess.run(["systemctl", "kill", "--signal=HUP", service], capture_output=True, text=True)
    if result.returncode:
        return f"error: systemctl kill --signal=HUP {service}: {(result.stderr or result.stdout).strip()[:200]}"
    deadline = time.monotonic() + RELOAD_SECONDS
    while time.monotonic() < deadline:
        time.sleep(3)
        outcome = reload_outcome(_journal(service, since))
        if outcome:
            return outcome
    return f"error: Snort didn't say it had reloaded its config within 4 minutes (journalctl -u {service})"


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: ids-rules-off <the dashboard's list> <status file>", file=sys.stderr)
        return 2
    listed, status_path = Path(sys.argv[1]), Path(sys.argv[2])
    status: dict = {"applied_ms": int(time.time() * 1000), "engines": {}}
    try:
        rules = rules_in(listed) if listed.exists() else []
    except (OSError, ValueError) as error:
        status["error"] = f"The dashboard's list wasn't applied: {error}"
        rules = None
    if rules is not None:
        status["rules"] = [{"engine": engine, "gid": gid, "sid": sid} for engine, gid, sid in rules]
        suricata = [(gid, sid) for engine, gid, sid in rules if engine == "suricata"]
        snort = [(gid, sid) for engine, gid, sid in rules if engine == "snort"]
        if SURICATA_THRESHOLDS.parent.is_dir():
            current = SURICATA_THRESHOLDS.read_text() if SURICATA_THRESHOLDS.exists() else ""
            text = suricata_text(current, suricata)
            changed = write(SURICATA_THRESHOLDS, text)
            # Suricata counts every entry in the file, its own and these.
            entries = sum(1 for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#"))
            status["engines"]["suricata"] = reload_suricata(entries) if changed else "unchanged"
        if SNORT_FILE.parent.is_dir():
            changed = write(SNORT_FILE, snort_text(snort))
            status["engines"]["snort"] = reload_snort() if changed else "unchanged"
    status_path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    write(status_path, json.dumps(status, indent=2) + "\n")
    print(json.dumps(status))
    return 1 if "error" in status or any(value.startswith("error") for value in status["engines"].values()) else 0


if __name__ == "__main__":
    sys.exit(main())
