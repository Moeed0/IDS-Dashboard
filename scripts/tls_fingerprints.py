#!/usr/bin/env python3
"""The TLS fingerprints each device has used, and naming them.

    PYTHONPATH=src .venv/bin/python scripts/tls_fingerprints.py
    PYTHONPATH=src .venv/bin/python scripts/tls_fingerprints.py --device 192.168.50.120
    PYTHONPATH=src .venv/bin/python scripts/tls_fingerprints.py --label <JA4> "Chrome"
    PYTHONPATH=src .venv/bin/python scripts/tls_fingerprints.py --label <JA4> ""
    PYTHONPATH=src .venv/bin/python scripts/tls_fingerprints.py --bad <JA4 or JA3> "sqlmap"

The list (from the dashboard's database, ids/tls_fingerprints.py): each
device's client fingerprints, the newest first, with the app it was named
as (or else the program the threat-intel database knows it as), how many
connections used it and the sites (SNI) it went to, under the service each
belongs to.

--label names the program a fingerprint is (empty takes the name away); the
dashboard and the combined JSON show the name. --bad adds a fingerprint to
the known-bad lists (deploy/suricata/tls-fingerprints/known-bad-*.txt), so
every connection that uses it raises an alert once
``sudo deploy/install-tls-fingerprints.sh`` has put the lists into Suricata.
"""

from __future__ import annotations

import argparse
import re
import sys
import time
from datetime import datetime
from pathlib import Path

from ids.combined_detections import PKT
from ids.config import get_settings
from ids.offline_intelligence import DEFAULT_DB_PATH as INTEL_DB
from ids.tls_fingerprints import fingerprint_list, set_label

LISTS = Path(__file__).resolve().parents[1] / "deploy" / "suricata" / "tls-fingerprints"
JA4 = re.compile(r"^[tqd][0-9a-z]{2}[di][0-9]{4}[0-9a-z]{2}_[0-9a-f]{12}_[0-9a-f]{12}$")
MD5 = re.compile(r"^(?:(ja3s?):)?([0-9a-f]{32})$")


def _when(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, tz=PKT).strftime("%Y-%m-%d %H:%M:%S")


def show(db_path: Path, device: str | None) -> None:
    rows = [
        row for row in fingerprint_list(db_path, INTEL_DB)["fingerprints"]
        if device is None or row["device"] == device
    ]
    if not rows:
        print("No TLS fingerprints stored yet." if device is None else f"None for {device}.")
        return
    for row in rows:
        known = row["known_app"]
        name = row["app"] or (
            f"{known['name']} ({'known malware, ' if known['malware'] else ''}from {known['source']})"
            if known else "(not named)"
        )
        print(f"{row['device']}  {row['fingerprint']}  {name}")
        print(
            f"    {row['connections']} connections ({', '.join(row['protocols'])}), "
            f"first {_when(row['first_seen_ms'])}, last {_when(row['last_seen_ms'])}, "
            f"on {row['devices']} device{'s' if row['devices'] != 1 else ''}"
        )
        for group in row["services"]:
            sites = ", ".join(group["sites"][:5]) + (f" (+{len(group['sites']) - 5})" if len(group["sites"]) > 5 else "")
            print(f"    {group['name'] or 'other sites'}: {sites}")
        ja3 = [value for value in row["ja3"] if row["fingerprint"] != f"ja3:{value}"]
        if ja3:
            print(f"    JA3: {', '.join(ja3[:3])}")
        if row["note"]:
            print(f"    note: {row['note']}")


def add_bad(value: str, note: str) -> None:
    value = value.strip().lower()
    if JA4.match(value):
        kind = "ja4"
    elif match := MD5.match(value):
        kind, value = match.group(1) or "ja3", match.group(2)
    else:
        sys.exit(f"{value!r} is neither a JA4 nor a JA3 or JA3S hash (ja3s:<hash> for a JA3S)")
    listed = LISTS / f"known-bad-{kind}.txt"
    text = listed.read_text(encoding="utf-8")
    known = {line.split("#", 1)[0].strip().lower() for line in text.splitlines()}
    if value in known:
        print(f"Already in {listed.name}.")
        return
    note = " ".join(note.split())
    if not text.endswith("\n"):
        text += "\n"
    listed.write_text(text + value + (f"  # {note}" if note else "") + "\n", encoding="utf-8")
    print(f"Added to {listed.name}. Put it into Suricata with:")
    print("    sudo deploy/install-tls-fingerprints.sh")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--label", nargs=2, metavar=("FINGERPRINT", "APP"), help="name the program a fingerprint is")
    action.add_argument("--bad", nargs="+", metavar=("FINGERPRINT", "NOTE"), help="add a fingerprint to the known-bad lists")
    parser.add_argument("--device", help="only this device's fingerprints")
    parser.add_argument("--note", default=None, help="a note to keep with --label")
    args = parser.parse_args()
    db_path = get_settings().db_file
    if args.label:
        try:
            set_label(db_path, args.label[0], args.label[1], args.note, now_ms=int(time.time() * 1000))
        except ValueError as exc:
            sys.exit(str(exc))
        print("Saved." if args.label[1].strip() else "Name taken away.")
    elif args.bad:
        add_bad(args.bad[0], " ".join(args.bad[1:]))
    else:
        show(db_path, args.device)


if __name__ == "__main__":
    main()
