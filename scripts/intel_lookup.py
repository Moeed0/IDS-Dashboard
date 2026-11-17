#!/usr/bin/env python3
"""The threat-intelligence database on the LLM PC: fetch it from the IDS
dashboard, and look up the CVEs and ATT&CK techniques a combined JSON file
names, for the LLM to enrich the alerts with.

The combined JSON has no enrichment: each rule's text names its CVEs
(``reference:cve,2014-6271``), Suricata's alert metadata names CVEs
(``CVE_2014_6271``) and ATT&CK techniques (``mitre_technique_id``), and a
rule's message can name a CVE. This script finds those IDs and reads what
the database holds on them.

Copy this one file to the LLM PC (Windows or Linux; Python 3.8 or newer, no
packages) and run it there:

    python intel_lookup.py download http://172.16.20.142:8501/
    python intel_lookup.py enrich snort_suricata_combined_20261117_1651_last20.json
    python intel_lookup.py lookup CVE-2014-6271 T1190

``download`` saves the dashboard's intel.db (about 1.4 GB; the IDS machine
refreshes it) next to this script, or at --db; it is written under a
temporary name and renamed when complete. ``enrich`` prints, as JSON, each
CVE and technique the file names with what the database says of it;
``lookup`` does the same for IDs given. With the dashboard's API token on,
give it with --token or IDS_API_TOKEN.

For a CVE: the NVD summary, publication date, CVSS (score, version,
severity, vector), CWEs, EPSS (score, percentile, date) and, when it is in
CISA's Known Exploited Vulnerabilities catalog, its KEV entry. For a
technique: its name, tactics, platforms and description. An ID the database
doesn't hold is listed under "unknown".
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sqlite3
import sys
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Iterable

DEFAULT_DB = Path(__file__).resolve().with_name("intel.db")
# CVE-2014-6271, CVE_2014_6271 (Suricata's metadata) and reference:cve,2014-6271.
_CVE_RE = re.compile(r"\bCVE[-_](\d{4})[-_](\d{4,7})\b", re.IGNORECASE)
_CVE_REFERENCE_RE = re.compile(r"reference\s*:\s*cve\s*,\s*(\d{4})-(\d{4,7})", re.IGNORECASE)
_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def _json(text: Any, default: Any) -> Any:
    try:
        return json.loads(text) if text else default
    except ValueError:
        return default


def named_ids(text: str) -> tuple[list[str], list[str]]:
    """The CVE IDs and ATT&CK technique IDs a text names, each once."""
    cves = {f"CVE-{year}-{number}" for year, number in _CVE_RE.findall(text)}
    cves |= {f"CVE-{year}-{number}" for year, number in _CVE_REFERENCE_RE.findall(text)}
    return sorted(cves), sorted(set(_TECHNIQUE_RE.findall(text)))


def _without_empty(value: Any) -> Any:
    if isinstance(value, dict):
        kept = {key: _without_empty(item) for key, item in value.items()}
        return {key: item for key, item in kept.items() if item not in (None, "", [], {})}
    return value


def cve_details(connection: sqlite3.Connection, cve: str) -> dict[str, Any] | None:
    nvd = connection.execute(
        "SELECT description, published, cvss_score, cvss_version, cvss_severity, cvss_vector,"
        " cwe_json FROM cves WHERE cve_id = ?", (cve,),
    ).fetchone()
    epss = connection.execute(
        "SELECT score, percentile, score_date FROM epss WHERE cve_id = ?", (cve,),
    ).fetchone()
    kev = connection.execute(
        "SELECT vendor_project, product, vulnerability_name, date_added, short_description,"
        " required_action, due_date, known_ransomware_campaign_use FROM kev WHERE cve_id = ?",
        (cve,),
    ).fetchone()
    if not (nvd or epss or kev):
        return None
    details: dict[str, Any] = {}
    if nvd:
        details.update({
            "summary": nvd["description"],
            "published": (nvd["published"] or "")[:10],
            "cvss": {
                "score": nvd["cvss_score"], "version": nvd["cvss_version"],
                "severity": nvd["cvss_severity"], "vector": nvd["cvss_vector"],
            } if nvd["cvss_score"] is not None else None,
            "cwe": _json(nvd["cwe_json"], []),
        })
    if epss:
        details["epss"] = {
            "score": epss["score"], "percentile": epss["percentile"], "date": epss["score_date"],
        }
    if kev:
        details["cisa_kev"] = dict(kev)
    return _without_empty(details)


def technique_details(connection: sqlite3.Connection, technique: str) -> dict[str, Any] | None:
    row = connection.execute(
        "SELECT name, tactics_json, platforms_json, description FROM attack_techniques"
        " WHERE technique_id = ?", (technique,),
    ).fetchone()
    if row is None:
        return None
    return _without_empty({
        "name": row["name"],
        "tactics": _json(row["tactics_json"], []),
        "platforms": _json(row["platforms_json"], []),
        "description": row["description"],
    })


def lookup(db: Path, ids: Iterable[str]) -> dict[str, Any]:
    """What the database holds on each CVE and technique ID."""
    if not db.is_file():
        raise SystemExit(f"No database at {db}: run `python {Path(__file__).name} download <dashboard URL>` first")
    connection = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    found: dict[str, Any] = {"cves": {}, "attack_techniques": {}, "unknown": []}
    try:
        for given in ids:
            name = given.strip().upper().replace("_", "-")
            if name.startswith("CVE-"):
                details = cve_details(connection, name)
                section = "cves"
            else:
                details = technique_details(connection, name)
                section = "attack_techniques"
            if details is None:
                found["unknown"].append(name)
            else:
                found[section][name] = details
        found["sources"] = {
            row["source"]: row["data_as_of"] or row["imported_at"]
            for row in connection.execute("SELECT source, data_as_of, imported_at FROM source_metadata")
        }
    finally:
        connection.close()
    return _without_empty(found)


def enrich(db: Path, combined_file: Path) -> dict[str, Any]:
    """What the database holds on each CVE and technique the file names."""
    cves, techniques = named_ids(combined_file.read_text(encoding="utf-8"))
    return lookup(db, [*cves, *techniques])


def download(base_url: str, db: Path, token: str | None) -> Path:
    """The dashboard's intel.db, saved whole at db."""
    url = urllib.parse.urljoin(base_url.rstrip("/") + "/", "intel/intel.db")
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    part = db.with_name(db.name + ".part")
    db.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=60) as answer:
        total = int(answer.headers.get("Content-Length") or 0)
        done = 0
        with open(part, "wb") as out:
            while chunk := answer.read(1 << 20):
                out.write(chunk)
                done += len(chunk)
                if total:
                    print(f"\r{done >> 20} / {total >> 20} MB", end="", file=sys.stderr, flush=True)
    print(file=sys.stderr)
    if total and done != total:
        os.remove(part)
        raise SystemExit(f"The download stopped at {done} of {total} bytes; nothing was replaced.")
    shutil.move(str(part), str(db))
    return db


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--db", type=Path, default=DEFAULT_DB, help=f"the database (default: {DEFAULT_DB})")
    commands = parser.add_subparsers(dest="command", required=True)
    fetch = commands.add_parser("download", help="fetch intel.db from the dashboard")
    fetch.add_argument("url", help="the dashboard, such as http://172.16.20.142:8501/")
    fetch.add_argument("--token", default=os.environ.get("IDS_API_TOKEN") or None)
    file_command = commands.add_parser("enrich", help="look up what a combined JSON file names")
    file_command.add_argument("file", type=Path)
    ids_command = commands.add_parser("lookup", help="look up CVE and ATT&CK IDs")
    ids_command.add_argument("ids", nargs="+")
    args = parser.parse_args(argv)

    if args.command == "download":
        saved = download(args.url, args.db, args.token)
        print(f"Saved {saved} ({saved.stat().st_size >> 20} MB)")
        return
    found = enrich(args.db, args.file) if args.command == "enrich" else lookup(args.db, args.ids)
    print(json.dumps(found, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
