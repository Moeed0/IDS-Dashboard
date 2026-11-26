"""Import locally supplied vulnerability and ATT&CK data into SQLite.

This program deliberately does not download anything.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import io
import ipaddress
import json
import os
import shutil
import re
import sqlite3
import subprocess
import tarfile
import tempfile
import zipfile
from datetime import datetime, timezone
from itertools import chain
from pathlib import Path
from typing import Any, Iterable, Iterator

from ids.offline_intelligence import DEFAULT_DB_PATH, SCHEMA_SQL

# Talos's documentation of Snort's rules: the local copy (by SID), and the
# pages scripts/download_talos_docs.py saved from snort.org, which win. And
# Snort's own description of its built-in rules, from its source (installed
# with it). They go in the database so that the LLM PC, which fetches the
# database, has them.
DEFAULT_RULE_DOCS_PATH = (
    Path(__file__).resolve().parents[1] / "data" / "json" / "rule_docs_preprocessed_by_sid.json"
)
DEFAULT_TALOS_PAGES_PATH = (
    Path(__file__).resolve().parents[1] / "data" / "intel" / "sources" / "talos" / "rule_docs.jsonl"
)
DEFAULT_BUILTIN_STUBS_PATH = Path("/usr/local/share/doc/snort/builtin_stubs.txt")
# Which program a TLS fingerprint is: FoxIO's JA4+ mapping (the free list in
# its JA4 repository; the full JA4+ database at ja4db.foxio.io needs a paid
# account to export) and abuse.ch's SSL Blacklist of malware JA3s.
# scripts/download_intel_sources.py fetches both.
FINGERPRINT_SOURCES = Path(__file__).resolve().parents[1] / "data" / "intel" / "sources" / "fingerprints"
DEFAULT_FOXIO_MAPPING_PATH = FINGERPRINT_SOURCES / "ja4plus-mapping.csv"
DEFAULT_SSLBL_JA3_PATH = FINGERPRINT_SOURCES / "sslbl_ja3_fingerprints.csv"
TLS_FINGERPRINT_SQL = """
DROP TABLE IF EXISTS tls_fingerprint_intel;
CREATE TABLE tls_fingerprint_intel (
    fingerprint TEXT NOT NULL,
    kind TEXT NOT NULL,
    application TEXT,
    library TEXT,
    device TEXT,
    os TEXT,
    notes TEXT,
    first_seen TEXT,
    last_seen TEXT,
    source TEXT NOT NULL
);
CREATE INDEX idx_tls_fingerprint_intel ON tls_fingerprint_intel(fingerprint);
"""
# Which service (app) each site name belongs to: v2fly's domain-list-community
# (MIT licence), one list per service of the names it uses ("youtube":
# youtube.com, googlevideo.com, ytimg.com…). Its lists of kinds of sites
# (category-*, geolocation-*, tld-*, private, cn) and of the domain endings a
# company sells (google-registry-tld: .app, .dev, .page…) are left out: they
# name no service. scripts/download_intel_sources.py fetches it.
DEFAULT_SITE_LIST_PATH = FINGERPRINT_SOURCES / "domain-list-community.tar.gz"
SITE_SERVICES_SQL = """
DROP TABLE IF EXISTS site_services;
CREATE TABLE site_services (
    domain TEXT NOT NULL,
    match TEXT NOT NULL,
    service TEXT NOT NULL,
    PRIMARY KEY (domain, match, service)
);
"""
# Which network owns each IP address: iptoasn.com's ip2asn-combined.tsv.gz
# (public domain, PDDL 1.0): one range per line, with its AS number,
# country and the AS's name. Names an alert's server when nothing in the
# traffic does. scripts/download_intel_sources.py fetches it.
DEFAULT_IP_OWNERS_PATH = (
    Path(__file__).resolve().parents[1] / "data" / "intel" / "sources" / "iptoasn" / "ip2asn-combined.tsv.gz"
)
IP_OWNERS_SQL = """
DROP TABLE IF EXISTS ip_owners;
CREATE TABLE ip_owners (
    range_start TEXT PRIMARY KEY,
    range_end TEXT NOT NULL,
    asn INTEGER NOT NULL,
    country TEXT,
    description TEXT NOT NULL
) WITHOUT ROWID;
"""
_SITE_LIST_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9.!-]*$")
_SITE_DOMAIN_RE = re.compile(r"^[a-z0-9_]([a-z0-9_.-]*[a-z0-9_])?$")
_SITE_LIST_SKIPPED = ("category-", "geolocation-", "tld-")
# Names whose capitals a list's name can't give ("whatsapp" → "WhatsApp"), and
# lists better known by another name ("qcloud" → "Tencent Cloud"). Every other
# list's name is written with each word capitalized ("google-play" → "Google
# Play").
_SERVICE_NAMES = {
    "4chan": "4chan",
    "adguard": "AdGuard",
    "amd": "AMD",
    "aws": "AWS",
    "bbc": "BBC",
    "bilibili": "bilibili",
    "bmw": "BMW",
    "bytedance": "ByteDance",
    "cctv": "CCTV",
    "cnn": "CNN",
    "digitalocean": "DigitalOcean",
    "dmm": "DMM",
    "duckduckgo": "DuckDuckGo",
    "ea": "EA",
    "epicgames": "Epic Games",
    "github": "GitHub",
    "gitlab": "GitLab",
    "google-deepmind": "Google DeepMind",
    "googlefcm": "Google FCM",
    "hbo": "HBO",
    "hp": "HP",
    "hoyoverse": "HoYoverse",
    "ibm": "IBM",
    "icloud": "iCloud",
    "iqiyi": "iQIYI",
    "jd": "JD",
    "jetbrains": "JetBrains",
    "lg": "LG",
    "linkedin": "LinkedIn",
    "mihoyo": "miHoYo",
    "msn": "MSN",
    "nvidia": "NVIDIA",
    "nytimes": "New York Times",
    "ok": "OK.ru",
    "onedrive": "OneDrive",
    "oneplus": "OnePlus",
    "openai": "OpenAI",
    "paypal": "PayPal",
    "pikpak": "PikPak",
    "playstation": "PlayStation",
    "protonmail": "Proton Mail",
    "pubg": "PUBG",
    "qcloud": "Tencent Cloud",
    "soundcloud": "SoundCloud",
    "softbank": "SoftBank",
    "tiktok": "TikTok",
    "uc": "UC Browser",
    "vk": "VK",
    "whatsapp": "WhatsApp",
    "wordpress": "WordPress",
    "xbox": "Xbox",
    "youtube": "YouTube",
}
_MAX_SITE_LIST_BYTES = 5_000_000
# FoxIO's columns that hold a fingerprint, and the kind of each.
_FOXIO_KINDS = ("ja4", "ja4s", "ja4h", "ja4x", "ja4t", "ja4tscan")
_JA3_RE = re.compile(r"^[0-9a-f]{32}$")
BUILTIN_DOCS_SQL = """
DROP TABLE IF EXISTS snort_builtin_docs;
CREATE TABLE snort_builtin_docs (
    gid INTEGER NOT NULL,
    sid INTEGER NOT NULL,
    description TEXT NOT NULL,
    PRIMARY KEY (gid, sid)
);
"""
_BUILTIN_ID_RE = re.compile(r"^(\d+):(\d+)\s*$")
RULE_DOCS_SQL = """
DROP TABLE IF EXISTS talos_rule_docs;
CREATE TABLE talos_rule_docs (
    gid INTEGER NOT NULL,
    sid INTEGER NOT NULL,
    rev INTEGER,
    msg TEXT,
    url TEXT,
    category TEXT,
    explanation TEXT,
    what_to_look_for TEXT,
    false_positives TEXT,
    known_usage TEXT,
    vulnerability TEXT,
    cve_ids TEXT,
    mitre_technique_id TEXT,
    contributors TEXT,
    rule_groups TEXT,
    PRIMARY KEY (gid, sid)
);
"""


# Suricata's rules (Emerging Threats Open, Suricata's own, this lab's local
# ones) and what their classtypes mean: the rules' own documentation, since
# ET Open has no pages like Talos's.
DEFAULT_SURICATA_RULES_PATHS = (
    Path("/var/lib/suricata/rules/suricata.rules"),
    Path("/etc/suricata/rules/local.rules"),
)
DEFAULT_CLASSIFICATION_PATH = Path("/var/lib/suricata/rules/classification.config")
SURICATA_RULE_DOCS_SQL = """
DROP TABLE IF EXISTS suricata_rule_docs;
CREATE TABLE suricata_rule_docs (
    gid INTEGER NOT NULL,
    sid INTEGER NOT NULL,
    rev INTEGER,
    msg TEXT,
    ruleset TEXT,
    category TEXT,
    classtype TEXT,
    class_description TEXT,
    priority INTEGER,
    protocol TEXT,
    confidence TEXT,
    signature_severity TEXT,
    created_at TEXT,
    updated_at TEXT,
    cve_ids TEXT,
    mitre_tactic_id TEXT,
    mitre_technique_id TEXT,
    references_json TEXT,
    metadata_json TEXT,
    rule_text TEXT,
    PRIMARY KEY (gid, sid)
);
"""
# Snort's built-in rules (GID 2 and up, no rule text): the module that raises
# each and what Snort says that module is, from the snort binary itself.
DEFAULT_SNORT = "snort"
BUILTIN_RULES_SQL = """
DROP TABLE IF EXISTS snort_builtin_rules;
CREATE TABLE snort_builtin_rules (
    gid INTEGER NOT NULL,
    sid INTEGER NOT NULL,
    msg TEXT,
    module TEXT,
    module_type TEXT,
    module_help TEXT,
    PRIMARY KEY (gid, sid)
);
"""
_RULE_START_RE = re.compile(r"^(alert|drop|reject|pass)\s", re.IGNORECASE)
_RULE_OPTION_RE = re.compile(r'\s*([A-Za-z_][\w.-]*)\s*(?::\s*((?:"(?:[^"\\]|\\.)*"|[^;])*))?;')
_ANY_CVE_RE = re.compile(r"CVE[-_](\d{4})[-_](\d{4,7})", re.IGNORECASE)
_BUILTIN_LINE_RE = re.compile(r"^(\d+):(\d+) \(([^)]+)\) (.*)$")

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _source_files(
    paths: list[str | Path],
    *,
    allowed_suffixes: tuple[str, ...],
) -> list[Path]:
    """Find files whose formats are allowed for the requested source."""
    files: list[Path] = []
    allowed = tuple(suffix.lower() for suffix in allowed_suffixes)

    for value in paths:
        path = Path(value).expanduser().resolve()
        if not path.exists():
            raise FileNotFoundError(f"Input does not exist: {path}")

        if path.is_dir():
            candidates = [
                item for item in path.rglob("*")
                if item.is_file()
                and item.name.lower().endswith(allowed)
            ]
        elif path.is_file() and path.name.lower().endswith(allowed):
            candidates = [path]
        else:
            raise ValueError(
                f"Unsupported input format: {path}. "
                f"Expected one of: {', '.join(allowed)}"
            )

        files.extend(candidates)

    unique = sorted(set(files), key=lambda item: (
        "modified" in item.name.lower(),
        str(item),
    ))
    if not unique:
        raise ValueError(
            "No supported source files found. Expected: "
            + ", ".join(allowed)
        )
    return unique


def _sha256_files(paths: list[Path]) -> str:
    digest = hashlib.sha256()
    for path in paths:
        digest.update(path.name.encode("utf-8"))
        digest.update(b"\0")
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    return digest.hexdigest()


def _read_json_payloads(path: Path) -> Iterator[tuple[dict[str, Any], str]]:
    """Yield JSON payloads from plain JSON, gzip, or ZIP files."""
    if path.suffix.lower() == ".zip":
        with zipfile.ZipFile(path) as archive:
            for name in sorted(archive.namelist()):
                if not name.lower().endswith(".json"):
                    continue
                with archive.open(name) as raw:
                    payload = json.load(io.TextIOWrapper(raw, encoding="utf-8"))
                if isinstance(payload, dict):
                    yield payload, name
        return

    opener = gzip.open if path.name.lower().endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8") as handle:
        payload = json.load(handle)

    if isinstance(payload, dict):
        yield payload, path.name


def _extract_cvss(cve: dict[str, Any]) -> dict[str, Any] | None:
    metrics = cve.get("metrics")
    if not isinstance(metrics, dict):
        return None

    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if not isinstance(entries, list):
            continue

        for entry in entries:
            if not isinstance(entry, dict):
                continue
            data = entry.get("cvssData")
            if not isinstance(data, dict):
                continue
            return {
                "version": data.get("version"),
                "base_score": data.get("baseScore"),
                "base_severity": data.get("baseSeverity") or entry.get("baseSeverity"),
                "vector": data.get("vectorString"),
                "source": entry.get("source"),
                "type": entry.get("type"),
            }

    return None


def _nvd_summary(cve: dict[str, Any]) -> dict[str, Any]:
    description = ""
    descriptions = cve.get("descriptions", [])
    if isinstance(descriptions, list):
        for entry in descriptions:
            if isinstance(entry, dict) and entry.get("lang") == "en":
                description = str(entry.get("value") or "")
                break

    weaknesses: set[str] = set()
    for weakness in cve.get("weaknesses", []):
        if not isinstance(weakness, dict):
            continue
        for desc in weakness.get("description", []):
            if isinstance(desc, dict) and desc.get("value"):
                weaknesses.add(str(desc["value"]))

    references: list[dict[str, Any]] = []
    for reference in cve.get("references", []):
        if isinstance(reference, dict) and reference.get("url"):
            references.append({
                "url": reference["url"],
                "source": reference.get("source"),
                "tags": reference.get("tags", []),
            })

    cvss = _extract_cvss(cve) or {}

    return {
        "cve_id": str(cve["id"]).upper(),
        "description": description,
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "vulnerability_status": cve.get("vulnStatus"),
        "cvss": cvss,
        "cwe": sorted(weaknesses),
        "references": references,
        "configurations": cve.get("configurations", []),
    }


class _StreamingJSONReader:
    """Read JSON values incrementally without loading a whole feed into RAM."""

    def __init__(self, handle):
        self.handle = handle
        self.decoder = json.JSONDecoder()
        self.buffer = ""
        self.position = 0
        self.eof = False

    def _fill(self) -> None:
        if self.position:
            self.buffer = self.buffer[self.position:]
            self.position = 0
        chunk = self.handle.read(1024 * 1024)
        if chunk:
            self.buffer += chunk
        else:
            self.eof = True

    def peek(self) -> str:
        while True:
            while self.position < len(self.buffer):
                if not self.buffer[self.position].isspace():
                    return self.buffer[self.position]
                self.position += 1
            if self.eof:
                return ""
            self._fill()

    def expect(self, character: str) -> None:
        actual = self.peek()
        if actual != character:
            raise ValueError(
                f"Expected JSON character {character!r}, got {actual!r}"
            )
        self.position += 1

    def read_value(self):
        self.peek()
        while True:
            try:
                value, end = self.decoder.raw_decode(
                    self.buffer, self.position
                )
                self.position = end
                return value
            except json.JSONDecodeError as exc:
                if self.eof:
                    raise ValueError(
                        f"Invalid or truncated JSON input: {exc}"
                    ) from exc
                self._fill()


def _iter_nvd_json_stream(handle):
    """Yield (feed_metadata, CVE record) pairs from an NVD JSON document."""
    reader = _StreamingJSONReader(handle)
    reader.expect("{")

    metadata: dict[str, Any] = {}
    saw_vulnerabilities = False
    first_key = True

    while True:
        character = reader.peek()
        if character == "}":
            reader.expect("}")
            break

        if not first_key:
            reader.expect(",")
        first_key = False

        key = reader.read_value()
        if not isinstance(key, str):
            raise ValueError("NVD JSON contains a non-string object key")
        reader.expect(":")

        if key != "vulnerabilities":
            metadata[key] = reader.read_value()
            continue

        saw_vulnerabilities = True
        reader.expect("[")
        first_item = True

        while True:
            character = reader.peek()
            if character == "]":
                reader.expect("]")
                break

            if not first_item:
                reader.expect(",")
            first_item = False

            item = reader.read_value()
            if not isinstance(item, dict):
                continue

            cve = item.get("cve", item)
            if isinstance(cve, dict) and cve.get("id"):
                yield metadata.copy(), cve

    if not saw_vulnerabilities:
        # Accept small, single-CVE NVD JSON records as well as bulk feeds.
        nested = metadata.get("cve")
        if isinstance(nested, dict) and nested.get("id"):
            yield metadata, nested
        elif CVE_RE.fullmatch(str(metadata.get("id") or "")):
            yield metadata, metadata
        else:
            raise ValueError(
                "Input is not a recognized NVD CVE feed or single-CVE record"
            )


def _iter_nvd_records(path: Path):
    """Stream NVD records from JSON, gzip-compressed JSON, or ZIP archives."""
    if path.name.lower().endswith(".zip"):
        with zipfile.ZipFile(path) as archive:
            names = sorted(
                name for name in archive.namelist()
                if name.lower().endswith(".json")
                and not name.startswith("__MACOSX/")
            )
            if not names:
                raise ValueError(f"No JSON feed found inside {path}")
            for name in names:
                with archive.open(name) as raw:
                    with io.TextIOWrapper(raw, encoding="utf-8") as handle:
                        yield from _iter_nvd_json_stream(handle)
    elif path.name.lower().endswith(".gz"):
        with gzip.open(path, "rt", encoding="utf-8") as handle:
            yield from _iter_nvd_json_stream(handle)
    else:
        with path.open("r", encoding="utf-8") as handle:
            yield from _iter_nvd_json_stream(handle)

def _import_nvd(
    connection: sqlite3.Connection,
    paths: list[Path],
) -> tuple[int, str | None, str | None]:
    """Import NVD records incrementally, keeping memory use bounded."""
    count = 0
    latest_date: str | None = None
    latest_version: str | None = None

    for path in paths:
        for metadata, cve in _iter_nvd_records(path):
            candidates = (
                metadata.get("timestamp"),
                cve.get("lastModified"),
            )
            for value in candidates:
                if isinstance(value, str) and value:
                    if latest_date is None or value > latest_date:
                        latest_date = value

            version = metadata.get("version")
            if version is not None:
                latest_version = str(version)

            summary = _nvd_summary(cve)
            cve_id = summary["cve_id"]
            cvss = summary["cvss"]

            connection.execute(
                """
                INSERT OR REPLACE INTO cves (
                    cve_id, description, published, last_modified,
                    vulnerability_status, cvss_version, cvss_score,
                    cvss_severity, cvss_vector, cvss_source, cvss_type,
                    cwe_json, references_json, configurations_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    cve_id,
                    summary["description"],
                    summary["published"],
                    summary["last_modified"],
                    summary["vulnerability_status"],
                    cvss.get("version"),
                    cvss.get("base_score"),
                    cvss.get("base_severity"),
                    cvss.get("vector"),
                    cvss.get("source"),
                    cvss.get("type"),
                    json.dumps(summary["cwe"], ensure_ascii=False),
                    json.dumps(summary["references"], ensure_ascii=False),
                    json.dumps(summary["configurations"], ensure_ascii=False),
                ),
            )
            count += 1

    return count, latest_date, latest_version


def _open_csv(path: Path):
    if path.name.lower().endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8-sig", newline="")
    return path.open("r", encoding="utf-8-sig", newline="")


def _import_epss(
    connection: sqlite3.Connection,
    paths: list[Path],
) -> tuple[int, str | None, str | None]:
    """Import EPSS CSVs and prefer their explicit score date over filename dates."""
    count = 0
    source_dates: list[str] = []
    version = None

    for path in paths:
        explicit_score_dates: list[str] = []
        comment_dates: list[str] = []
        filename_dates: list[str] = []

        filename_date = re.search(r"\d{4}-\d{2}-\d{2}", path.name)
        if filename_date:
            filename_dates.append(filename_date.group(0))

        with _open_csv(path) as handle:
            header = None

            for line in handle:
                if line.lstrip().startswith("#"):
                    comment = line.strip()

                    score_match = re.search(
                        r"\bscore_date\s*[:=]\s*(\d{4}-\d{2}-\d{2})",
                        comment,
                        re.IGNORECASE,
                    )
                    if score_match:
                        explicit_score_dates.append(score_match.group(1))
                    else:
                        date_match = re.search(r"\d{4}-\d{2}-\d{2}", comment)
                        if date_match:
                            comment_dates.append(date_match.group(0))

                    if "model_version" in comment.lower():
                        version = comment.lstrip("# ").strip()
                    continue

                if line.strip():
                    header = line
                    break

            if explicit_score_dates:
                file_score_date = max(explicit_score_dates)
            elif comment_dates:
                file_score_date = max(comment_dates)
            elif filename_dates:
                file_score_date = max(filename_dates)
            else:
                file_score_date = None

            if file_score_date:
                source_dates.append(file_score_date)

            if header is None:
                continue

            reader = csv.DictReader(chain([header], handle))
            fields = {
                str(field).strip().lower()
                for field in (reader.fieldnames or [])
            }
            if not {"cve", "epss", "percentile"}.issubset(fields):
                raise ValueError(
                    f"EPSS CSV must contain cve, epss, percentile columns: {path}"
                )

            for row in reader:
                normalized = {
                    str(key).strip().lower(): value
                    for key, value in row.items()
                    if key is not None
                }
                cve = str(normalized.get("cve") or "").strip().upper()
                if not CVE_RE.fullmatch(cve):
                    continue

                try:
                    score = float(normalized["epss"])
                    percentile = float(normalized["percentile"])
                except (KeyError, TypeError, ValueError):
                    continue

                connection.execute(
                    """
                    INSERT OR REPLACE INTO epss
                        (cve_id, score, percentile, score_date)
                    VALUES (?, ?, ?, ?)
                    """,
                    (cve, score, percentile, file_score_date),
                )
                count += 1

    return count, max(source_dates) if source_dates else None, version


def _load_one_json(path: Path) -> dict[str, Any]:
    payloads = list(_read_json_payloads(path))
    if len(payloads) != 1:
        raise ValueError(f"Expected one JSON payload in {path}")
    return payloads[0][0]


def _import_kev(connection: sqlite3.Connection, path: Path) -> tuple[int, str | None, str | None]:
    data = _load_one_json(path)
    entries = data.get("vulnerabilities", [])
    if not isinstance(entries, list):
        raise ValueError("CISA KEV JSON has no vulnerabilities list.")

    count = 0
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        cve = str(entry.get("cveID") or "").strip().upper()
        if not CVE_RE.fullmatch(cve):
            continue

        connection.execute(
            """
            INSERT OR REPLACE INTO kev (
                cve_id, vendor_project, product, vulnerability_name, date_added,
                short_description, required_action, due_date,
                known_ransomware_campaign_use, notes, details_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                cve,
                entry.get("vendorProject"),
                entry.get("product"),
                entry.get("vulnerabilityName"),
                entry.get("dateAdded"),
                entry.get("shortDescription"),
                entry.get("requiredAction"),
                entry.get("dueDate"),
                entry.get("knownRansomwareCampaignUse"),
                entry.get("notes"),
                json.dumps(entry, ensure_ascii=False),
            ),
        )
        count += 1

    return (
        count,
        str(data.get("dateReleased") or "") or None,
        str(data.get("catalogVersion") or "") or None,
    )


def _mitre_metadata(path: Path) -> dict[str, Any]:
    sidecar = path.with_suffix(".meta.json")
    if not sidecar.is_file():
        return {}
    try:
        with sidecar.open(encoding="utf-8") as handle:
            value = json.load(handle)
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _import_mitre(connection: sqlite3.Connection, path: Path) -> tuple[int, str | None, str | None]:
    data = _load_one_json(path)
    objects = data.get("objects", [])
    if not isinstance(objects, list):
        raise ValueError("MITRE ATT&CK STIX JSON has no objects list.")

    count = 0
    for obj in objects:
        if not isinstance(obj, dict) or obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        technique_id = None
        technique_url = None
        for reference in obj.get("external_references", []):
            if not isinstance(reference, dict):
                continue
            external_id = str(reference.get("external_id") or "").upper()
            if (
                TECHNIQUE_RE.fullmatch(external_id)
                and reference.get("source_name") in (None, "mitre-attack")
            ):
                technique_id = external_id
                technique_url = reference.get("url")
                if reference.get("source_name") == "mitre-attack":
                    break

        if not technique_id:
            continue

        tactics = sorted({
            str(phase.get("phase_name"))
            for phase in obj.get("kill_chain_phases", [])
            if isinstance(phase, dict)
            and phase.get("kill_chain_name") == "mitre-attack"
            and phase.get("phase_name")
        })

        platforms = obj.get("x_mitre_platforms", [])
        data_sources = obj.get("x_mitre_data_sources", [])
        if not isinstance(platforms, list):
            platforms = []
        if not isinstance(data_sources, list):
            data_sources = []

        connection.execute(
            """
            INSERT OR REPLACE INTO attack_techniques (
                technique_id, stix_id, name, description, tactics_json,
                platforms_json, data_sources_json, url, is_subtechnique
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                technique_id,
                obj.get("id"),
                obj.get("name") or technique_id,
                obj.get("description") or "",
                json.dumps(tactics, ensure_ascii=False),
                json.dumps(platforms, ensure_ascii=False),
                json.dumps(data_sources, ensure_ascii=False),
                technique_url,
                int(bool(obj.get("x_mitre_is_subtechnique"))),
            ),
        )
        count += 1

    meta = _mitre_metadata(path)
    return (
        count,
        str(meta.get("retrieved_at") or "") or None,
        str(meta.get("dataset_version") or "") or None,
    )


def _write_source_metadata(
    connection: sqlite3.Connection,
    source: str,
    data_as_of: str | None,
    version: str | None,
    record_count: int,
    files: list[Path],
) -> None:
    connection.execute(
        """
        INSERT OR REPLACE INTO source_metadata (
            source, data_as_of, imported_at, version,
            record_count, files_json, sha256
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            source,
            data_as_of,
            _now_iso(),
            version,
            record_count,
            json.dumps([path.name for path in files], ensure_ascii=False),
            _sha256_files(files),
        ),
    )


def _number(value: Any) -> int | None:
    text = str(value if value is not None else "").strip()
    return int(text) if text.isdigit() else None


def _rule_doc_row(doc: dict[str, Any]) -> tuple[Any, ...]:
    return (
        _number(doc.get("gid")) or 1,
        _number(doc.get("sid")),
        _number(doc.get("rev")),
        doc.get("msg"),
        doc.get("doc_url"),
        doc.get("rule_category"),
        doc.get("rule_explanation"),
        doc.get("what_to_look_for"),
        doc.get("false_positives"),
        doc.get("known_usage"),
        doc.get("rule_vulnerability"),
        doc.get("cve_ids"),
        doc.get("mitre_id"),
        doc.get("contributors"),
        doc.get("rule_groups"),
    )


def _import_rule_docs(
    connection: sqlite3.Connection, path: Path | None, pages: Path | None = None,
) -> int:
    """Talos's documentation of each Snort rule it documents, in
    talos_rule_docs: the local copy, then the downloaded pages over it. A
    rule Talos has no page for is left out."""
    connection.executescript(RULE_DOCS_SQL)
    documents: dict[tuple[int, int], dict[str, Any]] = {}
    files = []
    if path is not None and path.is_file():
        files.append(path)
        for doc in json.loads(path.read_text(encoding="utf-8")).values():
            key = (_number(doc.get("gid")) or 1, _number(doc.get("sid")))
            if str(doc.get("doc_found")) == "1" and key[1] is not None:
                documents[key] = doc
    if pages is not None and pages.is_file():
        files.append(pages)
        for line in pages.read_text(encoding="utf-8").splitlines():
            try:
                doc = json.loads(line)
            except ValueError:
                continue
            key = (_number(doc.get("gid")) or 1, _number(doc.get("sid")))
            if str(doc.get("doc_found")) == "1" and key[1] is not None:
                documents[key] = {"rev": documents.get(key, {}).get("rev"), **doc}
    connection.executemany(
        f"INSERT OR REPLACE INTO talos_rule_docs VALUES ({', '.join('?' * 15)})",
        [_rule_doc_row(doc) for doc in documents.values()],
    )
    count = connection.execute("SELECT COUNT(*) FROM talos_rule_docs").fetchone()[0]
    if files:
        as_of = max(
            datetime.fromtimestamp(file.stat().st_mtime, tz=timezone.utc) for file in files
        ).date().isoformat()
        _write_source_metadata(connection, "talos_rule_docs", as_of, None, count, files)
    return count


def _text_or_none(value: Any) -> str | None:
    text = " ".join(str(value or "").split())
    return text or None


def _import_tls_fingerprints(
    connection: sqlite3.Connection, foxio: Path | None, sslbl: Path | None,
) -> int:
    """Which program each known TLS fingerprint is, in tls_fingerprint_intel:
    one row per fingerprint a source lists, its kind (ja4, ja4s, ja4h, ja4x,
    ja4t, ja4tscan or ja3) and what the source says of it. The fingerprint
    is lower-case, as Suricata writes it."""
    connection.executescript(TLS_FINGERPRINT_SQL)
    count = 0
    if foxio is not None and foxio.is_file():
        rows = []
        with foxio.open(encoding="utf-8-sig", newline="") as handle:
            for record in csv.DictReader(handle):
                record = {(key or "").strip().lower(): value for key, value in record.items()}
                described = [
                    _text_or_none(record.get(name))
                    for name in ("application", "library", "device", "os", "notes")
                ]
                for kind in _FOXIO_KINDS:
                    fingerprint = _text_or_none(record.get(kind))
                    if fingerprint:
                        rows.append((fingerprint.lower(), kind, *described, None, None, "foxio_ja4plus_mapping"))
        connection.executemany(
            f"INSERT INTO tls_fingerprint_intel VALUES ({', '.join('?' * 10)})", rows
        )
        as_of = datetime.fromtimestamp(foxio.stat().st_mtime, tz=timezone.utc).date().isoformat()
        _write_source_metadata(connection, "foxio_ja4plus_mapping", as_of, None, len(rows), [foxio])
        count += len(rows)
    if sslbl is not None and sslbl.is_file():
        rows = []
        updated = None
        for line in sslbl.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("#"):
                match = re.search(r"Last updated:\s*(\d{4}-\d{2}-\d{2})", line)
                updated = match.group(1) if match else updated
                continue
            parts = [part.strip() for part in line.split(",")]
            if len(parts) < 4 or not _JA3_RE.match(parts[0].lower()):
                continue
            reason = _text_or_none(",".join(parts[3:]))
            rows.append((
                parts[0].lower(), "ja3", reason, None, None, None,
                "Listed by abuse.ch's SSL Blacklist: a JA3 seen in the TLS traffic of malware"
                + (f" ({reason})" if reason else "") + ". A JA3 can be shared with ordinary software.",
                parts[1] or None, parts[2] or None, "sslbl_ja3",
            ))
        connection.executemany(
            f"INSERT INTO tls_fingerprint_intel VALUES ({', '.join('?' * 10)})", rows
        )
        as_of = updated or datetime.fromtimestamp(sslbl.stat().st_mtime, tz=timezone.utc).date().isoformat()
        _write_source_metadata(connection, "sslbl_ja3", as_of, None, len(rows), [sslbl])
        count += len(rows)
    return count


def _service_name(list_name: str) -> str:
    """A list's name as a service's: "google-play" → "Google Play",
    "whatsapp" → "WhatsApp"."""
    if list_name in _SERVICE_NAMES:
        return _SERVICE_NAMES[list_name]
    return " ".join(word.capitalize() for word in list_name.split("-") if word)


def _import_site_services(connection: sqlite3.Connection, path: Path | None) -> int:
    """Which service each site name belongs to, in site_services, from
    domain-list-community's archive (read as it is, never unpacked): a row
    per name and service, ``match`` 'domain' for the name and every name
    under it, 'full' for that name only. Its include:, keyword: and regexp:
    lines are left out (an included list's names are in that list)."""
    if path is None or not path.is_file():
        return 0
    connection.executescript(SITE_SERVICES_SQL)
    rows: set[tuple[str, str, str]] = set()
    newest = 0
    with tarfile.open(path, "r:gz") as archive:
        for member in archive:
            parent, _, name = member.name.rpartition("/")
            if (
                not member.isfile()
                or not parent.endswith("/data")
                or not _SITE_LIST_NAME_RE.match(name)
                or name.startswith(_SITE_LIST_SKIPPED)
                or name.endswith("-tld")
                or name in ("private", "cn")
                or member.size > _MAX_SITE_LIST_BYTES
            ):
                continue
            handle = archive.extractfile(member)
            if handle is None:
                continue
            newest = max(newest, int(member.mtime))
            service = _service_name(name)
            for line in handle.read().decode("utf-8", errors="replace").splitlines():
                words = line.split("#", 1)[0].split()
                if not words:
                    continue
                kind, _, value = words[0].rpartition(":")
                kind = kind or "domain"
                value = value.lower().strip(".")
                if kind in ("domain", "full") and _SITE_DOMAIN_RE.match(value):
                    rows.add((value, kind, service))
    connection.executemany("INSERT INTO site_services VALUES (?, ?, ?)", sorted(rows))
    as_of = datetime.fromtimestamp(
        newest or path.stat().st_mtime, tz=timezone.utc
    ).date().isoformat()
    _write_source_metadata(connection, "domain_list_community", as_of, None, len(rows), [path])
    return len(rows)


def ip_key(value: str) -> str:
    """An IP address as ip_owners keys it: its version, then the address as
    32 hex digits, so that text order is address order."""
    address = ipaddress.ip_address(value.strip())
    return f"{address.version}{int(address):032x}"


def _import_ip_owners(connection: sqlite3.Connection, path: Path | None) -> int:
    """Which network owns each address range, in ip_owners (ranges no one
    routes are left out)."""
    if path is None or not path.is_file():
        return 0
    connection.executescript(IP_OWNERS_SQL)
    count = 0
    with gzip.open(path, "rt", encoding="utf-8", errors="replace") as handle:
        batch = []
        for line in handle:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 5 or not parts[2].isdigit() or parts[2] == "0":
                continue
            try:
                start, end = ip_key(parts[0]), ip_key(parts[1])
            except ValueError:
                continue
            country = parts[3].strip()
            batch.append((
                start, end, int(parts[2]),
                country if country and country != "None" else None, parts[4].strip(),
            ))
            if len(batch) >= 50_000:
                connection.executemany("INSERT OR REPLACE INTO ip_owners VALUES (?, ?, ?, ?, ?)", batch)
                count += len(batch)
                batch = []
        connection.executemany("INSERT OR REPLACE INTO ip_owners VALUES (?, ?, ?, ?, ?)", batch)
        count += len(batch)
    as_of = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).date().isoformat()
    _write_source_metadata(connection, "iptoasn", as_of, None, count, [path])
    return count


def _import_builtin_docs(connection: sqlite3.Connection, path: Path | None) -> int:
    """Snort's own description of each built-in rule (builtin_stubs.txt: a
    line ``gid:sid``, then the description), in snort_builtin_docs."""
    if path is None or not path.is_file():
        return 0
    connection.executescript(BUILTIN_DOCS_SQL)
    descriptions: dict[tuple[int, int], list[str]] = {}
    current: list[str] | None = None
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = _BUILTIN_ID_RE.match(line)
        if match:
            current = descriptions.setdefault((int(match.group(1)), int(match.group(2))), [])
        elif current is not None:
            current.append(line.strip())
    rows = [
        (gid, sid, " ".join(" ".join(lines).split()))
        for (gid, sid), lines in descriptions.items()
        if " ".join(lines).strip()
    ]
    connection.executemany("INSERT OR REPLACE INTO snort_builtin_docs VALUES (?, ?, ?)", rows)
    as_of = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).date().isoformat()
    _write_source_metadata(connection, "snort_builtin_docs", as_of, None, len(rows), [path])
    return len(rows)


def _classifications(path: Path | None) -> dict[str, tuple[str, int | None]]:
    """classification.config: each classtype's description and priority."""
    classes: dict[str, tuple[str, int | None]] = {}
    if path is None or not path.is_file():
        return classes
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        name, _, rest = line.strip().partition("config classification:")
        if name or not rest:
            continue
        parts = [part.strip() for part in rest.split(",")]
        if len(parts) >= 2:
            classes[parts[0]] = (parts[1], _number(parts[2]) if len(parts) > 2 else None)
    return classes


def _ruleset(path: Path, msg: str) -> tuple[str, str]:
    """Where a Suricata rule comes from, and its category (the message's
    leading words: ET MALWARE, GPL MISC, SURICATA)."""
    words = msg.split()
    if path.name == "local.rules":
        return "Local rule of this lab", words[0] if words else ""
    if words[:1] == ["ET"]:
        return "Emerging Threats Open", " ".join(words[:2])
    if words[:1] == ["GPL"]:
        return "Emerging Threats Open (GPL rules, from the old Snort ruleset)", " ".join(words[:2])
    return "Suricata's own rules (decoder, stream, protocol and file events)", words[0] if words else ""


def _suricata_rule_row(
    text: str, path: Path, classes: dict[str, tuple[str, int | None]],
) -> tuple[Any, ...] | None:
    start, end = text.find("("), text.rfind(")")
    if start < 0 or end <= start:
        return None
    options: dict[str, list[str]] = {}
    for match in _RULE_OPTION_RE.finditer(text[start + 1:end]):
        value = str(match.group(2) or "").strip()
        if len(value) >= 2 and value[0] == value[-1] == '"':
            value = re.sub(r"\\(.)", r"\1", value[1:-1])
        options.setdefault(match.group(1).lower(), []).append(value)
    sid = _number((options.get("sid") or [""])[0])
    if sid is None:
        return None
    metadata: dict[str, list[str]] = {}
    for entry in options.get("metadata", []):
        for item in entry.split(","):
            key, _, value = item.strip().partition(" ")
            if key and value.strip() and value.strip() not in metadata.setdefault(key, []):
                metadata[key].append(value.strip())
    references = options.get("reference", [])
    cves = {
        f"CVE-{year}-{number}"
        for year, number in _ANY_CVE_RE.findall(" ".join(metadata.get("cve", [])))
    } | {
        f"CVE-{value[4:].strip()}" for value in references if value.lower().startswith("cve,")
    }

    def first(key: str) -> str | None:
        return (metadata.get(key) or [None])[0]

    def date(key: str) -> str | None:
        value = first(key)
        return value.replace("_", "-") if value else None

    msg = (options.get("msg") or [""])[0]
    ruleset, category = _ruleset(path, msg)
    classtype = (options.get("classtype") or [None])[0]
    description, class_priority = classes.get(classtype or "", (None, None))
    priority = _number((options.get("priority") or [""])[0]) or class_priority
    header = text[:start].split()
    return (
        _number((options.get("gid") or ["1"])[0]) or 1,
        sid,
        _number((options.get("rev") or [""])[0]),
        msg,
        ruleset,
        category,
        classtype,
        description,
        priority,
        header[1] if len(header) > 1 else None,
        first("confidence"),
        first("signature_severity"),
        date("created_at"),
        date("updated_at"),
        ", ".join(sorted(cves)),
        ", ".join(metadata.get("mitre_tactic_id", [])),
        ", ".join(metadata.get("mitre_technique_id", [])),
        json.dumps(references, ensure_ascii=False),
        json.dumps(metadata, ensure_ascii=False),
        text,
    )


def _import_suricata_rule_docs(
    connection: sqlite3.Connection, paths: Iterable[Path | None], classification: Path | None,
) -> int:
    """Each loaded Suricata rule's own documentation, in suricata_rule_docs:
    its message, ruleset and category, what its classtype means, its
    confidence, severity and dates, its references, CVEs and ATT&CK IDs, and
    its text. Rules commented out in the files are left out."""
    files = [path for path in paths if path is not None and path.is_file()]
    if not files:
        return 0
    connection.executescript(SURICATA_RULE_DOCS_SQL)
    classes = _classifications(classification)
    rows = []
    for path in files:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if _RULE_START_RE.match(line):
                row = _suricata_rule_row(line, path, classes)
                if row is not None:
                    rows.append(row)
    connection.executemany(
        f"INSERT OR REPLACE INTO suricata_rule_docs VALUES ({', '.join('?' * 20)})", rows,
    )
    count = connection.execute("SELECT COUNT(*) FROM suricata_rule_docs").fetchone()[0]
    used = files + ([classification] if classification is not None and classification.is_file() else [])
    as_of = max(datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc) for path in files)
    _write_source_metadata(connection, "suricata_rule_docs", as_of.date().isoformat(), None, count, used)
    return count


def _import_builtin_rules(connection: sqlite3.Connection, snort: str | None) -> int:
    """Snort's built-in rules from the snort binary (--list-builtin): each
    rule's module and message, and what Snort says the module is
    (--help-modules-json). None when snort isn't installed here."""
    binary = shutil.which(snort) if snort else None
    if binary is None:
        return 0
    try:
        listed = subprocess.run(
            [binary, "--list-builtin"], capture_output=True, text=True, timeout=60, check=True,
        ).stdout
        modules = {
            module["module"]: module
            for module in json.loads(subprocess.run(
                [binary, "--help-modules-json"], capture_output=True, text=True, timeout=60, check=True,
            ).stdout)
        }
    except (OSError, subprocess.SubprocessError, ValueError):
        return 0
    rows = []
    for line in listed.splitlines():
        match = _BUILTIN_LINE_RE.match(line.strip())
        if match:
            module = modules.get(match.group(3), {})
            rows.append((
                int(match.group(1)), int(match.group(2)), match.group(4).strip(), match.group(3),
                module.get("type"), module.get("help"),
            ))
    if not rows:
        return 0
    connection.executescript(BUILTIN_RULES_SQL)
    connection.executemany("INSERT OR REPLACE INTO snort_builtin_rules VALUES (?, ?, ?, ?, ?, ?)", rows)
    try:
        answer = subprocess.run([binary, "-V"], capture_output=True, text=True, timeout=60)
        version = answer.stdout + answer.stderr
    except (OSError, subprocess.SubprocessError):
        version = ""
    found = re.search(r"Version ([\d.]+)", version)
    _write_source_metadata(
        connection, "snort_builtin_rules", datetime.now(timezone.utc).date().isoformat(),
        found.group(1) if found else None, len(rows), [],
    )
    return len(rows)


COPY_CHUNK = 64 << 20


def _copy_uncached(source: Path, target: Path) -> None:
    """source copied to target, 64 MB at a time, each piece written out and
    then dropped from the page cache. The database is 1.4 GB: copied whole
    through the cache (shutil.copyfile) it pushed this VM, with about 1 GB
    free, into swapping to compressed RAM, and the copy took 20 minutes."""
    with source.open("rb") as reading, target.open("wb") as writing:
        done = 0
        while True:
            chunk = reading.read(COPY_CHUNK)
            if not chunk:
                break
            writing.write(chunk)
            writing.flush()
            os.fdatasync(writing.fileno())
            if hasattr(os, "posix_fadvise"):
                os.posix_fadvise(reading.fileno(), done, len(chunk), os.POSIX_FADV_DONTNEED)
                os.posix_fadvise(writing.fileno(), done, len(chunk), os.POSIX_FADV_DONTNEED)
            done += len(chunk)
    shutil.copymode(source, target)


def add_rule_docs(
    database: str | Path = DEFAULT_DB_PATH,
    rule_docs_path: str | Path | None = DEFAULT_RULE_DOCS_PATH,
    talos_pages_path: str | Path | None = DEFAULT_TALOS_PAGES_PATH,
    builtin_stubs_path: str | Path | None = DEFAULT_BUILTIN_STUBS_PATH,
    suricata_rules_paths: Iterable[str | Path] | None = DEFAULT_SURICATA_RULES_PATHS,
    classification_path: str | Path | None = DEFAULT_CLASSIFICATION_PATH,
    snort: str | None = DEFAULT_SNORT,
) -> dict[str, Any]:
    """The rule documentation (Talos's for Snort's rules, Snort's own for its
    built-in rules, and Suricata's rules' own) put in an existing database,
    replacing what it had of it: on a copy, which then replaces the database
    whole, so a reader or download in progress keeps the old one."""
    return _update_copy(database, lambda connection: {
        "talos_rule_docs": _import_rule_docs(
            connection, _resolved(rule_docs_path), _resolved(talos_pages_path)
        ),
        "snort_builtin_docs": _import_builtin_docs(connection, _resolved(builtin_stubs_path)),
        "snort_builtin_rules": _import_builtin_rules(connection, snort),
        "suricata_rule_docs": _import_suricata_rule_docs(
            connection, [_resolved(path) for path in suricata_rules_paths or ()],
            _resolved(classification_path),
        ),
    })


def add_tls_fingerprints(
    database: str | Path = DEFAULT_DB_PATH,
    foxio_mapping_path: str | Path | None = DEFAULT_FOXIO_MAPPING_PATH,
    sslbl_ja3_path: str | Path | None = DEFAULT_SSLBL_JA3_PATH,
    site_list_path: str | Path | None = DEFAULT_SITE_LIST_PATH,
    ip_owners_path: str | Path | None = DEFAULT_IP_OWNERS_PATH,
) -> dict[str, Any]:
    """The known TLS fingerprints (FoxIO's JA4+ mapping, abuse.ch's malware
    JA3s), the services of site names (domain-list-community) and the
    owners of IP addresses (iptoasn.com) put in an existing database,
    replacing what it had of them, the same way as add_rule_docs."""
    return _update_copy(database, lambda connection: {
        "tls_fingerprint_intel": _import_tls_fingerprints(
            connection, _resolved(foxio_mapping_path), _resolved(sslbl_ja3_path)
        ),
        "site_services": _import_site_services(connection, _resolved(site_list_path)),
        "ip_owners": _import_ip_owners(connection, _resolved(ip_owners_path)),
    })


def _resolved(path: str | Path | None) -> Path | None:
    return Path(path).expanduser().resolve() if path is not None else None


def _update_copy(database: str | Path, change) -> dict[str, Any]:
    """``change`` (a function of a connection, giving its counts) made on a
    copy of the existing database, which then replaces it whole, so a
    reader or download in progress keeps the old one."""
    target = Path(database).expanduser().resolve()
    if not target.is_file():
        raise FileNotFoundError(f"Database does not exist: {target}")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".tmp", dir=target.parent
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        _copy_uncached(target, temporary)
        connection = sqlite3.connect(temporary)
        try:
            counts = change(connection)
            connection.commit()
            check = connection.execute("PRAGMA quick_check").fetchone()[0]
            if check != "ok":
                raise sqlite3.DatabaseError(f"Staged database check failed: {check}")
        finally:
            connection.close()
        os.replace(temporary, target)
    finally:
        if temporary.exists():
            temporary.unlink()
    return {"database": str(target), "counts": counts}


def import_sources(
    *,
    nvd_paths: list[str | Path],
    epss_paths: list[str | Path],
    kev_path: str | Path,
    mitre_path: str | Path,
    output_path: str | Path = DEFAULT_DB_PATH,
    replace: bool = False,
    rule_docs_path: str | Path | None = DEFAULT_RULE_DOCS_PATH,
    talos_pages_path: str | Path | None = DEFAULT_TALOS_PAGES_PATH,
    builtin_stubs_path: str | Path | None = DEFAULT_BUILTIN_STUBS_PATH,
    suricata_rules_paths: Iterable[str | Path] | None = DEFAULT_SURICATA_RULES_PATHS,
    classification_path: str | Path | None = DEFAULT_CLASSIFICATION_PATH,
    snort: str | None = DEFAULT_SNORT,
    foxio_mapping_path: str | Path | None = DEFAULT_FOXIO_MAPPING_PATH,
    sslbl_ja3_path: str | Path | None = DEFAULT_SSLBL_JA3_PATH,
    site_list_path: str | Path | None = DEFAULT_SITE_LIST_PATH,
    ip_owners_path: str | Path | None = DEFAULT_IP_OWNERS_PATH,
) -> dict[str, Any]:
    """Build a validated database from local files and atomically publish it."""
    target = Path(output_path).expanduser().resolve()

    if target.exists() and not replace:
        raise FileExistsError(
            f"Database already exists: {target}. "
            "Use replace=True/--replace only after backing it up."
        )

    nvd_files = _source_files(nvd_paths, allowed_suffixes=(".json", ".json.gz", ".zip"))
    epss_files = _source_files(epss_paths, allowed_suffixes=(".csv", ".csv.gz"))
    kev_file = Path(kev_path).expanduser().resolve()
    mitre_file = Path(mitre_path).expanduser().resolve()

    for path in (kev_file, mitre_file):
        if not path.is_file():
            raise FileNotFoundError(f"Input file does not exist: {path}")

    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.",
        suffix=".tmp",
        dir=target.parent,
    )
    os.close(descriptor)
    temporary = Path(temporary_name)

    counts: dict[str, int] = {}

    try:
        connection = sqlite3.connect(temporary)
        try:
            connection.executescript(SCHEMA_SQL)

            count, date, version = _import_nvd(connection, nvd_files)
            counts["nvd"] = connection.execute(
                "SELECT COUNT(*) FROM cves"
            ).fetchone()[0]
            _write_source_metadata(
                connection, "nvd", date, version, counts["nvd"], nvd_files
            )

            count, date, version = _import_epss(connection, epss_files)
            counts["epss"] = connection.execute(
                "SELECT COUNT(*) FROM epss"
            ).fetchone()[0]
            _write_source_metadata(
                connection, "epss", date, version, counts["epss"], epss_files
            )

            count, date, version = _import_kev(connection, kev_file)
            counts["cisa_kev"] = connection.execute(
                "SELECT COUNT(*) FROM kev"
            ).fetchone()[0]
            _write_source_metadata(
                connection, "cisa_kev", date, version, counts["cisa_kev"], [kev_file]
            )

            count, date, version = _import_mitre(connection, mitre_file)
            counts["mitre_attack"] = connection.execute(
                "SELECT COUNT(*) FROM attack_techniques"
            ).fetchone()[0]
            _write_source_metadata(
                connection, "mitre_attack", date, version, counts["mitre_attack"], [mitre_file]
            )

            counts["talos_rule_docs"] = _import_rule_docs(
                connection,
                Path(rule_docs_path).expanduser().resolve() if rule_docs_path else None,
                Path(talos_pages_path).expanduser().resolve() if talos_pages_path else None,
            )
            counts["snort_builtin_docs"] = _import_builtin_docs(
                connection,
                Path(builtin_stubs_path).expanduser().resolve() if builtin_stubs_path else None,
            )
            counts["snort_builtin_rules"] = _import_builtin_rules(connection, snort)
            counts["suricata_rule_docs"] = _import_suricata_rule_docs(
                connection,
                [Path(path).expanduser().resolve() for path in suricata_rules_paths or ()],
                Path(classification_path).expanduser().resolve() if classification_path else None,
            )
            counts["tls_fingerprint_intel"] = _import_tls_fingerprints(
                connection, _resolved(foxio_mapping_path), _resolved(sslbl_ja3_path)
            )
            counts["site_services"] = _import_site_services(
                connection, _resolved(site_list_path)
            )
            counts["ip_owners"] = _import_ip_owners(connection, _resolved(ip_owners_path))

            connection.commit()

            check = connection.execute("PRAGMA integrity_check").fetchone()[0]
            if check != "ok":
                raise sqlite3.DatabaseError(
                    f"Staged database integrity check failed: {check}"
                )
        finally:
            connection.close()

        os.replace(temporary, target)

    finally:
        if temporary.exists():
            temporary.unlink()

    return {
        "database": str(target),
        "counts": counts,
        "size_bytes": target.stat().st_size,
        "integrity": "ok",
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Import local NVD, EPSS, CISA KEV and MITRE ATT&CK files. "
            "This script does not access the network."
        )
    )
    parser.add_argument(
        "--add-rule-docs",
        action="store_true",
        help=(
            "Only put the rule documentation (--rule-docs, --talos-pages, "
            "--builtin-stubs, --snort, --suricata-rules, --classification) in the "
            "existing database at --output; the other sources are kept."
        ),
    )
    parser.add_argument(
        "--add-tls-fingerprints",
        action="store_true",
        help=(
            "Only put the known TLS fingerprints (--foxio-mapping, --sslbl-ja3), the "
            "services of site names (--site-list) and the owners of IP addresses "
            "(--ip-owners) in the existing database at --output; the other sources are kept."
        ),
    )
    parser.add_argument(
        "--foxio-mapping",
        default=str(DEFAULT_FOXIO_MAPPING_PATH),
        help="FoxIO's JA4+ mapping CSV (default: data/intel/sources/fingerprints/ja4plus-mapping.csv).",
    )
    parser.add_argument(
        "--sslbl-ja3",
        default=str(DEFAULT_SSLBL_JA3_PATH),
        help="abuse.ch's SSLBL JA3 CSV (default: data/intel/sources/fingerprints/sslbl_ja3_fingerprints.csv).",
    )
    parser.add_argument(
        "--site-list",
        default=str(DEFAULT_SITE_LIST_PATH),
        help=(
            "v2fly's domain-list-community archive (default: "
            "data/intel/sources/fingerprints/domain-list-community.tar.gz)."
        ),
    )
    parser.add_argument(
        "--ip-owners",
        default=str(DEFAULT_IP_OWNERS_PATH),
        help="iptoasn.com's ip2asn-combined.tsv.gz (default: data/intel/sources/iptoasn/ip2asn-combined.tsv.gz).",
    )
    parser.add_argument(
        "--rule-docs",
        default=str(DEFAULT_RULE_DOCS_PATH),
        help="Talos's rule documentation, by SID (default: data/json/rule_docs_preprocessed_by_sid.json).",
    )
    parser.add_argument(
        "--talos-pages",
        default=str(DEFAULT_TALOS_PAGES_PATH),
        help="The pages scripts/download_talos_docs.py saved (default: data/intel/sources/talos/rule_docs.jsonl).",
    )
    parser.add_argument(
        "--builtin-stubs",
        default=str(DEFAULT_BUILTIN_STUBS_PATH),
        help=f"Snort's descriptions of its built-in rules (default: {DEFAULT_BUILTIN_STUBS_PATH}).",
    )
    parser.add_argument(
        "--suricata-rules",
        action="append",
        help=(
            "A Suricata rules file whose rules are documented (repeatable; default: "
            + ", ".join(str(path) for path in DEFAULT_SURICATA_RULES_PATHS) + ")."
        ),
    )
    parser.add_argument(
        "--classification",
        default=str(DEFAULT_CLASSIFICATION_PATH),
        help=f"Suricata's classtypes (default: {DEFAULT_CLASSIFICATION_PATH}).",
    )
    parser.add_argument(
        "--snort",
        default=DEFAULT_SNORT,
        help="The snort binary that lists its built-in rules and modules (default: snort on the PATH).",
    )
    parser.add_argument(
        "--nvd-path",
        action="append",
        help="NVD JSON, JSON.GZ or ZIP file, or directory (repeatable).",
    )
    parser.add_argument(
        "--epss-csv",
        action="append",
        help="EPSS CSV or CSV.GZ file, or directory (repeatable).",
    )
    parser.add_argument("--kev-json", help="Local CISA KEV JSON file.")
    parser.add_argument("--mitre-json", help="Local ATT&CK STIX JSON file.")
    parser.add_argument(
        "--output",
        default=str(DEFAULT_DB_PATH),
        help="Output database path (default: data/intel/intel.db).",
    )
    parser.add_argument(
        "--replace",
        action="store_true",
        help="Replace an existing output database after successful import.",
    )
    args = parser.parse_args()

    if args.add_tls_fingerprints:
        print(json.dumps(add_tls_fingerprints(
            args.output, args.foxio_mapping, args.sslbl_ja3, args.site_list, args.ip_owners,
        ), indent=2))
        return
    if args.add_rule_docs:
        print(json.dumps(add_rule_docs(
            args.output, args.rule_docs, args.talos_pages, args.builtin_stubs,
            args.suricata_rules or DEFAULT_SURICATA_RULES_PATHS, args.classification, args.snort,
        ), indent=2))
        return
    missing = [
        option for option, value in (
            ("--nvd-path", args.nvd_path), ("--epss-csv", args.epss_csv),
            ("--kev-json", args.kev_json), ("--mitre-json", args.mitre_json),
        ) if not value
    ]
    if missing:
        parser.error(f"the following arguments are required: {', '.join(missing)}")
    result = import_sources(
        nvd_paths=args.nvd_path,
        epss_paths=args.epss_csv,
        kev_path=args.kev_json,
        mitre_path=args.mitre_json,
        output_path=args.output,
        replace=args.replace,
        rule_docs_path=args.rule_docs,
        talos_pages_path=args.talos_pages,
        builtin_stubs_path=args.builtin_stubs,
        suricata_rules_paths=args.suricata_rules or DEFAULT_SURICATA_RULES_PATHS,
        classification_path=args.classification,
        snort=args.snort,
        foxio_mapping_path=args.foxio_mapping,
        sslbl_ja3_path=args.sslbl_ja3,
        site_list_path=args.site_list,
        ip_owners_path=args.ip_owners,
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
