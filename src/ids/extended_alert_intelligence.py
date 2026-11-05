#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any, Mapping

from ids.alert_intelligence import (
    build_alert_intelligence_context,
)
from ids.pattern_words import read_content, read_pcre


PROJECT_ROOT = Path(__file__).resolve().parents[2]

NVD_DIR = (
    PROJECT_ROOT
    / "data/lab/intelligence/nvd/cves"
)

CISA_FILE = (
    PROJECT_ROOT
    / "data/lab/intelligence/cisa"
    / "known_exploited_vulnerabilities.json"
)

EPSS_DIR = (
    PROJECT_ROOT
    / "data/lab/intelligence/epss"
)

CIRCL_DIR = (
    PROJECT_ROOT
    / "data/lab/intelligence/circl"
)

ENRICHED_ALERTS_FILE = (
    PROJECT_ROOT
    / "data/lab/enriched/all_alerts_enriched.json"
)

NVD_API = (
    "https://services.nvd.nist.gov/rest/json/cves/2.0"
)

EPSS_API = (
    "https://api.first.org/data/v1/epss"
)

CIRCL_API = (
    "https://vulnerability.circl.lu/api/vulnerability"
)

CVE_RE = re.compile(
    r"\bCVE-\d{4}-\d{4,7}\b",
    re.IGNORECASE,
)

MITRE_RE = re.compile(
    r"\bT\d{4}(?:\.\d{3})?\b",
    re.IGNORECASE,
)

CACHE_MAX_AGE_SECONDS = 24 * 60 * 60


def _now_iso() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


def _read_json(
    path: Path,
) -> Any:

    with path.open(
        "r",
        encoding="utf-8",
    ) as handle:
        return json.load(handle)


def _write_json(
    path: Path,
    value: Any,
) -> None:

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary = path.with_suffix(
        path.suffix + ".tmp"
    )

    with temporary.open(
        "w",
        encoding="utf-8",
    ) as handle:
        json.dump(
            value,
            handle,
            indent=2,
            ensure_ascii=False,
        )
        handle.write("\n")

    temporary.replace(path)


def _cache_is_fresh(
    path: Path,
    max_age_seconds: int = CACHE_MAX_AGE_SECONDS,
) -> bool:

    if not path.exists():
        return False

    age = (
        time.time()
        - path.stat().st_mtime
    )

    return age < max_age_seconds


def _load_project_env() -> None:

    env_file = (
        PROJECT_ROOT
        / ".env"
    )

    if not env_file.exists():
        return

    for raw_line in env_file.read_text(
        encoding="utf-8"
    ).splitlines():

        line = raw_line.strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        if "=" not in line:
            continue

        key, value = line.split(
            "=",
            1,
        )

        key = key.strip()

        if not key:
            continue

        value = value.strip()

        if (
            len(value) >= 2
            and value[0] == value[-1]
            and value[0] in {
                '"',
                "'",
            }
        ):
            value = value[1:-1]

        os.environ.setdefault(
            key,
            value,
        )


def _get_nvd_api_key() -> str | None:

    _load_project_env()

    value = os.environ.get(
        "NVD_API_KEY"
    )

    if value:
        return value.strip()

    return None


def _request_json(
    url: str,
    headers: dict[str, str] | None = None,
    timeout: int = 20,
) -> Any:

    request_headers = {
        "User-Agent": (
            "Real-Time-Network-IDS-Dashboard/"
            "extended-alert-intelligence"
        ),
        "Accept": "application/json",
    }

    if headers:
        request_headers.update(
            headers
        )

    request = urllib.request.Request(
        url,
        headers=request_headers,
        method="GET",
    )

    with urllib.request.urlopen(
        request,
        timeout=timeout,
    ) as response:

        raw = response.read()

    return json.loads(
        raw.decode("utf-8")
    )


def _recursive_ids(
    value: Any,
    pattern: re.Pattern[str],
) -> list[str]:

    found: set[str] = set()

    def walk(item: Any) -> None:

        if isinstance(item, str):

            for match in pattern.findall(
                item
            ):
                found.add(
                    match.upper()
                )

            return

        if isinstance(item, dict):

            for child in item.values():
                walk(child)

            return

        if isinstance(item, list):

            for child in item:
                walk(child)

    walk(value)

    return sorted(found)


def _json_list(
    value: Any,
) -> list[Any]:

    if value is None:
        return []

    if isinstance(
        value,
        list,
    ):
        return value

    if isinstance(
        value,
        str,
    ):

        try:

            parsed = json.loads(
                value
            )

            if isinstance(
                parsed,
                list,
            ):
                return parsed

            if parsed:
                return [parsed]

        except json.JSONDecodeError:
            return [
                value
            ]

    return [
        value
    ]


def _load_cached_nvd(
    cve_id: str,
) -> dict[str, Any] | None:

    path = (
        NVD_DIR
        / f"{cve_id.upper()}.json"
    )

    if not path.exists():
        return None

    try:
        value = _read_json(path)
    except (
        OSError,
        json.JSONDecodeError,
    ):
        return None

    if not isinstance(
        value,
        dict,
    ):
        return None

    return value


def _fetch_nvd(
    cve_id: str,
    force: bool = False,
) -> dict[str, Any] | None:

    cache = _load_cached_nvd(
        cve_id
    )

    path = (
        NVD_DIR
        / f"{cve_id.upper()}.json"
    )

    if (
        cache is not None
        and not force
    ):
        return cache

    api_key = _get_nvd_api_key()

    if not api_key:
        return cache

    query = urllib.parse.urlencode(
        {
            "cveId": cve_id.upper(),
            "resultsPerPage": "20",
        }
    )

    try:

        data = _request_json(
            f"{NVD_API}?{query}",
            headers={
                "apiKey": api_key,
            },
        )

    except (
        urllib.error.URLError,
        TimeoutError,
        OSError,
        json.JSONDecodeError,
    ):

        return cache

    _write_json(
        path,
        data,
    )

    return data


def _extract_nvd_item(
    data: dict[str, Any] | None,
) -> dict[str, Any] | None:

    if not data:
        return None

    vulnerabilities = data.get(
        "vulnerabilities"
    )

    if isinstance(
        vulnerabilities,
        list,
    ):

        if vulnerabilities:

            item = vulnerabilities[0]

            if isinstance(
                item,
                dict,
            ):
                return item

        return None

    if "cve" in data:
        return data

    return None


def _extract_cvss(
    cve: dict[str, Any],
) -> dict[str, Any] | None:

    metrics = cve.get(
        "metrics"
    )

    if not isinstance(
        metrics,
        dict,
    ):
        return None

    ordered_versions = [
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    ]

    for version_key in ordered_versions:

        entries = metrics.get(
            version_key
        )

        if not isinstance(
            entries,
            list,
        ):
            continue

        for entry in entries:

            if not isinstance(
                entry,
                dict,
            ):
                continue

            cvss_data = entry.get(
                "cvssData"
            )

            if not isinstance(
                cvss_data,
                dict,
            ):
                continue

            return {
                "version": cvss_data.get(
                    "version"
                ),
                "base_score": cvss_data.get(
                    "baseScore"
                ),
                "base_severity": (
                    cvss_data.get(
                        "baseSeverity"
                    )
                    or entry.get(
                        "baseSeverity"
                    )
                ),
                "vector": cvss_data.get(
                    "vectorString"
                ),
                "source": entry.get(
                    "source"
                ),
                "type": entry.get(
                    "type"
                ),
            }

    return None


def _extract_nvd_summary(
    data: dict[str, Any] | None,
) -> dict[str, Any]:

    item = _extract_nvd_item(
        data
    )

    if not item:
        return {}

    cve = item.get(
        "cve",
        {}
    )

    if not isinstance(
        cve,
        dict,
    ):
        return {}

    descriptions = cve.get(
        "descriptions",
        []
    )

    description = ""

    if isinstance(
        descriptions,
        list,
    ):

        for entry in descriptions:

            if not isinstance(
                entry,
                dict,
            ):
                continue

            if entry.get(
                "lang"
            ) == "en":

                description = str(
                    entry.get(
                        "value",
                        ""
                    )
                )

                break

    weaknesses: list[str] = []

    for weakness in cve.get(
        "weaknesses",
        [],
    ):

        if not isinstance(
            weakness,
            dict,
        ):
            continue

        for desc in weakness.get(
            "description",
            [],
        ):

            if not isinstance(
                desc,
                dict,
            ):
                continue

            value = desc.get(
                "value"
            )

            if value:
                weaknesses.append(
                    str(value)
                )

    references: list[dict[str, Any]] = []

    for reference in cve.get(
        "references",
        [],
    ):

        if not isinstance(
            reference,
            dict,
        ):
            continue

        url = reference.get(
            "url"
        )

        if not url:
            continue

        references.append(
            {
                "url": url,
                "source": reference.get(
                    "source"
                ),
                "tags": reference.get(
                    "tags",
                    [],
                ),
            }
        )

    return {
        "id": cve.get(
            "id"
        ),
        "description": description,
        "published": cve.get(
            "published"
        ),
        "last_modified": cve.get(
            "lastModified"
        ),
        "vulnerability_status": cve.get(
            "vulnStatus"
        ),
        "cvss": _extract_cvss(
            cve
        ),
        "cwe": sorted(
            set(
                weaknesses
            )
        ),
        "references": references,
        "configurations": cve.get(
            "configurations",
            [],
        ),
    }


@lru_cache(maxsize=1)
def _load_kev_catalog() -> dict[str, Any]:

    if not CISA_FILE.exists():
        return {}

    try:
        data = _read_json(
            CISA_FILE
        )
    except (
        OSError,
        json.JSONDecodeError,
    ):
        return {}

    entries = data.get(
        "vulnerabilities",
        []
    )

    result: dict[str, Any] = {}

    if not isinstance(
        entries,
        list,
    ):
        return result

    for entry in entries:

        if not isinstance(
            entry,
            dict,
        ):
            continue

        cve = entry.get(
            "cveID"
        )

        if cve:
            result[str(cve).upper()] = entry

    return result


def _get_kev(
    cve_id: str,
) -> dict[str, Any] | None:

    return _load_kev_catalog().get(
        cve_id.upper()
    )


def _fetch_epss(
    cves: list[str],
    force: bool = False,
) -> dict[str, Any]:

    result: dict[str, Any] = {}

    missing: list[str] = []

    EPSS_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    for cve in cves:

        path = (
            EPSS_DIR
            / f"{cve.upper()}.json"
        )

        if (
            not force
            and _cache_is_fresh(path)
        ):

            try:
                value = _read_json(
                    path
                )
            except (
                OSError,
                json.JSONDecodeError,
            ):
                value = None

            if isinstance(
                value,
                dict,
            ):
                result[cve.upper()] = value
                continue

        missing.append(
            cve.upper()
        )

    if not missing:
        return result

    query = urllib.parse.urlencode(
        {
            "cve": ",".join(
                missing
            )
        }
    )

    try:

        response = _request_json(
            f"{EPSS_API}?{query}"
        )

        rows = response.get(
            "data",
            []
        )

    except (
        urllib.error.URLError,
        TimeoutError,
        OSError,
        json.JSONDecodeError,
    ):

        rows = []

    if isinstance(
        rows,
        list,
    ):

        for row in rows:

            if not isinstance(
                row,
                dict,
            ):
                continue

            cve = row.get(
                "cve"
            )

            if not cve:
                continue

            cve = str(
                cve
            ).upper()

            payload = {
                "retrieved_at": _now_iso(),
                "source": EPSS_API,
                "data": row,
            }

            path = (
                EPSS_DIR
                / f"{cve}.json"
            )

            _write_json(
                path,
                payload,
            )

            result[cve] = payload

    return result


def _fetch_circl(
    cve_id: str,
    force: bool = False,
) -> dict[str, Any] | None:

    CIRCL_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    path = (
        CIRCL_DIR
        / f"{cve_id.upper()}.json"
    )

    if (
        not force
        and _cache_is_fresh(path)
    ):

        try:
            cached = _read_json(
                path
            )

            if isinstance(
                cached,
                dict,
            ):
                return cached

        except (
            OSError,
            json.JSONDecodeError,
        ):
            pass

    quoted_id = urllib.parse.quote(
        cve_id.upper(),
        safe="",
    )

    url = (
        f"{CIRCL_API}/{quoted_id}"
        "?with_meta=true"
        "&with_linked=true"
        "&with_sightings=true"
    )

    try:

        data = _request_json(
            url
        )

    except (
        urllib.error.URLError,
        TimeoutError,
        OSError,
        json.JSONDecodeError,
    ):

        if path.exists():

            try:
                return _read_json(
                    path
                )
            except (
                OSError,
                json.JSONDecodeError,
            ):
                return None

        return None

    payload = {
        "retrieved_at": _now_iso(),
        "source": CIRCL_API,
        "data": data,
    }

    _write_json(
        path,
        payload,
    )

    return payload


def _collect_urls(
    value: Any,
) -> list[str]:

    urls: set[str] = set()

    def walk(item: Any) -> None:

        if isinstance(
            item,
            str,
        ):

            if item.startswith(
                "http://"
            ) or item.startswith(
                "https://"
            ):
                urls.add(item)

            return

        if isinstance(
            item,
            dict,
        ):

            for child in item.values():
                walk(child)

            return

        if isinstance(
            item,
            list,
        ):

            for child in item:
                walk(child)

    walk(value)

    return sorted(
        urls
    )


def _extract_circl_summary(
    payload: dict[str, Any] | None,
) -> dict[str, Any]:

    if not payload:
        return {}

    data = payload.get(
        "data",
        payload,
    )

    if not isinstance(
        data,
        dict,
    ):
        return {}

    summary = {
        "urls": _collect_urls(
            data
        ),
        "sighting_types": [],
        "sighting_sources": [],
    }

    sighting_types: set[str] = set()
    sighting_sources: set[str] = set()

    def walk(item: Any) -> None:

        if isinstance(
            item,
            dict,
        ):

            item_type = item.get(
                "type"
            )

            if (
                isinstance(
                    item_type,
                    str,
                )
                and item_type
            ):
                sighting_types.add(
                    item_type
                )

            source = item.get(
                "source"
            )

            if (
                isinstance(
                    source,
                    str,
                )
                and source
            ):
                sighting_sources.add(
                    source
                )

            for child in item.values():
                walk(child)

            return

        if isinstance(
            item,
            list,
        ):

            for child in item:
                walk(child)

    walk(data)

    summary[
        "sighting_types"
    ] = sorted(
        sighting_types
    )

    summary[
        "sighting_sources"
    ] = sorted(
        sighting_sources
    )

    return summary


@lru_cache(maxsize=1)
def _load_project_enriched() -> list[dict[str, Any]]:

    if not ENRICHED_ALERTS_FILE.exists():
        return []

    try:
        data = _read_json(
            ENRICHED_ALERTS_FILE
        )
    except (
        OSError,
        json.JSONDecodeError,
    ):
        return []

    if not isinstance(
        data,
        list,
    ):
        return []

    return [
        item
        for item in data
        if isinstance(
            item,
            dict,
        )
    ]


def _find_project_mitre_details(
    technique_id: str,
) -> list[dict[str, Any]]:

    matches: list[dict[str, Any]] = []

    for record in _load_project_enriched():

        external = record.get(
            "external_enrichment",
            {},
        )

        if not isinstance(
            external,
            dict,
        ):
            continue

        identifiers = external.get(
            "identifiers",
            {},
        )

        if not isinstance(
            identifiers,
            dict,
        ):
            continue

        techniques = identifiers.get(
            "mitre_technique_ids",
            [],
        )

        if technique_id.upper() not in {
            str(value).upper()
            for value in _json_list(
                techniques
            )
        }:
            continue

        mitre = external.get(
            "mitre_attack",
            {},
        )

        if not isinstance(
            mitre,
            dict,
        ):
            continue

        enrichment = mitre.get(
            "enrichment",
            [],
        )

        if not isinstance(
            enrichment,
            list,
        ):
            continue

        for entry in enrichment:

            if not isinstance(
                entry,
                dict,
            ):
                continue

            entry_text = json.dumps(
                entry
            ).upper()

            if technique_id.upper() in entry_text:
                matches.append(
                    entry
                )

    deduped: list[dict[str, Any]] = []
    seen: set[str] = set()

    for entry in matches:

        key = json.dumps(
            entry,
            sort_keys=True,
            default=str,
        )

        if key in seen:
            continue

        seen.add(key)
        deduped.append(entry)

    return deduped


def _highest_cvss(
    vulnerabilities: dict[str, Any],
) -> dict[str, Any] | None:
    """Return the highest CVSS score, preferring v3.x/v4 over v2.

    CVSS v2 scores are systematically higher than v3 scores for the same
    flaw, so v2 is used only when no CVE has a newer score.
    """
    by_basis: dict[str, dict[str, Any]] = {}
    for cve, info in sorted(vulnerabilities.items()):
        nvd = info.get("nvd") if isinstance(info, dict) else None
        cvss = nvd.get("cvss") if isinstance(nvd, dict) else None
        if not isinstance(cvss, dict):
            continue
        try:
            score = float(cvss.get("base_score"))
        except (TypeError, ValueError):
            continue
        version = str(cvss.get("version") or "")
        basis = "cvss_v2" if version.startswith("2") else "cvss_v3_or_later"
        current = by_basis.get(basis)
        if current is None or score > current["base_score"]:
            by_basis[basis] = {
                "cve": cve,
                "base_score": score,
                "version": version or None,
                "basis": basis,
            }
    return by_basis.get("cvss_v3_or_later") or by_basis.get("cvss_v2")


def _cvss_basis_note(cvss_version: str | None) -> str:
    if cvss_version and str(cvss_version).startswith("2"):
        return (
            f" (CVSS v{cvss_version}; no CVSS v3 score is available, and v2 "
            "scores tend to run higher)"
        )
    return f" (CVSS v{cvss_version})" if cvss_version else ""


def _priority_guidance(
    cvss_score: float | None,
    epss_score: float | None,
    known_exploited: bool,
    cvss_version: str | None = None,
) -> dict[str, str]:

    if known_exploited:

        return {
            "label": "High attention",
            "reason": (
                "At least one CVE associated with "
                "this rule is listed in the CISA Known "
                "Exploited Vulnerabilities catalog."
            ),
        }

    if (
        cvss_score is not None
        and cvss_score >= 9.0
    ):

        return {
            "label": "Critical vulnerability context",
            "reason": (
                "The highest associated CVE has a "
                "CVSS base score of 9.0 or higher"
                + _cvss_basis_note(cvss_version) + "."
            ),
        }

    if (
        epss_score is not None
        and epss_score >= 0.50
    ):

        return {
            "label": "Elevated attention",
            "reason": (
                "The highest associated EPSS score "
                "is 0.50 or higher."
            ),
        }

    if (
        cvss_score is not None
        and cvss_score >= 7.0
    ):

        return {
            "label": "Elevated attention",
            "reason": (
                "The highest associated CVE has a "
                "CVSS base score of 7.0 or higher"
                + _cvss_basis_note(cvss_version) + "."
            ),
        }

    return {
        "label": "Contextual",
        "reason": (
            "No high-priority vulnerability or active "
            "exploitation signal was found in the "
            "available enrichment."
        ),
    }


_REFERENCE_CVE_RE = re.compile(
    r"cve,\s*(\d{4}-\d{4,7})",
    re.IGNORECASE,
)

_QUOTED_CONTENT_RE = re.compile(
    r'"((?:[^"\\]|\\.)*)"'
)


def _rule_reference_cves(
    rule: Any,
) -> list[str]:
    """Normalise Snort-style 'cve,YYYY-NNNN' rule references to CVE IDs."""
    if not isinstance(rule, dict):
        return []

    found: set[str] = set()

    for reference in _json_list(rule.get("references_json")):
        match = _REFERENCE_CVE_RE.fullmatch(str(reference).strip())

        if match:
            found.add(f"CVE-{match.group(1)}")

    return sorted(found)


def _content_patterns(
    rule: dict[str, Any],
) -> list[str]:
    """Return the literal content patterns a rule searches for."""
    patterns: list[str] = []

    for item in _json_list(rule.get("content_matches_json")):
        text = str(item).strip()
        quoted = _QUOTED_CONTENT_RE.match(text)
        pattern = (quoted.group(1) if quoted else text).strip()

        if pattern and pattern not in patterns:
            patterns.append(pattern)

    return patterns


# Sticky buffers / content modifiers (Snort 3 and Suricata spellings).
_RULE_BUFFER_LABELS = {
    "http_header": "HTTP headers",
    "http.header": "HTTP headers",
    "http_raw_header": "raw HTTP headers",
    "http.header.raw": "raw HTTP headers",
    "http_uri": "HTTP URI",
    "http.uri": "HTTP URI",
    "http_raw_uri": "raw HTTP URI",
    "http.uri.raw": "raw HTTP URI",
    "http_method": "HTTP method",
    "http.method": "HTTP method",
    "http_cookie": "HTTP cookie",
    "http.cookie": "HTTP cookie",
    "http_user_agent": "HTTP User-Agent",
    "http.user_agent": "HTTP User-Agent",
    "http_client_body": "HTTP request body",
    "http.request_body": "HTTP request body",
    "http_stat_code": "HTTP status code",
    "http.stat_code": "HTTP status code",
    "file_data": "file data",
    "file.data": "file data",
    "pkt_data": "packet payload",
    "dns.query": "DNS query",
    "dns_query": "DNS query",
    "tls.sni": "TLS SNI",
}

_RULE_OPTION_RE = re.compile(
    r'\s*([A-Za-z_][\w.-]*)\s*(?::\s*((?:"(?:[^"\\]|\\.)*"|[^;])*))?;'
)

# ICMP message types; 128 and above exist only in ICMPv6.
_ICMP_TYPE_NAMES = {
    0: "Echo Reply", 3: "Destination Unreachable", 4: "Source Quench",
    5: "Redirect", 8: "Echo Request", 9: "Router Advertisement",
    10: "Router Solicitation", 11: "Time Exceeded", 12: "Parameter Problem",
    13: "Timestamp Request", 14: "Timestamp Reply",
    17: "Address Mask Request", 18: "Address Mask Reply",
    128: "Echo Request", 129: "Echo Reply",
    130: "Multicast Listener Query", 131: "Multicast Listener Report",
    132: "Multicast Listener Done", 133: "Router Solicitation",
    134: "Router Advertisement", 135: "Neighbor Solicitation",
    136: "Neighbor Advertisement", 137: "Redirect",
    143: "Multicast Listener Report v2",
}
_ICMP_CODE_NAMES = {
    3: {
        0: "Network Unreachable", 1: "Host Unreachable",
        2: "Protocol Unreachable", 3: "Port Unreachable",
        4: "Fragmentation Needed", 9: "Network Administratively Prohibited",
        10: "Host Administratively Prohibited",
        13: "Communication Administratively Prohibited",
    },
    11: {0: "TTL Exceeded in Transit", 1: "Fragment Reassembly Time Exceeded"},
}
# Suricata rules that fire on an event its own engine raises, not on content.
_ENGINE_EVENT_SOURCES = {
    "stream-event": "TCP stream engine",
    "decode-event": "packet decoder",
    "app-layer-event": "application-layer parser",
}
_HEX_BLOCK_RE = re.compile(r"\|([0-9A-Fa-f\s]+)\|")
# "alert ip SRC SPORT -> DST DPORT (": Snort 3 service rules have no header.
_RULE_HEADER_RE = re.compile(
    r"^\s*\w+\s+\S+\s+(\S+)\s+(\S+)\s+(?:->|<>)\s+(\S+)\s+(\S+)\s*\("
)


def _port_range(value: str) -> str:
    """Word a rule's port range: "1024:" is 1024 or higher."""
    low, colon, high = value.partition(":")
    if not colon:
        return value
    if low and high:
        return f"{low} to {high}"
    return f"{low} or higher" if low else f"{high} or lower"


def _header_literal_checks(rule_text: str) -> list[str]:
    """Addresses and ports the rule header names literally (not "any" or a
    $VARIABLE, whose value depends on the sensor's configuration)."""
    header = _RULE_HEADER_RE.match(rule_text)
    if not header:
        return []
    checks = []
    for value, label in zip(
        header.groups(),
        ("source address", "source port", "destination address", "destination port"),
    ):
        if value == "any" or "$" in value:
            continue
        negated = value.startswith("!")
        items = value.lstrip("!").strip("[]").split(",")
        if "port" in label:
            items = [_port_range(item) for item in items]
        listed = ", ".join(items)
        several = len(items) > 1 or "/" in value
        verb = ("is not" if negated else "is") + (" in" if several else "")
        checks.append(f"the {label} {verb} {listed}")
    return checks


def _decode_rule_content(value: str) -> str:
    """Render |hex| blocks as text when every decoded byte is printable."""
    def replace(match: re.Match[str]) -> str:
        hex_digits = "".join(match.group(1).split())
        try:
            data = bytes.fromhex(hex_digits)
        except ValueError:
            return match.group(0)
        if data and all(32 <= byte < 127 for byte in data):
            return data.decode("ascii")
        return match.group(0)

    return _HEX_BLOCK_RE.sub(replace, value)


def _rule_conditions(rule_text: Any) -> list[dict[str, Any]]:
    """Return the content/pcre conditions of a rule in evaluation order.

    Each condition records the inspected buffer, the literal pattern and its
    modifiers. Only what the rule text states is returned.
    """
    text = str(rule_text or "")
    start, end = text.find("("), text.rfind(")")
    if start < 0 or end <= start:
        return []

    conditions: list[dict[str, Any]] = []
    buffer = None
    for match in _RULE_OPTION_RE.finditer(text[start + 1:end]):
        name = match.group(1).lower()
        value = (match.group(2) or "").strip()

        if name in _RULE_BUFFER_LABELS and not value:
            buffer = _RULE_BUFFER_LABELS[name]
            continue

        if name in ("content", "pcre"):
            negated = value.startswith("!")
            quoted = _QUOTED_CONTENT_RE.search(value)
            pattern = quoted.group(1) if quoted else value.lstrip("!")
            modifiers = {
                part.strip().lower()
                for part in value[quoted.end():].split(",")
            } if quoted else set()
            condition: dict[str, Any] = {
                "type": name,
                "buffer": buffer,
                "pattern": pattern,
                "negated": negated,
                "nocase": "nocase" in modifiers,
            }
            if name == "content":
                decoded = _decode_rule_content(pattern)
                if decoded != pattern:
                    condition["decoded"] = decoded
            conditions.append(condition)
            continue

        # Snort 2 style content modifiers apply to the previous content.
        if name in _RULE_BUFFER_LABELS and conditions and not value:
            conditions[-1]["buffer"] = _RULE_BUFFER_LABELS[name]
        elif name == "nocase" and conditions:
            conditions[-1]["nocase"] = True

    return conditions


def _rule_header_checks(rule_text: Any) -> list[str]:
    """Describe ICMP type/code tests and Suricata engine-event triggers."""
    text = str(rule_text or "")
    start, end = text.find("("), text.rfind(")")
    if start < 0 or end <= start:
        return []

    options: dict[str, str] = {}
    events: list[str] = []
    for match in _RULE_OPTION_RE.finditer(text[start + 1:end]):
        name = match.group(1).lower()
        value = (match.group(2) or "").strip()
        if not value:
            continue
        if name in ("itype", "icode"):
            options[name] = value
        elif name in _ENGINE_EVENT_SOURCES:
            events.append(
                f"Suricata's {_ENGINE_EVENT_SOURCES[name]} reports the "
                f"`{value}` event"
            )

    # Rules may list icode before itype; the code's name depends on the type.
    checks = _header_literal_checks(text)
    icmp_type = options.get("itype")
    type_number = int(icmp_type) if icmp_type and icmp_type.isdigit() else None
    if icmp_type:
        label = _ICMP_TYPE_NAMES.get(type_number)
        checks.append(
            f"the ICMP type is {icmp_type}" + (f" ({label})" if label else "")
        )
    icmp_code = options.get("icode")
    if icmp_code:
        codes = _ICMP_CODE_NAMES.get(type_number, {})
        label = codes.get(int(icmp_code)) if icmp_code.isdigit() else None
        checks.append(
            f"the ICMP code is {icmp_code}" + (f" ({label})" if label else "")
        )
    return checks + events


_BUILTIN_COMPONENT_RE = re.compile(r"^\(([\w.-]+)\)")


def _describe_builtin_rule(alert: Mapping[str, Any]) -> str | None:
    """Describe a Snort built-in rule (GID other than 1), which has no rule text."""
    try:
        gid = int(alert.get("gid"))
    except (TypeError, ValueError):
        return None
    if gid <= 1 or str(alert.get("engine") or "").lower() != "snort":
        return None
    # Built-in messages name the component first, e.g. "(stream_tcp) ...".
    match = _BUILTIN_COMPONENT_RE.match(str(alert.get("msg") or ""))
    source = f"Snort's {match.group(1)} component" if match else "Snort itself"
    return (
        f"A built-in Snort rule ({gid}:{alert.get('sid')}): {source} raised this "
        "event while decoding or inspecting the traffic. Built-in rules have no "
        "rule text; the message names the check that failed."
    )


def _describe_condition(condition: Mapping[str, Any]) -> str:
    """One content or pcre check, its pattern in words with no backslashes
    (bytes as 0x81), so that it reads the same in every JSON viewer; the
    rule text keeps the pattern as written."""
    pattern = str(condition.get("pattern") or "")
    buffer = condition.get("buffer")
    negated = condition.get("negated")
    if condition.get("type") == "pcre":
        words, modifier_buffer = read_pcre(pattern)
        buffer = buffer or modifier_buffer
    else:
        words = read_content(pattern)
    where = f"the {buffer}" if buffer else "the inspected data"
    plural = bool(buffer) and str(buffer).endswith("s")
    if condition.get("type") == "pcre":
        verb = ("do not match" if plural else "does not match") if negated else (
            "match" if plural else "matches"
        )
        return f"{where} {verb} the regular expression" + (
            f": {words}" if words else " in the rule text"
        )
    verb = ("do not contain" if plural else "does not contain") if negated else (
        "contain" if plural else "contains"
    )
    text = f"{where} {verb} {words or 'the pattern in the rule text'}"
    if condition.get("nocase"):
        text += " (case-insensitive)"
    return text


def _describe_rule_logic(
    rule: dict[str, Any],
) -> str:
    """Describe what a rule inspects, using only the rule's own fields."""
    protocol = str(rule.get("protocol") or "").upper()
    service = str(rule.get("service") or "")
    flow = str(rule.get("flow") or "")
    conditions = _rule_conditions(rule.get("rule_text"))
    patterns = [] if conditions else _content_patterns(rule)

    if not (protocol or service or flow or patterns or conditions):
        return (
            "The traffic matched the conditions "
            "defined by the IDS rule."
        )

    sentence = (
        # Suricata's "pkthdr" rules see every packet, whatever its protocol.
        "The rule inspects packet headers"
        if protocol == "PKTHDR"
        else f"The rule inspects {protocol} traffic"
        if protocol
        else "The rule inspects traffic"
    )

    if service:
        sentence += f" for the {service} service"

    if "to_server" in flow:
        sentence += " sent to a server"
    elif "to_client" in flow:
        sentence += " sent to a client"

    if "established" in flow:
        sentence += " in an established session"

    sentence += "."

    described = _rule_header_checks(rule.get("rule_text")) + [
        _describe_condition(item) for item in conditions[:6]
    ]
    if described:
        # Semicolons between the checks: a pattern's words have commas.
        joiner = "; and " if len(described) > 1 else ""
        sentence += (
            " It alerts only when "
            + ("; ".join(described[:-1]) + joiner if len(described) > 1 else "")
            + described[-1]
            + "."
        )
        if len(conditions) > 6:
            sentence += f" The rule has {len(conditions) - 6} further condition(s)."
    elif patterns:
        listed = "; ".join(read_content(pattern) or f"`{pattern}`" for pattern in patterns[:5])
        sentence += f" It looks for: {listed}."

    return sentence


def _describe_observation(alert: Mapping[str, Any], message: str) -> str:
    """State what the IDS recorded, using only the alert's own fields."""
    engine = str(alert.get("engine") or "The IDS").strip()
    engine = engine[:1].upper() + engine[1:]
    protocol = str(alert.get("protocol") or "").upper()

    def endpoint(addr_key: str, port_key: str, combined_key: str) -> str | None:
        addr = alert.get(addr_key)
        port = alert.get(port_key)
        if addr:
            return f"{addr}:{port}" if port not in (None, "") else str(addr)
        combined = alert.get(combined_key)
        return str(combined) if combined else None

    source = endpoint("src_addr", "src_port", "src")
    destination = endpoint("dst_addr", "dst_port", "dst")

    sentence = f"{engine} recorded"
    sentence += f" {protocol} traffic" if protocol else " traffic"
    if source or destination:
        sentence += (
            f" from {source or 'an unrecorded source'}"
            f" to {destination or 'an unrecorded destination'}"
        )
    service = alert.get("service")
    if service:
        sentence += f" ({service})"
    sentence += f" that matched the rule '{message}'."
    sentence += (
        " Payload bytes are not part of this alert record, so the exact "
        "matched content is not shown."
        if not alert.get("http_method") and not alert.get("http")
        else ""
    )
    return sentence


# Guidance sentences that do not depend on the particular rule: they are added
# for every alert, or for every rule with or without CVEs. Exports that list
# many rules state them once instead of repeating them per rule.
MEANING_WITHOUT_CVES = (
    "This alert shows that traffic matched the detection rule. Whether the "
    "activity is malicious depends on the source, target, environment, and "
    "surrounding events."
)
MEANING_CVE_CAVEAT = (
    "This association provides vulnerability context; the alert alone does "
    "not prove that the affected software is installed or that exploitation "
    "succeeded."
)
MEANING_NOTE_CAVEAT = "The alert itself still does not prove successful exploitation."
CHECK_FALSE_POSITIVES = (
    "Check for the documented false-positive conditions before treating the "
    "alert as malicious: "
)
CHECK_AFFECTED_PRODUCT = (
    "Verify whether the destination system actually runs an affected product "
    "or version."
)
CHECK_CONTEXT = (
    "Review the source and destination addresses, the surrounding network "
    "activity, and any follow-up connections."
)
ACTION_KEV_PRIORITY = (
    "Prioritize checking the affected asset because an associated CVE is "
    "present in CISA KEV."
)
ACTION_CONFIRM_EXPECTED = "Confirm whether this traffic is expected in the environment."
ACTION_REVIEW_LOGS = (
    "Review surrounding IDS alerts and host logs before concluding that "
    "compromise occurred."
)


def _build_explanation(
    alert: dict[str, Any],
    base: dict[str, Any],
    cves: list[str],
    mitre_ids: list[str],
    vulnerabilities: dict[str, Any],
) -> dict[str, Any]:

    rule = base.get(
        "rule",
        {},
    )

    documentation = base.get(
        "documentation",
        {},
    )

    if not isinstance(
        rule,
        dict,
    ):
        rule = {}

    if not isinstance(
        documentation,
        dict,
    ):
        documentation = {}

    message = (
        alert.get("msg")
        or rule.get("msg")
        or "Unknown IDS alert"
    )

    protocol = (
        alert.get("protocol")
        or rule.get("protocol")
        or ""
    )

    # The vendor documentation stays in detection.documentation. Vendor text
    # for many Snort rules is a copy of the NVD CVE description, which says
    # nothing about this alert, so the analysis is built from the alert and
    # the rule text instead.
    explanation_text = _describe_observation(alert, str(message))
    why_triggered = (
        not rule.get("rule_text") and _describe_builtin_rule(alert)
    ) or _describe_rule_logic(rule)

    known_usage = (
        documentation.get(
            "known_usage"
        )
        or ""
    )

    false_positives = (
        documentation.get(
            "false_positives"
        )
        or ""
    )

    vulnerability_note = (
        documentation.get(
            "rule_vulnerability"
        )
        or ""
    )

    known_exploited_cves = [
        cve
        for cve, info in vulnerabilities.items()
        if info.get(
            "cisa_kev"
        )
    ]

    if cves:

        cve_sentence = (
            f"The rule is associated with "
            f"{len(cves)} CVE"
            f"{'' if len(cves) == 1 else 's'}: "
            f"{', '.join(cves)}."
        )

        meaning = cve_sentence

        if known_exploited_cves:

            meaning += (
                " At least one of those CVEs is "
                "listed in CISA's Known Exploited "
                "Vulnerabilities catalog."
            )

        meaning += f" {MEANING_CVE_CAVEAT}"

    elif vulnerability_note:

        meaning = str(
            vulnerability_note
        )

        meaning += f" {MEANING_NOTE_CAVEAT}"

    else:

        meaning = MEANING_WITHOUT_CVES

    what_to_check: list[str] = []

    if false_positives:
        what_to_check.append(
            f"{CHECK_FALSE_POSITIVES}{false_positives}"
        )

    if cves:

        what_to_check.append(CHECK_AFFECTED_PRODUCT)

    what_to_check.append(CHECK_CONTEXT)

    action_items: list[str] = []

    if known_exploited_cves:

        action_items.append(ACTION_KEV_PRIORITY)

    if cves:
        highest = _highest_cvss(vulnerabilities)
        score = highest["base_score"] if highest else None
        basis = _cvss_basis_note(highest["version"]) if highest else ""

        if score is None:
            action_items.append(
                "Check the affected product/version and "
                "apply the vendor or operating-system "
                "security update when applicable."
            )
        elif known_exploited_cves or score >= 9.0:
            action_items.append(
                f"Check this destination first: {highest['cve']} scores "
                f"{score:g}{basis}. Verify the affected product/version and "
                "apply the vendor or operating-system security update if it "
                "is affected."
            )
        elif score >= 7.0:
            action_items.append(
                f"Check the destination during routine triage: the highest "
                f"associated CVE, {highest['cve']}, scores {score:g}{basis}. "
                "Apply the vendor update if the affected product/version is "
                "present."
            )
        else:
            action_items.append(
                f"Treat the associated CVEs as context: the highest, "
                f"{highest['cve']}, scores {score:g}{basis}. Verify the "
                "product/version only if this traffic is unexpected for the "
                "destination."
            )

    if not cves:

        action_items.append(ACTION_CONFIRM_EXPECTED)

    action_items.append(ACTION_REVIEW_LOGS)

    return {
        "title": str(message),
        "explanation_source": (
            "alert_fields_and_rule_text"
            if rule.get("rule_text")
            else "alert_fields_and_rule_fields"
        ),
        "what_happened": str(
            explanation_text
        ),
        "why_triggered": str(
            why_triggered
        ),
        "what_it_means": meaning,
        "known_usage": str(
            known_usage
        ),
        "false_positives": str(
            false_positives
        ),
        "what_to_check": what_to_check,
        "recommended_actions": action_items,
        "mitre_context": mitre_ids,
        "confidence_note": (
            "This intelligence is deterministic and "
            "source-backed. It explains the detection "
            "and its vulnerability context; it does "
            "not infer compromise."
        ),
    }


def build_extended_alert_intelligence_context(
    alert: dict[str, Any],
    force_refresh: bool = False,
    allow_network: bool = True,
) -> dict[str, Any]:

    base = build_alert_intelligence_context(
        alert
    )

    cves = sorted(
        set(_rule_reference_cves(base.get("rule", {})))
        | set(
            _recursive_ids(
                base.get(
                    "rule",
                    {},
                ),
                CVE_RE,
            )
        )
        | set(
            _recursive_ids(
                base.get(
                    "documentation",
                    {},
                ),
                CVE_RE,
            )
        )
        | set(
            _recursive_ids(
                alert,
                CVE_RE,
            )
        )
    )

    mitre_ids = sorted(
        set(
            _recursive_ids(
                base.get(
                    "rule",
                    {},
                ),
                MITRE_RE,
            )
        )
        | set(
            _recursive_ids(
                base.get(
                    "documentation",
                    {},
                ),
                MITRE_RE,
            )
        )
        | set(
            _recursive_ids(
                alert,
                MITRE_RE,
            )
        )
    )

    vulnerabilities: dict[str, Any] = {}

    epss_records: dict[str, Any] = {}

    if allow_network and cves:
        epss_records = _fetch_epss(
            cves,
            force=force_refresh,
        )

    max_cvss: float | None = None
    max_epss: float | None = None
    known_exploited = False

    for cve in cves:

        nvd_raw = (
            _fetch_nvd(
                cve,
                force=force_refresh,
            )
            if allow_network
            else _load_cached_nvd(
                cve
            )
        )

        nvd_summary = _extract_nvd_summary(
            nvd_raw
        )

        kev = _get_kev(
            cve
        )

        epss_payload = epss_records.get(
            cve
        )

        epss_data = {}

        if isinstance(
            epss_payload,
            dict,
        ):

            epss_data = epss_payload.get(
                "data",
                {}
            )

            if isinstance(
                epss_data,
                list,
            ):

                epss_data = (
                    epss_data[0]
                    if epss_data
                    else {}
                )

        circl_payload = None

        if allow_network:
            circl_payload = _fetch_circl(
                cve,
                force=force_refresh,
            )

        epss_score = None
        epss_percentile = None

        try:

            if epss_data.get(
                "epss"
            ) is not None:
                epss_score = float(
                    epss_data[
                        "epss"
                    ]
                )

            if epss_data.get(
                "percentile"
            ) is not None:
                epss_percentile = float(
                    epss_data[
                        "percentile"
                    ]
                )

        except (
            TypeError,
            ValueError,
        ):
            pass

        cvss = nvd_summary.get(
            "cvss"
        )

        cvss_score = None

        if isinstance(
            cvss,
            dict,
        ):

            try:

                if cvss.get(
                    "base_score"
                ) is not None:
                    cvss_score = float(
                        cvss[
                            "base_score"
                        ]
                    )

            except (
                TypeError,
                ValueError,
            ):
                pass

        if (
            cvss_score is not None
            and (
                max_cvss is None
                or cvss_score > max_cvss
            )
        ):
            max_cvss = cvss_score

        if (
            epss_score is not None
            and (
                max_epss is None
                or epss_score > max_epss
            )
        ):
            max_epss = epss_score

        if kev:
            known_exploited = True

        vulnerabilities[cve] = {
            "nvd": nvd_summary,
            "cisa_kev": kev,
            "epss": {
                "score": epss_score,
                "percentile": epss_percentile,
                "raw": epss_data,
            },
            "circl": (
                _extract_circl_summary(
                    circl_payload
                )
                if circl_payload
                else {}
            ),
        }

    mitre_enrichment = {}

    for technique_id in mitre_ids:

        details = (
            _find_project_mitre_details(
                technique_id
            )
        )

        if details:
            mitre_enrichment[
                technique_id
            ] = details

    highest_cvss = _highest_cvss(vulnerabilities)
    max_cvss = highest_cvss["base_score"] if highest_cvss else None

    priority = _priority_guidance(
        max_cvss,
        max_epss,
        known_exploited,
        highest_cvss["version"] if highest_cvss else None,
    )

    explanation = _build_explanation(
        alert,
        base,
        cves,
        mitre_ids,
        vulnerabilities,
    )

    references: list[dict[str, str]] = []

    for source_name, url in [
        (
            "NVD",
            NVD_API,
        ),
        (
            "FIRST EPSS",
            EPSS_API,
        ),
        (
            "CIRCL Vulnerability-Lookup",
            CIRCL_API,
        ),
        (
            "CISA KEV",
            "https://www.cisa.gov/"
            "known-exploited-vulnerabilities-catalog",
        ),
    ]:

        references.append(
            {
                "source": source_name,
                "url": url,
            }
        )

    for cve, info in vulnerabilities.items():

        nvd = info.get(
            "nvd",
            {}
        )

        for reference in nvd.get(
            "references",
            [],
        ):

            if not isinstance(
                reference,
                dict,
            ):
                continue

            url = reference.get(
                "url"
            )

            if url:

                references.append(
                    {
                        "source": (
                            reference.get(
                                "source"
                            )
                            or f"NVD {cve}"
                        ),
                        "url": str(
                            url
                        ),
                    }
                )

        for url in info.get(
            "circl",
            {}
        ).get(
            "urls",
            [],
        ):

            references.append(
                {
                    "source": (
                        f"CIRCL {cve}"
                    ),
                    "url": str(
                        url
                    ),
                }
            )

    deduped_references = []
    seen_urls: set[str] = set()

    for reference in references:

        url = reference.get(
            "url"
        )

        if not url or url in seen_urls:
            continue

        seen_urls.add(url)
        deduped_references.append(
            reference
        )

    return {
        "alert": alert,
        "base_intelligence": base,
        "identifiers": {
            "cves": cves,
            "mitre_attack": mitre_ids,
        },
        "vulnerabilities": vulnerabilities,
        "mitre_enrichment": mitre_enrichment,
        "risk_context": {
            "priority_guidance": priority,
            "highest_cvss": max_cvss,
            "highest_cvss_detail": highest_cvss,
            "highest_epss": max_epss,
            "known_exploited": known_exploited,
            "known_exploited_cves": [
                cve
                for cve, info in vulnerabilities.items()
                if info.get(
                    "cisa_kev"
                )
            ],
            "disclaimer": (
                "This is vulnerability-priority context, "
                "not proof that the alert is malicious or "
                "that exploitation succeeded."
            ),
        },
        "explanation": explanation,
        "references": deduped_references,
        "retrieved_at": _now_iso(),
        "sources": {
            "rule_database": (
                "data/lab/rules/ids_rules.db"
            ),
            "rule_documentation": (
                "data/json/"
                "rule_docs_preprocessed_by_sid.json"
            ),
            "nvd": NVD_API,
            "epss": EPSS_API,
            "cisa_kev": (
                "CISA Known Exploited "
                "Vulnerabilities Catalog"
            ),
            "circl": CIRCL_API,
        },
    }


__all__ = [
    "build_extended_alert_intelligence_context",
]
