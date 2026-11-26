#!/usr/bin/env python3
"""Download the public threat-intel sources the combined export's offline
enrichment is built from, and optionally build data/intel/intel.db from them
with scripts/import_offline_intelligence.py:

- NVD's CVE feeds (JSON 2.0): one file per year from 2002, and the CVEs
  modified recently;
- FIRST's EPSS scores;
- CISA's Known Exploited Vulnerabilities catalog;
- MITRE ATT&CK for Enterprise (STIX);
- which program a TLS fingerprint is: FoxIO's JA4+ mapping (the free list in
  its JA4 repository; the full JA4+ database at ja4db.foxio.io needs a paid
  account to export) and abuse.ch's SSL Blacklist of malware JA3s;
- which service (app) a site name belongs to: v2fly's domain-list-community
  (its GitHub repository as one archive, about 0.4 MB);
- which network owns each IP address: iptoasn.com's ip2asn-combined.tsv.gz
  (public domain, about 11 MB).

    .venv/bin/python scripts/download_intel_sources.py --build

Only the TLS fingerprint lists, the site list and the address owners, into
the existing database:

    .venv/bin/python scripts/download_intel_sources.py --fingerprints-only

About 300 MB of downloads, and a database of about 1.6 GB. An NVD year whose
feed has not changed since the last download is not downloaded again; a
year whose feed NVD isn't serving (HTTP 404, as for 2025 on 17 Nov 2026,
while its .meta was there) is left out with a warning, keeping the copy from
an earlier download if there is one, and the next run fetches it. Each
file is written under a temporary name first, so a stopped download leaves
no half file behind.
"""

from __future__ import annotations

import argparse
import sys
import urllib.error
import urllib.request
from datetime import date
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCES = PROJECT_ROOT / "data" / "intel" / "sources"
NVD_FEED = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{name}.{suffix}"
FIRST_NVD_YEAR = 2002
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
MITRE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)
FOXIO_MAPPING_URL = "https://raw.githubusercontent.com/FoxIO-LLC/ja4/main/ja4plus-mapping.csv"
SSLBL_JA3_URL = "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv"
SITE_LIST_URL = "https://codeload.github.com/v2fly/domain-list-community/tar.gz/refs/heads/master"
IP_OWNERS_URL = "https://iptoasn.com/data/ip2asn-combined.tsv.gz"
USER_AGENT = "IDS-Dashboard threat-intel download"
CHUNK = 1 << 20


def _open(url: str):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    return urllib.request.urlopen(request, timeout=60)


def fetch(url: str, target: Path) -> int:
    """Download url to target, through a temporary file; the bytes written."""
    target.parent.mkdir(parents=True, exist_ok=True)
    partial = target.with_name(f"{target.name}.part")
    written = 0
    with _open(url) as answer, partial.open("wb") as out:
        while chunk := answer.read(CHUNK):
            out.write(chunk)
            written += len(chunk)
    partial.replace(target)
    return written


def read_meta(text: str) -> dict[str, str]:
    """An NVD .meta file: lastModifiedDate, size, gzSize, sha256 and so on."""
    return dict(line.split(":", 1) for line in text.splitlines() if ":" in line)


def download_nvd(folder: Path, years: list[int]) -> list[str]:
    """Each year's feed and the modified one; the years NVD didn't serve."""
    missing = []
    for name in [*map(str, years), "modified"]:
        feed = folder / f"nvdcve-2.0-{name}.json.gz"
        meta_file = folder / f"nvdcve-2.0-{name}.meta"
        with _open(NVD_FEED.format(name=name, suffix="meta")) as answer:
            meta_text = answer.read().decode("utf-8")
        meta = read_meta(meta_text)
        old = read_meta(meta_file.read_text(encoding="utf-8")) if meta_file.is_file() else {}
        if (
            feed.is_file()
            and old.get("lastModifiedDate") == meta.get("lastModifiedDate")
            and str(feed.stat().st_size) == meta.get("gzSize")
        ):
            print(f"  NVD {name}: unchanged")
            continue
        try:
            size = fetch(NVD_FEED.format(name=name, suffix="json.gz"), feed)
        except urllib.error.HTTPError as error:
            if error.code != 404 or name == "modified":
                raise
            kept = " (the earlier download is kept)" if feed.is_file() else ""
            print(f"  NVD {name}: not on NVD's server now (HTTP 404), left out{kept}")
            missing.append(name)
            continue
        if str(size) != meta.get("gzSize"):
            raise RuntimeError(f"NVD {name}: got {size} bytes, the feed says {meta.get('gzSize')}")
        meta_file.write_text(meta_text, encoding="utf-8")
        print(f"  NVD {name}: {size / 1e6:.1f} MB")
    return missing


def download_fingerprints(folder: Path) -> dict[str, Path]:
    """The two TLS fingerprint lists and the site list into folder/fingerprints,
    the address owners into folder/iptoasn."""
    paths = {
        "foxio_mapping": folder / "fingerprints" / "ja4plus-mapping.csv",
        "sslbl_ja3": folder / "fingerprints" / "sslbl_ja3_fingerprints.csv",
        "site_list": folder / "fingerprints" / "domain-list-community.tar.gz",
        "ip_owners": folder / "iptoasn" / "ip2asn-combined.tsv.gz",
    }
    for name, url, label in (
        ("foxio_mapping", FOXIO_MAPPING_URL, "FoxIO JA4+ mapping"),
        ("sslbl_ja3", SSLBL_JA3_URL, "abuse.ch SSLBL JA3"),
        ("site_list", SITE_LIST_URL, "domain-list-community (site names)"),
        ("ip_owners", IP_OWNERS_URL, "iptoasn.com (address owners)"),
    ):
        print(f"  {label}: {fetch(url, paths[name]) / 1e3:.1f} KB")
    return paths


def download(folder: Path, years: list[int]) -> dict[str, Path]:
    """Every source into folder; where each one is, for the import."""
    print(f"Downloading into {folder}")
    missing = download_nvd(folder / "nvd", years)
    paths = {
        "epss": folder / "epss" / "epss_scores-current.csv.gz",
        "kev": folder / "kev" / "known_exploited_vulnerabilities.json",
        "mitre": folder / "mitre" / "enterprise-attack.json",
    }
    for name, url in (("epss", EPSS_URL), ("kev", KEV_URL), ("mitre", MITRE_URL)):
        print(f"  {name.upper()}: {fetch(url, paths[name]) / 1e6:.1f} MB")
    paths.update(download_fingerprints(folder))
    if missing:
        print(f"  Left out: NVD {', '.join(missing)}. Run this again later to add them.")
    return {"nvd": folder / "nvd", **paths}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--into", default=str(SOURCES), help="folder for the downloads (default: data/intel/sources)")
    parser.add_argument(
        "--nvd-years", type=int, nargs="+",
        help=f"only these NVD years (default: every year from {FIRST_NVD_YEAR})",
    )
    parser.add_argument(
        "--build", action="store_true",
        help="then build the database, replacing the old one once the new one is complete",
    )
    parser.add_argument("--output", help="the database to build (default: data/intel/intel.db)")
    parser.add_argument(
        "--fingerprints-only", action="store_true",
        help="only the TLS fingerprint lists, the site list and the address owners, put into the existing database",
    )
    args = parser.parse_args()

    if args.fingerprints_only:
        sys.path[:0] = [str(PROJECT_ROOT / "src"), str(PROJECT_ROOT / "scripts")]
        from import_offline_intelligence import add_tls_fingerprints
        from ids.offline_intelligence import DEFAULT_DB_PATH

        try:
            print(f"Downloading into {Path(args.into).expanduser().resolve()}")
            paths = download_fingerprints(Path(args.into).expanduser().resolve())
        except (OSError, RuntimeError) as error:
            sys.exit(f"Download failed: {error}")
        print("Adding them to the database (a copy of it is made first: a few minutes)")
        result = add_tls_fingerprints(
            args.output or DEFAULT_DB_PATH, paths["foxio_mapping"], paths["sslbl_ja3"], paths["site_list"],
            paths["ip_owners"],
        )
        counts = result["counts"]
        print(
            f"{result['database']}: {counts['tls_fingerprint_intel']} known TLS fingerprints, "
            f"{counts['site_services']} site names with their service, "
            f"{counts['ip_owners']} address ranges with their owner"
        )
        return

    years = args.nvd_years or list(range(FIRST_NVD_YEAR, date.today().year + 1))
    try:
        paths = download(Path(args.into).expanduser().resolve(), years)
    except (OSError, RuntimeError) as error:
        sys.exit(f"Download failed: {error}")
    if not args.build:
        print("Downloaded. Build the database with --build, or with scripts/import_offline_intelligence.py.")
        return

    sys.path[:0] = [str(PROJECT_ROOT / "src"), str(PROJECT_ROOT / "scripts")]
    from import_offline_intelligence import import_sources
    from ids.offline_intelligence import DEFAULT_DB_PATH

    print("Building the database (this takes several minutes)")
    result = import_sources(
        nvd_paths=[paths["nvd"]],
        epss_paths=[paths["epss"]],
        kev_path=paths["kev"],
        mitre_path=paths["mitre"],
        output_path=args.output or DEFAULT_DB_PATH,
        replace=True,
        foxio_mapping_path=paths["foxio_mapping"],
        sslbl_ja3_path=paths["sslbl_ja3"],
        site_list_path=paths["site_list"],
        ip_owners_path=paths["ip_owners"],
    )
    counts = ", ".join(f"{name} {count}" for name, count in result["counts"].items())
    print(f"Built {result['database']} ({result['size_bytes'] / 1e9:.2f} GB): {counts}")


if __name__ == "__main__":
    main()
