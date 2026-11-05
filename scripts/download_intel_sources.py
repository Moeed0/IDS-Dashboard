#!/usr/bin/env python3
"""Download the public threat-intel sources the combined export's offline
enrichment is built from, and optionally build data/intel/intel.db from them
with scripts/import_offline_intelligence.py:

- NVD's CVE feeds (JSON 2.0): one file per year from 2002, and the CVEs
  modified recently;
- FIRST's EPSS scores;
- CISA's Known Exploited Vulnerabilities catalog;
- MITRE ATT&CK for Enterprise (STIX).

    .venv/bin/python scripts/download_intel_sources.py --build

About 300 MB of downloads, and a database of about 1.6 GB. An NVD year whose
feed has not changed since the last download is not downloaded again. Each
file is written under a temporary name first, so a stopped download leaves
no half file behind.
"""

from __future__ import annotations

import argparse
import sys
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


def download_nvd(folder: Path, years: list[int]) -> None:
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
        size = fetch(NVD_FEED.format(name=name, suffix="json.gz"), feed)
        if str(size) != meta.get("gzSize"):
            raise RuntimeError(f"NVD {name}: got {size} bytes, the feed says {meta.get('gzSize')}")
        meta_file.write_text(meta_text, encoding="utf-8")
        print(f"  NVD {name}: {size / 1e6:.1f} MB")


def download(folder: Path, years: list[int]) -> dict[str, Path]:
    """Every source into folder; where each one is, for the import."""
    print(f"Downloading into {folder}")
    download_nvd(folder / "nvd", years)
    paths = {
        "epss": folder / "epss" / "epss_scores-current.csv.gz",
        "kev": folder / "kev" / "known_exploited_vulnerabilities.json",
        "mitre": folder / "mitre" / "enterprise-attack.json",
    }
    for name, url in (("epss", EPSS_URL), ("kev", KEV_URL), ("mitre", MITRE_URL)):
        print(f"  {name.upper()}: {fetch(url, paths[name]) / 1e6:.1f} MB")
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
    args = parser.parse_args()

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
    )
    counts = ", ".join(f"{name} {count}" for name, count in result["counts"].items())
    print(f"Built {result['database']} ({result['size_bytes'] / 1e9:.2f} GB): {counts}")


if __name__ == "__main__":
    main()
