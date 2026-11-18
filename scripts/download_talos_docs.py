#!/usr/bin/env python3
"""Download Talos's documentation of each Snort rule this machine has, once,
into data/intel/sources/talos/rule_docs.jsonl, for the threat-intel database
(scripts/import_offline_intelligence.py reads it). After that nothing reads
snort.org: the database, and the LLM PC's copy of it, hold the documents.

    .venv/bin/python scripts/download_talos_docs.py

The rules are the registered snapshot's text rules (GID 1) and SO rules
(GID 3) under /usr/local/etc/snort/registered; each has a page at
https://www.snort.org/rule_docs/<gid>-<sid>. A rule already in the file is
not fetched again (--refresh fetches them all), so a run that stops picks up
where it was, and after the nightly rule update only the new rules are
fetched. A rule snort.org has no page for is written with "doc_found": 0.
Built-in rules (GID 2 and up) are left out: their pages only repeat the
rule's message, and Snort's own builtin_stubs.txt describes them.

Each line is one rule, in the fields the local copy
(data/json/rule_docs_preprocessed_by_sid.json) uses: gid, sid, doc_found,
doc_url, msg, rule_category, rule_explanation, what_to_look_for,
known_usage, false_positives, contributors, rule_groups, mitre_id, cve_ids
and rule_vulnerability, each as the page writes it; the page's placeholders
("No information provided", "No known false positives", "None", …) are left
out.

The rules the local copy (data/json/rule_docs_preprocessed_by_sid.json)
already has, about 4,000, are not fetched.

snort.org limits how fast pages may be fetched: three at a time were
refused (HTTP 429) after about 50, and one at a time it allowed about ten a
minute. So it fetches one page at a time, a page every 3 seconds at most
(the pace it settled at), and when snort.org answers 429 it waits (as long
as its Retry-After says, else a minute), fetches the page again and leaves
more time between pages; after 100 pages without a 429 it goes a little
faster again, down to that 3 seconds. The 48,600 pages take a day or two;
run it where it can keep going, and again if it stops (only one at a time):

    nohup .venv/bin/python scripts/download_talos_docs.py > data/intel/sources/talos/download.log 2>&1 &

www.snort.org's address is looked up once every half hour, not for each
page: this machine's lookups reach the lab network (through VMware's NAT and
the host), where Suricata alerts on each one, and a lookup per page made
most of its alerts.
"""

from __future__ import annotations

import argparse
import fcntl
import html
import json
import re
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Iterable

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = PROJECT_ROOT / "data" / "intel" / "sources" / "talos" / "rule_docs.jsonl"
DEFAULT_RULES = Path("/usr/local/etc/snort/registered")
PAGE_URL = "https://www.snort.org/rule_docs/{gid}-{sid}"
PAGE_HOST = "www.snort.org"
# How long a lookup of PAGE_HOST's address is used.
ADDRESS_SECONDS = 1800
USER_AGENT = "IDS-Dashboard rule documentation download"

# What a page writes when it has nothing to say.
PLACEHOLDERS = {
    "no information provided", "none provided", "no public information",
    "no known false positives", "no rule groups", "none",
}
_GID_RE = re.compile(r"\bgid\s*:\s*(\d+)\s*;")
_SID_RE = re.compile(r"\bsid\s*:\s*(\d+)\s*;")
_HEADING_RE = re.compile(r"<h3[^>]*>(.*?)</h3>", re.S)
_TAG_RE = re.compile(r"<[^>]+>")


def rule_ids(rules_dir: Path) -> list[tuple[int, int]]:
    """Each (GID, SID) of the text and SO rules under rules_dir, once."""
    found: set[tuple[int, int]] = set()
    for folder, default_gid in (("rules", 1), ("so_rules", 3)):
        for path in sorted((rules_dir / folder).glob("*.rules")):
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                sid = _SID_RE.search(line)
                if not sid:
                    continue
                gid = _GID_RE.search(line)
                found.add((int(gid.group(1)) if gid else default_gid, int(sid.group(1))))
    return sorted(found)


def _text(fragment: str) -> str:
    """A piece of the page as text: tags removed, its line breaks kept."""
    text = html.unescape(_TAG_RE.sub("", re.sub(r"<br\s*/?>", "\n", fragment)))
    lines = [line.strip() for line in text.strip().splitlines()]
    text = "\n".join(lines).strip()
    return "" if text.lower() in PLACEHOLDERS else text


def _paragraphs(chunk: str, css_class: str | None = None) -> list[str]:
    pattern = (
        rf'<p[^>]*class="[^"]*\b{css_class}\b[^"]*"[^>]*>(.*?)</p>'
        if css_class else r"<p[^>]*>(.*?)</p>"
    )
    return [text for text in (_text(body) for body in re.findall(pattern, chunk, re.S)) if text]


def parse_page(page: str) -> dict[str, Any]:
    """The documentation on one rule page, by the local copy's field names."""
    start = page.find("TABBED CONTENT BEGIN")
    page = page[start:] if start >= 0 else page
    parts = _HEADING_RE.split(page)
    sections = {_text(name): body for name, body in zip(parts[1::2], parts[2::2])}

    def first(name: str) -> str:
        found = _paragraphs(sections.get(name, ""))
        return found[0] if found else ""

    groups = sections.get("Rule Groups", "")
    vulnerability = sections.get("Rule Vulnerability", "")
    kind = _paragraphs(vulnerability, "rule_vulnerability")
    about = _paragraphs(vulnerability, "rule_vulnerability_blurb")
    if not kind:
        kind = [text for text in _paragraphs(vulnerability) if text]
    return {
        "msg": first("Alert Message"),
        "rule_category": first("Rule Category"),
        "rule_explanation": first("Rule Explanation"),
        "what_to_look_for": first("What To Look For"),
        "known_usage": first("Known Usage"),
        "false_positives": first("False Positives"),
        "contributors": first("Contributors"),
        "rule_groups": ", ".join(_paragraphs(groups, "rg-fqn")),
        "mitre_id": ", ".join(_paragraphs(groups, "rg-mitre-id")),
        "cve_ids": ", ".join(
            _text(entry) for entry in re.findall(
                r'<span class="cve-entry">(.*?)</span>', sections.get("CVE", ""), re.S
            )
        ),
        "rule_vulnerability": "\n".join([*kind[:1], *about[:1]]),
    }


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # snort.org answers a rule it has no page for with a redirect.
    def redirect_request(self, *args, **kwargs):
        return None


_opener = urllib.request.build_opener(_NoRedirect)


class _Pace:
    """How fast to go. When snort.org says too many (HTTP 429) every worker
    waits (its Retry-After, else a minute) and the gap between pages grows
    by half; after each 100 pages without one it shrinks by a tenth, down
    to the --pause given. So the pace settles where snort.org allows it."""

    def __init__(self, gap: float = 1.0) -> None:
        self.lock = threading.Lock()
        self.resume_at = 0.0
        self.least_gap = gap
        self.gap = gap
        self.since_refused = 0

    def hold(self) -> None:
        while True:
            with self.lock:
                left = self.resume_at - time.monotonic()
            if left <= 0:
                return
            time.sleep(min(left, 5))

    def slow_down(self, retry_after: str | None) -> float:
        with self.lock:
            try:
                wait = float(retry_after) if retry_after else 60.0
            except ValueError:
                wait = 60.0
            self.gap = min(self.gap * 1.5, 60.0)
            self.since_refused = 0
            self.resume_at = max(self.resume_at, time.monotonic() + wait)
            return wait

    def went_well(self) -> None:
        with self.lock:
            self.since_refused += 1
            if self.since_refused % 100 == 0:
                self.gap = max(self.least_gap, self.gap * 0.9)


_pace = _Pace()

_lookup = socket.getaddrinfo
# PAGE_HOST's addresses: when they were looked up and what they were.
_addresses: dict[tuple[Any, ...], tuple[float, Any]] = {}


def _remembered_lookup(host: Any, *args: Any, **kwargs: Any) -> Any:
    """socket.getaddrinfo, looking PAGE_HOST up once every ADDRESS_SECONDS.
    The connection still names the host (TLS checks its certificate)."""
    if host != PAGE_HOST:
        return _lookup(host, *args, **kwargs)
    key = (host, *args, *sorted(kwargs.items()))
    looked_up = _addresses.get(key)
    if looked_up is not None and time.monotonic() - looked_up[0] < ADDRESS_SECONDS:
        return looked_up[1]
    found = _lookup(host, *args, **kwargs)
    _addresses[key] = (time.monotonic(), found)
    return found


def fetch(gid: int, sid: int, attempts: int = 3, slowdowns: int = 20) -> dict[str, Any]:
    url = PAGE_URL.format(gid=gid, sid=sid)
    attempt = 0
    while True:
        _pace.hold()
        try:
            request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with _opener.open(request, timeout=30) as answer:
                page = answer.read().decode("utf-8", errors="replace")
            document = {key: value for key, value in parse_page(page).items() if value}
            _pace.went_well()
            return {"gid": gid, "sid": sid, "doc_found": 1, "doc_url": url, **document}
        except urllib.error.HTTPError as error:
            if error.code in (301, 302, 303, 404):
                _pace.went_well()
                return {"gid": gid, "sid": sid, "doc_found": 0, "doc_url": url}
            if error.code == 429 and slowdowns > 0:
                slowdowns -= 1
                wait = _pace.slow_down(error.headers.get("Retry-After"))
                print(f"   snort.org asked to slow down: waiting {wait:.0f} s, "
                      f"then a page every {_pace.gap:.1f} s", flush=True)
                continue
            attempt += 1
            if attempt >= attempts:
                raise
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            _addresses.clear()  # the address may have changed: look it up again
            attempt += 1
            if attempt >= attempts:
                raise
        time.sleep(5 * attempt)


def local_copy(path: Path | None) -> set[tuple[int, int]]:
    """The rules the local copy of Talos's documentation already has (with or
    without a page): the same pages, fetched before."""
    if path is None or not path.is_file():
        return set()
    return {
        (int(doc.get("gid") or 1), int(doc["sid"]))
        for doc in json.loads(path.read_text(encoding="utf-8")).values()
        if str(doc.get("sid", "")).isdigit()
    }


def fetched(output: Path) -> set[tuple[int, int]]:
    if not output.is_file():
        return set()
    done = set()
    for line in output.read_text(encoding="utf-8").splitlines():
        try:
            record = json.loads(line)
            done.add((int(record["gid"]), int(record["sid"])))
        except (ValueError, KeyError, TypeError):
            continue
    return done


def download(rules: Iterable[tuple[int, int]], output: Path, workers: int, pause: float) -> dict[str, int]:
    global _pace
    _pace = _Pace(pause)
    output.parent.mkdir(parents=True, exist_ok=True)
    rules = list(rules)
    lock = threading.Lock()
    counts = {"pages": 0, "no_page": 0, "failed": 0}
    started = time.monotonic()

    def one(rule: tuple[int, int]) -> None:
        try:
            record = fetch(*rule)
        except Exception as error:  # noqa: BLE001 - one rule's failure is reported, the rest go on
            with lock:
                counts["failed"] += 1
                print(f"!! {rule[0]}:{rule[1]}: {error}", file=sys.stderr, flush=True)
            return
        with lock:
            with output.open("a", encoding="utf-8") as out:
                out.write(json.dumps(record, ensure_ascii=False) + "\n")
            counts["pages" if record["doc_found"] else "no_page"] += 1
            done = counts["pages"] + counts["no_page"] + counts["failed"]
            if done % 500 == 0 or done == len(rules):
                rate = done / max(time.monotonic() - started, 1)
                left = (len(rules) - done) / rate / 60 if rate else 0
                print(f"{done} / {len(rules)} ({counts['no_page']} without a page), "
                      f"about {left:.0f} minutes left", flush=True)
        time.sleep(_pace.gap)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(one, rules))
    return counts


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES, help=f"the registered snapshot (default: {DEFAULT_RULES})")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="where the documents go")
    parser.add_argument("--workers", type=int, default=1, help="requests at a time (default: 1)")
    parser.add_argument("--pause", type=float, default=3.0, help="seconds each worker waits between pages, at least (default: 3)")
    parser.add_argument("--refresh", action="store_true", help="fetch every rule again, the local copy's too")
    parser.add_argument(
        "--local-copy", type=Path, default=PROJECT_ROOT / "data" / "json" / "rule_docs_preprocessed_by_sid.json",
        help="the local copy of Talos's documentation, whose rules are not fetched",
    )
    parser.add_argument("--limit", type=int, help="fetch at most this many (to try it)")
    args = parser.parse_args(argv)
    socket.getaddrinfo = _remembered_lookup

    # One run at a time: two would fetch the same pages, twice as fast.
    args.output.parent.mkdir(parents=True, exist_ok=True)
    lock = open(args.output.with_name(args.output.name + ".lock"), "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        raise SystemExit("It is running already (pgrep -af download_talos_docs); one run at a time.")
    rules = rule_ids(args.rules)
    if not rules:
        raise SystemExit(f"No Snort rules under {args.rules}: run deploy/update-rules.sh first")
    if args.refresh:
        args.local_copy = None
        if args.output.exists():
            args.output.unlink()
    done = fetched(args.output) | local_copy(args.local_copy)
    todo = [rule for rule in rules if rule not in done]
    if args.limit is not None:
        todo = todo[: args.limit]
    print(f"{len(rules)} Snort rules; {len(done)} documented already; fetching {len(todo)}", flush=True)
    counts = download(todo, args.output, max(1, args.workers), args.pause)
    print(json.dumps({"output": str(args.output), **counts}))
    if counts["failed"]:
        print("Run it again to fetch the ones that failed.", file=sys.stderr)


if __name__ == "__main__":
    main()
