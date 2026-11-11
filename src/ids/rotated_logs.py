"""
The lines a tailer missed when its log was rotated: the rest of the file it
was reading, now a rotated copy, and any newer rotated copies it never saw
(when the collector was stopped through more than one rotation).

logrotate names the copies <log>.1, <log>.2.gz, … (newest first), whether
it renames the log or copies and truncates it, compressed or not. The copy
the tailer was reading is the newest one that starts with the bytes the
tailer fingerprinted; it is read from the tailer's offset, and the newer
copies whole. Lines read twice are harmless: the database skips alerts it
has (event_hash).
"""

from __future__ import annotations

import gzip
import hashlib
import re
from collections.abc import Iterator
from pathlib import Path
from typing import IO

ROTATED = re.compile(r"\.(\d+)(\.gz)?$")


def rotated_files(path: Path) -> list[Path]:
    """The log's rotated copies, newest first; a plain copy before a gzipped
    one of the same number, which logrotate may still be compressing."""
    found = []
    for candidate in path.parent.glob(f"{path.name}.*"):
        match = ROTATED.fullmatch(candidate.name[len(path.name):])
        if match and candidate.is_file():
            found.append((int(match.group(1)), match.group(2) is not None, candidate))
    return [candidate for _, _, candidate in sorted(found)]


def _open(path: Path) -> IO[bytes]:
    return gzip.open(path, "rb") if path.suffix == ".gz" else path.open("rb")


def _starts_with(path: Path, fingerprint: str, length: int) -> bool:
    try:
        with _open(path) as file:
            prefix = file.read(length)
    except (OSError, EOFError):
        # Gone meanwhile, or a gzip still being written.
        return False
    return len(prefix) == length and hashlib.sha256(prefix).hexdigest() == fingerprint


def _lines(path: Path, offset: int = 0) -> Iterator[str]:
    with _open(path) as file:
        file.seek(offset)
        for line in file:
            yield line.decode("utf-8", "replace").rstrip("\r\n")


def missed_lines(
    path: Path, offset: int, fingerprint: str | None, fingerprint_length: int,
) -> Iterator[str]:
    """The lines after ``offset`` in the rotated copy of ``path`` that
    starts with the fingerprinted bytes, then every line of the copies
    rotated after it, oldest first. Nothing when no copy matches, as when
    the copy was deleted or there was no fingerprint."""
    if not fingerprint or fingerprint_length <= 0:
        return
    copies = rotated_files(path)
    for index, copy in enumerate(copies):
        if _starts_with(copy, fingerprint, fingerprint_length):
            yield from _lines(copy, offset)
            for newer in reversed(copies[:index]):
                yield from _lines(newer)
            return
