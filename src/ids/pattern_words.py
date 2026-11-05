"""Snort and Suricata rule patterns in plain words.

A rule's text keeps its content and pcre patterns as written (`|0D 0A|`,
`\\x81`). A JSON file writes each backslash twice, so `\\x81` shows as
`\\\\x81` in an editor and as `\\x81` in Firefox's JSON viewer. The words here
use no backslashes: a byte that is not plain text is written as 0x81, and a
regular expression is told step by step ("at the start, any 2 bytes, then a
byte from 0x81 to 0x87"), so they read the same in every program.
"""

from __future__ import annotations

import re
import warnings
from typing import Any

try:  # The parser behind re, in Python 3.11 and later.
    from re import _constants as _codes, _parser
except ImportError:  # pragma: no cover
    _codes = _parser = None

# Suricata's pcre modifiers that name the HTTP buffer the pattern looks in.
PCRE_BUFFERS = {
    "U": "HTTP URI",
    "I": "raw HTTP URI",
    "P": "HTTP request body",
    "Q": "HTTP response body",
    "H": "HTTP headers",
    "D": "raw HTTP headers",
    "M": "HTTP method",
    "C": "HTTP cookie",
    "S": "HTTP status code",
    "Y": "HTTP status message",
    "V": "HTTP User-Agent",
    "W": "HTTP host",
    "Z": "raw HTTP host",
}
# The other modifiers: case, dot, line and space handling (i s m x),
# anchoring (A), $ at the very end (E), laziness (G), the match limit (O),
# R (from the end of the previous match) and B (kept for old rules).
_PCRE_FLAGS = set("ismxAEGORB") | set(PCRE_BUFFERS)
# Longer words say less than the rule text does.
MAX_WORDS = 1000


class _Unreadable(Exception):
    """A part of a pattern that is not worded here."""


def _byte(code: int) -> str:
    return f"0x{code:02x}"


def _plain(code: int) -> bool:
    """Shown as itself: printable ASCII but the double quote and the
    backslash, which JSON writes with a backslash, and the backtick, which
    quotes text here."""
    return 0x20 <= code < 0x7F and code not in (0x22, 0x5C, 0x60)


def _char(code: int) -> str:
    """One byte: quoted when it is plain text, else 0x.. (a space too)."""
    return f"`{chr(code)}`" if _plain(code) and code != 0x20 else _byte(code)


def _runs(tokens: list[tuple[int, bool]]) -> list[str]:
    """Bytes in order, each marked plain or not: plain text quoted
    (`Host: `), the others as "the byte 0x00" or "the bytes 0x0d 0x0a"."""
    runs: list[tuple[bool, list[int]]] = []
    for code, plain in tokens:
        if runs and runs[-1][0] == plain:
            runs[-1][1].append(code)
        else:
            runs.append((plain, [code]))
    merged: list[tuple[bool, list[int]]] = []
    for plain, run in runs:
        # Spaces alone are clearer as bytes.
        plain = plain and any(code != 0x20 for code in run)
        if merged and not plain and not merged[-1][0]:
            merged[-1][1].extend(run)
        else:
            merged.append((plain, list(run)))
    return [
        f"`{bytes(run).decode('ascii')}`" if plain
        else ("the byte " if len(run) == 1 else "the bytes ") + " ".join(map(_byte, run))
        for plain, run in merged
    ]


def _literal_tokens(codes: list[int]) -> list[tuple[int, bool]]:
    """A regular expression's literal bytes, marked plain. One printable
    byte between other bytes (U in \\x00\\x55\\x04) is rarely text, so it is
    shown as a byte too."""
    tokens = [(code, _plain(code)) for code in codes]
    for index in range(1, len(tokens) - 1):
        if tokens[index][1] and not tokens[index - 1][1] and not tokens[index + 1][1]:
            tokens[index] = (tokens[index][0], False)
    return tokens


def _or(items: list[str]) -> str:
    return items[0] if len(items) == 1 else f"{', '.join(items[:-1])} or {items[-1]}"


def read_content(pattern: str) -> str | None:
    """A rule's content value (GET, |0D 0A|Host|3A| ) in words: "the bytes
    0x0d 0x0a followed by `Host: `". A |hex| block of printable bytes
    (|3A 2F 2F|) reads as text; one with other bytes is given byte by byte.
    None when a |hex| block is not well formed."""
    tokens: list[tuple[int, bool]] = []
    hex_digits: str | None = None
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if hex_digits is not None:
            if char == "|":
                try:
                    block = bytes.fromhex("".join(hex_digits.split()))
                except ValueError:
                    return None
                plain = all(_plain(code) for code in block)
                tokens.extend((code, plain) for code in block)
                hex_digits = None
            else:
                hex_digits += char
        elif char == "|":
            hex_digits = ""
        else:
            if char == "\\" and index + 1 < len(pattern):
                # \" \; \\ and \: stand for the character itself.
                index += 1
                char = pattern[index]
            tokens.extend((code, _plain(code)) for code in char.encode("utf-8"))
        index += 1
    if hex_digits is not None or not tokens:
        return None
    return " followed by ".join(_runs(tokens))


def read_pcre(value: str) -> tuple[str | None, str | None]:
    """A rule's pcre value (/^..[\\x81-\\x87]\\x85/i) in words, and the HTTP
    buffer its Suricata modifier names (None for none).

    The words are None when the regular expression cannot be worded
    exactly: Python's parser does not read it (PCRE-only syntax such as
    \\x{..}, \\h or (?<name>..)), it holds a part not worded here, or the
    words would be longer than MAX_WORDS.
    """
    end = value.rfind("/")
    if not value.startswith("/") or end == 0:
        return None, None
    pattern, flags = value[1:end], value[end + 1:]
    if set(flags) - _PCRE_FLAGS:
        return None, None
    buffer = next((PCRE_BUFFERS[flag] for flag in flags if flag in PCRE_BUFFERS), None)
    if _parser is None:
        return None, buffer
    try:
        with warnings.catch_warnings():
            # Python reads a POSIX class such as [[:alpha:]] as a plain set,
            # with a warning: it would be worded wrongly.
            warnings.simplefilter("error")
            # As bytes, the way PCRE reads a rule's pattern.
            parsed = _parser.parse(
                pattern.encode("utf-8"), re.VERBOSE if "x" in flags else 0
            )
        inline = parsed.state.flags
        reader = _Reader(
            dotall="s" in flags or bool(inline & re.DOTALL),
            multiline="m" in flags or bool(inline & re.MULTILINE),
            relative="R" in flags,
            referenced=_referenced_groups(parsed),
        )
        words = reader.sequence(list(parsed), anchored="A" in flags)
    except Exception:  # re.error, a warning, _Unreadable or a parser oddity
        return None, buffer
    notes = []
    if "i" in flags or inline & re.IGNORECASE:
        notes.append("case-insensitive")
    if "R" in flags and not reader.started_relative:
        notes.append("searched from the end of the previous match")
    if notes:
        words += f" ({', '.join(notes)})"
    if not words or len(words) > MAX_WORDS:
        return None, buffer
    return words, buffer


def _referenced_groups(items: Any) -> set[int]:
    """The groups a back-reference (\\1) names; the words number them."""
    found: set[int] = set()
    for op, arg in items:
        if op is _codes.GROUPREF:
            found.add(arg)
        elif op in (_codes.MAX_REPEAT, _codes.MIN_REPEAT, _codes.POSSESSIVE_REPEAT):
            found |= _referenced_groups(arg[2])
        elif op is _codes.SUBPATTERN:
            found |= _referenced_groups(arg[3])
        elif op is _codes.ATOMIC_GROUP:
            found |= _referenced_groups(arg)
        elif op is _codes.BRANCH:
            for alternative in arg[1]:
                found |= _referenced_groups(alternative)
        elif op in (_codes.ASSERT, _codes.ASSERT_NOT):
            found |= _referenced_groups(arg[1])
    return found


def _times(low: int, high: int) -> str:
    if high == _codes.MAXREPEAT:
        return f"{low} or more"
    if low == high:
        return str(low)
    return f"up to {high}" if low == 0 else f"{low} to {high}"


class _Reader:
    """Words for the parts of one parsed regular expression."""

    def __init__(self, *, dotall: bool, multiline: bool, relative: bool, referenced: set[int]):
        self.dotall = dotall
        self.multiline = multiline
        self.relative = relative
        self.referenced = referenced
        self.started_relative = False
        c = _codes
        # (one, several, as one of a set's members)
        self.categories = {
            c.CATEGORY_DIGIT: ("a digit", "digits", "a digit"),
            c.CATEGORY_NOT_DIGIT: ("a byte that is not a digit", "bytes that are not digits", "a non-digit"),
            c.CATEGORY_SPACE: ("a whitespace byte", "whitespace bytes", "whitespace"),
            c.CATEGORY_NOT_SPACE: (
                "a byte that is not whitespace", "bytes that are not whitespace", "a non-whitespace byte",
            ),
            c.CATEGORY_WORD: ("a letter, digit or `_`", "letters, digits or `_`", "a word character"),
            c.CATEGORY_NOT_WORD: ("a non-word character", "non-word characters", "a non-word character"),
        }

    def _start(self, at: Any) -> str:
        if self.relative:
            # With R the pattern is matched from where the previous match
            # ended, so ^ is that point.
            self.started_relative = True
            return "right after the previous match"
        if at is _codes.AT_BEGINNING and self.multiline:
            return "at the start of a line"
        return "at the start"

    def _end(self, at: Any) -> str:
        return "at the end of a line" if at is _codes.AT_END and self.multiline else "at the end"

    def sequence(self, items: list[Any], *, anchored: bool = False) -> str:
        """Parts one after the other, joined with ", then "."""
        c = _codes
        starts, ends = (c.AT_BEGINNING, c.AT_BEGINNING_STRING), (c.AT_END, c.AT_END_STRING)
        start = end = ""
        if items and items[0][0] is c.AT and items[0][1] in starts:
            start, items = self._start(items[0][1]), items[1:]
        elif anchored:
            start = self._start(c.AT_BEGINNING)
        if items and items[-1][0] is c.AT and items[-1][1] in ends:
            end, items = self._end(items[-1][1]), items[:-1]
        parts: list[tuple[str, str]] = []
        index = 0
        while index < len(items):
            op, arg = items[index]
            if op is c.LITERAL:
                run = [arg]
                while index + 1 < len(items) and items[index + 1][0] is c.LITERAL:
                    index += 1
                    run.append(items[index][1])
                parts.extend((", then ", words) for words in _runs(_literal_tokens(run)))
            elif op is c.ANY:
                count = 1
                while index + 1 < len(items) and items[index + 1][0] is c.ANY:
                    index += 1
                    count += 1
                parts.append((", then ", self._any(count, count)))
            elif op in (c.IN, c.CATEGORY, c.NOT_LITERAL):
                # \d\d\d is 3 digits.
                count = 1
                while index + 1 < len(items) and items[index + 1] == items[index]:
                    index += 1
                    count += 1
                parts.append((", then ", self.item(op, arg) if count == 1 else f"{count} {self._several(op, arg)}"))
            elif op in (c.ASSERT, c.ASSERT_NOT):
                parts.append((", ", self._assertion(op, *arg, first=not parts)))
            else:
                parts.append((", then ", self.item(op, arg)))
            index += 1
        text = ""
        for joiner, words in parts:
            text = f"{text}{joiner}{words}" if text else words
        if start:
            text = f"{start}, {text}" if text else start
        if end:
            text = f"{text} {end}" if text else end
        return text

    def item(self, op: Any, arg: Any) -> str:
        c = _codes
        if op is c.LITERAL:
            return _runs([(arg, _plain(arg))])[0]
        if op is c.NOT_LITERAL:
            return f"a byte other than {_char(arg)}"
        if op is c.ANY:
            return self._any(1, 1)
        if op is c.IN:
            return self._set(arg)[0]
        if op is c.CATEGORY:
            return self.categories[arg][0]
        if op in (c.MAX_REPEAT, c.MIN_REPEAT, c.POSSESSIVE_REPEAT):
            return self._repeat(*arg)
        if op is c.SUBPATTERN:
            return self._group(*arg)
        if op is c.ATOMIC_GROUP:
            return self._inner(list(arg))
        if op is c.BRANCH:
            return self._branch(arg[1])
        if op is c.GROUPREF:
            return f"the same bytes as group {arg}"
        if op is c.AT:
            words = {
                c.AT_BOUNDARY: "a word boundary",
                c.AT_NON_BOUNDARY: "a point that is not a word boundary",
                c.AT_BEGINNING: "the start of a line" if self.multiline else "the start",
                c.AT_BEGINNING_STRING: "the start",
                c.AT_END: "the end of a line" if self.multiline else "the end",
                c.AT_END_STRING: "the end",
            }
            return words[arg]
        if op in (c.ASSERT, c.ASSERT_NOT):
            return self._assertion(op, *arg, first=False)
        raise _Unreadable(op)

    def _assertion(self, op: Any, direction: int, sub: Any, *, first: bool) -> str:
        """A look-ahead or look-behind, which checks bytes without moving on."""
        words = self._inner(list(sub))
        positive = op is _codes.ASSERT
        if direction == 1 and first:
            # Nothing before it: what it checks is where the match begins.
            return ("where the next bytes are " if positive else "where the next bytes are not ") + words
        if direction == 1:
            return ("followed by " if positive else "not followed by ") + words
        return ("preceded by " if positive else "not preceded by ") + words

    def _inner(self, items: list[Any]) -> str:
        """A group's or a repeat's parts, in brackets when there are several."""
        if len(items) == 1 and items[0][0] is _codes.BRANCH:
            return self._branch(items[0][1][1])
        if len(items) == 1 and items[0][0] in (_codes.SUBPATTERN, _codes.ATOMIC_GROUP):
            # A group puts itself in brackets.
            return self.item(*items[0])
        words = self.sequence(items)
        if not words:
            raise _Unreadable("an empty group")
        return f"({words})" if ", " in words else words

    def _any(self, low: int, high: int) -> str:
        other = "" if self.dotall else " other than 0x0a"
        if (low, high) == (1, 1):
            return f"any byte{other}"
        if (low, high) == (0, 1):
            return f"optionally any byte{other}"
        if (low, high) == (0, _codes.MAXREPEAT):
            return f"any number of bytes{other}"
        if low == high:
            return f"any {low} bytes{other}"
        return f"{_times(low, high)} bytes{other or ' of any value'}"

    def _repeat(self, low: int, high: int, sub: Any) -> str:
        items = list(sub)
        if len(items) == 1 and items[0][0] is _codes.ANY:
            return self._any(low, high)
        one = self._inner(items)
        if (low, high) == (1, 1):
            return one
        if (low, high) == (0, 1):
            return f"optionally {one}"
        several = self._several(*items[0]) if len(items) == 1 else None
        if several:
            return f"{_times(low, high)} {several}"
        return f"{one}, {_times(low, high)} times"

    def _several(self, op: Any, arg: Any) -> str | None:
        """The plural words for a byte class, for "1 or more digits"."""
        if op is _codes.IN:
            return self._set(arg)[1]
        if op is _codes.CATEGORY:
            return self.categories[arg][1]
        if op is _codes.NOT_LITERAL:
            return f"bytes other than {_char(arg)}"
        return None

    def _set(self, items: Any) -> tuple[str, str]:
        """A [...] set: the words for one byte and for several."""
        c = _codes
        negated, spans, classes = False, [], []
        for op, arg in items:
            if op is c.NEGATE:
                negated = True
            elif op is c.LITERAL:
                spans.append([arg, arg])
            elif op is c.RANGE:
                spans.append([arg[0], arg[1]])
            elif op is c.CATEGORY:
                classes.append(arg)
            else:
                raise _Unreadable(op)
        if not spans and len(classes) == 1 and not negated:
            one, several, _ = self.categories[classes[0]]
            return one, several
        opposites = (
            {c.CATEGORY_DIGIT, c.CATEGORY_NOT_DIGIT},
            {c.CATEGORY_SPACE, c.CATEGORY_NOT_SPACE},
            {c.CATEGORY_WORD, c.CATEGORY_NOT_WORD},
        )
        if not negated and any(pair <= set(classes) for pair in opposites):
            # [\s\S] and the like: every byte.
            return "any byte", "bytes of any value"
        merged: list[list[int]] = []
        for low, high in sorted(spans):
            if merged and low <= merged[-1][1] + 1:
                merged[-1][1] = max(merged[-1][1], high)
            else:
                merged.append([low, high])
        members = []
        for low, high in merged:
            if low == high:
                members.append(_char(low))
            elif high == low + 1:
                members += [_char(low), _char(high)]
            else:
                members.append(f"{_char(low)} to {_char(high)}")
        members += [self.categories[category][2] for category in classes]
        if not members:
            raise _Unreadable("an empty set")
        listed = _or(members)
        if negated:
            return f"a byte other than {listed}", f"bytes other than {listed}"
        if len(merged) == 1 and not classes and merged[0][0] != merged[0][1] and len(members) == 1:
            return f"a byte from {listed}", f"bytes from {listed}"
        return f"one of {listed}", f"bytes, each one of {listed}"

    def _group(self, group: int | None, add_flags: int, del_flags: int, sub: Any) -> str:
        known = re.IGNORECASE | re.DOTALL | re.MULTILINE
        if (add_flags | del_flags) & ~known:
            raise _Unreadable("group flags")
        saved = self.dotall, self.multiline
        if add_flags & re.DOTALL or del_flags & re.DOTALL:
            self.dotall = bool(add_flags & re.DOTALL)
        if add_flags & re.MULTILINE or del_flags & re.MULTILINE:
            self.multiline = bool(add_flags & re.MULTILINE)
        try:
            items = list(sub)
            if group in self.referenced:
                inner = (
                    self._branch(items[0][1][1])
                    if len(items) == 1 and items[0][0] is _codes.BRANCH
                    else self.sequence(items)
                )
                words = f"(group {group}: {inner})"
            else:
                words = self._inner(items)
        finally:
            self.dotall, self.multiline = saved
        if add_flags & re.IGNORECASE:
            words += " (case-insensitive)"
        elif del_flags & re.IGNORECASE:
            words += " (case-sensitive)"
        return words

    def _branch(self, alternatives: Any) -> str:
        options = []
        for alternative in alternatives:
            words = self.sequence(list(alternative)) or "nothing"
            options.append(f"({words})" if ", " in words else words)
        if len(options) == 2:
            return f"either {options[0]} or {options[1]}"
        return f"one of {_or(options)}"
