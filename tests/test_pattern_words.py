import pytest

from ids.pattern_words import MAX_WORDS, read_content, read_pcre


def test_bytes_are_written_as_0x_values_and_text_is_quoted():
    assert read_pcre(r"/^..[\x81\x82\x83\x84\x85\x86\x87]\x85/") == (
        "at the start, any 2 bytes other than 0x0a, then a byte from 0x81 to 0x87, "
        "then the byte 0x85",
        None,
    )
    # \x2f is a slash: printable bytes read as text, whatever their spelling.
    assert read_pcre(r"/\x2fcgi-bin\x2f[^\x2f]*\.cgi/i")[0] == (
        "`/cgi-bin/`, then 0 or more bytes other than `/`, then `.cgi` (case-insensitive)"
    )
    # One printable byte among others is rarely text.
    assert read_pcre(r"/\x00\x01\x55\x04/")[0] == "the bytes 0x00 0x01 0x55 0x04"


def test_classes_repeats_groups_and_alternatives():
    assert read_pcre(r"/^GET\s+\/[^\s]*\.php\?id=\d+$/s")[0] == (
        "at the start, `GET`, then 1 or more whitespace bytes, then `/`, then 0 or more "
        "bytes other than whitespace, then `.php?id=`, then 1 or more digits at the end"
    )
    assert read_pcre(r"/\.(exe|dll|scr)\b/")[0] == (
        "`.`, then one of `exe`, `dll` or `scr`, then a word boundary"
    )
    assert read_pcre(r"/(\/\w+){2}[\s\S]{0,35}x?/")[0] == (
        "(`/`, then 1 or more letters, digits or `_`), 2 times, then up to 35 bytes "
        "of any value, then optionally `x`"
    )
    assert read_pcre(r"/(foo|bar)\1/")[0] == (
        "(group 1: either `foo` or `bar`), then the same bytes as group 1"
    )
    assert read_pcre(r"/O=(?!GoDaddy)[A-Z]/")[0] == (
        "`O=`, not followed by `GoDaddy`, then a byte from `A` to `Z`"
    )
    assert read_pcre(r"/(?=\d{3})x/")[0] == "where the next bytes are 3 digits, then `x`"


def test_modifiers():
    # R: matched from where the previous match ended, which ^ then marks.
    assert read_pcre(r"/^\s*(?:GET|POST)\s/R")[0] == (
        "right after the previous match, 0 or more whitespace bytes, then either `GET` "
        "or `POST`, then a whitespace byte"
    )
    assert read_pcre(r"/a.b/R")[0] == (
        "`a`, then any byte other than 0x0a, then `b` (searched from the end of the "
        "previous match)"
    )
    assert read_pcre(r"/^[^\r\n]{200,}/m")[0] == (
        "at the start of a line, 200 or more bytes other than 0x0a or 0x0d"
    )
    # Suricata's U: the pattern looks in the HTTP URI.
    assert read_pcre(r"/\/admin\.php$/Ui") == (
        "`/admin.php` at the end (case-insensitive)", "HTTP URI",
    )


@pytest.mark.parametrize("value", [
    r"/[[:alpha:]]+/",  # a POSIX class, which Python reads as a plain set
    r"/\x{41}/",  # PCRE-only syntax
    r"/(?<name>a)/",
    "/a/=",  # not a pcre modifier
    "no slashes",
    "/" + "a.b" * 400 + "/",  # longer than the rule text says it
])
def test_patterns_that_cannot_be_worded_exactly_give_none(value):
    assert read_pcre(value)[0] is None


def test_words_are_kept_up_to_the_limit():
    # The words quote the text: `aa…a`, two characters longer.
    assert read_pcre("/" + "a" * (MAX_WORDS - 2) + "/")[0] == "`" + "a" * (MAX_WORDS - 2) + "`"
    assert read_pcre("/" + "a" * (MAX_WORDS - 1) + "/")[0] is None
    assert read_pcre(r"/\d\d\d-[a-f][a-f]/")[0] == (
        "3 digits, then `-`, then 2 bytes from `a` to `f`"
    )


def test_content_hex_blocks():
    assert read_content("|11|") == "the byte 0x11"
    # A block of printable bytes reads as text; one with other bytes byte by byte.
    assert read_content("|0D 0A|Host|3A 20|x") == "the bytes 0x0d 0x0a followed by `Host: x`"
    assert read_content("|31 0b|US") == "the bytes 0x31 0x0b followed by `US`"
    # Escaped characters, and the bytes JSON would write with a backslash.
    assert read_content('a\\;b|22 5C|') == "`a;b` followed by the bytes 0x22 0x5c"
    assert read_content("|20|") == "the byte 0x20"
    assert read_content("|1|") is None
    assert read_content("|00") is None
