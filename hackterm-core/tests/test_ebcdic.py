import pytest
from hackterm_core.ebcdic import EbcdicCodec


def test_default_codepage_is_cp037():
    c = EbcdicCodec()
    assert c.codepage == "cp037"


def test_to_ascii_basic_letters():
    """EBCDIC uppercase A-I are 0xC1-0xC9."""
    c = EbcdicCodec()
    assert c.to_ascii(b"\xc1\xc2\xc3") == "ABC"


def test_to_ascii_lowercase():
    """EBCDIC lowercase a-i are 0x81-0x89."""
    c = EbcdicCodec()
    assert c.to_ascii(b"\x81\x82\x83") == "abc"


def test_to_ascii_digits():
    """EBCDIC digits 0-9 are 0xF0-0xF9."""
    c = EbcdicCodec()
    assert c.to_ascii(b"\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9") == "0123456789"


def test_to_ascii_space():
    """EBCDIC space is 0x40."""
    c = EbcdicCodec()
    assert c.to_ascii(b"\x40") == " "


def test_to_ascii_control_byte_uses_fallback():
    """Bytes that codecs maps to control chars get bracketed-hex display.

    0x00-0x3F in EBCDIC are mostly control characters. The legacy table
    rendered them as '[0xNN]' and we preserve that behavior because the
    GUI's log viewer relies on it for telnet-negotiation display.
    """
    c = EbcdicCodec()
    # 0x00 is NUL in both encodings
    assert c.to_ascii(b"\x00") == "[0x00]"
    # 0x11 is DC1 control char (and also 3270 SBA order byte)
    assert c.to_ascii(b"\x11") == "[0x11]"


def test_to_ascii_mixed_text_and_control():
    c = EbcdicCodec()
    # 'A' + NUL + 'B'
    assert c.to_ascii(b"\xc1\x00\xc2") == "A[0x00]B"


def test_to_ebcdic_basic():
    c = EbcdicCodec()
    assert c.to_ebcdic("ABC") == b"\xc1\xc2\xc3"


def test_to_ebcdic_digits():
    c = EbcdicCodec()
    assert c.to_ebcdic("0123") == b"\xf0\xf1\xf2\xf3"


def test_round_trip_printable_ascii():
    """All printable ASCII should round-trip cleanly through cp037."""
    c = EbcdicCodec()
    # Skip backslash and a few chars that differ between EBCDIC variants
    safe = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 .,;:!?"
    assert c.to_ascii(c.to_ebcdic(safe)) == safe


def test_alternate_codepage_cp500():
    """cp500 differs from cp037 at a handful of code points (e.g. brackets)."""
    c037 = EbcdicCodec("cp037")
    c500 = EbcdicCodec("cp500")
    # We just verify both codepages load without error
    assert c037.codepage == "cp037"
    assert c500.codepage == "cp500"
    # Both should agree on 'A'
    assert c037.to_ascii(b"\xc1") == c500.to_ascii(b"\xc1") == "A"


def test_to_ascii_returns_string_not_bytes():
    c = EbcdicCodec()
    result = c.to_ascii(b"\xc1")
    assert isinstance(result, str)


def test_to_ebcdic_returns_bytes():
    c = EbcdicCodec()
    result = c.to_ebcdic("A")
    assert isinstance(result, bytes)


def test_unsupported_codepage_raises():
    with pytest.raises(LookupError):
        EbcdicCodec("not-a-real-codepage")


def test_to_ascii_full_256_no_crash():
    """Every byte value must produce SOMETHING — never raise."""
    c = EbcdicCodec()
    for b in range(256):
        result = c.to_ascii(bytes([b]))
        assert isinstance(result, str)
        assert len(result) > 0


def test_telnet_bytes_bracketed_for_regex_compat():
    """Telnet control bytes (0xFF, 0xFD, etc.) MUST render as [0xNN]
    even though cp037 maps them to printable Latin chars.

    The TELNET_PATTERNS regexes at libhack3270.py:66-92 match the
    bracketed form: [0xFF] -> [IAC], [0xFD] -> [DO], etc.
    """
    c = EbcdicCodec()
    assert c.to_ascii(b"\xff") == "[0xFF]"  # IAC (cp037: Ÿ)
    assert c.to_ascii(b"\xfd") == "[0xFD]"  # DO  (cp037: ý)
    assert c.to_ascii(b"\xfb") == "[0xFB]"  # WILL
    # Full IAC DO TERMINAL-TYPE sequence
    assert c.to_ascii(b"\xff\xfd\x18") == "[0xFF][0xFD][0x18]"


def test_legacy_divergence_documented():
    """Document where the new codec differs from the legacy e2a table.

    Legacy bugs we intentionally fix:
      - 0x5F: legacy='≠' (wrong), cp037='¬' (also non-ASCII) -> now '[0x5F]'
      - 0x74: legacy='[074]' (typo) -> now '[0x74]'

    Behavior change vs legacy that we accept:
      - 0x4A: legacy='¢' (kept as-is) -> now '[0x4A]' (¢ is non-ASCII)
        This is fine — ¢ rarely appears in 3270 streams and the bracket
        form is more diagnostic.
    """
    c = EbcdicCodec()
    assert c.to_ascii(b"\x5f") == "[0x5F]"
    assert c.to_ascii(b"\x74") == "[0x74]"
    assert c.to_ascii(b"\x4a") == "[0x4A]"
