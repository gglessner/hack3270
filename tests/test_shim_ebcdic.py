"""
256-byte diff: legacy e2a table vs EbcdicCodec("cp037").

Per spec §5.1.2 (medium risk): the legacy table at libhack3270.py:44-60
has known divergences from cp037. We document them here as ACCEPTED
DIVERGENCES — they're cosmetic (display only) and don't affect packet
bytes on the wire.

The shim's get_ascii MUST still produce '[0xFF]' for IAC etc. so
TELNET_PATTERNS (L66-92) keep matching.
"""
import pytest


# Bytes where legacy e2a and EbcdicCodec("cp037") disagree, with rationale.
# After Task 2 the shim uses the codec, so display strings change for
# these bytes. Each is non-load-bearing (no TELNET_PATTERNS regex matches them).
#
# Format: byte: (legacy_e2a_value, codec_to_ascii_value)
ACCEPTED_DIVERGENCES = {
    # --- Legacy had non-ASCII glyphs; codec brackets them (correct: keeps
    #     get_ascii output pure-ASCII so logs/regexes are deterministic) ---
    0x4A: ('¢',     '[0x4A]'),  # cp037: U+00A2 CENT SIGN. Non-ASCII -> bracketed.
    0x5F: ('≠',     '[0x5F]'),  # cp037: U+00AC NOT SIGN. Legacy '≠' was wrong glyph anyway.
    0x6A: ('|',     '[0x6A]'),  # cp037: U+00A6 BROKEN BAR. Legacy duplicated '|' (also at 0x4F).

    # --- Legacy typo (missing 'x' in bracket format) ---
    0x74: ('[074]', '[0x74]'),  # Pure bug fix. No regex matched '[074]'.

    # --- Legacy bracketed valid ASCII printables; codec emits them (improvement:
    #     more readable display strings, e.g. mainframe '[' chars now visible) ---
    0xB0: ('[0xB0]', '^'),      # cp037 0xB0 = ASCII '^'. Legacy table missed it.
    0xBA: ('[0xBA]', '['),      # cp037 0xBA = ASCII '['. Legacy table missed it.
    0xBB: ('[0xBB]', ']'),      # cp037 0xBB = ASCII ']'. Legacy table missed it.
}


def test_documented_divergence_bytes_pinned():
    """Phase 1 Task 6 deleted the e2a table. This test now pins the
    codec's output on the 7 bytes that diverged from legacy, so any
    future codec change would be caught here. The legacy half of the
    comparison is gone (the table is deleted)."""
    from hackterm_core import EbcdicCodec

    codec = EbcdicCodec("cp037")

    for b, (_legacy, exp_new) in ACCEPTED_DIVERGENCES.items():
        actual = codec.to_ascii(bytes([b]))
        assert actual == exp_new, \
            f"0x{b:02X}: ACCEPTED_DIVERGENCES claims codec={exp_new!r} but got {actual!r}"


def test_telnet_pattern_bytes_still_bracketed(legacy_hack3270):
    """The TELNET_PATTERNS regexes (L66-92) match strings like
    '[0xFF]', '[0x28]', '[0xFD]'. After shimming get_ascii through
    EbcdicCodec, these bytes MUST still produce bracketed output."""
    h = legacy_hack3270
    # All bytes referenced in TELNET_PATTERNS
    critical = [0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0x28, 0x29,
                0x18, 0x19, 0x00, 0x01]
    for b in critical:
        out = h.get_ascii(bytes([b]))
        assert out == f"[0x{b:02X}]", \
            f"byte 0x{b:02X} -> {out!r}, TELNET_PATTERNS regex won't match"


def test_get_ascii_printable_unchanged(legacy_hack3270):
    """EBCDIC 'HELLO' (C8 C5 D3 D3 D6) -> 'HELLO' — both old and new."""
    h = legacy_hack3270
    assert h.get_ascii(b"\xC8\xC5\xD3\xD3\xD6") == "HELLO"


def test_get_ebcdic_round_trip(legacy_hack3270):
    """ASCII -> EBCDIC -> ASCII for printables."""
    h = legacy_hack3270
    for s in ["HELLO", "USER01", "PASS WORD", "1234567890"]:
        assert h.get_ascii(h.get_ebcdic(s)) == s


def test_get_ebcdic_uses_codec_not_a2e(legacy_hack3270):
    """Legacy a2e (L63) silently DROPS chars not in e2a (L1786-1792:
    `if char in a2e`). EbcdicCodec.to_ebcdic raises UnicodeEncodeError
    instead. The shim must adopt codec behavior — silently dropping
    bytes produces malformed packets, that's a bug fix."""
    h = legacy_hack3270
    # ASCII printables that ARE in cp037 must encode
    assert h.get_ebcdic("A") == b"\xC1"
    assert h.get_ebcdic("*") == b"\x5C"  # mask char — used by inject


def test_shim_get_ascii_delegates_to_codec(legacy_hack3270):
    """Verify the shim actually has an EbcdicCodec instance."""
    h = legacy_hack3270
    from hackterm_core import EbcdicCodec
    assert hasattr(h, "_codec")
    assert isinstance(h._codec, EbcdicCodec)
    assert h._codec.codepage == "cp037"
