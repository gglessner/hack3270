import pytest
from hackterm_core.inject import MaskInjector
from hackterm_core.ebcdic import EbcdicCodec


@pytest.fixture
def codec():
    return EbcdicCodec("cp037")


@pytest.fixture
def injector(codec):
    return MaskInjector(codec, mask_char="*")


def test_capture_finds_mask_run(injector, codec):
    """Packet with **** in the middle splits correctly.

    Packet structure (simplified): [header bytes] **** [trailer bytes]
    EBCDIC '*' is 0x5C.
    """
    pre = b"\x7d\x40\x40\x11\x40\x40"  # AID + cursor + SBA + addr (3270-ish)
    mask = b"\x5c\x5c\x5c\x5c"          # **** in EBCDIC
    post = b"\xff\xef"                   # IAC EOR
    packet = pre + mask + post

    found = injector.capture(packet)
    assert found is True
    assert injector.mask_len == 4
    assert injector.preamble == pre
    assert injector.postamble == post


def test_capture_no_mask_returns_false(injector):
    packet = b"\x7d\x40\x40\xc1\xc2\xc3\xff\xef"  # ABC, no asterisks
    assert injector.capture(packet) is False
    assert injector.mask_len == 0


def test_capture_mask_at_start(injector):
    """Mask at byte 0 — preamble is empty."""
    packet = b"\x5c\x5c\x5c\xff\xef"
    injector.capture(packet)
    assert injector.preamble == b""
    assert injector.mask_len == 3
    assert injector.postamble == b"\xff\xef"


def test_capture_mask_at_end(injector):
    """Mask runs to end of packet — postamble is empty."""
    packet = b"\x7d\x40\x5c\x5c\x5c\x5c"
    injector.capture(packet)
    assert injector.preamble == b"\x7d\x40"
    assert injector.mask_len == 4
    assert injector.postamble == b""


def test_capture_only_first_run(injector):
    """If two mask runs exist, capture the first one (legacy behavior)."""
    packet = b"\xc1\x5c\x5c\xc2\x5c\x5c\x5c\xc3"
    injector.capture(packet)
    assert injector.preamble == b"\xc1"
    assert injector.mask_len == 2
    assert injector.postamble == b"\xc2\x5c\x5c\x5c\xc3"


def test_build_trunc_pads_short_payload(injector, codec):
    """TRUNC mode pads with EBCDIC space (0x40) to mask_len."""
    pre = b"\x7d"
    post = b"\xff\xef"
    injector.capture(pre + b"\x5c" * 6 + post)  # mask_len=6

    result = injector.build("AB", mode="TRUNC")
    payload = codec.to_ebcdic("AB") + b"\x40" * 4  # AB + 4 spaces
    assert result == pre + payload + post


def test_build_trunc_truncates_long_payload(injector):
    pre = b"\x7d"
    post = b"\xff\xef"
    injector.capture(pre + b"\x5c" * 3 + post)  # mask_len=3

    result = injector.build("ABCDEF", mode="TRUNC")
    # Only first 3 chars: ABC = 0xC1 0xC2 0xC3
    assert result == pre + b"\xc1\xc2\xc3" + post


def test_build_skip_returns_none_for_oversized(injector):
    pre = b"\x7d"
    post = b"\xff\xef"
    injector.capture(pre + b"\x5c" * 3 + post)

    assert injector.build("ABCDEF", mode="SKIP") is None


def test_build_skip_returns_packet_for_fitting_payload(injector):
    pre = b"\x7d"
    post = b"\xff\xef"
    injector.capture(pre + b"\x5c" * 6 + post)

    result = injector.build("ABC", mode="SKIP")
    assert result is not None
    # SKIP still pads to mask_len
    assert len(result) == len(pre) + 6 + len(post)


def test_build_overflow_sends_full_payload(injector):
    """OVERFLOW ignores mask_len — tests pre-truncation validation
    (added in hack3270 v2.0.2)."""
    pre = b"\x7d"
    post = b"\xff\xef"
    injector.capture(pre + b"\x5c" * 3 + post)

    result = injector.build("ABCDEF", mode="OVERFLOW")
    # Full payload, packet is now LONGER than original
    assert result == pre + b"\xc1\xc2\xc3\xc4\xc5\xc6" + post


def test_build_without_capture_raises(injector):
    with pytest.raises(RuntimeError):
        injector.build("ABC", mode="TRUNC")


def test_build_invalid_mode_raises(injector):
    pre = b"\x7d"
    injector.capture(pre + b"\x5c\x5c\x5c" + b"\xff\xef")
    with pytest.raises(ValueError):
        injector.build("ABC", mode="BOGUS")


def test_alternate_mask_char():
    """5250 might use a different mask char than '*'."""
    codec = EbcdicCodec()
    inj = MaskInjector(codec, mask_char="#")
    # EBCDIC '#' is 0x7B
    packet = b"\xc1\x7b\x7b\x7b\xc2"
    inj.capture(packet)
    assert inj.mask_len == 3


def test_is_ready(injector):
    assert injector.is_ready() is False
    injector.capture(b"\x5c\x5c\x5c")
    assert injector.is_ready() is True
