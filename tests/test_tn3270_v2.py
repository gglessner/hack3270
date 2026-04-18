"""
Tests for the clean tn3270 parser.

Golden-file driven: each test loads a synthetic .bin packet from
tests/golden/ and asserts the parsed Screen matches expectations.
"""
import pytest
from hackterm_core.protocol import Screen, Field, MutateOpts, FieldWrite, QueryLies


# ===========================================================================
# Sub-task 1a: address codec
# ===========================================================================

def test_addr_table_is_64_bytes():
    from hack3270_libs.tn3270_v2 import ADDR_TABLE
    assert len(ADDR_TABLE) == 64


def test_addr_table_position_0_is_0x40():
    """ADDR_TABLE[0] = 0x40 → encoding addr 0 gives bytes 40 40."""
    from hack3270_libs.tn3270_v2 import ADDR_TABLE
    assert ADDR_TABLE[0] == 0x40


def test_decode_addr_12bit_zero():
    """0x40 0x40 decodes to buffer position 0 (row 1, col 1)."""
    from hack3270_libs.tn3270_v2 import decode_addr
    assert decode_addr(0x40, 0x40) == 0


def test_decode_addr_12bit_position_80():
    """Position 80 (row 2, col 1 on 80-col screen).
    80 = (1 << 6) | 16 → ADDR_TABLE[1]=0xC1, ADDR_TABLE[16]=0x50."""
    from hack3270_libs.tn3270_v2 import decode_addr
    assert decode_addr(0xC1, 0x50) == 80


def test_decode_addr_14bit():
    """14-bit addressing: top 2 bits of b1 are 00.
    addr = ((b1 & 0x3F) << 8) | b2."""
    from hack3270_libs.tn3270_v2 import decode_addr
    # 0x01 0x50 → high bits 00, addr = (0x01 << 8) | 0x50 = 336
    assert decode_addr(0x01, 0x50) == 336


def test_encode_addr_12bit_roundtrip():
    from hack3270_libs.tn3270_v2 import encode_addr, decode_addr
    for pos in [0, 1, 79, 80, 1919]:  # 1919 = 24*80 - 1
        b1, b2 = encode_addr(pos)
        assert decode_addr(b1, b2) == pos


def test_encode_addr_returns_bytes():
    from hack3270_libs.tn3270_v2 import encode_addr
    result = encode_addr(0)
    assert isinstance(result, bytes)
    assert len(result) == 2


def test_addr_to_rowcol():
    """Convert linear buffer address to (row, col), 1-indexed."""
    from hack3270_libs.tn3270_v2 import addr_to_rowcol
    assert addr_to_rowcol(0, cols=80) == (1, 1)
    assert addr_to_rowcol(79, cols=80) == (1, 80)
    assert addr_to_rowcol(80, cols=80) == (2, 1)
    assert addr_to_rowcol(1919, cols=80) == (24, 80)


def test_rowcol_to_addr():
    from hack3270_libs.tn3270_v2 import rowcol_to_addr
    assert rowcol_to_addr(1, 1, cols=80) == 0
    assert rowcol_to_addr(2, 1, cols=80) == 80
    assert rowcol_to_addr(24, 80, cols=80) == 1919


# ===========================================================================
# Sub-task 1b: parse() — golden-file driven
# ===========================================================================

@pytest.fixture
def tn3270():
    from hack3270_libs.tn3270_v2 import TN3270
    return TN3270()


def test_tn3270_implements_protocol(tn3270):
    from hackterm_core.protocol import Protocol
    assert isinstance(tn3270, Protocol)


def test_tn3270_class_attrs(tn3270):
    assert tn3270.name == "tn3270"
    assert tn3270.default_codepage == "cp037"
    assert "ENTER" in tn3270.aid_table
    assert tn3270.aid_table["ENTER"] == 0x7D


def test_parse_simple_sf(tn3270, gold):
    """One protected field containing 'ABC'."""
    screen = tn3270.parse(gold("simple_sf.bin"))
    assert isinstance(screen, Screen)
    assert screen.rows == 24
    assert screen.cols == 80
    assert len(screen.fields) == 1

    f = screen.fields[0]
    assert f.protected is True
    assert f.hidden is False
    assert f.numeric is False
    assert f.content == b"\xc1\xc2\xc3"   # raw EBCDIC "ABC"


def test_parse_simple_sf_rendered(tn3270, gold):
    """Rendered grid should show 'ABC' at the field's position.
    The SF order itself takes 1 buffer cell (the attribute byte lives
    in the buffer), so 'ABC' starts at position 1 (row 1, col 2)."""
    screen = tn3270.parse(gold("simple_sf.bin"))
    # rendered is rows×cols of single-char strings
    assert screen.rendered[0][1] == "A"
    assert screen.rendered[0][2] == "B"
    assert screen.rendered[0][3] == "C"


def test_parse_simple_sf_text_property(tn3270, gold):
    """Screen.text flattens the grid for regex matching."""
    screen = tn3270.parse(gold("simple_sf.bin"))
    assert "ABC" in screen.text


def test_parse_preserves_raw(tn3270, gold):
    """Screen.raw must be the original bytes — needed for replay."""
    raw = gold("simple_sf.bin")
    screen = tn3270.parse(raw)
    assert screen.raw == raw


def test_parse_sba_positioning(tn3270, gold):
    """SBA 40 40 → field at buffer addr 0, content starts at addr 1."""
    screen = tn3270.parse(gold("sba_positioned.bin"))
    assert len(screen.fields) == 1
    f = screen.fields[0]
    # SF was placed at addr 0, so field data starts at addr 1 → row 1, col 2
    assert f.row == 1
    assert f.col == 2


def test_parse_hidden_field(tn3270, gold):
    """Attr 0x6C: bits 3+2 both set = non-display."""
    screen = tn3270.parse(gold("hidden_field.bin"))
    assert len(screen.fields) == 1
    f = screen.fields[0]
    assert f.hidden is True
    assert f.protected is True
    # Content is still parsed (we need it for analysis), just hidden on render
    assert f.content == b"\xe2\xc5\xc3\xd9\xc5\xe3"  # "SECRET"


def test_parse_hidden_field_not_rendered(tn3270, gold):
    """Hidden field content does NOT appear in rendered grid."""
    screen = tn3270.parse(gold("hidden_field.bin"))
    assert "SECRET" not in screen.text


def test_parse_tn3270e_header_stripped(tn3270, gold):
    """5-byte TN3270E header is recognized and skipped before parsing.
    Header: 00 00 00 00 01 (data-type=3270-DATA, seq=1)."""
    screen = tn3270.parse(gold("tn3270e_wrapped.bin"))
    # Should produce same result as simple_sf.bin
    assert len(screen.fields) == 1
    assert screen.fields[0].content == b"\xc1\xc2\xc3"


def test_parse_tn3270e_header_recorded(tn3270, gold):
    """The parser remembers it saw a TN3270E header so build_inbound
    knows to prepend one on the reply."""
    tn3270.parse(gold("tn3270e_wrapped.bin"))
    assert tn3270.is_tn3270e is True


def test_parse_basic_tn3270_no_e_header(tn3270, gold):
    """A non-TN3270E packet should NOT set the flag."""
    tn3270.parse(gold("simple_sf.bin"))
    assert tn3270.is_tn3270e is False


def test_parse_sfe_extended(tn3270, gold):
    """SFE with 2 attribute pairs. Type 0xC0 carries the basic attr."""
    screen = tn3270.parse(gold("sfe_extended.bin"))
    assert len(screen.fields) == 1
    f = screen.fields[0]
    assert f.protected is True   # 0xC0 → 0x60 has bit 5 set
    assert f.content == b"\xc8\xc9"  # "HI"


def test_parse_iac_unescape(tn3270, gold):
    """0xFF 0xFF on the wire → single 0xFF in field content.
    This is the bug that breaks legacy parsers: they see 0xFF and
    either crash or treat it as IAC."""
    screen = tn3270.parse(gold("iac_escaped.bin"))
    assert len(screen.fields) == 1
    f = screen.fields[0]
    # Wire bytes were C1 FF FF C2 → content should be C1 FF C2
    assert f.content == b"\xc1\xff\xc2"
    assert len(f.content) == 3


def test_parse_multi_field(tn3270, gold):
    """Three fields. Verify lengths close correctly when next SF appears."""
    screen = tn3270.parse(gold("multi_field.bin"))
    assert len(screen.fields) == 3

    # Field 1: protected, "USER:"
    assert screen.fields[0].protected is True
    assert screen.fields[0].content == b"\xe4\xe2\xc5\xd9\x7a"
    assert screen.fields[0].length == 5

    # Field 2: unprotected, 8 spaces — this is the input field
    assert screen.fields[1].protected is False
    assert screen.fields[1].length == 8

    # Field 3: protected, "PASS:"
    assert screen.fields[2].protected is True
    assert screen.fields[2].content == b"\xd7\xc1\xe2\xe2\x7a"


def test_parse_multi_field_rendered_text(tn3270, gold):
    screen = tn3270.parse(gold("multi_field.bin"))
    assert "USER:" in screen.text
    assert "PASS:" in screen.text


def test_parse_ra_repeat(tn3270, gold):
    """RA fills buffer from current pos to target addr with one char.
    RA to addr 10 with '-' (0x60) starting from addr 0 → 10 dashes."""
    screen = tn3270.parse(gold("ra_repeat.bin"))
    # No fields (no SF), but rendered grid should show the dashes
    assert screen.rendered[0][0] == "-"
    assert screen.rendered[0][9] == "-"


def test_parse_no_false_positive_on_0x1d_in_text():
    """The big one. 0x1D in EBCDIC cp037 is a control char, but if it
    appears as a literal data byte (e.g. via GE or in a packet that
    doesn't start with a write command), the parser must NOT treat it
    as Start Field.

    Construct: write command + WCC + SF + GE 0x1D + more text.
    GE (0x08) means "next byte is a graphic, not an order"."""
    from hack3270_libs.tn3270_v2 import TN3270
    p = TN3270()
    pkt = bytes([
        0xF5, 0xC3,           # EW + WCC
        0x1D, 0x40,           # SF unprotected
        0xC1,                 # 'A'
        0x08, 0x1D,           # GE → next byte (0x1D) is GRAPHIC, not SF order
        0xC2,                 # 'B'
        0xFF, 0xEF,
    ])
    screen = p.parse(pkt)
    # Must be exactly ONE field — the GE'd 0x1D is data, not a second SF
    assert len(screen.fields) == 1
    # Content includes the 0x1D as a data byte
    assert b"\xc1\x1d\xc2" == screen.fields[0].content


def test_parse_empty_packet():
    from hack3270_libs.tn3270_v2 import TN3270
    p = TN3270()
    screen = p.parse(b"")
    assert screen.fields == []
    assert screen.rows == 24


def test_parse_just_iac_eor():
    from hack3270_libs.tn3270_v2 import TN3270
    p = TN3270()
    screen = p.parse(b"\xff\xef")
    assert screen.fields == []


def test_parse_unknown_write_command_returns_empty():
    """Garbage byte where write command should be → empty screen, no crash."""
    from hack3270_libs.tn3270_v2 import TN3270
    p = TN3270()
    screen = p.parse(b"\x99\x99\x99\xff\xef")
    assert isinstance(screen, Screen)


def test_negotiate_hook_splice_lu_name(tn3270):
    """spoof_device_name rewrites the CONNECT <luname> portion of a
    DEVICE-TYPE REQUEST suboption. LU names are ASCII at telnet layer."""
    from hackterm_core.protocol import NegotiateOpts
    # IAC SB TN3270E DEVICE-TYPE REQUEST IBM-3278-2 CONNECT TCP00001 IAC SE
    pkt = (b"\xff\xfa\x28\x02\x07" + b"IBM-3278-2"
           + b"\x01" + b"TCP00001" + b"\xff\xf0")
    out = tn3270.negotiate_hook(pkt, "c2s",
                                NegotiateOpts(spoof_device_name="CICSA01"))
    assert b"CICSA01" in out
    assert b"TCP00001" not in out
    assert b"IBM-3278-2" in out  # device type preserved
    assert out.startswith(b"\xff\xfa\x28\x02\x07")
    assert out.endswith(b"\xff\xf0")


def test_negotiate_hook_splice_lu_name_no_connect(tn3270):
    """No CONNECT clause present → append one."""
    from hackterm_core.protocol import NegotiateOpts
    pkt = b"\xff\xfa\x28\x02\x07" + b"IBM-3278-2" + b"\xff\xf0"
    out = tn3270.negotiate_hook(pkt, "c2s",
                                NegotiateOpts(spoof_device_name="CICSA01"))
    assert b"\x01CICSA01" in out
    assert out.endswith(b"\xff\xf0")


def test_negotiate_hook_no_spoof_passthrough(tn3270):
    """No spoof_device_name → bytes unchanged."""
    from hackterm_core.protocol import NegotiateOpts
    pkt = b"\xff\xfa\x28\x02\x07IBM-3278-2\x01TCP00001\xff\xf0"
    out = tn3270.negotiate_hook(pkt, "c2s", NegotiateOpts())
    assert out == pkt


def test_detect_recognizes_datastream(tn3270, gold):
    """detect() returns True for non-IAC traffic."""
    assert tn3270.detect(gold("simple_sf.bin")) is True


def test_detect_ignores_telnet_negotiation(tn3270):
    """detect() returns False for IAC traffic."""
    assert tn3270.detect(b"\xff\xfd\x28") is False  # IAC DO TN3270E


# ===========================================================================
# Sub-task 1c: mutate() — same flips as legacy manipulate(), context-aware
# ===========================================================================

def test_mutate_unprotect_clears_bit5(tn3270, gold):
    """unprotect=True clears bit 5 (0x20) of every SF attr byte."""
    opts = MutateOpts(unprotect=True)
    out = tn3270.mutate(gold("simple_sf.bin"), opts)
    # Original attr at offset 3 is 0x60 (0110 0000).
    # After clearing bit 5: 0x40 (0100 0000).
    assert out[3] == 0x40


def test_mutate_no_opts_is_noop(tn3270, gold):
    """All flags False → bytes unchanged."""
    opts = MutateOpts()
    raw = gold("simple_sf.bin")
    assert tn3270.mutate(raw, opts) == raw


def test_mutate_reveal_hidden_clears_display_bits(tn3270, gold):
    """reveal_hidden=True clears bits 3+2 (0x0C) when both set."""
    opts = MutateOpts(reveal_hidden=True)
    out = tn3270.mutate(gold("hidden_field.bin"), opts)
    # Original attr at offset 3 is 0x6C (0110 1100).
    # After clearing 0x0C: 0x60 (0110 0000).
    assert out[3] == 0x60


def test_mutate_reveal_hidden_reparse(tn3270, gold):
    """Round-trip: mutate → re-parse → field is no longer hidden."""
    opts = MutateOpts(reveal_hidden=True)
    out = tn3270.mutate(gold("hidden_field.bin"), opts)
    screen = tn3270.parse(out)
    assert len(screen.fields) == 1
    assert screen.fields[0].hidden is False
    assert "SECRET" in screen.text  # now rendered


def test_mutate_remove_numeric_clears_bit4(tn3270):
    """Attr with bit 4 (numeric) set → cleared."""
    opts = MutateOpts(remove_numeric=True)
    pkt = bytes([0xF5, 0xC3, 0x1D, 0x50, 0xC1, 0xFF, 0xEF])  # 0x50 = bit6+bit4
    out = tn3270.mutate(pkt, opts)
    assert out[3] == 0x40  # bit 4 cleared


def test_mutate_preserves_iac_eor(tn3270, gold):
    """Mutation must not strip the trailing IAC EOR."""
    opts = MutateOpts(unprotect=True)
    out = tn3270.mutate(gold("simple_sf.bin"), opts)
    assert out.endswith(b"\xff\xef")


def test_mutate_preserves_tn3270e_header(tn3270, gold):
    """If a TN3270E header is present, mutation must keep it."""
    opts = MutateOpts(unprotect=True)
    out = tn3270.mutate(gold("tn3270e_wrapped.bin"), opts)
    assert out[:5] == bytes([0x00, 0x00, 0x00, 0x00, 0x01])
    # And the attr (now at offset 5+3=8) is flipped
    assert out[8] == 0x40


def test_mutate_does_not_flip_data_bytes(tn3270):
    """A 0x60 in field CONTENT must not be flipped — only SF attr bytes.
    This is the bug legacy manipulate() has."""
    opts = MutateOpts(unprotect=True)
    # SF attr=0x60, then content byte that ALSO happens to be 0x60 (EBCDIC '-')
    pkt = bytes([0xF5, 0xC3, 0x1D, 0x60, 0x60, 0x60, 0xFF, 0xEF])
    out = tn3270.mutate(pkt, opts)
    assert out[3] == 0x40   # SF attr flipped
    assert out[4] == 0x60   # data byte UNTOUCHED
    assert out[5] == 0x60   # data byte UNTOUCHED


def test_mutate_does_not_flip_0x29_in_sba_operand(tn3270):
    """0x29 is the SFE order code. Legacy manipulate() naively scans for
    0x29 anywhere — including inside SBA address operands. This parser
    only treats 0x29 as SFE when in order position, not as an operand.

    14-bit SBA: 0x11 0x01 0x29 → address (0x01<<8)|0x29 = 297.
    The 0x29 here is the LOW byte of the address, NOT an SFE order.
    Legacy would see it, treat the next byte (0x1D) as the SFE count,
    and corrupt the stream."""
    opts = MutateOpts(unprotect=True)
    pkt = bytes([
        0xF5, 0xC3,           # EW + WCC
        0x11, 0x01, 0x29,     # SBA → addr 297 (14-bit, 0x29 is LOW BYTE)
        0x1D, 0x60,           # SF protected — THIS is the only attr to flip
        0xC1,                 # 'A'
        0xFF, 0xEF,
    ])
    out = tn3270.mutate(pkt, opts)
    assert out[4] == 0x29   # SBA low byte UNTOUCHED — not treated as SFE
    assert out[5] == 0x1D   # SF order byte preserved
    assert out[6] == 0x40   # SF attr flipped (0x60 → 0x40)


def test_mutate_does_not_flip_0x1d_after_ge(tn3270):
    """GE 0x1D is data, not an SF order. Mutate must skip the GE'd byte
    and NOT treat the byte after it as an attr to flip."""
    opts = MutateOpts(unprotect=True)
    pkt = bytes([
        0xF5, 0xC3,
        0x1D, 0x60,           # real SF — flip this
        0x08, 0x1D,           # GE → 0x1D is graphic data, NOT an order
        0x60,                 # 'A' equiv — must NOT be flipped
        0xFF, 0xEF,
    ])
    out = tn3270.mutate(pkt, opts)
    assert out[3] == 0x40   # real attr flipped
    assert out[5] == 0x1D   # GE'd byte preserved
    assert out[6] == 0x60   # data byte after GE'd 0x1D — NOT flipped


def test_mutate_handles_sfe_basic_attr(tn3270, gold):
    """SFE attr pair with type 0xC0 gets the same bit-flip treatment."""
    opts = MutateOpts(unprotect=True)
    out = tn3270.mutate(gold("sfe_extended.bin"), opts)
    # In sfe_extended.bin: F5 C3 29 02 C0 60 42 F4 ...
    # Offset 5 is the value of the C0 pair (0x60). After unprotect: 0x40.
    assert out[5] == 0x40
    # The color pair (42 F4) at offsets 6-7 untouched
    assert out[6] == 0x42
    assert out[7] == 0xF4


def test_mutate_preserves_length(tn3270, gold):
    """In-place mutation — output length identical to input."""
    opts = MutateOpts(unprotect=True, reveal_hidden=True, remove_numeric=True)
    raw = gold("multi_field.bin")
    out = tn3270.mutate(raw, opts)
    assert len(out) == len(raw)


# ===========================================================================
# Sub-task 1d: build_inbound() + spoof_aid()
# ===========================================================================

def test_build_inbound_basic(tn3270):
    """AID + cursor(2) + IAC EOR. No fields = shortest valid inbound."""
    pkt = tn3270.build_inbound(aid=0x7D, cursor=(1, 1), fields=[])
    # Cursor (1,1) → addr 0 → encode → 0x40 0x40
    assert pkt == b"\x7d\x40\x40\xff\xef"


def test_build_inbound_with_field(tn3270):
    """One field: SBA + addr(2) + EBCDIC data."""
    pkt = tn3270.build_inbound(
        aid=0x7D, cursor=(1, 1),
        fields=[FieldWrite(row=1, col=2, data=b"\xc1\xc2\xc3")],
    )
    # row=1,col=2 → addr 1 → encode → ADDR_TABLE[0]=0x40, ADDR_TABLE[1]=0xC1
    # Layout: AID cursor(2) SBA addr(2) data IAC EOR
    assert pkt == b"\x7d\x40\x40\x11\x40\xc1\xc1\xc2\xc3\xff\xef"


def test_build_inbound_multiple_fields(tn3270):
    """Two fields → two SBA blocks."""
    pkt = tn3270.build_inbound(
        aid=0x7D, cursor=(1, 1),
        fields=[
            FieldWrite(row=1, col=1, data=b"\xc1"),
            FieldWrite(row=2, col=1, data=b"\xc2"),
        ],
    )
    # row=2,col=1 → addr 80 → encode → ADDR_TABLE[1]=0xC1, ADDR_TABLE[16]=0x50
    assert pkt == (b"\x7d\x40\x40"
                   b"\x11\x40\x40\xc1"
                   b"\x11\xc1\x50\xc2"
                   b"\xff\xef")


def test_build_inbound_tn3270e_prepends_header(tn3270, gold):
    """If is_tn3270e is True (set by a prior parse()), prepend the
    5-byte TN3270E inbound header: 00 00 00 <seq-hi> <seq-lo>."""
    tn3270.parse(gold("tn3270e_wrapped.bin"))   # sets is_tn3270e=True, last_seq=1
    pkt = tn3270.build_inbound(aid=0x7D, cursor=(1, 1), fields=[])
    assert pkt[:5] == bytes([0x00, 0x00, 0x00, 0x00, 0x01])
    assert pkt[5:] == b"\x7d\x40\x40\xff\xef"


def test_build_inbound_escapes_iac_in_data(tn3270):
    """If field data contains 0xFF, it must be doubled for the wire."""
    pkt = tn3270.build_inbound(
        aid=0x7D, cursor=(1, 1),
        fields=[FieldWrite(row=1, col=1, data=b"\xc1\xff\xc2")],
    )
    # The 0xFF in data should appear as 0xFF 0xFF on the wire
    assert b"\xc1\xff\xff\xc2" in pkt
    # And the trailing IAC EOR is NOT escaped (it's the framing, not data)
    assert pkt.endswith(b"\xff\xef")
    assert not pkt.endswith(b"\xff\xff\xef")


def test_spoof_aid_basic_tn3270(tn3270):
    """Replace AID byte at offset 0 (no TN3270E header)."""
    original = b"\x7d\x40\x40\xff\xef"   # ENTER
    out = tn3270.spoof_aid(original, 0xF3)   # → PF3
    assert out == b"\xf3\x40\x40\xff\xef"


def test_spoof_aid_tn3270e(tn3270, gold):
    """With TN3270E header, AID is at offset 5."""
    tn3270.parse(gold("tn3270e_wrapped.bin"))   # set is_tn3270e
    original = bytes([0x00, 0x00, 0x00, 0x00, 0x01, 0x7D, 0x40, 0x40, 0xFF, 0xEF])
    out = tn3270.spoof_aid(original, 0xF3)
    assert out[5] == 0xF3
    assert out[:5] == original[:5]   # header preserved
    assert out[6:] == original[6:]   # rest preserved


def test_spoof_aid_short_packet_no_crash(tn3270):
    """Empty/short packet → return unchanged, don't IndexError."""
    assert tn3270.spoof_aid(b"", 0xF3) == b""
