"""
Golden tests for TN3270Legacy.

The contract: feed the same bytes through TN3270Legacy._do_manipulate
that we fed through legacy hack3270.manipulate() in _make_golden.py.
Output must be byte-identical.
"""
import os
import pytest
from types import SimpleNamespace

GOLDEN_DIR = os.path.join(os.path.dirname(__file__), "golden")


def golden(name: str) -> bytes:
    """Load a golden fixture from tests/golden/."""
    with open(os.path.join(GOLDEN_DIR, name), "rb") as f:
        return f.read()


# Mirror the flag combo used in _make_golden.py
def _everything_on_flags():
    return SimpleNamespace(
        hack_on=True, hack_prot=True, hack_hf=True, hack_rnr=True,
        hack_ei=False, hack_sf=True, hack_sfe=True, hack_mf=True,
        hack_hv=True,
        hack_color_on=True, hack_color_sfe=True, hack_color_mf=True,
        hack_color_sa=True, hack_color_hv=True,
    )


# ── Golden byte tests ──────────────────────────────────────────────

@pytest.mark.parametrize("name", [
    "sf_protected.bin",
    "sfe_hidden.bin",
    "sa_color_black.bin",
    "telnet_iac.bin",
])
def test_golden_manipulate(name):
    from tn3270_legacy import TN3270Legacy
    p = TN3270Legacy()
    inp = golden("in_" + name)
    expected = golden(name)
    got = p._do_manipulate(inp, _everything_on_flags())
    assert bytes(got) == bytes(expected), \
        f"{name}: {bytes(got).hex()} != {bytes(expected).hex()}"


def test_telnet_passthrough():
    """L1874: data starting with 0xFF (IAC) returns unchanged."""
    from tn3270_legacy import TN3270Legacy
    p = TN3270Legacy()
    iac = b"\xFF\xFD\x28"
    assert bytes(p._do_manipulate(iac, _everything_on_flags())) == iac


def test_all_flags_off_passthrough():
    """hack_on=False AND hack_color_on=False → identity transform."""
    from tn3270_legacy import TN3270Legacy
    p = TN3270Legacy()
    flags = SimpleNamespace(
        hack_on=False, hack_color_on=False,
        # rest don't matter when both gates are off
        hack_prot=False, hack_hf=False, hack_rnr=False, hack_ei=False,
        hack_sf=False, hack_sfe=False, hack_mf=False, hack_hv=False,
        hack_color_sfe=False, hack_color_mf=False,
        hack_color_sa=False, hack_color_hv=False,
    )
    data = b"\x05\x1D\x6C\xC8\xC5\xD3\xD3\xD6\xFF\xEF"
    assert bytes(p._do_manipulate(data, flags)) == data


# ── Protocol ABC compliance ────────────────────────────────────────

def test_implements_protocol_abc():
    from hackterm_core import Protocol
    from tn3270_legacy import TN3270Legacy
    p = TN3270Legacy()
    assert isinstance(p, Protocol)


def test_class_attrs():
    from tn3270_legacy import TN3270Legacy
    assert TN3270Legacy.name == "tn3270"
    assert TN3270Legacy.default_codepage == "cp037"
    assert TN3270Legacy.aid_table["ENTER"] == 0x7D
    assert TN3270Legacy.aid_table["PF1"] == 0xF1
    assert TN3270Legacy.aid_table["CLEAR"] == 0x6D


# ── detect() — replaces check_inject_3270e (L462-482) ──────────────

def test_detect_tn3270e_via_option_byte():
    """Legacy check_inject_3270e read SQLite row 1 and checked
    row[5][2] == 40 (0x28). New version inspects bytes directly:
    IAC DO TN3270E = ff fd 28."""
    from tn3270_legacy import TN3270Legacy
    p = TN3270Legacy()
    # IAC DO TN3270E
    assert p.detect(b"\xFF\xFD\x28") is True
    # IAC WILL TN3270E
    assert p.detect(b"\xFF\xFB\x28") is True


def test_detect_plain_tn3270():
    from tn3270_legacy import TN3270Legacy
    p = TN3270Legacy()
    # IAC DO TERMINAL-TYPE (0x18, not 0x28)
    assert p.detect(b"\xFF\xFD\x18") is True   # still tn3270, just not E
    # Detect always returns True for tn3270 family — it's the only
    # protocol hack3270 supports. The is_tn3270e *property* is
    # what distinguishes E from plain.
    assert p.is_tn3270e is False


def test_detect_remembers_tn3270e_state():
    """After detect() sees 0x28, is_tn3270e stays True."""
    from tn3270_legacy import TN3270Legacy
    p = TN3270Legacy()
    p.detect(b"\xFF\xFD\x28")
    assert p.is_tn3270e is True


def test_detect_non_telnet_returns_false():
    """detect() returning False keeps ProxyDaemon in negotiate phase."""
    from tn3270_legacy import TN3270Legacy
    p = TN3270Legacy()
    # 3270 datastream (not telnet IAC) — handshake not done yet
    assert p.detect(b"\x05\x1D\x40hello") is False


# ── negotiate_hook() — passthrough no-op ───────────────────────────

def test_negotiate_hook_passthrough():
    from tn3270_legacy import TN3270Legacy
    from hackterm_core import NegotiateOpts
    p = TN3270Legacy()
    data = b"\xFF\xFD\x28"
    assert p.negotiate_hook(data, "s2c", NegotiateOpts()) == data
    assert p.negotiate_hook(data, "c2s", NegotiateOpts()) == data


# ── parse() — Screen.empty() stub ──────────────────────────────────

def test_parse_returns_empty_screen():
    from tn3270_legacy import TN3270Legacy
    from hackterm_core import Screen
    p = TN3270Legacy()
    screen = p.parse(b"\x05\x1D\x40hello\xFF\xEF")
    assert isinstance(screen, Screen)
    assert screen.fields == []
    assert screen.rows == 24
    assert screen.cols == 80


# ── mutate() — MutateOpts → legacy flag mapping ────────────────────

def test_mutate_unprotect_clears_protected_bit():
    """MutateOpts.unprotect → hack_prot=True path.
    SF + 0x60 (bit5 set) → bit5 cleared → 0x40."""
    from tn3270_legacy import TN3270Legacy
    from hackterm_core import MutateOpts
    p = TN3270Legacy()
    # SF order, attr=0x60 (just protected bit + bit6 pad)
    inp = b"\x05\x1D\x60\xFF\xEF"
    out = p.mutate(inp, MutateOpts(unprotect=True))
    assert out[2] == 0x40, f"protected bit not cleared: {out.hex()}"


def test_mutate_no_opts_passthrough():
    from tn3270_legacy import TN3270Legacy
    from hackterm_core import MutateOpts
    p = TN3270Legacy()
    inp = b"\x05\x1D\x60\xFF\xEF"
    out = p.mutate(inp, MutateOpts())
    assert bytes(out) == inp


# ── spoof_aid() — port from L1615-1649 ─────────────────────────────

def test_spoof_aid_plain_tn3270():
    """Plain TN3270: AID is byte 0."""
    from tn3270_legacy import TN3270Legacy
    p = TN3270Legacy()
    p._is_tn3270e = False
    # ENTER (7D) + cursor + IAC EOR
    pkt = b"\x7D\x40\x40\xFF\xEF"
    out = p.spoof_aid(pkt, 0xF1)  # spoof to PF1
    assert out[0] == 0xF1
    assert out[1:] == pkt[1:]


def test_spoof_aid_tn3270e():
    """TN3270E: 5-byte header, AID is byte 5."""
    from tn3270_legacy import TN3270Legacy
    p = TN3270Legacy()
    p._is_tn3270e = True
    # 5-byte header + ENTER + cursor + IAC EOR
    pkt = b"\x00\x00\x00\x00\x01" + b"\x7D\x40\x40\xFF\xEF"
    out = p.spoof_aid(pkt, 0xF1)
    assert out[:5] == pkt[:5]
    assert out[5] == 0xF1
    assert out[6:] == pkt[6:]


def test_spoof_aid_short_packet_unchanged():
    from tn3270_legacy import TN3270Legacy
    p = TN3270Legacy()
    p._is_tn3270e = True
    pkt = b"\x00\x00\x00"  # too short for 5-byte header + AID
    assert p.spoof_aid(pkt, 0xF1) == pkt


# ── build_inbound() — port from send_key (L1531-1540) ──────────────

def test_build_inbound_plain():
    from tn3270_legacy import TN3270Legacy
    p = TN3270Legacy()
    p._is_tn3270e = False
    # ENTER, cursor (0,0), no fields
    out = p.build_inbound(0x7D, (0, 0), [])
    # AID + cursor(2) + IAC EOR
    assert out == b"\x7D\x00\x00\xFF\xEF"


def test_build_inbound_tn3270e():
    from tn3270_legacy import TN3270Legacy
    p = TN3270Legacy()
    p._is_tn3270e = True
    out = p.build_inbound(0x7D, (0, 0), [])
    # 5-byte header + AID + cursor(2) + IAC EOR
    assert out == b"\x00\x00\x00\x00\x01\x7D\x00\x00\xFF\xEF"
