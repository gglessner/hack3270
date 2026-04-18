"""
LU-name spoofing tests.

The splice itself lives in tn3270_v2._splice_lu_name (tested here too).
The LUSpoofer class is the campaign driver: wordlist, harvest, results.
"""
import pytest


# ---------------------------------------------------------------------------
# Splice mechanics (the byte surgery — already implemented in tn3270_v2)
# ---------------------------------------------------------------------------

# Real DEVICE-TYPE REQUEST as x3270 sends it:
# IAC SB TN3270E DEVICE-TYPE REQUEST IBM-3278-2-E CONNECT TCP00042 IAC SE
DEVTYPE_REQ = (
    b"\xff\xfa\x28\x02\x07"          # IAC SB TN3270E DEVICE-TYPE REQUEST
    + b"IBM-3278-2-E"                # device type (ASCII)
    + b"\x01"                        # CONNECT
    + b"TCP00042"                    # LU name (ASCII)
    + b"\xff\xf0"                    # IAC SE
)

# Without a CONNECT clause (some emulators don't request a specific LU)
DEVTYPE_REQ_NO_CONNECT = (
    b"\xff\xfa\x28\x02\x07"
    + b"IBM-3278-2-E"
    + b"\xff\xf0"
)


def test_splice_replaces_lu_name():
    from hack3270_libs.tn3270_v2 import _splice_lu_name
    out = _splice_lu_name(DEVTYPE_REQ, "CICSA01")
    assert b"CICSA01" in out
    assert b"TCP00042" not in out


def test_splice_preserves_device_type():
    from hack3270_libs.tn3270_v2 import _splice_lu_name
    out = _splice_lu_name(DEVTYPE_REQ, "CICSA01")
    assert b"IBM-3278-2-E" in out


def test_splice_preserves_iac_se_terminator():
    from hack3270_libs.tn3270_v2 import _splice_lu_name
    out = _splice_lu_name(DEVTYPE_REQ, "CICSA01")
    assert out.endswith(b"\xff\xf0")


def test_splice_appends_connect_when_missing():
    """If the original has no CONNECT clause, add one."""
    from hack3270_libs.tn3270_v2 import _splice_lu_name
    out = _splice_lu_name(DEVTYPE_REQ_NO_CONNECT, "CICSA01")
    assert b"\x01CICSA01" in out
    assert out.endswith(b"\xff\xf0")


def test_splice_no_match_returns_unchanged():
    """If there's no DEVICE-TYPE REQUEST in the data, pass through."""
    from hack3270_libs.tn3270_v2 import _splice_lu_name
    other = b"\xff\xfd\x18"   # IAC DO TERMINAL-TYPE (different negotiation)
    assert _splice_lu_name(other, "CICSA01") == other


def test_splice_handles_shorter_replacement():
    from hack3270_libs.tn3270_v2 import _splice_lu_name
    out = _splice_lu_name(DEVTYPE_REQ, "LU1")
    assert b"LU1\xff\xf0" in out
    # No leftover bytes from old name
    assert b"00042" not in out


def test_splice_handles_longer_replacement():
    from hack3270_libs.tn3270_v2 import _splice_lu_name
    out = _splice_lu_name(DEVTYPE_REQ, "VERYLONGLUNAME01")
    assert b"VERYLONGLUNAME01" in out


def test_splice_ascii_not_ebcdic():
    """LU names in telnet negotiation are ASCII (it's the telnet layer)."""
    from hack3270_libs.tn3270_v2 import _splice_lu_name
    out = _splice_lu_name(DEVTYPE_REQ, "ABC")
    # ASCII 'A' = 0x41, EBCDIC 'A' = 0xC1. Must be ASCII.
    assert b"\x41\x42\x43" in out
    assert b"\xc1\xc2\xc3" not in out


# ---------------------------------------------------------------------------
# Integration: negotiate_hook drives the splice
# ---------------------------------------------------------------------------

def test_negotiate_hook_invokes_splice():
    from hack3270_libs.tn3270_v2 import TN3270
    from hackterm_core.protocol import NegotiateOpts
    p = TN3270()
    opts = NegotiateOpts(spoof_device_name="CICSA01")
    out = p.negotiate_hook(DEVTYPE_REQ, "c2s", opts)
    assert b"CICSA01" in out


def test_negotiate_hook_no_spoof_passes_through():
    from hack3270_libs.tn3270_v2 import TN3270
    from hackterm_core.protocol import NegotiateOpts
    p = TN3270()
    opts = NegotiateOpts(spoof_device_name=None)
    out = p.negotiate_hook(DEVTYPE_REQ, "c2s", opts)
    assert out == DEVTYPE_REQ


def test_negotiate_hook_ignores_s2c():
    """Spoof only applies client→server. Server's response is observed
    but not rewritten."""
    from hack3270_libs.tn3270_v2 import TN3270
    from hackterm_core.protocol import NegotiateOpts
    p = TN3270()
    opts = NegotiateOpts(spoof_device_name="CICSA01")
    out = p.negotiate_hook(DEVTYPE_REQ, "s2c", opts)
    assert out == DEVTYPE_REQ


# ---------------------------------------------------------------------------
# LUSpoofer — the campaign driver
# ---------------------------------------------------------------------------

@pytest.fixture
def spoofer():
    from hack3270_libs.attacks.negotiation import LUSpoofer
    from hack3270_libs.tn3270_v2 import TN3270
    return LUSpoofer(protocol=TN3270())


def test_spoofer_starts_in_single_mode(spoofer):
    assert spoofer.mode == "single"


def test_spoofer_set_target_lu(spoofer, fake_daemon):
    """In single mode, setting target_lu writes negotiate_opts."""
    spoofer.attach(fake_daemon)
    spoofer.set_target("CICSA01")
    assert fake_daemon.negotiate_opts.spoof_device_name == "CICSA01"


def test_spoofer_load_wordlist(spoofer, tmp_path):
    wl = tmp_path / "lus.txt"
    wl.write_text("LU01\nLU02\nLU03\n# comment\n\nLU04\n")
    spoofer.load_wordlist(str(wl))
    # Comments and blank lines stripped
    assert spoofer.wordlist == ["LU01", "LU02", "LU03", "LU04"]


def test_spoofer_wordlist_next(spoofer, fake_daemon, tmp_path):
    """next_lu() advances through the wordlist and updates daemon opts."""
    wl = tmp_path / "lus.txt"
    wl.write_text("LU01\nLU02\nLU03\n")
    spoofer.load_wordlist(str(wl))
    spoofer.attach(fake_daemon)
    spoofer.mode = "wordlist"

    assert spoofer.next_lu() == "LU01"
    assert fake_daemon.negotiate_opts.spoof_device_name == "LU01"
    assert spoofer.next_lu() == "LU02"
    assert spoofer.next_lu() == "LU03"
    assert spoofer.next_lu() is None  # exhausted


def test_spoofer_harvest_extracts_lu_from_c2s_request(spoofer, fake_daemon):
    """Harvest watches c2s DEVICE-TYPE REQUEST packets passing through —
    captures whatever LU the real client is asking for."""
    spoofer.attach(fake_daemon)
    fake_daemon.fire_c2s(DEVTYPE_REQ)  # client requests TCP00042
    assert "TCP00042" in spoofer.harvested


def test_spoofer_harvest_extracts_lu_from_s2c_response(spoofer, fake_daemon):
    """Harvest also watches s2c DEVICE-TYPE IS responses — the LU the
    server actually assigned (may differ from request).
    Server response: IAC SB TN3270E DEVICE-TYPE IS ... CONNECT <lu> IAC SE
                     ff  fa  28      02         04   ...  01     ...   ff f0
    """
    spoofer.attach(fake_daemon)
    response = (b"\xff\xfa\x28\x02\x04"   # IAC SB TN3270E DEVICE-TYPE IS
                + b"IBM-3278-2-E"
                + b"\x01"                  # CONNECT
                + b"TERM0099"
                + b"\xff\xf0")
    fake_daemon.fire_s2c(response)
    assert "TERM0099" in spoofer.harvested


def test_spoofer_harvest_ignores_non_devtype(spoofer, fake_daemon):
    spoofer.attach(fake_daemon)
    fake_daemon.fire_c2s(b"\xff\xfd\x18")  # IAC DO TERM-TYPE
    fake_daemon.fire_s2c(b"\xff\xfb\x18")  # IAC WILL TERM-TYPE
    assert spoofer.harvested == set()


def test_spoofer_harvest_ignores_no_connect(spoofer, fake_daemon):
    """DEVICE-TYPE without a CONNECT clause has no LU to harvest."""
    spoofer.attach(fake_daemon)
    fake_daemon.fire_c2s(DEVTYPE_REQ_NO_CONNECT)
    assert spoofer.harvested == set()


def test_spoofer_record_result(spoofer):
    """Results table: [(lu_name, screen_summary), ...]"""
    spoofer.record_result("CICSA01", "MAIN MENU - CICS REGION A")
    spoofer.record_result("TCP00042", "CESN")
    assert len(spoofer.results) == 2
    assert spoofer.results[0] == ("CICSA01", "MAIN MENU - CICS REGION A")


def test_spoofer_fingerprint_set_and_match(spoofer):
    """Fingerprint of rendered screen text — same content matches,
    different content does not."""
    from hack3270_libs.tn3270_v2 import TN3270
    p = TN3270()

    pkt_abc = bytes([0xF5, 0xC3, 0x1D, 0x40, 0xC1, 0xC2, 0xC3, 0xFF, 0xEF])
    pkt_xyz = bytes([0xF5, 0xC3, 0x1D, 0x40, 0xE7, 0xE8, 0xE9, 0xFF, 0xEF])

    screen_abc = p.parse(pkt_abc)
    screen_xyz = p.parse(pkt_xyz)

    spoofer.set_fingerprint(screen_abc)
    assert spoofer.login_screen_fingerprint is not None
    assert spoofer.screen_matches_fingerprint(screen_abc) is True
    assert spoofer.screen_matches_fingerprint(screen_xyz) is False


def test_spoofer_fingerprint_unset_never_matches(spoofer):
    from hack3270_libs.tn3270_v2 import TN3270
    p = TN3270()
    pkt = bytes([0xF5, 0xC3, 0x1D, 0x40, 0xC1, 0xC2, 0xC3, 0xFF, 0xEF])
    screen = p.parse(pkt)
    assert spoofer.screen_matches_fingerprint(screen) is False
