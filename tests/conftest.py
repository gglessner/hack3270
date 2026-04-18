"""
Phase 1 test fixtures.

The `legacy_hack3270` fixture creates a hack3270 instance WITHOUT
hitting the network — db_init runs (creates a tmp .db) but
client_connect/server_connect are never called. This is enough to
exercise manipulate(), get_ascii(), capture_mask(), etc.
"""
import sys
import os
import pytest
import logging

# Make hack3270_libs and the vendored hackterm-core importable
_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_root, "hackterm-core"))
sys.path.insert(0, os.path.join(_root, "hack3270_libs"))

GOLDEN_DIR = os.path.join(os.path.dirname(__file__), "golden")


@pytest.fixture
def legacy_hack3270(tmp_path, monkeypatch):
    """A hack3270 instance with a throwaway SQLite db, no sockets."""
    monkeypatch.chdir(tmp_path)  # db file lands in tmp
    import libhack3270
    h = libhack3270.hack3270(
        server_ip="127.0.0.1",
        server_port=23,
        proxy_port=3271,
        proxy_ip="127.0.0.1",
        offline_mode=False,
        project_name="testproj",
        loglevel=logging.CRITICAL,
        tls_enabled=False,
    )
    yield h
    try:
        h.sql_con.close()
    except Exception:
        pass


def golden(name: str) -> bytes:
    """Load a golden fixture from tests/golden/."""
    with open(os.path.join(GOLDEN_DIR, name), "rb") as f:
        return f.read()


# ===========================================================================
# Phase 3 fixtures — FakeDaemon + synthetic 3270 golden packets
# ===========================================================================
#
# Golden files below are SYNTHETIC — hand-crafted byte sequences documented
# inline. They are NOT live captures. The generator runs once (idempotent)
# so the .bin files are git-tracked and tests don't need a mainframe.
#
# Byte legend (3270 datastream, GA23-0059):
#   Write commands:  0xF5 = Erase/Write   0xF1 = Write   0x7E = EW Alternate
#   WCC byte:        follows write cmd; 0xC3 = reset+unlock-keyboard+sound-alarm
#   Orders:          0x1D=SF  0x29=SFE  0x11=SBA  0x13=IC  0x3C=RA
#                    0x28=SA  0x2C=MF  0x12=EUA  0x05=PT  0x08=GE
#   Telnet:          0xFF 0xEF = IAC EOR (end of record)
#   TN3270E header:  5 bytes — data-type, req-flag, resp-flag, seq-num(2)
#
# EBCDIC quick ref (cp037):
#   0xC1-0xC9 = A-I    0xD1-0xD9 = J-R    0xE2-0xE9 = S-Z
#   0xF0-0xF9 = 0-9    0x40 = space       0x7A = ':'
#
# SF attribute byte (verified against tn3270_legacy._check_hidden: & 0x0C == 0x0C):
#   bit 6 (0x40) — graphic-escape pad bit, always set in valid attrs
#   bit 5 (0x20) — protected
#   bit 4 (0x10) — numeric-only
#   bits 3-2 (0x0C) — both set = non-display (hidden)
#   bit 0 (0x01) — MDT (modified data tag)
#   → 0x60 = protected, normal display
#   → 0x6C = protected + non-display (hidden)
#   → 0x40 = unprotected, normal display

import pathlib

_GOLDEN_PATH = pathlib.Path(GOLDEN_DIR)

_PHASE3_GOLDENS = {
    # The minimal datastream: Erase/Write, WCC, one protected field, "ABC", EOR
    #   F5    Erase/Write command
    #   C3    WCC (reset MDT + unlock keyboard + sound alarm)
    #   1D 60 SF, attr=0x60 (bit6 + bit5=protected; normal display, alpha)
    #   C1 C2 C3   EBCDIC "ABC"
    #   FF EF IAC EOR
    "simple_sf.bin": bytes([
        0xF5, 0xC3,
        0x1D, 0x60,
        0xC1, 0xC2, 0xC3,
        0xFF, 0xEF,
    ]),

    # Same as simple_sf but with SBA positioning the buffer first.
    # SBA 0x40 0x40 → buffer address 0 (row 1, col 1) per 12-bit addressing
    #   (ADDR_TABLE[0]=0x40 → high=0, low=0 → addr 0)
    "sba_positioned.bin": bytes([
        0xF5, 0xC3,
        0x11, 0x40, 0x40,        # SBA → position 0
        0x1D, 0x60,              # SF protected
        0xC1, 0xC2, 0xC3,        # "ABC"
        0xFF, 0xEF,
    ]),

    # Hidden (non-display) field. Attr 0x6C = 0110 1100:
    #   bit 6 (0x40) — graphic-escape pad bit (always set in valid attrs)
    #   bit 5 (0x20) — protected
    #   bits 3-2 (0x0C) — both set = non-display (hidden)
    # Verified: tn3270_legacy._check_hidden(0x6C) → True (0x6C & 0x0C == 0x0C)
    "hidden_field.bin": bytes([
        0xF5, 0xC3,
        0x1D, 0x6C,              # SF: protected + hidden
        0xE2, 0xC5, 0xC3, 0xD9, 0xC5, 0xE3,  # "SECRET"
        0xFF, 0xEF,
    ]),

    # TN3270E-wrapped: 5-byte header before the datastream.
    # Header: data-type=0x00 (3270-DATA), req=0, resp=0, seq=0x0001
    "tn3270e_wrapped.bin": bytes([
        0x00, 0x00, 0x00, 0x00, 0x01,   # TN3270E header
        0xF5, 0xC3,
        0x1D, 0x60,
        0xC1, 0xC2, 0xC3,
        0xFF, 0xEF,
    ]),

    # Start Field Extended — attribute pairs instead of single attr byte.
    # SFE format: 0x29 <count> (<type> <value>)*count
    # Type 0xC0 = basic 3270 attr (same bits as SF attr byte)
    "sfe_extended.bin": bytes([
        0xF5, 0xC3,
        0x29, 0x02,              # SFE, 2 attribute pairs
        0xC0, 0x60,              #   pair 1: basic attr = protected
        0x42, 0xF4,              #   pair 2: foreground color = green (0xF4)
        0xC8, 0xC9,              # "HI"
        0xFF, 0xEF,
    ]),

    # IAC escaping: a data byte 0xFF must be doubled on the wire (0xFF 0xFF)
    # so it isn't confused with telnet IAC. The parser must un-escape this
    # back to a single 0xFF in the field content.
    # 0xFF in cp037 EBCDIC = 'Ÿ' (eo-superset codepoint) — rare but legal.
    "iac_escaped.bin": bytes([
        0xF5, 0xC3,
        0x1D, 0x40,              # SF: unprotected (attr=0x40, only bit6 set)
        0xC1, 0xFF, 0xFF, 0xC2,  # "A" + escaped-0xFF + "B" → content is C1 FF C2
        0xFF, 0xEF,
    ]),

    # Three fields on one screen — exercises field-length closure.
    # Field 1 at addr 0:   protected, "USER:"
    # Field 2 at addr 6:   unprotected (input), 8 blanks
    # Field 3 at addr 15:  protected, "PASS:"
    "multi_field.bin": bytes([
        0xF5, 0xC3,
        0x11, 0x40, 0x40,        # SBA → 0
        0x1D, 0x60,              # SF protected
        0xE4, 0xE2, 0xC5, 0xD9, 0x7A,  # "USER:"  (0x7A = ':')
        0x1D, 0x40,              # SF unprotected (input field)
        0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,  # 8 spaces
        0x1D, 0x60,              # SF protected
        0xD7, 0xC1, 0xE2, 0xE2, 0x7A,  # "PASS:"
        0xFF, 0xEF,
    ]),

    # Repeat-to-Address: RA <addr:2> <char:1>
    # Fills from current position to <addr> with <char>.
    # RA to addr 10 (encode 10: high=0,low=10 → ADDR_TABLE[0]=0x40, ADDR_TABLE[10]=0x4A)
    # with EBCDIC '-' (0x60).
    "ra_repeat.bin": bytes([
        0xF5, 0xC3,
        0x11, 0x40, 0x40,        # SBA → 0
        0x3C, 0x40, 0x4A, 0x60,  # RA to addr 10, fill with '-'
        0xFF, 0xEF,
    ]),

    # 0x1D appears in EBCDIC text — but ONLY as an order, not as text.
    # The byte 0x1D is the SF order; in cp037, 0x1D is a control char (GS),
    # not the printable ']'. The printable ']' is EBCDIC 0xBD.
    # This packet has 0xBD in text content — a parser MUST treat it as data,
    # NOT mistake it for any order. Guards against off-by-one in order-byte
    # tables (some tables erroneously list 0xBD or treat high-bit text as
    # control).
    #   F5 C3       Erase/Write + WCC
    #   1D 60       SF protected
    #   C1 BD C2    "A" + ']' (0xBD) + "B"  — 0xBD must be treated as text
    #   FF EF       IAC EOR
    "text_with_bracket.bin": bytes([
        0xF5, 0xC3,
        0x1D, 0x60,
        0xC1, 0xBD, 0xC2,        # "A]B" — 0xBD is ']' in cp037, NOT an order
        0xFF, 0xEF,
    ]),
}


def _materialize_phase3_goldens():
    """Write Phase 3 .bin files if they don't exist. Idempotent."""
    _GOLDEN_PATH.mkdir(exist_ok=True)
    for name, data in _PHASE3_GOLDENS.items():
        path = _GOLDEN_PATH / name
        if not path.exists():
            path.write_bytes(data)


_materialize_phase3_goldens()


@pytest.fixture
def gold():
    """Load a golden file by name: gold('simple_sf.bin') → bytes.

    Phase 3's preferred loader (returns bytes directly, knows about
    both Phase 1 and Phase 3 .bin files).
    """
    def _load(name: str) -> bytes:
        return (_GOLDEN_PATH / name).read_bytes()
    return _load


# Convenience direct fixtures — one per Phase 3 packet, for tests that
# only need one specific packet and want it in the signature.

@pytest.fixture
def pkt3270_minimal():
    """Erase/Write + WCC + one protected SF + "ABC" + IAC EOR. 9 bytes."""
    return _PHASE3_GOLDENS["simple_sf.bin"]


@pytest.fixture
def pkt3270_one_field():
    """Single protected field (attr 0x60). Same as pkt3270_minimal."""
    return _PHASE3_GOLDENS["simple_sf.bin"]


@pytest.fixture
def pkt3270_hidden_field():
    """SF with attr 0x6C (protected + non-display). Content: "SECRET"."""
    return _PHASE3_GOLDENS["hidden_field.bin"]


@pytest.fixture
def pkt3270_with_sba():
    """SBA → addr 0, then SF protected + "ABC"."""
    return _PHASE3_GOLDENS["sba_positioned.bin"]


@pytest.fixture
def pkt3270_tn3270e():
    """5-byte TN3270E header (3270-DATA, seq=1) + simple_sf payload."""
    return _PHASE3_GOLDENS["tn3270e_wrapped.bin"]


@pytest.fixture
def pkt3270_iac_escaped():
    """Field content has wire-escaped 0xFF 0xFF → must un-escape to single 0xFF."""
    return _PHASE3_GOLDENS["iac_escaped.bin"]


@pytest.fixture
def pkt3270_text_with_0x1d():
    """']' (EBCDIC 0xBD) in field text — must NOT be parsed as an order."""
    return _PHASE3_GOLDENS["text_with_bracket.bin"]


# ---------------------------------------------------------------------------
# FakeDaemon — substitute for ProxyDaemon in attack-module tests.
# ---------------------------------------------------------------------------
#
# Records inject_to_server / inject_to_client calls. Lets tests fire
# observers and intercepts directly without sockets.
#
# Real ProxyDaemon (hackterm_core) signature:
#   .add_observer(fn)         — fn(data: bytes, direction: str) called on traffic
#   .set_client_intercept(fn) — fn(data: bytes) -> bytes|None, mutates c2s
#   .negotiate_opts           — NegotiateOpts dataclass
#   .mutate_opts              — MutateOpts dataclass
#   .inject_to_server(data)   — push bytes to mainframe
#   .inject_to_client(data)   — push bytes to terminal emulator
#   .handshake_complete       — bool, True after telnet negotiation done

from hackterm_core.protocol import NegotiateOpts, MutateOpts


class FakeDaemon:
    """Drop-in for ProxyDaemon in unit tests. No sockets — pure in-memory.

    Test-driver helpers (NOT on real ProxyDaemon):
      .fire_s2c(data)  — simulate server→client traffic, calls observers
      .fire_c2s(data)  — simulate client→server, calls intercept then observers
      .sent_to_server  — list of bytes from inject_to_server() calls
      .sent_to_client  — list of bytes from inject_to_client() calls
    """

    def __init__(self):
        self.negotiate_opts = NegotiateOpts()
        self.mutate_opts = MutateOpts()
        self.handshake_complete = True
        self._observers = []
        self._client_intercept = None
        self.sent_to_server = []
        self.sent_to_client = []

    # --- ProxyDaemon API ---

    def add_observer(self, fn):
        self._observers.append(fn)

    def set_client_intercept(self, fn):
        self._client_intercept = fn

    def inject_to_server(self, data: bytes):
        self.sent_to_server.append(data)

    def inject_to_client(self, data: bytes):
        self.sent_to_client.append(data)

    # --- Test-driver helpers (NOT part of real ProxyDaemon API) ---

    def fire_s2c(self, data: bytes):
        """Simulate server→client traffic hitting observers."""
        for obs in self._observers:
            obs(data, "s2c")

    def fire_c2s(self, data: bytes):
        """Simulate client→server traffic: intercept first, then observers.

        Returns the (possibly mutated) data that observers saw, or None
        if the intercept dropped it.
        """
        if self._client_intercept:
            data = self._client_intercept(data)
            if data is None:
                return None
        for obs in self._observers:
            obs(data, "c2s")
        return data


@pytest.fixture
def fake_daemon():
    return FakeDaemon()
