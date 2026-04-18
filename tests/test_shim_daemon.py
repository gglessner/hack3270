"""
ProxyDaemon shim tests.

We can't easily test the full socket loop without a real server, so
these tests verify wiring: the shim creates a ProxyDaemon, sockets
get aliased back, the client-intercept callback dispatches correctly.
"""
import socket
import pytest
from unittest.mock import MagicMock


def test_shim_creates_proxy_daemon(legacy_hack3270):
    from hackterm_core import ProxyDaemon
    h = legacy_hack3270
    assert hasattr(h, "_daemon")
    assert isinstance(h._daemon, ProxyDaemon)


def test_shim_creates_protocol(legacy_hack3270):
    from tn3270_legacy import TN3270Legacy
    h = legacy_hack3270
    assert hasattr(h, "_protocol")
    assert isinstance(h._protocol, TN3270Legacy)
    assert h._daemon.protocol is h._protocol


def test_client_connect_aliases_socket(legacy_hack3270, monkeypatch):
    """After client_connect, self.client must point at the
    daemon's client socket — tend_server/send_key read it."""
    h = legacy_hack3270
    fake_sock = MagicMock(spec=socket.socket)

    def fake_wait():
        h._daemon.client = fake_sock
    monkeypatch.setattr(h._daemon, "wait_for_client", fake_wait)

    h.client_connect()
    assert h.client is fake_sock
    assert h.client is h._daemon.client


def test_server_connect_aliases_socket(legacy_hack3270, monkeypatch):
    h = legacy_hack3270
    fake_sock = MagicMock(spec=socket.socket)

    def fake_connect():
        h._daemon.server = fake_sock
    monkeypatch.setattr(h._daemon, "connect_to_server", fake_connect)

    h.server_connect()
    assert h.server is fake_sock


def test_server_connect_offline_raises(legacy_hack3270):
    """L807-808: offline mode → Hack3270Error."""
    import libhack3270
    h = legacy_hack3270
    h.offline_mode = True
    with pytest.raises(libhack3270.Hack3270Error):
        h.server_connect()


def test_daemon_pushes_hack_flags_to_mutate_opts(legacy_hack3270, monkeypatch):
    """Before tick(), shim must sync self.hack_* → daemon.mutate_opts."""
    h = legacy_hack3270
    h.client = MagicMock()
    h.server = MagicMock()
    h._daemon.client = h.client
    h._daemon.server = h.server
    monkeypatch.setattr(h._daemon, "tick", lambda: None)

    h.hack_on = True
    h.hack_prot = True
    h.hack_hf = True
    h.hack_color_on = True

    h.daemon()

    assert h._daemon.mutate_opts.unprotect is True
    assert h._daemon.mutate_opts.reveal_hidden is True
    assert h._daemon.mutate_opts.color_reveal is True


def test_daemon_intercept_capture_mask(legacy_hack3270, monkeypatch):
    """When inject_setup_capture is set, the client-intercept
    callback must call capture_mask and return None (drop)."""
    h = legacy_hack3270
    h.client = MagicMock()
    h.server = MagicMock()
    h._daemon.client = h.client
    h._daemon.server = h.server
    monkeypatch.setattr(h._daemon, "tick", lambda: None)

    captured = []
    monkeypatch.setattr(h, "capture_mask", lambda d: captured.append(d))

    h.inject_setup_capture = True
    h.daemon()  # installs the intercept

    intercept = h._daemon._client_intercept
    assert intercept is not None
    result = intercept(b"\x7D\x40\x40\x5C\x5C\x5C\xFF\xEF")
    assert result is None  # dropped, not forwarded
    assert captured == [b"\x7D\x40\x40\x5C\x5C\x5C\xFF\xEF"]


def test_daemon_intercept_aid_manual_spoof(legacy_hack3270, monkeypatch):
    """When aid_spoof_enabled + MANUAL mode, intercept rewrites AID."""
    h = legacy_hack3270
    h.client = MagicMock()
    h.server = MagicMock()
    h._daemon.client = h.client
    h._daemon.server = h.server
    h._daemon.handshake_complete = True  # past negotiation
    monkeypatch.setattr(h._daemon, "tick", lambda: None)

    h.aid_spoof_enabled = True
    h.aid_spoof_mode = "MANUAL"
    h.aid_spoof_value = "PF1"
    # Make check_inject_3270e return False (plain mode, AID at byte 0)
    monkeypatch.setattr(h, "check_inject_3270e", lambda: False)

    h.daemon()
    intercept = h._daemon._client_intercept
    assert intercept is not None
    out = intercept(b"\x7D\x40\x40\xFF\xEF")  # ENTER + cursor + IAC EOR
    # MANUAL mode sends directly to server.send and returns None
    # (to preserve single-log semantics)
    assert out is None
    sent = h.server.send.call_args[0][0]
    assert sent[0] == 0xF1  # PF1


def test_daemon_intercept_fuzzer_arm(legacy_hack3270, monkeypatch):
    """FUZZER mode armed → captures data, transitions to running, drops."""
    h = legacy_hack3270
    h.client = MagicMock()
    h.server = MagicMock()
    h._daemon.client = h.client
    h._daemon.server = h.server
    monkeypatch.setattr(h._daemon, "tick", lambda: None)

    h.aid_spoof_enabled = True
    h.aid_spoof_mode = "FUZZER"
    h.aid_fuzzer_armed = True
    h.aid_fuzzer_running = False

    cb_calls = []
    h.aid_fuzzer_callback = lambda *a: cb_calls.append(a)

    h.daemon()
    intercept = h._daemon._client_intercept
    out = intercept(b"\x7D\x40\x40\xFF\xEF")
    assert out is None
    assert h.aid_fuzzer_captured_data == b"\x7D\x40\x40\xFF\xEF"
    assert h.aid_fuzzer_armed is False
    assert h.aid_fuzzer_running is True
    assert h.aid_fuzzer_progress == 0
    assert cb_calls == [('captured', 0, 256, None)]


def test_daemon_no_intercept_when_idle(legacy_hack3270, monkeypatch):
    """No capture, no spoof, no fuzz → intercept is None (passthrough)."""
    h = legacy_hack3270
    h.client = MagicMock()
    h.server = MagicMock()
    h._daemon.client = h.client
    h._daemon.server = h.server
    monkeypatch.setattr(h._daemon, "tick", lambda: None)

    h.inject_setup_capture = False
    h.aid_spoof_enabled = False
    h.daemon()

    assert h._daemon._client_intercept is None


def test_check_inject_3270e_reads_protocol_state(legacy_hack3270):
    """After detect() has run, check_inject_3270e returns the cached
    protocol state — no more SQLite row-1 dependency."""
    h = legacy_hack3270
    h._protocol._is_tn3270e = True
    assert h.check_inject_3270e() is True
    h._protocol._is_tn3270e = False
    assert h.check_inject_3270e() is False


def test_check_inject_3270e_sqlite_fallback(legacy_hack3270):
    """gui.py:3794 calls check_inject_3270e right after server_connect,
    BEFORE daemon() runs. If row 1 exists from a previous session,
    fall back to the legacy SQLite check."""
    h = legacy_hack3270
    # protocol hasn't detected yet
    h._protocol._is_tn3270e = False
    h._daemon.handshake_complete = False
    # but row 1 has TN3270E negotiation
    h.write_database_log("S", "", b"\xFF\xFD\x28")
    assert h.check_inject_3270e() is True


def test_hack_toggled_resends_via_daemon(legacy_hack3270, monkeypatch):
    """L1414-1471: hack_toggled → re-send last server data through
    manipulate(). Now: re-send via daemon.inject_to_client."""
    h = legacy_hack3270
    h.client = MagicMock()
    h.server = MagicMock()
    h._daemon.client = h.client
    h._daemon.server = h.server
    monkeypatch.setattr(h._daemon, "tick", lambda: None)

    sent = []
    monkeypatch.setattr(h._daemon, "inject_to_client",
                        lambda d: sent.append(d))

    h.server_data = b"\x05\x1D\x60\xFF\xEF"
    h.hack_toggled = True
    h.hack_on = True
    h.hack_prot = True
    h.hack_sf = True

    h.daemon()

    assert h.hack_toggled == 0  # cleared
    assert len(sent) == 1
    assert sent[0][2] == 0x40  # protected bit cleared by manipulate()


def test_server_data_observer_stashes_last(legacy_hack3270):
    """The shim must register an observer that stashes server traffic
    into self.server_data — gui.py reads it directly."""
    h = legacy_hack3270
    # The observer should have been registered in __init__
    assert len(h._daemon._observers) >= 1
    # Trigger it
    for obs in h._daemon._observers:
        obs(b"server bytes", "s2c")
    assert h.server_data == b"server bytes"


def test_server_data_observer_ignores_c2s(legacy_hack3270):
    """Observer must NOT overwrite server_data on client→server traffic."""
    h = legacy_hack3270
    h.server_data = b"original"
    for obs in h._daemon._observers:
        obs(b"client bytes", "c2s")
    assert h.server_data == b"original"


def test_manipulate_delegates_to_protocol(legacy_hack3270):
    """The shim's manipulate() must call TN3270Legacy._do_manipulate
    with self as the flags object — full-fidelity 14-flag path."""
    h = legacy_hack3270
    h.hack_on = True
    h.hack_prot = True
    h.hack_sf = True
    inp = b"\x05\x1D\x60\xFF\xEF"
    out = h.manipulate(inp)
    assert out[2] == 0x40  # protected bit cleared


def test_manipulate_returns_bytes_compatible(legacy_hack3270):
    """Legacy callers do bytes(...) on result; ensure it stays compatible."""
    h = legacy_hack3270
    h.hack_on = False
    h.hack_color_on = False
    out = h.manipulate(b"\x05\x1D\x60\xFF\xEF")
    # bytearray or bytes — either works with bytes() and slicing
    assert bytes(out) == b"\x05\x1D\x60\xFF\xEF"
