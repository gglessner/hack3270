"""
Phase 3 Task 0 verification.

Proves the scaffold is wired up:
  - attacks package imports
  - FakeDaemon fixture works (observers fire, intercept mutates, inject captured)
  - golden packets materialized with expected sizes & key bytes
"""
import pytest


# ---------------------------------------------------------------------------
# attacks package
# ---------------------------------------------------------------------------

def test_attacks_package_imports():
    # hack3270_libs/ is on sys.path (conftest), so 'attacks' is a top-level pkg
    import attacks
    assert attacks.__name__ == "attacks"


def test_attacks_package_has_docstring():
    import attacks
    assert "Phase 3 attack modules" in attacks.__doc__


# ---------------------------------------------------------------------------
# FakeDaemon
# ---------------------------------------------------------------------------

def test_fake_daemon_constructs(fake_daemon):
    assert fake_daemon.handshake_complete is True
    assert fake_daemon.sent_to_server == []
    assert fake_daemon.sent_to_client == []
    assert fake_daemon._observers == []
    assert fake_daemon._client_intercept is None


def test_fake_daemon_has_negotiate_opts(fake_daemon):
    # Real attack modules read these dataclass instances
    from hackterm_core.protocol import NegotiateOpts, MutateOpts
    assert isinstance(fake_daemon.negotiate_opts, NegotiateOpts)
    assert isinstance(fake_daemon.mutate_opts, MutateOpts)


def test_fake_daemon_fire_s2c_triggers_observer(fake_daemon):
    seen = []
    fake_daemon.add_observer(lambda data, direction: seen.append((data, direction)))

    fake_daemon.fire_s2c(b"\xf5\xc3\xff\xef")

    assert seen == [(b"\xf5\xc3\xff\xef", "s2c")]


def test_fake_daemon_fire_s2c_multiple_observers(fake_daemon):
    a, b = [], []
    fake_daemon.add_observer(lambda d, dr: a.append(d))
    fake_daemon.add_observer(lambda d, dr: b.append(d))

    fake_daemon.fire_s2c(b"hello")

    assert a == [b"hello"]
    assert b == [b"hello"]


def test_fake_daemon_fire_c2s_no_intercept(fake_daemon):
    seen = []
    fake_daemon.add_observer(lambda data, direction: seen.append((data, direction)))

    result = fake_daemon.fire_c2s(b"\x7d\x40\x40\xff\xef")  # Enter AID

    assert result == b"\x7d\x40\x40\xff\xef"
    assert seen == [(b"\x7d\x40\x40\xff\xef", "c2s")]


def test_fake_daemon_fire_c2s_intercept_mutates(fake_daemon):
    seen = []
    fake_daemon.add_observer(lambda data, direction: seen.append(data))
    fake_daemon.set_client_intercept(lambda data: data + b"\x00")  # append a byte

    result = fake_daemon.fire_c2s(b"abc")

    assert result == b"abc\x00"
    assert seen == [b"abc\x00"]  # observer sees POST-intercept data


def test_fake_daemon_fire_c2s_intercept_drops(fake_daemon):
    seen = []
    fake_daemon.add_observer(lambda data, direction: seen.append(data))
    fake_daemon.set_client_intercept(lambda data: None)  # drop everything

    result = fake_daemon.fire_c2s(b"abc")

    assert result is None
    assert seen == []  # observer never fires when intercept drops


def test_fake_daemon_inject_to_server_captured(fake_daemon):
    fake_daemon.inject_to_server(b"\x7d\x40\x40\xff\xef")
    fake_daemon.inject_to_server(b"\xf3\xff\xef")

    assert fake_daemon.sent_to_server == [
        b"\x7d\x40\x40\xff\xef",
        b"\xf3\xff\xef",
    ]


def test_fake_daemon_inject_to_client_captured(fake_daemon):
    fake_daemon.inject_to_client(b"\xf5\xc3\xff\xef")
    assert fake_daemon.sent_to_client == [b"\xf5\xc3\xff\xef"]


def test_fake_daemon_isolated_per_test(fake_daemon):
    # Fixture is function-scoped: each test gets a fresh instance
    assert fake_daemon.sent_to_server == []
    fake_daemon.inject_to_server(b"x")
    # next test_ that uses fake_daemon will see [] again


# ---------------------------------------------------------------------------
# Golden packets — sizes & key bytes
# ---------------------------------------------------------------------------

EXPECTED_SIZES = {
    "simple_sf.bin": 9,
    "sba_positioned.bin": 12,
    "hidden_field.bin": 12,
    "tn3270e_wrapped.bin": 14,
    "sfe_extended.bin": 12,
    "iac_escaped.bin": 10,
    "multi_field.bin": 31,
    "ra_repeat.bin": 11,
    "text_with_bracket.bin": 9,
}


@pytest.mark.parametrize("name,size", sorted(EXPECTED_SIZES.items()))
def test_golden_file_size(gold, name, size):
    assert len(gold(name)) == size


def test_golden_all_end_with_iac_eor(gold):
    for name in EXPECTED_SIZES:
        data = gold(name)
        assert data[-2:] == b"\xff\xef", f"{name} missing IAC EOR trailer"


def test_golden_simple_sf_structure(gold):
    data = gold("simple_sf.bin")
    assert data[0] == 0xF5  # Erase/Write
    assert data[1] == 0xC3  # WCC
    assert data[2] == 0x1D  # SF order
    assert data[3] == 0x60  # protected attr
    assert data[4:7] == b"\xc1\xc2\xc3"  # EBCDIC "ABC"


def test_golden_hidden_field_attr_is_hidden(gold):
    data = gold("hidden_field.bin")
    attr = data[3]
    assert attr == 0x6C
    # Verify against the actual hidden-check logic from tn3270_legacy
    assert attr & 0x0C == 0x0C, "bits 2&3 must both be set for non-display"
    assert attr & 0x20 == 0x20, "bit 5 = protected"


def test_golden_tn3270e_header_then_payload(gold):
    data = gold("tn3270e_wrapped.bin")
    # 5-byte header: data-type, req-flag, resp-flag, seq-hi, seq-lo
    assert data[:5] == b"\x00\x00\x00\x00\x01"
    # Stripping header leaves a valid simple_sf
    assert data[5:] == gold("simple_sf.bin")


def test_golden_iac_escaped_has_doubled_ff(gold):
    data = gold("iac_escaped.bin")
    # On the wire: ...C1 FF FF C2... — the FF FF is one escaped data byte
    assert b"\xc1\xff\xff\xc2" in data
    # And it still ends with the real IAC EOR
    assert data[-2:] == b"\xff\xef"


def test_golden_multi_field_three_sf_orders(gold):
    data = gold("multi_field.bin")
    # Strip IAC EOR and count SF order bytes (0x1D) — should be exactly 3.
    # Note: 0x1D doesn't appear in any of the EBCDIC text bytes used here.
    payload = data[:-2]
    assert payload.count(b"\x1d") == 3


def test_golden_text_with_bracket_has_0xbd_not_0x1d(gold):
    data = gold("text_with_bracket.bin")
    # ']' is 0xBD in cp037 — appears in field text
    assert 0xBD in data
    # Only ONE 0x1D (the SF order itself), not two
    assert data.count(b"\x1d") == 1


# ---------------------------------------------------------------------------
# Direct packet fixtures
# ---------------------------------------------------------------------------

def test_pkt3270_minimal_fixture(pkt3270_minimal):
    assert len(pkt3270_minimal) == 9
    assert pkt3270_minimal[0] == 0xF5


def test_pkt3270_hidden_field_fixture(pkt3270_hidden_field):
    assert pkt3270_hidden_field[3] == 0x6C


def test_pkt3270_with_sba_fixture(pkt3270_with_sba):
    assert pkt3270_with_sba[2] == 0x11  # SBA order


def test_pkt3270_tn3270e_fixture(pkt3270_tn3270e, pkt3270_minimal):
    assert pkt3270_tn3270e[5:] == pkt3270_minimal


def test_pkt3270_iac_escaped_fixture(pkt3270_iac_escaped):
    assert b"\xff\xff" in pkt3270_iac_escaped[:-2]  # escaped FF in body


def test_pkt3270_text_with_0x1d_fixture(pkt3270_text_with_0x1d):
    # The fixture name says 0x1d but content has 0xBD (']' in cp037).
    # The point: a naive parser scanning for "looks like an order byte"
    # must not trip on EBCDIC text. 0xBD is in the printable range.
    assert 0xBD in pkt3270_text_with_0x1d


def test_pkt3270_one_field_fixture(pkt3270_one_field):
    # Alias for minimal — single protected field
    assert pkt3270_one_field[2] == 0x1D
    assert pkt3270_one_field[3] == 0x60
