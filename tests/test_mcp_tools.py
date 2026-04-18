"""
MCP tool registration tests.

The actual ApiServer is socket-based (tested in Phase 0). Here we test
that handlers are REGISTERED correctly and produce well-formed responses
when called directly via api._handlers["cmd"]("args").

All five attacks are wired:
  - ESMFingerprinter  → esm_get_findings
  - LUSpoofer         → lu_spoof_single, lu_spoof_next, lu_get_harvested,
                        lu_get_results
  - QueryReplyLiar    → qr_arm, qr_disarm
  - IndFileInterceptor→ indfile_set_mode, indfile_get_captures
  - StateFuzzer       → flow_record_start, flow_record_stop,
                        flow_analyze, flow_list_mutations
"""
import json
import sqlite3
import pytest
from hackterm_core.api_server import ApiServer


@pytest.fixture
def attacks(tmp_path, fake_daemon):
    """Build all five attack objects, attached to FakeDaemon."""
    from hack3270_libs.tn3270_v2 import TN3270
    from attacks.esm_passive import ESMFingerprinter
    from attacks.negotiation import LUSpoofer
    from attacks.structured import QueryReplyLiar, IndFileInterceptor
    from attacks.state_fuzz import StateFuzzer

    proto = TN3270()
    a = {
        "esm": ESMFingerprinter(proto),
        "lu": LUSpoofer(proto),
        "qr": QueryReplyLiar(),
        "indfile": IndFileInterceptor(capture_dir=str(tmp_path / "captures")),
        "fuzzer": StateFuzzer(proto, sqlite3.connect(":memory:")),
    }
    for v in a.values():
        v.attach(fake_daemon)
    return a


@pytest.fixture
def api(attacks):
    from hack3270_libs.mcp_tools import register_all
    server = ApiServer(port=0)   # never .start() — registry-only
    register_all(server, attacks)
    return server


# --- Registration ----------------------------------------------------------

def test_register_all_registers_expected_commands(api):
    expected = {
        "esm_get_findings",
        "lu_spoof_single", "lu_spoof_next",
        "lu_get_harvested", "lu_get_results",
        "qr_arm", "qr_disarm",
        "indfile_set_mode", "indfile_get_captures",
        "flow_record_start", "flow_record_stop",
        "flow_analyze", "flow_list_mutations",
    }
    assert expected.issubset(set(api._handlers.keys()))


def test_register_all_handlers_are_callable(api):
    for name, h in api._handlers.items():
        assert callable(h), f"{name} handler is not callable"


# --- ESM -------------------------------------------------------------------

def test_esm_get_findings_empty(api):
    resp = api._handlers["esm_get_findings"]("")
    assert json.loads(resp) == {}


def test_esm_get_findings_with_data(api, attacks, fake_daemon):
    from hackterm_core.ebcdic import EbcdicCodec
    codec = EbcdicCodec()
    # Synthetic CICS DFHCE3530 disclosure screen → username_enum finding
    pkt = (bytes([0xF5, 0xC3, 0x1D, 0x60])
           + codec.to_ebcdic("DFHCE3530 INVALID USERID")
           + b"\xff\xef")
    fake_daemon.fire_s2c(pkt)
    resp = api._handlers["esm_get_findings"]("")
    findings = json.loads(resp)
    assert "username_enum" in findings


# --- LU spoofing -----------------------------------------------------------

def test_lu_spoof_single(api, attacks, fake_daemon):
    resp = api._handlers["lu_spoof_single"]("CICSA01")
    assert resp == "OK"
    assert fake_daemon.negotiate_opts.spoof_device_name == "CICSA01"
    assert attacks["lu"].target_lu == "CICSA01"


def test_lu_spoof_single_no_arg(api):
    resp = api._handlers["lu_spoof_single"]("")
    assert resp.startswith("ERROR")


def test_lu_spoof_single_whitespace_arg(api):
    resp = api._handlers["lu_spoof_single"]("   ")
    assert resp.startswith("ERROR")


def test_lu_spoof_next_iterates_wordlist(api, attacks):
    attacks["lu"].wordlist = ["TERM0001", "TERM0002"]
    attacks["lu"]._wordlist_idx = 0
    assert api._handlers["lu_spoof_next"]("") == "TERM0001"
    assert api._handlers["lu_spoof_next"]("") == "TERM0002"
    assert api._handlers["lu_spoof_next"]("") == "DONE"


def test_lu_get_harvested(api, attacks):
    attacks["lu"].harvested.add("TERM0099")
    attacks["lu"].harvested.add("CICSA05")
    resp = api._handlers["lu_get_harvested"]("")
    data = json.loads(resp)
    assert data == ["CICSA05", "TERM0099"]   # sorted


def test_lu_get_results(api, attacks):
    attacks["lu"].record_result("CICSA01", "MAIN MENU")
    attacks["lu"].record_result("TERM0001", "LOGIN SCREEN")
    resp = api._handlers["lu_get_results"]("")
    data = json.loads(resp)
    assert ["CICSA01", "MAIN MENU"] in data
    assert ["TERM0001", "LOGIN SCREEN"] in data


# --- Query Reply -----------------------------------------------------------

def test_qr_arm_with_lies(api, attacks):
    resp = api._handlers["qr_arm"]('{"alt_rows": 62, "deny_color": true}')
    assert resp == "OK"
    assert attacks["qr"].armed is True
    assert attacks["qr"].lies.alt_rows == 62
    assert attacks["qr"].lies.deny_color is True
    assert attacks["qr"].lies.deny_highlighting is False   # default


def test_qr_arm_empty_json(api, attacks):
    resp = api._handlers["qr_arm"]("{}")
    assert resp == "OK"
    assert attacks["qr"].armed is True
    assert attacks["qr"].lies.alt_rows is None


def test_qr_arm_bad_json(api, attacks):
    resp = api._handlers["qr_arm"]("not json at all")
    assert resp.startswith("ERROR")
    assert attacks["qr"].armed is False   # never armed on bad input


def test_qr_disarm(api, attacks):
    api._handlers["qr_arm"]('{"alt_rows": 99}')
    assert attacks["qr"].armed is True
    resp = api._handlers["qr_disarm"]("")
    assert resp == "OK"
    assert attacks["qr"].armed is False


# --- IND$FILE --------------------------------------------------------------

def test_indfile_set_mode_valid(api, attacks):
    for mode in ("carbon_copy", "inject", "alert"):
        resp = api._handlers["indfile_set_mode"](mode)
        assert resp == "OK"
        assert attacks["indfile"].mode == mode


def test_indfile_set_mode_invalid(api, attacks):
    original = attacks["indfile"].mode
    resp = api._handlers["indfile_set_mode"]("not_a_mode")
    assert resp.startswith("ERROR")
    assert attacks["indfile"].mode == original   # unchanged


def test_indfile_set_mode_empty(api):
    resp = api._handlers["indfile_set_mode"]("")
    assert resp.startswith("ERROR")


def test_indfile_get_captures(api, attacks):
    attacks["indfile"].captures.append({"size": 42, "direction": "GET"})
    attacks["indfile"].captures.append({"size": 1024, "direction": "PUT"})
    resp = api._handlers["indfile_get_captures"]("")
    data = json.loads(resp)
    assert len(data) == 2
    assert data[0]["size"] == 42
    assert data[1]["direction"] == "PUT"


def test_indfile_get_captures_empty(api):
    resp = api._handlers["indfile_get_captures"]("")
    assert json.loads(resp) == []


# --- State fuzzer ----------------------------------------------------------

def test_flow_record_start(api, attacks):
    assert attacks["fuzzer"].recording is False
    resp = api._handlers["flow_record_start"]("login_flow")
    assert resp == "OK"
    assert attacks["fuzzer"].recording is True
    assert attacks["fuzzer"].current_flow.name == "login_flow"


def test_flow_record_start_unnamed(api, attacks):
    resp = api._handlers["flow_record_start"]("   ")
    assert resp == "OK"
    assert attacks["fuzzer"].current_flow.name == "unnamed"


def test_flow_record_stop_returns_id(api, attacks, fake_daemon):
    api._handlers["flow_record_start"]("test_flow")
    # Drive one s2c → c2s round-trip so there's a Step to persist
    fake_daemon.fire_s2c(
        bytes([0xF5, 0xC3, 0x1D, 0x40, 0xC1, 0xC2, 0xC3, 0xFF, 0xEF]))
    fake_daemon.fire_c2s(b"\x7d\x40\x40\xff\xef")
    resp = api._handlers["flow_record_stop"]("")
    flow_id = int(resp)   # must be a stringified int
    assert flow_id >= 1
    assert attacks["fuzzer"].recording is False


def test_flow_analyze_bad_arg(api):
    resp = api._handlers["flow_analyze"]("not_an_int")
    assert resp.startswith("ERROR")


def test_flow_analyze_returns_json(api, attacks, fake_daemon):
    # Record a flow with an echo: input "HELLO" appears on next screen
    from hackterm_core.ebcdic import EbcdicCodec
    codec = EbcdicCodec()
    api._handlers["flow_record_start"]("echo_flow")
    fake_daemon.fire_s2c(
        bytes([0xF5, 0xC3, 0x1D, 0x40]) + codec.to_ebcdic("ENTER:") + b"\xff\xef")
    fake_daemon.fire_c2s(
        b"\x7d\x40\x40\x11\x40\xc1" + codec.to_ebcdic("HELLO") + b"\xff\xef")
    fake_daemon.fire_s2c(
        bytes([0xF5, 0xC3, 0x1D, 0x40]) + codec.to_ebcdic("HELLO") + b"\xff\xef")
    flow_id = int(api._handlers["flow_record_stop"](""))

    resp = api._handlers["flow_analyze"](str(flow_id))
    targets = json.loads(resp)
    assert isinstance(targets, list)
    # If the analyzer found the echo, validate dict shape
    if targets:
        t = targets[0]
        assert "step_idx" in t
        assert "field_idx" in t
        assert "source_step" in t
        assert "confidence" in t


def test_flow_list_mutations(api):
    resp = api._handlers["flow_list_mutations"]("")
    muts = json.loads(resp)
    assert muts == ["length_plus_1", "length_double", "type_confusion",
                    "extra_sba", "step_swap"]


def test_fuzzer_optional_no_flow_handlers_without_fuzzer(fake_daemon, tmp_path):
    """register_all() must not fail if 'fuzzer' is absent from attacks."""
    from hack3270_libs.tn3270_v2 import TN3270
    from attacks.esm_passive import ESMFingerprinter
    from attacks.negotiation import LUSpoofer
    from attacks.structured import QueryReplyLiar, IndFileInterceptor
    from hack3270_libs.mcp_tools import register_all

    proto = TN3270()
    a = {
        "esm": ESMFingerprinter(proto),
        "lu": LUSpoofer(proto),
        "qr": QueryReplyLiar(),
        "indfile": IndFileInterceptor(capture_dir=str(tmp_path / "cap")),
    }
    for v in a.values():
        v.attach(fake_daemon)
    server = ApiServer(port=0)
    register_all(server, a)   # must not raise
    assert "flow_record_start" not in server._handlers
    assert "esm_get_findings" in server._handlers
