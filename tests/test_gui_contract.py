r"""
GUI contract test: every hack3270 method/attribute the GUI touches
must continue to exist on the shimmed hack3270 class.

This is the canary. It runs against the CURRENT code (passes trivially)
and must keep passing after every Phase 1 task.

Method list extracted from gui.py 2026-04-07 via:
    grep -oP 'self\.hack3270\.\w+' gui.py | sort -u
plus manual inspection of gui.py:3770-3815 where the GUI calls methods
on the local `hack3270` parameter (not self.hack3270) during __init__.

If gui.py adds new calls, add them here.
"""
import os
import pytest

GOLDEN_DIR = os.path.join(os.path.dirname(__file__), "golden")


def golden(name: str) -> bytes:
    """Load a golden fixture from tests/golden/."""
    with open(os.path.join(GOLDEN_DIR, name), "rb") as f:
        return f.read()


# Methods called as self.hack3270.X(...) in gui.py.
GUI_CALLED_METHODS = [
    # --- Connection & startup (gui.py:3775-3810, via local var) ---
    "client_connect",       # gui.py:3783
    "server_connect",       # gui.py:3793
    "get_proxy_ip_port",    # gui.py:3775
    "check_record",         # gui.py:3798
    "check_server",         # gui.py:3799,3804
    "play_record",          # gui.py:3800,3805
    "recv",                 # gui.py:3802
    "api_start",            # gui.py:3810
    # --- Daemon loop (gui.py:402-410) ---
    "daemon",               # gui.py:410
    "is_offline",           # gui.py:319,345,403,3791,3809
    "run_aid_fuzzer",       # gui.py:408
    # --- Storage / logs ---
    "all_logs",             # gui.py:1403,1705,2180
    "get_log",              # gui.py:2081,2093,3509,3577,3636
    "write_log",            # gui.py:3337
    "write_database_log",   # used internally by write_log; tested below directly
    "check_inject_3270e",   # gui.py:1571,2869,3164,3794
    "export_csv",           # gui.py:3529
    "expand_CS",            # gui.py:2194
    # --- EBCDIC / parse ---
    "get_ascii",            # gui.py:1755,1889,1982,2082,2094,3510,3580
    "get_ebcdic",           # gui.py:3333,3625
    "parse_3270",           # gui.py:1755,1888,1981,2086,2098,3514,3584
    "parse_telnet",         # gui.py:2084,2096,3512,3582
    # --- Inject ---
    "get_inject_config_set",   # gui.py:420,3358,3372
    "get_inject_mask_len",     # gui.py:422,3324
    "get_inject_preamble",     # gui.py:3334
    "get_inject_postamble",    # gui.py:3336
    "set_inject_setup_capture",# gui.py:3312
    "set_inject_config_set",   # gui.py:3460
    "set_inject_mask",         # gui.py:3311
    # --- Send / proxy ---
    "send_key",             # gui.py:3349,3351,3353,3354,3490
    "send_server",          # gui.py:2090,3338,3520
    "send_client",          # gui.py:2102,3518
    "api_send_raw",         # gui.py:2876,3171
    "tend_server",          # gui.py:3345
    "get_last_server",      # gui.py:2800,3120
    "get_last_server_raw",  # gui.py:2381,2801,3121
    # --- AID spoof / fuzzer ---
    "set_aid_spoof_enabled",   # gui.py:2252
    "set_aid_spoof_mode",      # gui.py:2277
    "set_aid_spoof_value",     # gui.py:2313
    "set_aid_fuzzer_callback", # gui.py:2322
    "arm_aid_fuzzer",          # gui.py:2323
    "disarm_aid_fuzzer",       # gui.py:2270
    "pause_aid_fuzzer",        # gui.py:2367
    "resume_aid_fuzzer",       # gui.py:2371
    "stop_aid_fuzzer",         # exists on lib; defensive include
    # --- Hack flags: getters ---
    "get_hack_on",          # gui.py:2213
    "get_hack_color_on",    # gui.py:2228
    # --- Hack flags: setters (checkbox handlers) ---
    "set_hack_on",          # gui.py:2214,2219
    "set_hack_color_on",    # gui.py:2229,2234
    "set_hack_toggled",     # gui.py:2217,2222,2243
    "set_hack_color_toggled", # gui.py:2232,2237,2247
    "set_hack_prot",        # gui.py:3277
    "set_hack_hf",          # gui.py:3278
    "set_hack_rnr",         # gui.py:3279
    "set_hack_sf",          # gui.py:3280
    "set_hack_sfe",         # gui.py:3281
    "set_hack_mf",          # gui.py:3282
    "set_hack_ei",          # gui.py:3283
    "set_hack_hv",          # gui.py:3284
    "set_hack_color_sfe",   # gui.py:3285
    "set_hack_color_mf",    # gui.py:3286
    "set_hack_color_sa",    # gui.py:3287
    "set_hack_color_hv",    # gui.py:3288
    # --- Misc ---
    "get_ip_port",          # gui.py:1568
    "get_tls",              # gui.py:1570
    "current_aids",         # gui.py:3682
    "on_closing",           # gui.py:3714
]

# Attributes the GUI reads directly (not method calls)
GUI_READ_ATTRS = [
    "AIDS",                 # gui.py:695,3473 (via class: libhack3270.hack3270.AIDS)
    "aid_fuzzer_running",   # gui.py:407 (read as bool)
    "project_name",         # gui.py:2115,3551 (read as str for filenames)
    "server_data",          # internal; get_last_server_raw() returns it
    # --- Phase 3 attack objects (gui.py Negotiation/Structured tabs + ESM dock) ---
    "esm",                  # gui.py:attack_refresh — ESMFingerprinter
    "lu_spoofer",           # gui.py:_lu_* handlers — LUSpoofer
    "qr_liar",              # gui.py:_qr_arm_toggled — QueryReplyLiar
    "indfile",              # gui.py:_ind_* handlers — IndFileInterceptor
    "state_fuzzer",         # gui.py:_on_record_toggle, _on_analyze_flow — StateFuzzer
]


def test_all_gui_methods_exist(legacy_hack3270):
    h = legacy_hack3270
    missing = []
    for name in GUI_CALLED_METHODS:
        if not hasattr(h, name):
            missing.append(name)
    assert not missing, f"GUI-called methods missing from shim: {missing}"


def test_all_gui_attrs_exist(legacy_hack3270):
    h = legacy_hack3270
    missing = [a for a in GUI_READ_ATTRS if not hasattr(h, a)]
    assert not missing, f"GUI-read attributes missing from shim: {missing}"


def test_get_log_returns_iterable(legacy_hack3270):
    """gui.py:2081 does `for row in self.hack3270.get_log(id):` —
    legacy returns a list (sql_cur.fetchall()). Storage.get_log may
    return one-or-None. Shim must wrap so iteration still works."""
    h = legacy_hack3270
    h.write_database_log("S", "test", b"\x05hello")
    result = h.get_log(1)
    # Must be iterable AND each element subscriptable (row[5])
    rows = list(result)
    assert len(rows) == 1
    assert rows[0][5] == b"\x05hello"


def test_get_log_missing_returns_empty_iterable(legacy_hack3270):
    """gui.py iterates result; nonexistent ID must not raise."""
    h = legacy_hack3270
    result = h.get_log(99999)
    assert list(result) == []


def test_AIDS_dict_has_bytes_values(legacy_hack3270):
    """gui.py:3490 does send_key(name, byte_code) where byte_code
    comes from AIDS dict — values must be single-byte bytes objects."""
    h = legacy_hack3270
    assert h.AIDS["ENTER"] == b"\x7d"
    assert h.AIDS["PF1"] == b"\xf1"
    assert h.AIDS["CLEAR"] == b"\x6d"
    for name, val in h.AIDS.items():
        assert isinstance(val, bytes), f"{name} is not bytes"
        assert len(val) == 1, f"{name} is not single byte"


# --- Golden fixture regression: manipulate() must produce identical bytes ---


@pytest.mark.parametrize("name", [
    "sf_protected.bin",
    "sfe_hidden.bin",
    "sa_color_black.bin",
    "telnet_iac.bin",
])
def test_manipulate_golden(legacy_hack3270, name):
    """manipulate() with all hack flags ON must produce byte-identical
    output to the captured golden fixtures. This is the safety net for
    Tasks 1-6: any behavioral drift in the shim/core fails here."""
    h = legacy_hack3270
    # Same flag combo as _make_golden.py
    h.hack_on = True
    h.hack_prot = True
    h.hack_hf = True
    h.hack_rnr = True
    h.hack_ei = False
    h.hack_sf = True
    h.hack_sfe = True
    h.hack_mf = True
    h.hack_hv = True
    h.hack_color_on = True
    h.hack_color_sfe = True
    h.hack_color_mf = True
    h.hack_color_sa = True
    h.hack_color_hv = True

    inp = golden("in_" + name)
    expected = golden(name)
    out = bytes(h.manipulate(inp))
    assert out == expected, (
        f"manipulate({inp.hex()}) -> {out.hex()}, "
        f"expected {expected.hex()}"
    )
