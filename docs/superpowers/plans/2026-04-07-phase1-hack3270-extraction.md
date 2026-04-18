# Phase 1 — hack3270 Extraction onto hackterm-core

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the existing `hack3270` tool onto the Phase-0 `hackterm-core` package. **Behavior must not change** — this is pure extraction. The 2,012-line god class at `hack3270_libs/libhack3270.py` becomes a thin shim that delegates to `ProxyDaemon`, `Storage`, `EbcdicCodec`, `MaskInjector`, and a new `TN3270Legacy(Protocol)` wrapper around the existing `manipulate()` / `flip_bits()` byte-mangler.

**Architecture — the shim approach:** `libhack3270.hack3270.__init__()` instantiates core objects and stores them. Every existing method name the GUI calls (`daemon`, `client_connect`, `write_database_log`, `get_ascii`, `get_inject_preamble`, …) becomes a one-line delegation. **The GUI does not change.** The `manipulate()` function — bugs and all — moves *unchanged* into `TN3270Legacy.mutate()` and is verified by golden-file byte comparison.

**Tech Stack:** Python 3.11+, `pytest`. `hackterm-core` is already installed editable in `.venv` (verified: `pip show hackterm-core` → 0.1.0).

**Spec reference:** `docs/superpowers/specs/2026-04-07-hackterm-design.md` §5 Phase 1

**Pytest invocation:** `/home/kali/hack3270-update/.venv/bin/pytest`

---

## File Structure

```
hack3270_libs/
  libhack3270.py              # SHRINKS: 2012 lines → ~600 lines (shim + AID fuzzer + parse_telnet/parse_3270 + API handlers)
  tn3270_legacy.py            # NEW: TN3270Legacy(Protocol) — wraps manipulate()/flip_bits() unchanged
  gui.py                      # UNCHANGED (this is the contract)
  hack3270_api.py             # UNCHANGED for Phase 1

tests/                        # NEW: top-level test dir for hack3270 (sibling to hackterm-core/tests/)
  __init__.py
  conftest.py
  golden/                     # captured packet fixtures
    sf_protected.bin
    sfe_hidden.bin
    sa_color_black.bin
    telnet_iac.bin
  test_tn3270_legacy.py       # golden bytes-in-bytes-out for mutate()
  test_shim_ebcdic.py         # 256-byte diff old e2a vs EbcdicCodec
  test_shim_storage.py        # old .db opens; write_database_log delegates
  test_shim_inject.py         # capture_mask delegates to MaskInjector
  test_shim_daemon.py         # daemon() delegates to ProxyDaemon.tick()
  test_gui_contract.py        # every method gui.py calls still exists with same signature
```

**Source extraction map** — what moves where:

| Legacy location (libhack3270.py) | Destination | Strategy |
|---|---|---|
| L44-63 `e2a`/`a2e` tables | DELETE → `EbcdicCodec("cp037")` | Shim `get_ascii`/`get_ebcdic` delegate |
| L138-174 `AIDS` dict | COPY → `TN3270Legacy.aid_table` (as `dict[str,int]`) | Keep `AIDS` on shim too (GUI reads `hack3270.AIDS` directly) |
| L287-413 `db_init` | DELETE → `Storage(...)` | Shim `__init__` creates Storage; offline-mode/mismatch checks ported |
| L414-437 `write_database_log` | DELEGATE → `Storage.log()` | One-liner. NOTE: legacy auto-tags `"tn3270 negotiation"`, core uses `"telnet negotiation"` — shim must override |
| L439-460 `all_logs`/`get_log` | DELEGATE → `Storage.all_logs`/`Storage.get_log` | `get_log` legacy returns list, core returns one-or-None — shim wraps in list |
| L462-482 `check_inject_3270e` | DELEGATE → `TN3270Legacy._is_tn3270e` (cached on shim) | New version inspects bytes, not row 1; result cached on first server packet |
| L484-505 `check_server`/`check_record` | DELEGATE → `Storage.is_server_record`/`is_telnet_record` | One-liners |
| L507-513 `play_record` | DELEGATE → `Storage.get_raw` + `ProxyDaemon.inject_to_client` | Two lines |
| L779-845 `client_connect`/`server_connect` | DELEGATE → `ProxyDaemon.wait_for_client`/`connect_to_server` | After connect, copy `daemon.client`/`daemon.server` back to `self.client`/`self.server` so legacy `tend_server`/`send_key`/`api_send_raw` keep working |
| L1299-1315 `handle_server` | KEEP — calls `manipulate()` which now delegates | Used by `tend_server` (L1317-1327) which AID fuzzer / inject loop need |
| L1329-1471 `daemon` | REPLACE → see Task 4 | Body becomes: build client-intercept callback from `inject_setup_capture`/`aid_spoof_*` flags, push hack flags onto `daemon.mutate_opts`, call `daemon.tick()`, handle `hack_toggled` resend |
| L1615-1649 `spoof_aid` | KEEP on shim, also implemented by `TN3270Legacy.spoof_aid` | Legacy version returns 3-tuple `(modified, orig_name, new_name)` — Protocol contract just returns bytes; shim keeps 3-tuple version, delegates byte-replacement to protocol |
| L1708-1747 `capture_mask` | DELEGATE → `MaskInjector.capture()` | Shim copies `injector.preamble`/`postamble`/`mask_len` back to legacy attrs |
| L1782-1792 `get_ascii`/`get_ebcdic` | DELEGATE → `EbcdicCodec.to_ascii`/`to_ebcdic` | One-liners |
| L1816-1996 `flip_bits`/`check_hidden`/`manipulate` | MOVE to `tn3270_legacy.py` UNCHANGED | Shim `manipulate()` delegates: `self._protocol._do_manipulate(data, self)` — passes `self` so legacy code reads `hack_*` flags off the shim |

**Critical insight — why `manipulate()` reads flags off the shim, not `MutateOpts`:** The legacy `manipulate()` reads **12 boolean flags** (`hack_on`, `hack_prot`, `hack_hf`, `hack_rnr`, `hack_ei`, `hack_sf`, `hack_sfe`, `hack_mf`, `hack_hv`, `hack_color_on`, `hack_color_sfe`, `hack_color_mf`, `hack_color_sa`, `hack_color_hv` — that's 14 actually). `MutateOpts` only has 5. For bit-perfect compat, `TN3270Legacy.mutate(data, opts)` does **two** things: (a) maps the 5 `MutateOpts` fields to legacy flags for the `ProxyDaemon` path, and (b) exposes `_do_manipulate(data, flags_obj)` that the shim's own `manipulate()` calls directly with `self` (which has all 14 flags). This way both call paths work: `ProxyDaemon.tick()` → `protocol.mutate(data, opts)` for the simple case, and `shim.manipulate(data)` → full-fidelity legacy path for `hack_toggled` resend.

---

## Task 0: Test infrastructure + golden capture harness

**Files:**
- Create: `tests/__init__.py`
- Create: `tests/conftest.py`
- Create: `tests/golden/` (directory + 4 binary fixtures)
- Create: `tests/test_gui_contract.py`

This task builds the safety net **before** any refactoring. Golden fixtures are generated by feeding hand-crafted 3270 datastreams through the *current* `manipulate()` and saving the output. The GUI-contract test enumerates every `self.hack3270.<method>` call in `gui.py` and asserts those methods exist with compatible signatures — this is the canary that breaks the moment a shim delegation is wrong.

- [ ] **Step 0.1: Create test directory structure**

```bash
mkdir -p /home/kali/hack3270-update/tests/golden
touch /home/kali/hack3270-update/tests/__init__.py
```

- [ ] **Step 0.2: Write `tests/conftest.py`**

Create `/home/kali/hack3270-update/tests/conftest.py`:

```python
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

# Make hack3270_libs importable
sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "hack3270_libs",
))

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
```

- [ ] **Step 0.3: Generate golden fixtures**

Create `/home/kali/hack3270-update/tests/_make_golden.py` (one-shot generator, not a test):

```python
"""
ONE-SHOT: capture output of CURRENT manipulate() before refactoring.
Run once: .venv/bin/python tests/_make_golden.py
Then never touch it again — these are the truth.

Synthetic 3270 datastreams covering each branch of manipulate()
(libhack3270.py:1869-1996):
  - L1888: SF (0x1D) + protected attr
  - L1907: SFE (0x29) with hidden 0xC0 attr pair
  - L1964: SA (0x28) with color 0x42 0xF8 black
  - L1874: telnet IAC (0xFF) — passthrough
"""
import sys, os, logging
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "hack3270_libs"))
os.chdir(os.path.dirname(__file__))  # so testproj.db lands here, we delete after

import libhack3270

GOLDEN = os.path.join(os.path.dirname(__file__), "golden")
os.makedirs(GOLDEN, exist_ok=True)

# Synthetic datastreams. Each is: WCC(1) + orders + IAC EOR.
# We don't need them to be *valid* 3270 — we need manipulate() to
# walk them and produce deterministic output.

# SF (0x1D) followed by attr byte 0xF8 (protected + numeric + nondisplay bits set:
#   0xF8 = 11111000 → bit5(prot)=1, bit4(num)=1, bits2-3(nondisp)=10... actually 0x0C = bits 2,3
# Use 0x6C = 01101100: prot(0x20) + nondisp(0x0C) + pad bits → flip_bits should clear all three)
INPUTS = {
    "sf_protected.bin":
        b"\x05" + b"\x1D\x6C" + b"\xC8\xC5\xD3\xD3\xD6" + b"\xFF\xEF",
        # WCC=05, SF, attr=0x6C (prot|nondisp|...), "HELLO" in EBCDIC, IAC EOR

    "sfe_hidden.bin":
        b"\x05" + b"\x29\x01\xC0\x4C" + b"\xE6\xD6\xD9\xD3\xC4" + b"\xFF\xEF",
        # WCC, SFE, 1 pair, type=0xC0(basic), val=0x4C (nondisp 0x0C set), "WORLD", IAC EOR

    "sa_color_black.bin":
        b"\x05" + b"\x28\x42\xF8" + b"\xC4\xC1\xD9\xD2" + b"\xFF\xEF",
        # WCC, SA, 0x42(color), 0xF8(black), "DARK", IAC EOR

    "telnet_iac.bin":
        b"\xFF\xFD\x28",
        # IAC DO TN3270E — manipulate() L1874 returns unchanged
}

# For each input, capture output under a specific flag combo.
# We use the "everything on" combo because it exercises the most branches.
def make_h():
    h = libhack3270.hack3270(
        server_ip="127.0.0.1", server_port=23, proxy_port=3271,
        project_name="_golden_tmp", loglevel=logging.CRITICAL,
    )
    # Enable everything (matches "everything on" attack mode)
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
    return h

h = make_h()
for name, data in INPUTS.items():
    out = h.manipulate(data)
    with open(os.path.join(GOLDEN, name), "wb") as f:
        f.write(bytes(out))
    print(f"  {name}: {data.hex()} -> {bytes(out).hex()}")

# Also save the inputs themselves
for name, data in INPUTS.items():
    with open(os.path.join(GOLDEN, "in_" + name), "wb") as f:
        f.write(data)

h.sql_con.close()
os.unlink("_golden_tmp.db")
print("golden fixtures written")
```

Run it:

```bash
.venv/bin/python tests/_make_golden.py
```

Expected: `golden fixtures written` and 8 files in `tests/golden/` (4 inputs + 4 outputs).

- [ ] **Step 0.4: Write the GUI-contract test**

This is the most important test in Phase 1. It introspects `gui.py` to find every `self.hack3270.X` reference and verifies `X` exists on the `hack3270` class. If any shim delegation is missing or misnamed, this fails immediately.

Create `/home/kali/hack3270-update/tests/test_gui_contract.py`:

```python
"""
GUI contract test: every hack3270 method/attribute the GUI touches
must continue to exist on the shimmed hack3270 class.

This is the canary. It runs against the CURRENT code (passes trivially)
and must keep passing after every Phase 1 task.

Method list extracted from grep on gui.py 2026-04-07. If the GUI
adds new calls, add them here.
"""
import inspect
import pytest


# Methods called as self.hack3270.X(...) in gui.py.
# Found via: grep -oP 'hack3270\.\w+' gui.py | sort -u
GUI_CALLED_METHODS = [
    # Connection (gui.py:3783-3805)
    "client_connect", "server_connect",
    # Daemon loop (gui.py:402-410)
    "daemon", "is_offline",
    # Storage (gui.py:1403,1705,2081,2093,2180,3509,3577,3636)
    "all_logs", "get_log", "write_log", "write_database_log",
    "check_inject_3270e", "check_server", "check_record", "play_record",
    # EBCDIC (gui.py:1755,2082,3333,3625)
    "get_ascii", "get_ebcdic", "parse_3270",
    # Inject (gui.py:420-422,3324-3338,3358-3372)
    "get_inject_config_set", "get_inject_mask_len",
    "get_inject_preamble", "get_inject_postamble",
    "set_inject_setup_capture", "set_inject_config_set", "set_inject_mask",
    # Send (gui.py:2876,3171,3338,3345,3349-3354,3490)
    "send_key", "send_server", "api_send_raw", "tend_server",
    # AID (gui.py:407-408 + AID tab)
    "aid_fuzzer_running", "run_aid_fuzzer",
    "set_aid_spoof_enabled", "set_aid_spoof_mode", "set_aid_spoof_value",
    "arm_aid_fuzzer", "disarm_aid_fuzzer",
    "stop_aid_fuzzer", "pause_aid_fuzzer", "resume_aid_fuzzer",
    "set_aid_fuzzer_callback",
    # Hack flags (set_* methods called by checkbox handlers)
    "get_hack_on", "get_hack_color_on",
    # Misc
    "get_ip_port", "get_proxy_ip_port", "get_tls",
    "current_aids", "on_closing",
]

# Class attributes the GUI reads directly (not calls)
GUI_READ_ATTRS = [
    "AIDS",            # gui.py uses hack3270.AIDS dict for combo boxes
    "server_data",     # gui.py reads last server bytes
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
    legacy returns a list. Storage.get_log returns one-or-None.
    Shim must wrap so iteration still works."""
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
```

- [ ] **Step 0.5: Run — establish baseline**

```bash
/home/kali/hack3270-update/.venv/bin/pytest tests/test_gui_contract.py -v
```

Expected: **5 passed** (against current unrefactored code).

- [ ] **Step 0.6: Add pytest config to repo root**

Create `/home/kali/hack3270-update/pytest.ini`:

```ini
[pytest]
testpaths = tests
```

(Keeps `pytest` invocations from also running `hackterm-core/tests/` which has its own config.)

- [ ] **Step 0.7: Commit**

```bash
cd /home/kali/hack3270-update
git add tests/ pytest.ini
git commit -m "test(phase1): golden fixtures + GUI contract baseline"
```

---

## Task 1: TN3270Legacy(Protocol) — golden bytes-in-bytes-out

**Files:**
- Create: `hack3270_libs/tn3270_legacy.py`
- Create: `tests/test_tn3270_legacy.py`

This is the highest-risk task because `manipulate()` is the core attack primitive. We **copy** `flip_bits` (L1816-1849), `check_hidden` (L1851-1867), and `manipulate` (L1869-1996) into the new module *byte-for-byte* — including the bugs (e.g. L1900: `x = x + 6` inside a `for x in range(...)` loop is a no-op in Python; L1903-1904: dead store of `data2` overwritten on next line). We are NOT fixing them. Phase 3 replaces this with `tn3270_v2`.

The class implements all 6 abstract methods of `Protocol`. The tricky part is `mutate()`: it gets a `MutateOpts` (5 fields) but legacy `manipulate()` reads 14 flags. Solution: `mutate()` builds a flags-namespace from `MutateOpts` (with sensible mapping) and calls the same `_do_manipulate(data, flags)` that the shim will also call directly with the full-fidelity shim object.

- [ ] **Step 1.1: Write failing test**

Create `/home/kali/hack3270-update/tests/test_tn3270_legacy.py`:

```python
"""
Golden tests for TN3270Legacy.

The contract: feed the same bytes through TN3270Legacy._do_manipulate
that we fed through legacy hack3270.manipulate() in _make_golden.py.
Output must be byte-identical.
"""
import pytest
from types import SimpleNamespace
from conftest import golden


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
```

- [ ] **Step 1.2: Run — expect ImportError**

```bash
/home/kali/hack3270-update/.venv/bin/pytest tests/test_tn3270_legacy.py -v
```

Expected: collection error, `ModuleNotFoundError: No module named 'tn3270_legacy'`.

- [ ] **Step 1.3: Implement `hack3270_libs/tn3270_legacy.py`**

Create `/home/kali/hack3270-update/hack3270_libs/tn3270_legacy.py`:

```python
"""
TN3270Legacy: wraps the existing manipulate()/flip_bits() byte-mangler
as a hackterm_core.Protocol implementation.

CRITICAL: _flip_bits, _check_hidden, _do_manipulate are copied
LINE-FOR-LINE from libhack3270.py:1816-1996. Bugs preserved:
  - L1900,1923,1939,1957,1962,1970,1973,1987,1992: `x = x + N` inside
    `for x in range(...)` is a no-op in Python (rebinds local x,
    overwritten next iteration). Legacy code has always worked this way.
  - L1903-1904: `data2 = ...` immediately overwritten on next line.
  - L1848: debug log shows ORIGINAL byte not flipped (cosmetic).

These get fixed in Phase 3 by tn3270_v2. For now: byte-perfect compat.

The Protocol contract is satisfied via mutate(data, MutateOpts) which
maps the 5 MutateOpts fields onto a subset of the 14 legacy flags.
The shim in libhack3270.py calls _do_manipulate(data, self) directly
to get full-fidelity 14-flag behavior for hack_toggled resends.
"""
import logging
from types import SimpleNamespace
from hackterm_core import (
    Protocol, Screen, MutateOpts, NegotiateOpts, FieldWrite,
)

_log = logging.getLogger(__name__)

# Copied from libhack3270.py:138-174 — values converted bytes→int
# because Protocol.aid_table is dict[str, int].
_AIDS_INT = {
    'NO': 0x60, 'QREPLY': 0x61, 'ENTER': 0x7D,
    'PF1': 0xF1, 'PF2': 0xF2, 'PF3': 0xF3, 'PF4': 0xF4, 'PF5': 0xF5,
    'PF6': 0xF6, 'PF7': 0xF7, 'PF8': 0xF8, 'PF9': 0xF9, 'PF10': 0x7A,
    'PF11': 0x7B, 'PF12': 0x7C, 'PF13': 0xC1, 'PF14': 0xC2, 'PF15': 0xC3,
    'PF16': 0xC4, 'PF17': 0xC5, 'PF18': 0xC6, 'PF19': 0xC7, 'PF20': 0xC8,
    'PF21': 0xC9, 'PF22': 0x4A, 'PF23': 0x4B, 'PF24': 0x4C,
    'OICR': 0xE6, 'MSR_MHS': 0xE7, 'SELECT': 0x7E,
    'PA1': 0x6C, 'PA2': 0x6E, 'PA3': 0x6B,
    'CLEAR': 0x6D, 'SYSREQ': 0xF0,
}

# TN3270E 5-byte header (libhack3270.py:1535)
_TN3270E_HEADER = b"\x00\x00\x00\x00\x01"
_IAC_EOR = b"\xFF\xEF"


class TN3270Legacy(Protocol):
    name = "tn3270"
    aid_table = _AIDS_INT
    default_codepage = "cp037"

    def __init__(self):
        # Cached after detect() runs. Replaces check_inject_3270e()
        # which read SQLite row 1 (libhack3270.py:462-482).
        self._is_tn3270e: bool = False

    @property
    def is_tn3270e(self) -> bool:
        return self._is_tn3270e

    # ── Protocol ABC ──────────────────────────────────────────────

    def detect(self, first_bytes: bytes) -> bool:
        """Replaces check_inject_3270e (L462-482).

        Legacy: read row 1, check row[5][2] == 40 (0x28 = TN3270E option).
        New: inspect bytes directly. The first server packet in tn3270
        negotiation is `IAC DO TN3270E` (ff fd 28) or `IAC DO TERMINAL-TYPE`
        (ff fd 18) for plain tn3270.

        Returns True (handshake complete) only when we see telnet
        negotiation traffic. Returns False for non-IAC data so
        ProxyDaemon stays in negotiate phase until the real handshake
        starts. As a side effect, sets self._is_tn3270e.
        """
        if len(first_bytes) < 3 or first_bytes[0] != 0xFF:
            return False
        # Check for TN3270E option byte (0x28) anywhere in this
        # negotiation chunk — same heuristic as legacy row[5][2]==40.
        # Legacy checked exactly byte index 2; we honor that.
        if first_bytes[2] == 0x28:
            self._is_tn3270e = True
        return True  # any IAC traffic = we're in tn3270 negotiation

    def negotiate_hook(self, data: bytes, direction: str,
                       opts: NegotiateOpts) -> bytes:
        """Legacy hack3270 has no negotiation rewriting. Passthrough.
        LU-name spoofing comes in Phase 3."""
        return data

    def parse(self, data: bytes) -> Screen:
        """Legacy hack3270 has no real parser — parse_3270() does
        regex string substitution for display only. Phase 3 brings
        tn3270_v2's actual parser. For now: empty screen."""
        return Screen.empty()

    def mutate(self, data: bytes, opts: MutateOpts) -> bytes:
        """Map MutateOpts → legacy flags, then run _do_manipulate.

        Mapping (per spec §5 Phase 1):
          unprotect       → hack_prot + hack_sf + hack_sfe + hack_mf
          reveal_hidden   → hack_hf  + hack_sf + hack_sfe + hack_mf
          remove_numeric  → hack_rnr + hack_sf + hack_sfe + hack_mf
          high_visibility → hack_hv
          color_reveal    → hack_color_on + hack_color_sa
                            + hack_color_sfe + hack_color_mf

        Note: unprotect/reveal/numeric all enable hack_on + the SF/SFE/MF
        order-handlers, because flip_bits is only called from inside those
        branches (L1888,1914,1930).
        """
        any_field = opts.unprotect or opts.reveal_hidden or opts.remove_numeric
        flags = SimpleNamespace(
            hack_on=any_field or opts.high_visibility,
            hack_prot=opts.unprotect,
            hack_hf=opts.reveal_hidden,
            hack_rnr=opts.remove_numeric,
            hack_ei=False,
            hack_sf=any_field,
            hack_sfe=any_field,
            hack_mf=any_field,
            hack_hv=opts.high_visibility,
            hack_color_on=opts.color_reveal,
            hack_color_sfe=opts.color_reveal,
            hack_color_mf=opts.color_reveal,
            hack_color_sa=opts.color_reveal,
            hack_color_hv=opts.high_visibility,
        )
        return bytes(self._do_manipulate(data, flags))

    def build_inbound(self, aid: int, cursor: tuple[int, int],
                      fields: list[FieldWrite]) -> bytes:
        """Port from send_key (L1531-1540).
        Legacy send_key only sends bare AID + IAC EOR (no cursor,
        no fields). We honor that but add cursor for Protocol contract
        compliance — Phase 3 attacks need it."""
        body = bytes([aid, cursor[0], cursor[1]])
        for fw in fields:
            # SBA (0x11) + 2-byte addr + data
            body += b"\x11" + bytes([fw.row, fw.col]) + fw.data
        body += _IAC_EOR
        if self._is_tn3270e:
            return _TN3270E_HEADER + body
        return body

    def spoof_aid(self, original: bytes, new_aid: int) -> bytes:
        """Port from spoof_aid (L1615-1649).
        TN3270E: AID at byte 5. Plain: AID at byte 0."""
        if self._is_tn3270e:
            if len(original) < 6:
                return original
            return original[:5] + bytes([new_aid]) + original[6:]
        else:
            if len(original) < 1:
                return original
            return bytes([new_aid]) + original[1:]

    # ── Legacy byte-mangler — copied verbatim ─────────────────────
    #
    # The following three methods are libhack3270.py:1816-1996 with
    # `self.hack_*` replaced by `flags.hack_*` and `self.logger` →
    # module-level `_log`. NO OTHER CHANGES. The bugs are load-bearing.

    @staticmethod
    def _flip_bits(tn3270_data, flags):
        """libhack3270.py:1816-1849"""
        value = tn3270_data
        # Turn off 'Protected' Flag (Bit 6) if Set
        if flags.hack_prot:
            if value & 0b00100000 == 0b00100000:
                value ^= 0b00100000
        # Turn off 'Non-display' Flag (Bit 4) if Set (i.e. Bits 3 and 4 are on)
        if flags.hack_hf:
            if value & 0b00001100 == 0b00001100:
                # Flip bit 3 instead of 4 if enable intensity is selected
                if flags.hack_ei:
                    value ^= 0b00000100
                else:
                    value ^= 0b00001000
        # Turn off 'Numeric Only' Flag (Bit 5) if Set
        if flags.hack_rnr:
            if value & 0b00010000 == 0b00010000:
                value ^= 0b00010000
        return value

    @staticmethod
    def _check_hidden(tn3270_data):
        """libhack3270.py:1851-1867"""
        if tn3270_data & 12 == 12:
            return True
        else:
            return False

    @classmethod
    def _do_manipulate(cls, tn3270_data, flags):
        """libhack3270.py:1869-1996.

        `flags` is anything with the 14 hack_* attributes — either
        a SimpleNamespace (mutate() path) or the hack3270 shim itself
        (legacy manipulate() path). This duck-typing is what makes
        both call paths bit-identical.
        """
        found_hidden_data = 0
        # Don't manipulate data if telnet
        if tn3270_data[0] == 255:
            return tn3270_data

        data = bytearray(len(tn3270_data))
        data[:] = tn3270_data

        # Process hacking of Basic Field Attributes
        if flags.hack_on:
            for x in range(len(data)):

                if flags.hack_sf and data[x] == 0x1d:  # Start Field

                    data[x + 1] = cls._flip_bits(data[x + 1], flags)
                    if flags.hack_hf and cls._check_hidden(data[x + 1]):
                        bfa_byte = data[x + 1].to_bytes(1, byteorder='little')
                        if flags.hack_hv:
                            data2 = bytearray(len(data) + 6)
                            data2 = data[:x] + b'\x29\x03\xc0' + bfa_byte + b'\x41\xf2\x42\xf6' + data[x + 2:]
                            data = data2
                            x = x + 6
                        else:
                            data2 = bytearray(len(data) + 4)
                            data2 = data[:x + 2] + b'\x28\x42\xf6' + data[x + 2:]
                            data2 = data[:x] + b'\x29\x02\xc0' + bfa_byte + b'\x42\xf6' + data[x + 2:]
                            x = x + 4

                elif data[x] == 0x29:  # Start Field Extended

                    for y in range(data[x + 1]):

                        if len(data) < ((x + 3) + (y * 2)):
                            continue
                        if flags.hack_sfe and data[((x + 3) + (y * 2)) - 1] == 0xc0:  # Basic 3270 field attributes
                            if cls._check_hidden(data[((x + 3) + (y * 2))]) and flags.hack_hv:
                                found_hidden_data = 1
                            data[((x + 3) + (y * 2))] = cls._flip_bits(data[((x + 3) + (y * 2))], flags)
                    if flags.hack_sfe and found_hidden_data:
                        data[x + 1] = data[x + 1] + 2
                        data2 = bytearray(len(data) + 4)
                        data2 = data[:x + (data[x + 1] * 2) - 2] + b'\x41\xf2\x42\xf6' + data[x + (data[x + 1] * 2) - 2:]
                        data = data2
                        x = x + 4
                        found_hidden_data = 0
                    continue
                elif data[x] == 0x2c:  # Modify Field
                    for y in range(data[x + 1]):
                        if len(data) < ((x + 3) + (y * 2)):
                            continue
                        if flags.hack_mf and data[((x + 3) + (y * 2)) - 1] == 0xc0:  # Basic 3270 field attributes
                            if cls._check_hidden(data[((x + 3) + (y * 2))]) and flags.hack_hv:
                                found_hidden_data = 1
                            data[((x + 3) + (y * 2))] = cls._flip_bits(data[((x + 3) + (y * 2))], flags)
                    if flags.hack_mf and found_hidden_data:
                        data[x + 1] = data[x + 1] + 2
                        data2 = bytearray(len(data) + 4)
                        data2 = data[:x + (data[x + 1] * 2) - 2] + b'\x41\xf2\x42\xf6' + data[x + (data[x + 1] * 2) - 2:]
                        data = data2
                        x = x + 4
                        found_hidden_data = 0
                    continue

        # Process hacking of Colors
        if flags.hack_color_on:
            for x in range(len(data)):
                if data[x] == 0x29:  # Start Field Extended
                    for y in range(data[x + 1]):
                        if len(data) < ((x + 3) + (y * 2)):
                            continue
                        if flags.hack_color_sfe and data[((x + 3) + (y * 2)) - 1] == 0x42:  # Color
                            if data[((x + 3) + (y * 2))] == 0xf8:  # Black
                                if flags.hack_color_hv:
                                    data[x + 1] = data[x + 1] + 2
                                    data2 = bytearray(len(data) + 4)
                                    data2 = data[:((x + 3) + (y * 2)) + 1] + b'\x41\xf2\x42\xf6' + data[((x + 3) + (y * 2)) + 1:]
                                    x = x + 4
                                else:
                                    data[x + 1] = data[x + 1] + 1
                                    data2 = bytearray(len(data) + 2)
                                    data2 = data[:((x + 3) + (y * 2)) + 1] + b'\x42\xf6' + data[((x + 3) + (y * 2)) + 1:]
                                    x = x + 2
                                data = data2
                elif data[x] == 0x28:  # Set Attribute
                    if flags.hack_color_sa and data[x + 1] == 0x42:  # Color
                        if data[x + 2] == 0xf8:  # Black
                            if flags.hack_color_hv:
                                data2 = bytearray(len(data) + 6)
                                data2 = data[:x + 3] + b'\x28\x41\xf2\x28\x42\xf6' + data[x + 3:]
                                x = x + 6
                            else:
                                data2 = bytearray(len(data) + 3)
                                data2 = data[:x + 3] + b'\x28\x42\xf6' + data[x + 3:]
                                x = x + 3
                            data = data2
                    continue
                elif data[x] == 0x2c:  # Modify Field
                    for y in range(data[x + 1]):
                        if len(data) < ((x + 3) + (y * 2)):
                            continue
                        if flags.hack_color_mf and data[((x + 3) + (y * 2)) - 1] == 0x42:  # Color
                            if data[((x + 3) + (y * 2))] == 0xf8:  # Black
                                if flags.hack_color_hv:
                                    data[x + 1] = data[x + 1] + 2
                                    data2 = bytearray(len(data) + 4)
                                    data2 = data[:((x + 3) + (y * 2)) + 1] + b'\x41\xf2\x42\xf6' + data[((x + 3) + (y * 2)) + 1:]
                                    x = x + 4
                                else:
                                    data[x + 1] = data[x + 1] + 1
                                    data2 = bytearray(len(data) + 2)
                                    data2 = data[:((x + 3) + (y * 2)) + 1] + b'\x42\xf6' + data[((x + 3) + (y * 2)) + 1:]
                                    x = x + 2
                                data = data2
                    continue

        return data
```

- [ ] **Step 1.4: Run — expect green**

```bash
/home/kali/hack3270-update/.venv/bin/pytest tests/test_tn3270_legacy.py -v
```

Expected: **all 19 tests pass.** If a golden test fails, do NOT "fix" `_do_manipulate` — re-check the copy against L1869-1996 character by character. The most likely transcription errors: indentation of `continue` (L1925/1941/1976/1994) and the dead-store at L1903-1904.

- [ ] **Step 1.5: Verify GUI contract still passes**

```bash
/home/kali/hack3270-update/.venv/bin/pytest tests/test_gui_contract.py -v
```

Expected: **5 passed** (we haven't touched libhack3270.py yet).

- [ ] **Step 1.6: Commit**

```bash
git add hack3270_libs/tn3270_legacy.py tests/test_tn3270_legacy.py
git commit -m "feat(phase1): TN3270Legacy(Protocol) wrapping legacy manipulate()"
```

---

## Task 2: EBCDIC shim — 256-byte diff verification

**Files:**
- Create: `tests/test_shim_ebcdic.py`
- Modify: `hack3270_libs/libhack3270.py` (L44-63 stays for now; L1782-1792 delegates)

Per spec §5 step 1.2: medium risk because the legacy `e2a` table has divergences from `cp037` (e.g. `[074]` typo at index 0x74, `≠` at 0x5F where cp037 has `^`). The TELNET_PATTERNS regexes (L66-92) match against `[0xNN]` strings, so we must verify those still produce. The 256-byte diff test enumerates every byte and documents accepted divergences.

**Strategy:** keep `e2a`/`a2e` at module level (TELNET_PATTERNS still imports them), but rewire `get_ascii`/`get_ebcdic` to delegate. The diff test asserts the *delegated* versions produce output the regexes can still consume.

- [ ] **Step 2.1: Write failing test**

Create `/home/kali/hack3270-update/tests/test_shim_ebcdic.py`:

```python
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


# Bytes where legacy e2a and cp037 disagree, with rationale.
# After Task 2 the shim uses cp037, so display strings change for
# these bytes. Each is non-load-bearing (no regex matches them).
ACCEPTED_DIVERGENCES = {
    0x4A: ("¢",   "["),     # legacy: cent sign / cp037: bracket — neither used by patterns
    0x5F: ("≠",   "^"),     # legacy: not-equal / cp037: caret
    0x6A: ("|",   "¦"),     # cp037 broken-bar maps outside ASCII → '[0x6A]' in EbcdicCodec
    0x74: ("[074]", "[0x74]"),  # legacy TYPO ('[074]' missing 'x') — cp037 fixes it
    # Add more here as discovered by test_full_256_diff
}


def test_full_256_diff():
    """The actual diff. Run this first — it tells you which bytes
    diverge so you can populate ACCEPTED_DIVERGENCES above."""
    import libhack3270
    from hackterm_core import EbcdicCodec

    codec = EbcdicCodec("cp037")
    legacy_e2a = libhack3270.e2a

    diffs = {}
    for b in range(256):
        legacy = legacy_e2a[b]
        new = codec.to_ascii(bytes([b]))
        if legacy != new:
            diffs[b] = (legacy, new)

    unexpected = {b: v for b, v in diffs.items()
                  if b not in ACCEPTED_DIVERGENCES}
    # If this fails, inspect `unexpected` and either fix the shim
    # or add to ACCEPTED_DIVERGENCES with rationale.
    assert not unexpected, \
        f"undocumented divergences: {unexpected!r}\n" \
        f"(add to ACCEPTED_DIVERGENCES if cosmetic-only)"


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
            f"byte 0x{b:02X} → {out!r}, TELNET_PATTERNS regex won't match"


def test_get_ascii_printable_unchanged(legacy_hack3270):
    """EBCDIC 'HELLO' (C8 C5 D3 D3 D6) → 'HELLO' — both old and new."""
    h = legacy_hack3270
    assert h.get_ascii(b"\xC8\xC5\xD3\xD3\xD6") == "HELLO"


def test_get_ebcdic_round_trip(legacy_hack3270):
    """ASCII → EBCDIC → ASCII for printables."""
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
```

- [ ] **Step 2.2: Run — expect 1 fail (delegate not wired)**

```bash
/home/kali/hack3270-update/.venv/bin/pytest tests/test_shim_ebcdic.py -v
```

Expected: `test_shim_get_ascii_delegates_to_codec` fails (no `_codec` attr). `test_full_256_diff` may also fail — that's expected, it shows you the actual diff to populate `ACCEPTED_DIVERGENCES`.

- [ ] **Step 2.3: Modify `libhack3270.py` — add codec, delegate**

Edit `/home/kali/hack3270-update/hack3270_libs/libhack3270.py`:

**At line 26** (after existing imports), add:

```python
from hackterm_core import EbcdicCodec
```

**At line 265** (inside `__init__`, after `self.logger.debug("Hack3270 Initializing")`), add:

```python
        # Phase 1: hackterm-core delegation
        self._codec = EbcdicCodec("cp037")
```

**Replace lines 1782-1792** (`get_ascii` / `get_ebcdic`) with:

```python
    def get_ascii(self, ebcdic_string):
        ''' Converts EBCDIC to ASCII — delegates to EbcdicCodec.'''
        return self._codec.to_ascii(ebcdic_string)

    def get_ebcdic(self, string):
        ''' Converts ASCII to EBCDIC — delegates to EbcdicCodec.
        BEHAVIOR CHANGE vs legacy: chars not in cp037 raise
        UnicodeEncodeError instead of being silently dropped.
        Legacy silently dropping was a bug (malformed packets).'''
        return self._codec.to_ebcdic(string)
```

**Do NOT delete `e2a`/`a2e` (L44-63)** — `parse_telnet` and `parse_3270` (kept in Phase 1) reference them via `TELNET_PATTERNS` regexes that match `[0xNN]` strings. The tables are now dead for encoding/decoding but live for documentation. Phase 3 deletes them when `parse_telnet` is replaced.

- [ ] **Step 2.4: Run — populate ACCEPTED_DIVERGENCES if needed**

```bash
/home/kali/hack3270-update/.venv/bin/pytest tests/test_shim_ebcdic.py -v
```

If `test_full_256_diff` fails: copy the `unexpected` dict from the assertion message into `ACCEPTED_DIVERGENCES`, verifying each entry is cosmetic-only (i.e. the byte does not appear in any TELNET_PATTERNS or TN3270_PATTERNS regex). Re-run.

Expected after iteration: **6 passed.**

- [ ] **Step 2.5: Verify nothing else broke**

```bash
/home/kali/hack3270-update/.venv/bin/pytest tests/ -v
```

Expected: GUI contract + golden + ebcdic all green.

- [ ] **Step 2.6: Commit**

```bash
git add hack3270_libs/libhack3270.py tests/test_shim_ebcdic.py
git commit -m "refactor(phase1): get_ascii/get_ebcdic delegate to EbcdicCodec"
```

---

## Task 3: Storage shim — old .db files replay

**Files:**
- Create: `tests/test_shim_storage.py`
- Modify: `hack3270_libs/libhack3270.py` (L287-513)

Per spec §5 step 1.4: low risk because `Storage` already uses the identical schema. The complication: legacy `db_init` has offline-mode validation (L302-310) and config-mismatch raising (L333-358) that `Storage` doesn't have. The shim wraps `Storage` and re-adds those checks.

**Subtle issue — note tagging:** legacy `write_database_log` (L416-417) auto-tags `"tn3270 negotiation"`; `Storage.log` (storage.py:113-114) auto-tags `"telnet negotiation"`. The GUI's log filter (gui.py log tab) may grep for the legacy string. The shim must override.

- [ ] **Step 3.1: Write failing test**

Create `/home/kali/hack3270-update/tests/test_shim_storage.py`:

```python
"""
Storage shim tests.

Verify libhack3270.hack3270 delegates db operations to
hackterm_core.Storage while preserving exact GUI-facing semantics.
"""
import sqlite3
import pytest


def test_shim_has_storage_instance(legacy_hack3270):
    from hackterm_core import Storage
    h = legacy_hack3270
    assert hasattr(h, "_storage")
    assert isinstance(h._storage, Storage)


def test_write_database_log_delegates(legacy_hack3270):
    h = legacy_hack3270
    h.write_database_log("S", "test note", b"\x05hello")
    rows = h.all_logs()
    assert len(rows) == 1
    assert rows[0][2] == "S"
    assert rows[0][3] == "test note"
    assert rows[0][5] == b"\x05hello"


def test_write_database_log_legacy_negotiation_tag(legacy_hack3270):
    """L416-417: data starting 0xFF gets 'tn3270 negotiation' appended.
    Storage.log uses 'telnet negotiation'. Shim must override to keep
    legacy tag — GUI log filter may match it."""
    h = legacy_hack3270
    h.write_database_log("S", "", b"\xFF\xFD\x28")
    rows = h.all_logs()
    assert "tn3270 negotiation" in rows[0][3]


def test_get_log_returns_list_not_tuple(legacy_hack3270):
    """Storage.get_log returns Optional[tuple]. Legacy returns list
    (fetchall). gui.py:2081 does `for row in get_log(id):` — must iterate."""
    h = legacy_hack3270
    h.write_database_log("S", "", b"data")
    result = h.get_log(1)
    assert isinstance(result, list)
    assert len(result) == 1
    assert result[0][5] == b"data"


def test_get_log_missing_returns_empty_list(legacy_hack3270):
    h = legacy_hack3270
    assert h.get_log(99999) == []


def test_check_server_delegates(legacy_hack3270):
    h = legacy_hack3270
    h.write_database_log("S", "", b"server")
    h.write_database_log("C", "", b"client")
    assert h.check_server(1) is True
    assert h.check_server(2) is False


def test_check_record_delegates(legacy_hack3270):
    """check_record (L495-505): True if first byte is 0xFF (telnet)."""
    h = legacy_hack3270
    h.write_database_log("S", "", b"\xFF\xFD\x28")
    h.write_database_log("S", "", b"\x05data")
    assert h.check_record(1) is True
    assert h.check_record(2) is False


def test_old_db_file_opens(tmp_path, monkeypatch):
    """Spec §5.1.4: existing .db files replay.
    Create a db with raw sqlite3 using the LEGACY schema, then open
    it via the shim."""
    monkeypatch.chdir(tmp_path)
    db = tmp_path / "oldproj.db"
    conn = sqlite3.connect(str(db))
    conn.execute(
        "CREATE TABLE Config (CREATION_TS TEXT NOT NULL, "
        "SERVER_IP TEXT NOT NULL, SERVER_PORT INT NOT NULL, "
        "PROXY_PORT INT NOT NULL, TLS_ENABLED INT NOT NULL)"
    )
    conn.execute(
        "INSERT INTO Config VALUES (?, ?, ?, ?, ?)",
        ("123.456", "10.0.0.1", 23, 3271, 0),
    )
    conn.execute(
        "CREATE TABLE Logs (ID INTEGER PRIMARY KEY AUTOINCREMENT, "
        "TIMESTAMP TEXT, C_S CHAR(1), NOTES TEXT, DATA_LEN INT, "
        "RAW_DATA BLOB(4000))"
    )
    conn.execute(
        "INSERT INTO Logs (TIMESTAMP, C_S, NOTES, DATA_LEN, RAW_DATA) "
        "VALUES (?, ?, ?, ?, ?)",
        ("123.456", "S", "old packet", 5, b"\x05old!"),
    )
    conn.commit()
    conn.close()

    import libhack3270, logging
    h = libhack3270.hack3270(
        server_ip="10.0.0.1", server_port=23, proxy_port=3271,
        project_name="oldproj", loglevel=logging.CRITICAL,
    )
    rows = h.all_logs()
    assert len(rows) == 1
    assert rows[0][5] == b"\x05old!"
    h.sql_con.close()


def test_sql_con_attr_still_exists(legacy_hack3270):
    """gui.py and on_closing (L276) reference self.sql_con directly.
    Shim must keep this alias to Storage's connection."""
    h = legacy_hack3270
    assert h.sql_con is h._storage.conn


def test_offline_mode_no_db_no_ip_raises(tmp_path, monkeypatch):
    """L302-310: offline mode + no existing db + no IP → SystemExit."""
    monkeypatch.chdir(tmp_path)
    import libhack3270, logging
    with pytest.raises(SystemExit):
        libhack3270.hack3270(
            server_ip=None, server_port=None, proxy_port=3271,
            offline_mode=True, project_name="nonexistent",
            loglevel=logging.CRITICAL,
        )
```

- [ ] **Step 3.2: Run — expect failures**

```bash
/home/kali/hack3270-update/.venv/bin/pytest tests/test_shim_storage.py -v
```

Expected: `test_shim_has_storage_instance` and `test_sql_con_attr_still_exists` fail; others pass (legacy code still works).

- [ ] **Step 3.3: Modify `libhack3270.py` — replace db_init body**

Edit `/home/kali/hack3270-update/hack3270_libs/libhack3270.py`:

**At line 26** (imports — `EbcdicCodec` already there from Task 2), extend:

```python
from hackterm_core import EbcdicCodec, Storage
```

**Replace `db_init` method body (L287-413)** with:

```python
    def db_init(self):
        '''Delegates to hackterm_core.Storage. Re-adds legacy
        offline-mode + config-mismatch validation that Storage
        intentionally omits (it's tool-specific policy).'''

        # Legacy validation L302-310: offline + no db + no IP → die
        if not Path(self.db_filename).is_file() and not self.server_ip:
            if self.offline_mode:
                print(f"Error: Project file '{self.db_filename}' not found.")
                print(f"Offline mode requires an existing project database.")
                print(f"Use -n to specify a project name: python hack3270.py -n <project> -o")
                raise SystemExit(1)
            else:
                raise Exception("Cannot initialize without a server IP and port")

        # Remember whether config existed BEFORE Storage opens it
        # (Storage creates Config if missing, so we can't check after)
        had_existing = Path(self.db_filename).is_file()
        if had_existing:
            _probe = sqlite3.connect(self.db_filename)
            _has_config = _probe.execute(
                "SELECT count(name) FROM sqlite_master "
                "WHERE TYPE='table' AND NAME='Config'"
            ).fetchone()[0] == 1
            _probe.close()
        else:
            _has_config = False

        self._storage = Storage(
            self.db_filename,
            server_ip=self.server_ip or "",
            server_port=self.server_port or 0,
            proxy_port=self.proxy_port,
            tls_enabled=self.tls_enabled,
        )

        # Legacy attr aliases — gui.py and on_closing (L276) read these
        self.sql_con = self._storage.conn
        self.sql_cur = self._storage.conn.cursor()

        # Legacy config-mismatch validation (L333-358)
        if _has_config and not self.offline_mode:
            if self.server_ip and self.server_ip != self._storage.server_ip:
                raise ProjectConfigError(
                    f"IP address mismatch with existing project '{self.project_name}.db'.\n"
                    f"  Command line: {self.server_ip}\n"
                    f"  Project file: {self._storage.server_ip}\n"
                    f"Either use the correct IP or delete '{self.project_name}.db' to start fresh."
                )
            if self.server_port and self.server_port != self._storage.server_port:
                raise ProjectConfigError(
                    f"Server port mismatch with existing project '{self.project_name}.db'.\n"
                    f"  Command line: {self.server_port}\n"
                    f"  Project file: {self._storage.server_port}\n"
                    f"Either use the correct port or delete '{self.project_name}.db' to start fresh."
                )

        # Adopt config from db (legacy L340-358)
        self.server_ip = self._storage.server_ip
        self.server_port = self._storage.server_port
        self.proxy_port = self._storage.proxy_port
        self.tls_enabled = self._storage.tls_enabled
```

**Replace `write_database_log` (L414-437)** with:

```python
    def write_database_log(self, direction, notes, data):
        '''Delegates to Storage.log. Override the auto-tag:
        Storage uses 'telnet negotiation', legacy used 'tn3270 negotiation'.
        GUI log filter may grep for the legacy string.'''
        if data and data[0] == 255:
            notes = notes + "tn3270 negotiation"
            # Pass a non-IAC marker so Storage doesn't double-tag.
            # Actually simpler: bypass Storage's auto-tag by going
            # straight to the cursor. But that breaks encapsulation.
            # Cleanest: Storage already tags; we want OUR tag instead.
            # So: don't let Storage see IAC. Tag here, then prepend
            # a fake non-IAC byte? No — that corrupts data.
            #
            # Real solution: Storage.log appends 'telnet negotiation'
            # to notes. We pre-empt by appending our tag, then check
            # in the test that 'tn3270' substring is present (which
            # it will be even if Storage appends 'telnet' too).
            #
            # Even simpler: just call the cursor directly here. The
            # shim is allowed to be ugly — that's its job.
            import time
            self.sql_cur.execute(
                "INSERT INTO Logs (TIMESTAMP, C_S, NOTES, DATA_LEN, RAW_DATA) "
                "VALUES (?, ?, ?, ?, ?)",
                (str(time.time()), direction, notes, len(data),
                 sqlite3.Binary(data)),
            )
            self.sql_con.commit()
            return
        self._storage.log(direction, notes, data)
```

**Replace `all_logs` (L439-454)** with:

```python
    def all_logs(self, start=0):
        return self._storage.all_logs(start)
```

**Replace `get_log` (L456-460)** with:

```python
    def get_log(self, record_id):
        '''Storage.get_log returns Optional[tuple]; legacy returned
        fetchall() list. GUI iterates: `for row in get_log(id)`.'''
        row = self._storage.get_log(record_id)
        return [row] if row else []
```

**Replace `check_server` (L484-493)** with:

```python
    def check_server(self, record_id):
        return self._storage.is_server_record(record_id)
```

**Replace `check_record` (L495-505)** with:

```python
    def check_record(self, record_id):
        return self._storage.is_telnet_record(record_id)
```

**Replace `play_record` (L507-513)** with:

```python
    def play_record(self, record_id):
        raw = self._storage.get_raw(record_id)
        if raw and self.client:
            self.client.send(raw)
```

**Keep `check_inject_3270e` (L462-482) for now** — it reads SQLite directly and the GUI calls it (gui.py:1571,2869,3164). Task 4 rewires it to read `self._protocol.is_tn3270e`.

- [ ] **Step 3.4: Run — expect green**

```bash
/home/kali/hack3270-update/.venv/bin/pytest tests/test_shim_storage.py -v
```

Expected: **10 passed.**

- [ ] **Step 3.5: Full suite**

```bash
/home/kali/hack3270-update/.venv/bin/pytest tests/ -v
```

Expected: all green.

- [ ] **Step 3.6: Commit**

```bash
git add hack3270_libs/libhack3270.py tests/test_shim_storage.py
git commit -m "refactor(phase1): db_init/write_database_log delegate to Storage"
```

---

## Task 4: ProxyDaemon shim — daemon() becomes tick() driver

**Files:**
- Create: `tests/test_shim_daemon.py`
- Modify: `hack3270_libs/libhack3270.py` (L779-845, L1329-1471, L462-482)

Per spec §5 step 1.3: medium risk. This is the most invasive change. The legacy `daemon()` is a 142-line monolith mixing: select() loop, API client handling, three different client-intercept modes (capture_mask / aid_fuzzer_armed / aid_spoof_manual), and the `hack_toggled` re-send.

**Strategy — keep `daemon()` as the GUI entry point but gut its body:**
1. `__init__` creates `ProxyDaemon` (lazily — sockets aren't bound until `client_connect`).
2. `client_connect` / `server_connect` delegate, then **alias** `self.client = self._daemon.client` so `tend_server`/`send_key`/`api_send_raw` (L1317,1535,1505) keep working without changes.
3. `daemon()` body: (a) sync `self.hack_*` flags onto `self._daemon.mutate_opts`, (b) build a client-intercept closure from current `inject_setup_capture`/`aid_*` state, (c) call `self._daemon.tick()`, (d) handle `hack_toggled` resend (which `ProxyDaemon` doesn't model — it's a "re-send last server packet through mutate again" hack).

**The hack_toggled problem:** `ProxyDaemon.tick()` always mutates server traffic (proxy.py:206). Legacy `daemon()` sends server traffic UNMUTATED via `handle_server` (L1309: only mutate `if hack_on or hack_color_on`), then SEPARATELY re-sends a mutated copy when toggles flip (L1469). These are different semantics. **Resolution:** `TN3270Legacy.mutate()` already does the right thing — when all `MutateOpts` are False, it returns input unchanged (verified by `test_mutate_no_opts_passthrough` in Task 1). So `ProxyDaemon`'s always-mutate is fine. The `hack_toggled` resend lives on the shim: it stashes last server bytes, and when toggled, re-injects via `self._daemon.inject_to_client(self.manipulate(self.server_data))`.

**check_inject_3270e rewrite:** Currently reads SQLite row 1 (L472-482). After this task, `TN3270Legacy.detect()` runs during the first `tick()` and caches `is_tn3270e`. The shim's `check_inject_3270e()` becomes `return self._protocol.is_tn3270e`. **But:** GUI calls it BEFORE the daemon loop starts (gui.py:3794, right after `server_connect`). At that point detect() hasn't run yet. **Workaround:** keep the SQLite-reading fallback for the case where `_protocol.is_tn3270e` hasn't been set yet AND row 1 exists from a previous session.

- [ ] **Step 4.1: Write failing test**

Create `/home/kali/hack3270-update/tests/test_shim_daemon.py`:

```python
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
    out = intercept(b"\x7D\x40\x40\xFF\xEF")  # ENTER + cursor + IAC EOR
    assert out is not None
    assert out[0] == 0xF1  # PF1


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


def test_server_data_observer_stashes_last(legacy_hack3270, monkeypatch):
    """The shim must register an observer that stashes server traffic
    into self.server_data — gui.py reads it directly."""
    h = legacy_hack3270
    # The observer should have been registered in __init__
    assert len(h._daemon._observers) >= 1
    # Trigger it
    for obs in h._daemon._observers:
        obs(b"server bytes", "s2c")
    assert h.server_data == b"server bytes"


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
```

- [ ] **Step 4.2: Run — expect failures**

```bash
/home/kali/hack3270-update/.venv/bin/pytest tests/test_shim_daemon.py -v
```

Expected: most fail with `AttributeError: 'hack3270' object has no attribute '_daemon'`.

- [ ] **Step 4.3: Modify `libhack3270.py` — wire ProxyDaemon**

Edit `/home/kali/hack3270-update/hack3270_libs/libhack3270.py`:

**Extend imports at line 26:**

```python
from hackterm_core import EbcdicCodec, Storage, ProxyDaemon, MutateOpts
from tn3270_legacy import TN3270Legacy
```

**In `__init__`, after `self._codec = EbcdicCodec("cp037")` (added Task 2), add:**

```python
        # Phase 1: protocol + proxy daemon
        self._protocol = TN3270Legacy()
        self._daemon = ProxyDaemon(
            protocol=self._protocol,
            storage=self._storage,
            listen_addr=(self.proxy_ip, self.proxy_port),
            target_addr=(self.server_ip or "", self.server_port or 0),
            use_tls=self.tls_enabled,
        )
        # Observer: stash last server bytes for hack_toggled resend
        # and gui.py direct reads (get_last_server_raw etc.)
        def _stash_server(data, direction):
            if direction == "s2c":
                self.server_data = data
                self.refresh_aids(data)
        self._daemon.add_observer(_stash_server)
```

**NOTE — ordering:** `self._storage` is created inside `db_init()` which is called at L266 — that's BEFORE this block. Good. But `self.proxy_port` may be overwritten by `db_init` adopting config from db. So this block must come AFTER `self.db_init()`. Place it right after L266 (`self.db_init()`) and before L268 (`self.logger.debug("Project Name...")`).

**Replace `client_connect` (L779-801)** with:

```python
    def client_connect(self):
        '''Delegates to ProxyDaemon.wait_for_client.
        Aliases socket back so tend_server/send_key keep working.'''
        self.logger.debug("Setting up proxy listener on {}:{}".format(
            self.proxy_ip, self.proxy_port))
        self._daemon.wait_for_client()
        self.client = self._daemon.client
```

**Replace `server_connect` (L803-845)** with:

```python
    def server_connect(self):
        '''Delegates to ProxyDaemon.connect_to_server.'''
        if self.offline_mode:
            raise Hack3270Error("Cannot connect when in Offline Mode")
        self.logger.debug("Connecting to {}:{}".format(
            self.server_ip, self.server_port))
        try:
            self._daemon.connect_to_server()
        except ConnectionRefusedError:
            raise ConnectionError(
                f"Connection refused by {self.server_ip}:{self.server_port}.\n"
                f"Make sure the TN3270 server is running and accessible."
            )
        except socket.timeout:
            raise ConnectionError(
                f"Connection timed out to {self.server_ip}:{self.server_port}."
            )
        except socket.gaierror as e:
            raise ConnectionError(f"Cannot resolve hostname '{self.server_ip}': {e}")
        except OSError as e:
            raise ConnectionError(
                f"Network error connecting to {self.server_ip}:{self.server_port}: {e}"
            )
        self.server = self._daemon.server
```

**Replace `check_inject_3270e` (L462-482)** with:

```python
    def check_inject_3270e(self):
        '''Replaces SQLite-row-1 inspection with TN3270Legacy.is_tn3270e.

        Fallback: gui.py:3794 calls this BEFORE daemon() runs, so the
        protocol may not have detected yet. If handshake isn't complete
        but a previous session left row 1 in the db, use that.'''
        if self._daemon.handshake_complete:
            return self._protocol.is_tn3270e
        # Fallback to legacy row-1 check
        row = self._storage.get_log(1)
        if row and row[5] and len(row[5]) >= 3 and row[5][2] == 40:
            # Sync the cached state too so subsequent calls are fast
            self._protocol._is_tn3270e = True
            return True
        return self._protocol.is_tn3270e
```

**Replace `daemon` (L1329-1471)** with:

```python
    def daemon(self):
        '''Drives ProxyDaemon.tick(). Replaces the 142-line monolith.

        Steps each call:
          1. Sync hack_* flags → daemon.mutate_opts (5-field subset)
          2. Build client-intercept callback from current state
          3. Pump API listener (still inline — Phase 2 moves to ApiServer)
          4. tick()
          5. Handle hack_toggled resend (not modeled by ProxyDaemon)
        '''
        # ── 1. Sync flags ──
        # Map 14 legacy flags onto 5 MutateOpts. Lossy on purpose:
        # the full-fidelity path is hack_toggled → manipulate() → _do_manipulate(self).
        # The tick() path uses MutateOpts so future Phase 3 attacks
        # see a clean interface.
        opts = self._daemon.mutate_opts
        opts.unprotect      = bool(self.hack_on and self.hack_prot)
        opts.reveal_hidden  = bool(self.hack_on and self.hack_hf)
        opts.remove_numeric = bool(self.hack_on and self.hack_rnr)
        opts.high_visibility = bool(self.hack_on and self.hack_hv)
        opts.color_reveal   = bool(self.hack_color_on)

        # ── 2. Client intercept ──
        # Replaces inline branches at L1381-1399.
        intercept = None
        if self.inject_setup_capture:
            def intercept(data):
                self.capture_mask(data)
                return None  # drop, don't forward
        elif (self.aid_spoof_enabled
              and self.aid_spoof_mode == 'FUZZER'
              and self.aid_fuzzer_armed
              and not self.aid_fuzzer_running):
            def intercept(data):
                self.aid_fuzzer_captured_data = data
                self.aid_fuzzer_armed = False
                self.aid_fuzzer_running = True
                self.aid_fuzzer_progress = 0
                if self.aid_fuzzer_callback:
                    self.aid_fuzzer_callback('captured', 0, 256, None)
                return None  # drop
        elif (self.aid_spoof_enabled
              and self.aid_spoof_mode == 'MANUAL'):
            def intercept(data):
                if len(data) < 1:
                    return data
                modified, orig, spoofed = self.spoof_aid(data)
                self.write_database_log(
                    'C', f"AID Spoofed: {orig} -> {spoofed}", modified)
                # Return modified — daemon forwards it & logs
                # (double-log is a known legacy quirk, kept)
                # Actually: returning modified makes daemon log AGAIN
                # via storage.log. Legacy logged once. To match: send
                # here, return None.
                self.server.send(modified)
                return None
        self._daemon.set_client_intercept(intercept)

        # ── 3. API listener (kept inline for Phase 1) ──
        # The legacy daemon() embedded API handling (L1334-1372).
        # ProxyDaemon doesn't know about it. Pump it separately.
        # Phase 2 moves this onto hackterm_core.ApiServer.
        if self.api_listener:
            self._pump_api()

        # ── 4. Tick ──
        self._daemon.tick()

        # Re-alias in case daemon swapped sockets (it doesn't, but be safe)
        self.client = self._daemon.client
        self.server = self._daemon.server

        # ── 5. hack_toggled resend (L1414-1471) ──
        if (self.hack_toggled or self.hack_color_toggled) and self.server_data:
            log_line = ''
            if self.hack_toggled:
                log_line = (self.hack_on_logline() if self.hack_on
                            else 'Hack Fields Attributes: TOGGLED OFF ')
                self.hack_toggled = 0
            if self.hack_color_toggled:
                log_line += (self.hack_color_on_logline() if self.hack_color_on
                             else 'Hack Text Color: TOGGLED OFF ')
                self.hack_color_toggled = 0
            hacked = self.manipulate(self.server_data)
            self._daemon.inject_to_client(hacked)
            self.write_database_log('S', log_line, hacked)

    def _pump_api(self):
        '''Legacy API listener pump — extracted from daemon() L1334-1372.
        Phase 2 replaces with hackterm_core.ApiServer.'''
        readable = [self.api_listener] + self.api_clients
        try:
            rlist, _, _ = select.select(readable, [], [], 0)
        except (ValueError, OSError):
            return
        if self.api_listener in rlist:
            try:
                api_client, addr = self.api_listener.accept()
                api_client.setblocking(False)
                self.api_clients.append(api_client)
            except Exception as e:
                self.logger.error(f"Error accepting API connection: {e}")
        for api_client in self.api_clients[:]:
            if api_client in rlist:
                try:
                    data = api_client.recv(BUFFER_MAX)
                    if len(data) > 0:
                        self.handle_api_request(api_client, data)
                    else:
                        self.api_clients.remove(api_client)
                        api_client.close()
                except Exception as e:
                    self.logger.error(f"Error handling API client: {e}")
                    self.api_clients.remove(api_client)
                    try: api_client.close()
                    except: pass
```

**Replace `manipulate` (L1869-1996)** with delegation:

```python
    def manipulate(self, tn3270_data):
        '''Delegates to TN3270Legacy._do_manipulate, passing self
        as the flags object. Full-fidelity 14-flag path.'''
        self.current_state_debug_msg()
        return self._protocol._do_manipulate(tn3270_data, self)
```

**Delete `flip_bits` (L1816-1849) and `check_hidden` (L1851-1867)** — they live in `tn3270_legacy.py` now and nothing else in `libhack3270.py` calls them.

**Delete `handle_server` (L1299-1315)** — no longer called. `tend_server` (L1317-1327) needs updating to inline what handle_server did, OR keep handle_server for tend_server's use. **Decision: keep handle_server.** It's used by `tend_server` which is used by AID fuzzer (L1697) and inject loop (gui.py:3345). Leave it; it calls `self.manipulate()` which now delegates. No change needed.

- [ ] **Step 4.4: Run — iterate to green**

```bash
/home/kali/hack3270-update/.venv/bin/pytest tests/test_shim_daemon.py -v
```

Expected first run: some tests fail on ordering issues (e.g. `_storage` not existing when `_daemon` is created if you put the daemon block before `db_init`). Fix ordering. Re-run.

Expected after fixes: **14 passed.**

- [ ] **Step 4.5: Verify golden tests still pass**

```bash
/home/kali/hack3270-update/.venv/bin/pytest tests/test_tn3270_legacy.py tests/test_gui_contract.py -v
```

Critical: `test_golden_manipulate` must still pass — proves `manipulate()` delegation is bit-perfect.

- [ ] **Step 4.6: Full suite**

```bash
/home/kali/hack3270-update/.venv/bin/pytest tests/ -v
```

Expected: all green.

- [ ] **Step 4.7: Commit**

```bash
git add hack3270_libs/libhack3270.py tests/test_shim_daemon.py
git commit -m "refactor(phase1): daemon() drives ProxyDaemon.tick(); manipulate() delegates"
```

---

## Task 5: MaskInjector shim — capture_mask delegates

**Files:**
- Create: `tests/test_shim_inject.py`
- Modify: `hack3270_libs/libhack3270.py` (L1708-1747)

Per spec §5 step 1.5: low risk. `MaskInjector.capture()` (inject.py:42-74) is functionally identical to `capture_mask` (L1708-1747). The shim must copy `injector.preamble`/`postamble`/`mask_len` back to `self.inject_*` attrs because gui.py reads them via `get_inject_preamble()` etc. (gui.py:3334-3336).

**Note:** `gui.py:3321-3354 _inject_one_line` does NOT use `MaskInjector.build()` — it manually concatenates `preamble + ebcdic + postamble` (gui.py:3334). Phase 1 keeps that working unchanged. Phase 2 will switch GUI to call `injector.build()` directly.

- [ ] **Step 5.1: Write failing test**

Create `/home/kali/hack3270-update/tests/test_shim_inject.py`:

```python
"""
MaskInjector shim tests.

capture_mask must delegate to MaskInjector.capture and copy results
back to legacy attributes that gui.py:3334 reads.
"""
import pytest


def test_shim_creates_injector(legacy_hack3270):
    from hackterm_core import MaskInjector
    h = legacy_hack3270
    assert hasattr(h, "_injector")
    assert isinstance(h._injector, MaskInjector)


def test_capture_mask_finds_run(legacy_hack3270):
    """EBCDIC '*' is 0x5C. Packet: pre + *** + post."""
    h = legacy_hack3270
    h.set_inject_mask("*")
    h.set_inject_setup_capture(1)
    # ENTER + cursor + *** + IAC EOR
    pkt = b"\x7D\x40\x40" + b"\x5C\x5C\x5C" + b"\xFF\xEF"
    h.capture_mask(pkt)
    assert h.inject_mask_len == 3
    assert h.inject_preamble == b"\x7D\x40\x40"
    assert h.inject_postamble == b"\xFF\xEF"
    assert h.inject_config_set == 1
    assert h.inject_setup_capture is False  # cleared after capture


def test_capture_mask_no_run(legacy_hack3270):
    h = legacy_hack3270
    h.set_inject_mask("*")
    h.set_inject_setup_capture(1)
    pkt = b"\x7D\x40\x40\xC8\xC5\xD3\xD3\xD6\xFF\xEF"  # no asterisks
    h.capture_mask(pkt)
    assert h.inject_mask_len == 0
    assert h.inject_config_set == 0


def test_capture_mask_logs(legacy_hack3270):
    """L1740/1746: capture_mask writes to db log."""
    h = legacy_hack3270
    h.set_inject_mask("*")
    h.capture_mask(b"\x7D\x40\x40\x5C\x5C\xFF\xEF")
    rows = h.all_logs()
    assert len(rows) == 1
    assert "Inject setup" in rows[0][3]


def test_get_inject_methods_unchanged(legacy_hack3270):
    """gui.py:3334 reads via getters — they must reflect injector state."""
    h = legacy_hack3270
    h.set_inject_mask("*")
    h.capture_mask(b"\x7D\x40\x40\x5C\x5C\x5C\x5C\xFF\xEF")
    assert h.get_inject_mask_len() == 4
    assert h.get_inject_preamble() == b"\x7D\x40\x40"
    assert h.get_inject_postamble() == b"\xFF\xEF"
    assert h.get_inject_config_set() == 1


def test_set_inject_mask_updates_injector(legacy_hack3270):
    """Changing mask char must propagate to MaskInjector."""
    h = legacy_hack3270
    h.set_inject_mask("#")
    # EBCDIC '#' is 0x7B
    h.capture_mask(b"\x7D\x40\x40\x7B\x7B\xFF\xEF")
    assert h.inject_mask_len == 2


def test_gui_inject_one_line_compat(legacy_hack3270):
    """Mirror exactly what gui.py:3333-3338 does after capture."""
    h = legacy_hack3270
    h.set_inject_mask("*")
    h.capture_mask(b"\x7D\x40\x40\x5C\x5C\x5C\x5C\x5C\xFF\xEF")  # 5 asterisks

    line = "HELLO"  # exactly 5 chars, fits TRUNC mode
    injection_ebcdic = h.get_ebcdic(line)
    bytes_ebcdic = (h.get_inject_preamble() +
                    injection_ebcdic +
                    h.get_inject_postamble())

    assert bytes_ebcdic == b"\x7D\x40\x40" + b"\xC8\xC5\xD3\xD3\xD6" + b"\xFF\xEF"
```

- [ ] **Step 5.2: Run — expect failures**

```bash
/home/kali/hack3270-update/.venv/bin/pytest tests/test_shim_inject.py -v
```

Expected: `test_shim_creates_injector` and `test_set_inject_mask_updates_injector` fail.

- [ ] **Step 5.3: Modify `libhack3270.py`**

**Extend imports:**

```python
from hackterm_core import EbcdicCodec, Storage, ProxyDaemon, MutateOpts, MaskInjector
```

**In `__init__`, after `self._codec = EbcdicCodec(...)`, add:**

```python
        self._injector = MaskInjector(self._codec, mask_char="*")
```

**Replace `set_inject_mask` (L772-775)** with:

```python
    def set_inject_mask(self, mask="*"):
        '''Sets the mask char. Recreates MaskInjector since mask_char
        is set in __init__.'''
        self.logger.debug("Setting mask to '{}'".format(mask))
        self.inject_mask = mask
        self._injector = MaskInjector(self._codec, mask_char=mask)
```

**Replace `capture_mask` (L1708-1747)** with:

```python
    def capture_mask(self, client_data):
        '''Delegates to MaskInjector.capture, copies results to
        legacy attrs that gui.py:3334 reads.'''
        self.logger.debug("Capturing mask with '{}'".format(self.inject_mask))

        found = self._injector.capture(client_data)

        if found:
            self.inject_mask_len = self._injector.mask_len
            self.inject_preamble = self._injector.preamble
            self.inject_postamble = self._injector.postamble
            self.inject_config_set = 1
            log = 'Inject setup - Mask: {} - Length: {}'.format(
                self.inject_mask, self._injector.mask_len)
        else:
            self.inject_mask_len = 0
            self.inject_config_set = 0
            log = 'Inject setup - Mask: {} - Mask not found!'.format(
                self.inject_mask)

        self.logger.debug(log)
        self.write_database_log('C', log, client_data)
        self.inject_setup_capture = False
```

- [ ] **Step 5.4: Run — expect green**

```bash
/home/kali/hack3270-update/.venv/bin/pytest tests/test_shim_inject.py -v
```

Expected: **7 passed.**

- [ ] **Step 5.5: Full suite**

```bash
/home/kali/hack3270-update/.venv/bin/pytest tests/ -v
```

- [ ] **Step 5.6: Commit**

```bash
git add hack3270_libs/libhack3270.py tests/test_shim_inject.py
git commit -m "refactor(phase1): capture_mask delegates to MaskInjector"
```

---

## Task 6: Dead-code removal + line-count verification

**Files:**
- Modify: `hack3270_libs/libhack3270.py`

After Tasks 2-5, large swaths of `libhack3270.py` are dead: the `e2a`/`a2e` tables are unused for encoding (kept only as documentation reference for `parse_telnet` regex behavior — but the regexes match `EbcdicCodec` output now, so even that is moot), `flip_bits`/`check_hidden` were already deleted in Task 4. This task does final cleanup and verifies the file has shrunk substantially.

- [ ] **Step 6.1: Verify what's still referenced**

```bash
cd /home/kali/hack3270-update
# What in libhack3270 does GUI still call?
grep -oP 'self\.hack3270\.\w+' hack3270_libs/gui.py | sort -u > /tmp/gui_calls.txt
# What methods does libhack3270 still define?
grep -oP 'def \w+' hack3270_libs/libhack3270.py | sort -u > /tmp/lib_defs.txt
# Diff: what's defined but never called?
comm -23 /tmp/lib_defs.txt <(sed 's/self.hack3270./def /' /tmp/gui_calls.txt | sort -u)
```

Review output. Methods like `expand_CS` (L1519), `recv` (L1473) may be dead — verify before deleting.

- [ ] **Step 6.2: Delete confirmed-dead module-level items**

Delete from `libhack3270.py`:
- L44-63: `e2a` and `a2e` tables — IF `parse_telnet`/`parse_3270` no longer reference `self.get_ascii` against these. **Check first:** `parse_telnet` (L1998) calls `self.get_ascii` which now uses `EbcdicCodec`. The TELNET_PATTERNS regexes (L66-92) match against `[0xNN]` strings — `EbcdicCodec.to_ascii` produces those (verified Task 2). **Safe to delete `e2a`/`a2e`.**
- Verify `BUFFER_MAX` (L134) still referenced by `_pump_api`, `tend_server`, `recv` — keep it.

- [ ] **Step 6.3: Run full suite — must stay green**

```bash
/home/kali/hack3270-update/.venv/bin/pytest tests/ -v
```

- [ ] **Step 6.4: Line count check**

```bash
wc -l /home/kali/hack3270-update/hack3270_libs/libhack3270.py
```

Expected: ~600-800 lines (down from 2012). The shim keeps: `__init__`, all `set_*`/`get_*` flag accessors (~40 one-liners), AID fuzzer state machine (`arm_aid_fuzzer` through `run_aid_fuzzer`, ~150 lines), `parse_telnet`/`parse_3270` (display formatting, ~20 lines), API request handlers (`handle_api_request` through `_api_get_last_server_raw`, ~200 lines), `tend_server`/`handle_server`/`send_key`/`api_send_raw` (~50 lines), `export_csv`/`refresh_aids`/`current_aids` (~30 lines).

- [ ] **Step 6.5: Commit**

```bash
git add hack3270_libs/libhack3270.py
git commit -m "refactor(phase1): delete e2a/a2e tables and dead helpers"
```

---

## Task 7: Manual DVCA verification + tag

**Files:** none

Per spec §5.1.3: "All 9 GUI tabs work against DVCA". This is the only verification step that can't be automated — it requires a live z/OS or DVCA (Damn Vulnerable CICS Application) target.

- [ ] **Step 7.1: Verify hackterm-core test suite still passes**

```bash
/home/kali/hack3270-update/.venv/bin/pytest hackterm-core/tests/ -v
```

Expected: **74 passed** (unchanged from Phase 0).

- [ ] **Step 7.2: Verify Phase 1 test suite passes**

```bash
/home/kali/hack3270-update/.venv/bin/pytest tests/ -v
```

Expected: ~60 passed (5 contract + 19 legacy + 6 ebcdic + 10 storage + 14 daemon + 7 inject).

- [ ] **Step 7.3: Smoke-test against DVCA — checklist**

```bash
cd /home/kali/hack3270-update
.venv/bin/python hack3270.py 192.168.x.x 23 -n dvca_phase1_test
```

Then connect `x3270` or `c3270` to `127.0.0.1:3271`.

Per-tab checklist:

| Tab | Action | Pass criteria |
|---|---|---|
| 0. Hack Fields | Toggle "Remove Field Protection", press a key | Protected field becomes editable in x3270 |
| 1. Hack Colors | Toggle "Set Attribute" + black→visible | Black-on-black text visible |
| 2. Inject Keys | Click PF3 button | Server receives PF3, screen changes |
| 3. Inject Strings | Set mask `*`, type `****` in field, click SETUP | Status shows "Mask set! Field length: 4" |
| 3. Inject Strings | Inject from file with `HELLO` | Field receives HELLO, server responds |
| 4. Logs | Browse history, click a row | Detail pane shows decoded packet |
| 5. AID Spoof | Set MANUAL → PF1, press ENTER in x3270 | Server sees PF1, not ENTER |
| 6. AID Fuzzer | Arm, press ENTER, observe progress | 256 iterations, log fills |
| 7. Stats | View | Protocol shows TN3270 or TN3270E correctly |
| 8. Replay | Pick server packet, replay to client | x3270 redraws |

- [ ] **Step 7.4: Tag**

```bash
git tag phase1-complete
```

---

## Self-Review

**Spec coverage check** (against §5 Phase 1 table):

| Spec step | Plan task | Verification | ✓ |
|---|---|---|---|
| 1.1 Add hackterm-core dep | Task 0 (already installed via Phase 0) | `import hackterm_core` in conftest | ✓ |
| 1.2 Replace EBCDIC tables → EbcdicCodec | Task 2 | `test_full_256_diff`, `test_telnet_pattern_bytes_still_bracketed` | ✓ |
| 1.3 daemon() → ProxyDaemon | Task 4 | `test_daemon_pushes_hack_flags_to_mutate_opts`, manual DVCA tab walk | ✓ |
| 1.4 SQLite → Storage | Task 3 | `test_old_db_file_opens` | ✓ |
| 1.5 mask-injection → MaskInjector | Task 5 | `test_gui_inject_one_line_compat` | ✓ |
| 1.6 manipulate() → TN3270Legacy(Protocol) | Task 1 | `test_golden_manipulate` (4 fixtures) | ✓ |

**TN3270Legacy abstract method coverage:**

| Method | Test | Source ported from |
|---|---|---|
| `detect()` | `test_detect_*` (4 tests) | `check_inject_3270e` L462-482 |
| `negotiate_hook()` | `test_negotiate_hook_passthrough` | (no-op — new in Phase 3) |
| `parse()` | `test_parse_returns_empty_screen` | (stub — Phase 3 brings tn3270_v2) |
| `mutate()` | `test_mutate_*` + `test_golden_*` | `manipulate` L1869-1996 |
| `build_inbound()` | `test_build_inbound_*` (2 tests) | `send_key` L1531-1540 |
| `spoof_aid()` | `test_spoof_aid_*` (3 tests) | `spoof_aid` L1615-1649 |

**Risk register:**

| Risk | Mitigation | Residual |
|---|---|---|
| `manipulate()` transcription error | Golden bytes-in-bytes-out (Task 0+1) | LOW — 4 fixtures cover SF/SFE/SA/IAC paths |
| `MutateOpts` lossy mapping (5 vs 14 flags) | Two call paths: `daemon.tick()→mutate(opts)` for simple, `shim.manipulate()→_do_manipulate(self)` for full-fidelity | LOW — `hack_toggled` uses full path |
| GUI calls method we missed | `test_gui_contract.py` enumerates all `self.hack3270.X` references | LOW — list is grep-derived, may miss dynamic getattr |
| `check_inject_3270e` race (called before `detect()` runs) | SQLite row-1 fallback (Task 4) | LOW — same as legacy when no row exists |
| Storage `"telnet"` vs legacy `"tn3270"` note tag | Shim overrides for IAC packets (Task 3) | NONE |
| `EbcdicCodec` divergences from `e2a` table | `ACCEPTED_DIVERGENCES` documented per-byte (Task 2) | LOW — all cosmetic, no regex matches |

**Type/name consistency check:**
- `TN3270Legacy` — defined Task 1, instantiated Task 4 (`self._protocol`)
- `_do_manipulate(data, flags)` — defined Task 1, called by both `mutate()` (Task 1) and `shim.manipulate()` (Task 4)
- `is_tn3270e` property — set by `detect()`, read by `check_inject_3270e` and `spoof_aid`
- `_storage`, `_codec`, `_injector`, `_daemon`, `_protocol` — all underscore-prefixed (private), GUI never reads them
- `self.client`/`self.server` — aliased from `_daemon.client`/`_daemon.server` after each connect AND each `daemon()` call
- `self.sql_con`/`self.sql_cur` — aliased from `_storage.conn` (`on_closing` L276, `export_csv` need them)

**Things deliberately NOT done in Phase 1:**
- API listener migration to `ApiServer` — kept inline (`_pump_api`), Phase 2
- `parse_telnet`/`parse_3270` replacement — display-only, Phase 3
- `e2a` divergence fixes — documented not fixed, Phase 3
- `manipulate()` bug fixes (no-op `x = x + N`) — Phase 3 (`tn3270_v2`)
- GUI changes — zero, by design
