# Phase 0 — hackterm-core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the shared `hackterm-core` package that both `hack3270` and `hack5250` will depend on — Protocol ABC, headless proxy daemon, codepage-aware EBCDIC, SQLite storage, mask-template injection, and API server scaffolding.

**Architecture:** Standalone pip-installable package living at `hackterm-core/` (sibling to `hack3270_libs/`). Pure Python, no GUI dependencies. Code is *extracted* from `hack3270_libs/libhack3270.py` (specific line ranges cited per task) but generalized: the proxy takes a `Protocol` object instead of having 3270 logic baked in. Phase 0 produces a working core with a mock protocol; Phase 1 will wire `hack3270` onto it.

**Tech Stack:** Python 3.11+, `pytest`, stdlib only (`socket`, `select`, `ssl`, `sqlite3`, `codecs`, `abc`, `dataclasses`). No external runtime deps.

**Spec reference:** `docs/superpowers/specs/2026-04-07-hackterm-design.md` §2.1–§2.4

---

## File Structure

```
hackterm-core/
  pyproject.toml
  hackterm_core/
    __init__.py         # public API re-exports
    protocol.py         # Protocol ABC, Field/Screen/MutateOpts/NegotiateOpts/etc dataclasses
    ebcdic.py           # EbcdicCodec — wraps codecs, fallback table for control bytes
    storage.py          # Storage — SQLite Logs/Config, schema-compatible with hack3270 .db files
    proxy.py            # ProxyDaemon — select() loop, headless, observer pattern
    inject.py           # MaskInjector — preamble/****/postamble template machinery
    api_server.py       # ApiServer — non-blocking :31337 listener, handler registry
  tests/
    __init__.py
    conftest.py         # shared fixtures: tmp_db, socketpair, MockProtocol
    test_protocol.py
    test_ebcdic.py
    test_storage.py
    test_proxy.py
    test_inject.py
    test_api_server.py
```

**Source extraction map** (from `hack3270_libs/libhack3270.py`):

| New module | Extracted from | What changes |
|---|---|---|
| `ebcdic.py` | L44-63 (`e2a`/`a2e` tables), L1782-1792 (`get_ascii`/`get_ebcdic`) | Replace hand-rolled table with `codecs.lookup('cp037')`; keep fallback for control bytes |
| `storage.py` | L287-413 (`db_init`), L414-437 (`write_database_log`), L439-513 (`all_logs`/`get_log`/`play_record`/`check_*`) | Same schema. Parameterized queries (fix string-format SQL at L449/458/486/497/509). |
| `proxy.py` | L779-845 (`client_connect`/`server_connect`), L1329-1471 (`daemon`) | Strip out 3270-specific branches (capture_mask/aid_spoof at L1381-1399). Add observer hook + negotiate phase. |
| `inject.py` | L1708-1747 (`capture_mask`) | Take an `EbcdicCodec` instead of calling `self.get_ascii` |
| `api_server.py` | L847-865 (`api_start`), L1344-1372 (api accept/dispatch in daemon) | Handler registry instead of hardcoded `handle_api_request` |

---

## Task 0: Package skeleton

**Files:**
- Create: `hackterm-core/pyproject.toml`
- Create: `hackterm-core/hackterm_core/__init__.py`
- Create: `hackterm-core/tests/__init__.py`
- Create: `hackterm-core/tests/conftest.py`

- [ ] **Step 1: Create directory structure**

```bash
mkdir -p hackterm-core/hackterm_core hackterm-core/tests
```

- [ ] **Step 2: Write `pyproject.toml`**

Create `hackterm-core/pyproject.toml`:

```toml
[build-system]
requires = ["setuptools>=61.0"]
build-backend = "setuptools.build_meta"

[project]
name = "hackterm-core"
version = "0.1.0"
description = "Shared MITM proxy core for tn3270/tn5250 pentesting"
requires-python = ">=3.11"
license = {text = "GPL-3.0"}
dependencies = []

[project.optional-dependencies]
dev = ["pytest>=7.0"]

[tool.setuptools.packages.find]
where = ["."]
include = ["hackterm_core*"]

[tool.pytest.ini_options]
testpaths = ["tests"]
```

- [ ] **Step 3: Write `hackterm_core/__init__.py`**

Create `hackterm-core/hackterm_core/__init__.py`:

```python
"""
hackterm-core: shared MITM proxy infrastructure for tn3270/tn5250 pentesting.

Public API is re-exported here. Implementation modules are private.
"""
__version__ = "0.1.0"
```

- [ ] **Step 4: Write empty test init + conftest**

Create `hackterm-core/tests/__init__.py` (empty file).

Create `hackterm-core/tests/conftest.py`:

```python
import pytest
```

- [ ] **Step 5: Install in editable mode and verify**

```bash
cd hackterm-core && pip install -e ".[dev]"
```

Expected: `Successfully installed hackterm-core-0.1.0`

- [ ] **Step 6: Verify import**

```bash
python -c "import hackterm_core; print(hackterm_core.__version__)"
```

Expected: `0.1.0`

- [ ] **Step 7: Commit**

```bash
git add hackterm-core/
git commit -m "feat(core): scaffold hackterm-core package"
```

---

## Task 1: Protocol ABC + dataclasses

**Files:**
- Create: `hackterm-core/hackterm_core/protocol.py`
- Create: `hackterm-core/tests/test_protocol.py`
- Modify: `hackterm-core/hackterm_core/__init__.py`
- Modify: `hackterm-core/tests/conftest.py`

This is the contract. Reference: spec §2.2. No logic — pure interface + data containers.

- [ ] **Step 1: Write failing test for dataclass instantiation**

Create `hackterm-core/tests/test_protocol.py`:

```python
import pytest
from hackterm_core.protocol import (
    Field, Screen, FieldWrite, MutateOpts, NegotiateOpts,
    StructuredField, QueryLies, Protocol,
)


def test_field_dataclass():
    f = Field(row=5, col=10, length=20, protected=True,
              hidden=False, numeric=False, mdt=True, content=b"\xc1\xc2\xc3")
    assert f.row == 5
    assert f.protected is True
    assert f.content == b"\xc1\xc2\xc3"


def test_screen_dataclass():
    s = Screen(rows=24, cols=80, fields=[], raw=b"", rendered=[])
    assert s.rows == 24
    assert s.cols == 80
    assert s.fields == []


def test_screen_text_helper():
    """Screen.text joins rendered grid into a single string for grep/regex."""
    rendered = [["H", "I", " "], [" ", "O", "K"]]
    s = Screen(rows=2, cols=3, fields=[], raw=b"", rendered=rendered)
    assert s.text == "HI \n OK"


def test_screen_empty_factory():
    s = Screen.empty()
    assert s.rows == 24
    assert s.cols == 80
    assert s.raw == b""
    assert len(s.rendered) == 24
    assert len(s.rendered[0]) == 80


def test_mutate_opts_defaults_all_false():
    opts = MutateOpts()
    assert opts.unprotect is False
    assert opts.reveal_hidden is False
    assert opts.remove_numeric is False
    assert opts.high_visibility is False
    assert opts.color_reveal is False


def test_negotiate_opts_defaults():
    opts = NegotiateOpts()
    assert opts.spoof_device_name is None
    assert opts.force_cleartext is False
    assert opts.downgrade_functions is False


def test_field_write():
    fw = FieldWrite(row=1, col=1, data=b"\xf1\xf2\xf3")
    assert fw.data == b"\xf1\xf2\xf3"


def test_structured_field():
    sf = StructuredField(sf_type=0xD0, payload=b"data")
    assert sf.sf_type == 0xD0


def test_query_lies_defaults():
    lies = QueryLies()
    assert lies.alt_rows is None
    assert lies.deny_color is False
    assert lies.rpq_name is None


def test_protocol_is_abstract():
    """Cannot instantiate Protocol directly."""
    with pytest.raises(TypeError):
        Protocol()


def test_protocol_subclass_must_implement_all_abstracts():
    """Subclass missing an abstract method cannot be instantiated."""
    class Incomplete(Protocol):
        name = "test"
        aid_table = {}
        default_codepage = "cp037"
        # missing detect, negotiate_hook, parse, mutate, build_inbound, spoof_aid
    with pytest.raises(TypeError):
        Incomplete()


def test_protocol_optional_methods_have_defaults():
    """parse_structured returns None by default; build_query_reply raises."""
    class Minimal(Protocol):
        name = "test"
        aid_table = {"ENTER": 0x7D}
        default_codepage = "cp037"
        def detect(self, b): return False
        def negotiate_hook(self, d, dr, o): return d
        def parse(self, d): return Screen.empty()
        def mutate(self, d, o): return d
        def build_inbound(self, a, c, f): return b""
        def spoof_aid(self, o, a): return o

    p = Minimal()
    assert p.parse_structured(b"") is None
    with pytest.raises(NotImplementedError):
        p.build_query_reply(QueryLies())
```

- [ ] **Step 2: Run test, verify it fails**

```bash
cd hackterm-core && pytest tests/test_protocol.py -v
```

Expected: `ModuleNotFoundError: No module named 'hackterm_core.protocol'`

- [ ] **Step 3: Implement `protocol.py`**

Create `hackterm-core/hackterm_core/protocol.py`:

```python
"""
Protocol abstraction for tn3270/tn5250 MITM proxying.

The Protocol ABC defines the contract that both TN3270 and TN5250
implementations must satisfy. Attack code is written against this
interface so it never knows which protocol it's running on.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Field:
    """A single field on a terminal screen."""
    row: int
    col: int
    length: int
    protected: bool
    hidden: bool
    numeric: bool
    mdt: bool
    content: bytes  # raw EBCDIC


@dataclass
class Screen:
    """Parsed terminal screen state."""
    rows: int
    cols: int
    fields: list[Field]
    raw: bytes                      # original datastream for replay
    rendered: list[list[str]]       # rows x cols ASCII grid

    @property
    def text(self) -> str:
        """Flatten rendered grid to a single string for regex/grep."""
        return "\n".join("".join(row) for row in self.rendered)

    @classmethod
    def empty(cls, rows: int = 24, cols: int = 80) -> "Screen":
        return cls(
            rows=rows, cols=cols, fields=[], raw=b"",
            rendered=[[" "] * cols for _ in range(rows)],
        )


@dataclass
class FieldWrite:
    """Data to write into a field when building an inbound packet."""
    row: int
    col: int
    data: bytes  # EBCDIC


@dataclass
class MutateOpts:
    """Toggles for in-flight datastream manipulation.

    Names are protocol-neutral. Each Protocol implementation maps
    these to its own bit/byte semantics:
                        3270                    5250
      unprotect       SF attr bit 5          FFW bypass bit (0x2000)
      reveal_hidden   attr bits 2&3 (0x0C)   screen-attr 0x27 -> 0x20
      remove_numeric  SF attr bit 4          FFW shift bits (0x0700)
      high_visibility inject SFE color       attr -> 0x22 white
      color_reveal    SA 0x42 0xF8           n/a (no-op on 5250)
    """
    unprotect: bool = False
    reveal_hidden: bool = False
    remove_numeric: bool = False
    high_visibility: bool = False
    color_reveal: bool = False


@dataclass
class NegotiateOpts:
    """Toggles for telnet-negotiation-phase manipulation."""
    spoof_device_name: Optional[str] = None   # 3270: LU name | 5250: DEVNAME
    force_cleartext: bool = False             # 5250 only: strip IBMRSEED seed
    downgrade_functions: bool = False         # 3270 only: strip BIND-IMAGE/RESPONSES


@dataclass
class StructuredField:
    """A parsed structured field (3270 WSF, 5250 0xF3)."""
    sf_type: int
    payload: bytes


@dataclass
class QueryLies:
    """Configuration for Query Reply spoofing (3270 only initially)."""
    alt_rows: Optional[int] = None
    alt_cols: Optional[int] = None
    deny_color: bool = False
    deny_highlighting: bool = False
    deny_graphics: bool = False
    rpq_name: Optional[str] = None


class Protocol(ABC):
    """Contract for a block-mode terminal protocol (tn3270 or tn5250).

    Class attributes must be set by subclasses:
        name: str                   -- "tn3270" / "tn5250"
        aid_table: dict[str, int]   -- {"ENTER": 0x7D, ...}
        default_codepage: str       -- "cp037" / "cp500" etc.
    """
    name: str
    aid_table: dict[str, int]
    default_codepage: str

    # --- Telnet negotiation layer --------------------------------------

    @abstractmethod
    def detect(self, first_bytes: bytes) -> bool:
        """Inspect handshake bytes; return True if this is my protocol.
        Called on the first server->client traffic. Replaces hack3270's
        check_inject_3270e() which read SQLite log row 1.
        """

    @abstractmethod
    def negotiate_hook(self, data: bytes, direction: str,
                       opts: NegotiateOpts) -> bytes:
        """Rewrite telnet negotiation in flight.

        direction: 'c2s' (client->server) or 's2c' (server->client)

        3270: rewrite LU-name in DEVICE-TYPE REQUEST (RFC 2355).
        5250: strip IBMRSEED seed to force cleartext password (RFC 2877),
              rewrite DEVNAME USERVAR.
        """

    # --- Datastream layer (host -> terminal) ---------------------------

    @abstractmethod
    def parse(self, data: bytes) -> Screen:
        """Decode an outbound datastream into a Screen model."""

    @abstractmethod
    def mutate(self, data: bytes, opts: MutateOpts) -> bytes:
        """In-flight attribute manipulation.

        3270: SF/SFE/MF attribute byte bit-flips.
        5250: FFW bit-flips, screen-attribute byte rewrites.
        """

    # --- Datastream layer (terminal -> host) ---------------------------

    @abstractmethod
    def build_inbound(self, aid: int, cursor: tuple[int, int],
                      fields: list[FieldWrite]) -> bytes:
        """Construct a packet the terminal would send.

        3270: AID + cursor(2) + (SBA + addr(2) + data)... + IAC EOR
        5250: row + col + AID + (SBA + row + col + data)... + IAC EOR
        """

    @abstractmethod
    def spoof_aid(self, original: bytes, new_aid: int) -> bytes:
        """Replace the AID byte in a captured inbound packet.
        Each protocol knows where its AID byte lives.
        """

    # --- Structured fields (optional) ----------------------------------

    def parse_structured(self, data: bytes) -> Optional[StructuredField]:
        """Parse a structured-field block. Default: not supported."""
        return None

    def build_query_reply(self, lies: QueryLies) -> bytes:
        """Build a Query Reply structured field with operator-chosen lies.
        3270 only initially. Default: raise.
        """
        raise NotImplementedError(
            f"{self.name} does not support Query Reply"
        )
```

- [ ] **Step 4: Run tests, verify pass**

```bash
cd hackterm-core && pytest tests/test_protocol.py -v
```

Expected: `13 passed`

- [ ] **Step 5: Add MockProtocol fixture to conftest**

Modify `hackterm-core/tests/conftest.py`:

```python
import pytest
from hackterm_core.protocol import (
    Protocol, Screen, MutateOpts, NegotiateOpts, FieldWrite,
)


class MockProtocol(Protocol):
    """Test protocol that uppercases bytes in mutate()."""
    name = "mock"
    aid_table = {"ENTER": 0x0D}
    default_codepage = "ascii"

    def __init__(self):
        self.detect_called_with = None
        self.negotiate_calls = []

    def detect(self, first_bytes):
        self.detect_called_with = first_bytes
        return b"MOCK" in first_bytes

    def negotiate_hook(self, data, direction, opts):
        self.negotiate_calls.append((data, direction))
        return data

    def parse(self, data):
        return Screen.empty()

    def mutate(self, data, opts):
        if opts.unprotect:
            return data.upper()
        return data

    def build_inbound(self, aid, cursor, fields):
        parts = bytes([aid, cursor[0], cursor[1]])
        for fw in fields:
            parts += bytes([fw.row, fw.col]) + fw.data
        return parts

    def spoof_aid(self, original, new_aid):
        return bytes([new_aid]) + original[1:]


@pytest.fixture
def mock_protocol():
    return MockProtocol()
```

- [ ] **Step 6: Re-export from `__init__.py`**

Modify `hackterm-core/hackterm_core/__init__.py`:

```python
"""
hackterm-core: shared MITM proxy infrastructure for tn3270/tn5250 pentesting.
"""
__version__ = "0.1.0"

from hackterm_core.protocol import (
    Protocol, Field, Screen, FieldWrite,
    MutateOpts, NegotiateOpts, StructuredField, QueryLies,
)
```

- [ ] **Step 7: Verify public import path**

```bash
python -c "from hackterm_core import Protocol, Screen, MutateOpts; print('ok')"
```

Expected: `ok`

- [ ] **Step 8: Commit**

```bash
git add hackterm-core/
git commit -m "feat(core): add Protocol ABC and datastream dataclasses"
```

---

## Task 2: EbcdicCodec

**Files:**
- Create: `hackterm-core/hackterm_core/ebcdic.py`
- Create: `hackterm-core/tests/test_ebcdic.py`
- Modify: `hackterm-core/hackterm_core/__init__.py`

Replaces three divergent hand-rolled tables. Wraps `codecs.lookup()`. Reference: source `e2a` table at `hack3270_libs/libhack3270.py:44-63`, `get_ascii`/`get_ebcdic` at L1782-1792.

The legacy table has a bug at index 0x74 (`'[074]'` instead of `'[0x74]'`) and uses non-ASCII chars (`¢` at 0x4A, `≠` at 0x5F). Python's `cp037` codec gives different results for some bytes — this task documents the divergences but does NOT replicate the bugs.

- [ ] **Step 1: Write failing tests**

Create `hackterm-core/tests/test_ebcdic.py`:

```python
import pytest
from hackterm_core.ebcdic import EbcdicCodec


def test_default_codepage_is_cp037():
    c = EbcdicCodec()
    assert c.codepage == "cp037"


def test_to_ascii_basic_letters():
    """EBCDIC uppercase A-I are 0xC1-0xC9."""
    c = EbcdicCodec()
    assert c.to_ascii(b"\xc1\xc2\xc3") == "ABC"


def test_to_ascii_lowercase():
    """EBCDIC lowercase a-i are 0x81-0x89."""
    c = EbcdicCodec()
    assert c.to_ascii(b"\x81\x82\x83") == "abc"


def test_to_ascii_digits():
    """EBCDIC digits 0-9 are 0xF0-0xF9."""
    c = EbcdicCodec()
    assert c.to_ascii(b"\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9") == "0123456789"


def test_to_ascii_space():
    """EBCDIC space is 0x40."""
    c = EbcdicCodec()
    assert c.to_ascii(b"\x40") == " "


def test_to_ascii_control_byte_uses_fallback():
    """Bytes that codecs maps to control chars get bracketed-hex display.

    0x00-0x3F in EBCDIC are mostly control characters. The legacy table
    rendered them as '[0xNN]' and we preserve that behavior because the
    GUI's log viewer relies on it for telnet-negotiation display.
    """
    c = EbcdicCodec()
    # 0x00 is NUL in both encodings
    assert c.to_ascii(b"\x00") == "[0x00]"
    # 0x11 is DC1 control char (and also 3270 SBA order byte)
    assert c.to_ascii(b"\x11") == "[0x11]"


def test_to_ascii_mixed_text_and_control():
    c = EbcdicCodec()
    # 'A' + NUL + 'B'
    assert c.to_ascii(b"\xc1\x00\xc2") == "A[0x00]B"


def test_to_ebcdic_basic():
    c = EbcdicCodec()
    assert c.to_ebcdic("ABC") == b"\xc1\xc2\xc3"


def test_to_ebcdic_digits():
    c = EbcdicCodec()
    assert c.to_ebcdic("0123") == b"\xf0\xf1\xf2\xf3"


def test_round_trip_printable_ascii():
    """All printable ASCII should round-trip cleanly through cp037."""
    c = EbcdicCodec()
    # Skip backslash and a few chars that differ between EBCDIC variants
    safe = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 .,;:!?"
    assert c.to_ascii(c.to_ebcdic(safe)) == safe


def test_alternate_codepage_cp500():
    """cp500 differs from cp037 at a handful of code points (e.g. brackets)."""
    c037 = EbcdicCodec("cp037")
    c500 = EbcdicCodec("cp500")
    # 0xBA: cp037='[' but cp500 differs (this is one of the known divergences)
    # We just verify both codepages load without error
    assert c037.codepage == "cp037"
    assert c500.codepage == "cp500"
    # Both should agree on 'A'
    assert c037.to_ascii(b"\xc1") == c500.to_ascii(b"\xc1") == "A"


def test_to_ascii_returns_string_not_bytes():
    c = EbcdicCodec()
    result = c.to_ascii(b"\xc1")
    assert isinstance(result, str)


def test_to_ebcdic_returns_bytes():
    c = EbcdicCodec()
    result = c.to_ebcdic("A")
    assert isinstance(result, bytes)


def test_unsupported_codepage_raises():
    with pytest.raises(LookupError):
        EbcdicCodec("not-a-real-codepage")


def test_to_ascii_full_256_no_crash():
    """Every byte value must produce SOMETHING — never raise."""
    c = EbcdicCodec()
    for b in range(256):
        result = c.to_ascii(bytes([b]))
        assert isinstance(result, str)
        assert len(result) > 0


def test_legacy_divergence_documented():
    """Document where the new codec differs from the legacy e2a table.

    These are intentional fixes, not regressions:
      - 0x4A: legacy='¢' (Unicode), cp037='¢' too, but legacy was inconsistent
      - 0x5F: legacy='≠' (Unicode), cp037='^' — the ≠ was a hand-coded mistake
      - 0x74: legacy='[074]' (typo!), should be '[0x74]'

    This test exists so Phase 1 step 1.2 has a reference to point at.
    """
    c = EbcdicCodec()
    # 0x5F: legacy table had ≠ but cp037 says ^
    # We follow cp037 because it's correct.
    assert c.to_ascii(b"\x5f") == "^"
    # 0x74: legacy had typo '[074]'. cp037 maps it to a control-ish range.
    # Whatever cp037 says, it's not the typo.
    assert c.to_ascii(b"\x74") != "[074]"
```

- [ ] **Step 2: Run test, verify failure**

```bash
cd hackterm-core && pytest tests/test_ebcdic.py -v
```

Expected: `ModuleNotFoundError: No module named 'hackterm_core.ebcdic'`

- [ ] **Step 3: Implement `ebcdic.py`**

Create `hackterm-core/hackterm_core/ebcdic.py`:

```python
"""
Codepage-aware EBCDIC <-> ASCII conversion.

Replaces three divergent hand-rolled tables in hack3270:
  - libhack3270.py:44-63   (e2a list, 256 entries, has '[074]' typo at 0x74)
  - hack3270_api.py:43-56  (~95-char subset)
  - gui.py:2843-2855       (inline copy of the api version)

Wraps Python's codecs module for the actual codepage tables, with a
fallback for control bytes that codecs maps to non-printable characters.
The fallback preserves the legacy '[0xNN]' display format because the
GUI log viewer and TELNET_PATTERNS regexes match against it.
"""
import codecs


class EbcdicCodec:
    """Convert between EBCDIC and ASCII/Unicode.

    Args:
        codepage: Python codec name. Common values:
            cp037  - USA/Canada (default for z/OS, also common on IBM i)
            cp500  - International (some European IBM i installs)
            cp1140 - cp037 + Euro sign
    """

    def __init__(self, codepage: str = "cp037"):
        # Raises LookupError if codepage doesn't exist — that's correct.
        self._codec = codecs.lookup(codepage)
        self.codepage = codepage

    def to_ascii(self, data: bytes) -> str:
        """Convert EBCDIC bytes to a displayable string.

        Bytes that map to printable characters are converted normally.
        Bytes that map to control characters (or fail to decode) are
        rendered as '[0xNN]' to match legacy hack3270 behavior — the
        TELNET_PATTERNS regexes in libhack3270.py:66-92 depend on this.
        """
        out = []
        for b in data:
            try:
                ch, _ = self._codec.decode(bytes([b]))
            except UnicodeDecodeError:
                out.append(f"[0x{b:02X}]")
                continue
            # codecs decodes control bytes to control characters.
            # We want those displayed as bracketed-hex.
            if ch.isprintable():
                out.append(ch)
            else:
                out.append(f"[0x{b:02X}]")
        return "".join(out)

    def to_ebcdic(self, text: str) -> bytes:
        """Convert ASCII/Unicode string to EBCDIC bytes.

        Characters that don't exist in the target codepage will raise
        UnicodeEncodeError. That's correct — silently dropping bytes
        (which the legacy get_ebcdic at libhack3270.py:1786-1792 does)
        produces malformed packets.
        """
        encoded, _ = self._codec.encode(text)
        return encoded
```

- [ ] **Step 4: Run tests, verify pass**

```bash
cd hackterm-core && pytest tests/test_ebcdic.py -v
```

Expected: `16 passed`

If `test_to_ascii_control_byte_uses_fallback` fails because cp037 decodes 0x00 to `'\x00'` (which is not printable, so should hit the fallback): check the `isprintable()` logic. `'\x00'.isprintable()` is `False`, so the fallback should fire. If it doesn't, the issue is the byte-by-byte decode — verify `codecs.lookup('cp037').decode(b'\x00')` returns `('\x00', 1)` not an error.

- [ ] **Step 5: Re-export from `__init__.py`**

Append to `hackterm-core/hackterm_core/__init__.py`:

```python
from hackterm_core.ebcdic import EbcdicCodec
```

- [ ] **Step 6: Commit**

```bash
git add hackterm-core/
git commit -m "feat(core): add EbcdicCodec with codepage support"
```

---

## Task 3: Storage (SQLite)

**Files:**
- Create: `hackterm-core/hackterm_core/storage.py`
- Create: `hackterm-core/tests/test_storage.py`
- Modify: `hackterm-core/hackterm_core/__init__.py`
- Modify: `hackterm-core/tests/conftest.py`

Extracted from `hack3270_libs/libhack3270.py`: `db_init` (L287-413), `write_database_log` (L414-437), `all_logs`/`get_log`/`play_record`/`check_server`/`check_record` (L439-513).

**Schema MUST be identical** so existing `.db` files open without migration. The legacy code uses string-format SQL (`"...WHERE ID=" + str(record_id)"` at L458/486/497/509) — fix that, but keep schema/behavior identical.

- [ ] **Step 1: Write failing tests**

Create `hackterm-core/tests/test_storage.py`:

```python
import pytest
import sqlite3
import time
from hackterm_core.storage import Storage


def test_creates_tables_on_fresh_db(tmp_path):
    db = tmp_path / "test.db"
    s = Storage(str(db), server_ip="10.0.0.1", server_port=23,
                proxy_port=3271, tls_enabled=False)
    # Verify Config table exists with our values
    cur = s.conn.cursor()
    cur.execute("SELECT SERVER_IP, SERVER_PORT, PROXY_PORT, TLS_ENABLED FROM Config")
    row = cur.fetchone()
    assert row == ("10.0.0.1", 23, 3271, 0)
    s.close()


def test_logs_table_schema_matches_legacy(tmp_path):
    """Schema must be byte-identical to hack3270 so old .db files open.

    Legacy schema (libhack3270.py:403-411):
      ID INTEGER PRIMARY KEY AUTOINCREMENT
      TIMESTAMP TEXT
      C_S CHAR(1)
      NOTES TEXT
      DATA_LEN INT
      RAW_DATA BLOB(4000)
    """
    db = tmp_path / "test.db"
    s = Storage(str(db), server_ip="10.0.0.1", server_port=23,
                proxy_port=3271, tls_enabled=False)
    cur = s.conn.cursor()
    cur.execute("PRAGMA table_info(Logs)")
    cols = {row[1]: row[2] for row in cur.fetchall()}
    assert "ID" in cols
    assert "TIMESTAMP" in cols
    assert "C_S" in cols
    assert "NOTES" in cols
    assert "DATA_LEN" in cols
    assert "RAW_DATA" in cols
    s.close()


def test_log_packet_and_retrieve(tmp_path):
    db = tmp_path / "test.db"
    s = Storage(str(db), server_ip="10.0.0.1", server_port=23,
                proxy_port=3271, tls_enabled=False)
    s.log("S", "test note", b"\xc1\xc2\xc3")
    rows = s.all_logs()
    assert len(rows) == 1
    assert rows[0][2] == "S"           # C_S
    assert rows[0][3] == "test note"   # NOTES
    assert rows[0][5] == b"\xc1\xc2\xc3"  # RAW_DATA
    s.close()


def test_log_telnet_negotiation_auto_tagged(tmp_path):
    """Legacy behavior (libhack3270.py:416-417): if data[0]==0xFF,
    'tn3270 negotiation' is appended to notes. We generalize the tag."""
    db = tmp_path / "test.db"
    s = Storage(str(db), server_ip="10.0.0.1", server_port=23,
                proxy_port=3271, tls_enabled=False)
    s.log("S", "", b"\xff\xfd\x18")  # IAC DO TERMINAL-TYPE
    rows = s.all_logs()
    assert "negotiation" in rows[0][3]
    s.close()


def test_get_log_by_id(tmp_path):
    db = tmp_path / "test.db"
    s = Storage(str(db), server_ip="10.0.0.1", server_port=23,
                proxy_port=3271, tls_enabled=False)
    s.log("C", "first", b"\x01")
    s.log("S", "second", b"\x02")
    row = s.get_log(2)
    assert row[3] == "second"
    s.close()


def test_get_log_nonexistent_returns_none(tmp_path):
    db = tmp_path / "test.db"
    s = Storage(str(db), server_ip="10.0.0.1", server_port=23,
                proxy_port=3271, tls_enabled=False)
    assert s.get_log(999) is None
    s.close()


def test_all_logs_with_start_offset(tmp_path):
    """all_logs(start=N) returns rows with ID > N (legacy: L449)."""
    db = tmp_path / "test.db"
    s = Storage(str(db), server_ip="10.0.0.1", server_port=23,
                proxy_port=3271, tls_enabled=False)
    s.log("C", "one", b"\x01")
    s.log("C", "two", b"\x02")
    s.log("C", "three", b"\x03")
    rows = s.all_logs(start=1)
    assert len(rows) == 2
    assert rows[0][3] == "two"
    s.close()


def test_is_server_record(tmp_path):
    """Replaces check_server (libhack3270.py:484-493)."""
    db = tmp_path / "test.db"
    s = Storage(str(db), server_ip="10.0.0.1", server_port=23,
                proxy_port=3271, tls_enabled=False)
    s.log("S", "", b"\x01")
    s.log("C", "", b"\x02")
    assert s.is_server_record(1) is True
    assert s.is_server_record(2) is False
    s.close()


def test_is_telnet_record(tmp_path):
    """Replaces check_record (libhack3270.py:495-505)."""
    db = tmp_path / "test.db"
    s = Storage(str(db), server_ip="10.0.0.1", server_port=23,
                proxy_port=3271, tls_enabled=False)
    s.log("S", "", b"\xff\xfd\x18")  # telnet
    s.log("S", "", b"\xc1\xc2\xc3")  # data
    assert s.is_telnet_record(1) is True
    assert s.is_telnet_record(2) is False
    s.close()


def test_get_raw_for_replay(tmp_path):
    """Replaces play_record (L507-513) — but returns bytes instead of
    sending directly. Caller (proxy) handles the send."""
    db = tmp_path / "test.db"
    s = Storage(str(db), server_ip="10.0.0.1", server_port=23,
                proxy_port=3271, tls_enabled=False)
    s.log("S", "", b"\xde\xad\xbe\xef")
    assert s.get_raw(1) == b"\xde\xad\xbe\xef"
    s.close()


def test_in_memory_db():
    """':memory:' should work for tests."""
    s = Storage(":memory:", server_ip="10.0.0.1", server_port=23,
                proxy_port=3271, tls_enabled=False)
    s.log("S", "", b"\x01")
    assert len(s.all_logs()) == 1
    s.close()


def test_parameterized_queries_no_injection(tmp_path):
    """The legacy code did string-format SQL. Verify the new code
    doesn't. We can't directly test 'no injection' but we can verify
    that a malicious-looking ID doesn't blow up — parameterized queries
    will treat it as a value, not SQL."""
    db = tmp_path / "test.db"
    s = Storage(str(db), server_ip="10.0.0.1", server_port=23,
                proxy_port=3271, tls_enabled=False)
    # If get_log used string formatting, a non-int would error or worse
    assert s.get_log("1; DROP TABLE Logs; --") is None
    # Logs table should still exist
    s.log("S", "", b"\x01")
    assert len(s.all_logs()) == 1
    s.close()


def test_reopen_existing_db_loads_config(tmp_path):
    """Opening an existing .db loads the saved config (legacy: L326-358)."""
    db = tmp_path / "test.db"
    s1 = Storage(str(db), server_ip="10.0.0.1", server_port=23,
                 proxy_port=3271, tls_enabled=True)
    s1.close()

    s2 = Storage(str(db), server_ip="10.0.0.1", server_port=23,
                 proxy_port=3271, tls_enabled=True)
    assert s2.server_ip == "10.0.0.1"
    assert s2.server_port == 23
    assert s2.tls_enabled is True
    s2.close()
```

- [ ] **Step 2: Run test, verify failure**

```bash
cd hackterm-core && pytest tests/test_storage.py -v
```

Expected: `ModuleNotFoundError`

- [ ] **Step 3: Implement `storage.py`**

Create `hackterm-core/hackterm_core/storage.py`:

```python
"""
SQLite-backed packet logging.

Schema is byte-identical to hack3270 so existing .db files open
without migration. Extracted from libhack3270.py:287-513.

Changes from legacy:
  - Parameterized queries (legacy used string formatting at L449/458/486/497/509)
  - get_log returns one row or None (legacy: list of rows)
  - play_record split into get_raw (returns bytes; caller sends)
  - Negotiation auto-tag generalized from "tn3270 negotiation" to
    "telnet negotiation" since this serves both protocols
"""
import sqlite3
import time
import logging
from typing import Optional


class Storage:
    """SQLite packet log + configuration store.

    Schema (must match libhack3270.py:362-411 exactly):

      Config:
        CREATION_TS TEXT NOT NULL
        SERVER_IP   TEXT NOT NULL
        SERVER_PORT INT  NOT NULL
        PROXY_PORT  INT  NOT NULL
        TLS_ENABLED INT  NOT NULL

      Logs:
        ID        INTEGER PRIMARY KEY AUTOINCREMENT
        TIMESTAMP TEXT
        C_S       CHAR(1)         -- 'C' (client->server) or 'S' (server->client)
        NOTES     TEXT
        DATA_LEN  INT
        RAW_DATA  BLOB(4000)
    """

    def __init__(self, db_path: str, server_ip: str, server_port: int,
                 proxy_port: int, tls_enabled: bool):
        self._log = logging.getLogger(__name__)
        self.conn = sqlite3.connect(db_path)
        self.conn.set_trace_callback(self._log.debug)

        self.server_ip = server_ip
        self.server_port = server_port
        self.proxy_port = proxy_port
        self.tls_enabled = tls_enabled

        self._init_config()
        self._init_logs()

    def _init_config(self):
        cur = self.conn.cursor()
        cur.execute(
            "SELECT count(name) FROM sqlite_master "
            "WHERE TYPE='table' AND NAME='Config'"
        )
        if cur.fetchone()[0] == 1:
            cur.execute("SELECT * FROM Config")
            row = cur.fetchone()
            if row:
                # Legacy column order: CREATION_TS, SERVER_IP, SERVER_PORT,
                # PROXY_PORT, TLS_ENABLED (libhack3270.py:362-369)
                self.server_ip = row[1]
                self.server_port = int(row[2])
                self.proxy_port = int(row[3])
                self.tls_enabled = bool(row[4])
        else:
            cur.execute(
                "CREATE TABLE Config ("
                "CREATION_TS TEXT NOT NULL, "
                "SERVER_IP TEXT NOT NULL, "
                "SERVER_PORT INT NOT NULL, "
                "PROXY_PORT INT NOT NULL, "
                "TLS_ENABLED INT NOT NULL)"
            )
            cur.execute(
                "INSERT INTO Config "
                "(CREATION_TS, SERVER_IP, SERVER_PORT, PROXY_PORT, TLS_ENABLED) "
                "VALUES (?, ?, ?, ?, ?)",
                (str(time.time()), self.server_ip, self.server_port,
                 self.proxy_port, int(self.tls_enabled)),
            )
            self.conn.commit()

    def _init_logs(self):
        cur = self.conn.cursor()
        cur.execute(
            "SELECT count(name) FROM sqlite_master "
            "WHERE TYPE='table' AND NAME='Logs'"
        )
        if cur.fetchone()[0] != 1:
            cur.execute(
                "CREATE TABLE Logs ("
                "ID INTEGER PRIMARY KEY AUTOINCREMENT, "
                "TIMESTAMP TEXT, "
                "C_S CHAR(1), "
                "NOTES TEXT, "
                "DATA_LEN INT, "
                "RAW_DATA BLOB(4000))"
            )
            self.conn.commit()

    def log(self, direction: str, notes: str, data: bytes) -> None:
        """Append a packet to the log.

        direction: 'C' (client->server) or 'S' (server->client)
        """
        # Legacy auto-tag (libhack3270.py:416-417): IAC byte means negotiation
        if data and data[0] == 0xFF:
            notes = notes + "telnet negotiation"
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO Logs (TIMESTAMP, C_S, NOTES, DATA_LEN, RAW_DATA) "
            "VALUES (?, ?, ?, ?, ?)",
            (str(time.time()), direction, notes, len(data),
             sqlite3.Binary(data)),
        )
        self.conn.commit()

    def all_logs(self, start: int = 0) -> list[tuple]:
        """Get all log rows with ID > start."""
        cur = self.conn.cursor()
        if start > 0:
            cur.execute("SELECT * FROM Logs WHERE ID > ? ORDER BY ID ASC",
                        (start,))
        else:
            cur.execute("SELECT * FROM Logs ORDER BY ID ASC")
        return cur.fetchall()

    def get_log(self, log_id) -> Optional[tuple]:
        """Get one log row by ID, or None if not found."""
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM Logs WHERE ID = ?", (log_id,))
        return cur.fetchone()

    def get_raw(self, log_id: int) -> Optional[bytes]:
        """Get just the RAW_DATA blob for replay."""
        row = self.get_log(log_id)
        return row[5] if row else None

    def is_server_record(self, log_id: int) -> bool:
        """Was this packet sent by the server (host)?"""
        row = self.get_log(log_id)
        return bool(row and row[2] == "S")

    def is_telnet_record(self, log_id: int) -> bool:
        """Is this packet telnet negotiation (starts with IAC)?"""
        row = self.get_log(log_id)
        return bool(row and row[5] and row[5][0] == 0xFF)

    def close(self) -> None:
        self.conn.close()
```

- [ ] **Step 4: Run tests, verify pass**

```bash
cd hackterm-core && pytest tests/test_storage.py -v
```

Expected: `13 passed`

- [ ] **Step 5: Add `tmp_storage` fixture to conftest**

Append to `hackterm-core/tests/conftest.py`:

```python
from hackterm_core.storage import Storage


@pytest.fixture
def tmp_storage(tmp_path):
    s = Storage(
        str(tmp_path / "test.db"),
        server_ip="127.0.0.1", server_port=23,
        proxy_port=3271, tls_enabled=False,
    )
    yield s
    s.close()
```

- [ ] **Step 6: Re-export**

Append to `hackterm-core/hackterm_core/__init__.py`:

```python
from hackterm_core.storage import Storage
```

- [ ] **Step 7: Commit**

```bash
git add hackterm-core/
git commit -m "feat(core): add Storage with hack3270-compatible schema"
```

---

## Task 4: MaskInjector

**Files:**
- Create: `hackterm-core/hackterm_core/inject.py`
- Create: `hackterm-core/tests/test_inject.py`
- Modify: `hackterm-core/hackterm_core/__init__.py`

Extracted from `capture_mask` at `hack3270_libs/libhack3270.py:1708-1747`. Pure byte-level — operator types `****` in a field, proxy intercepts the packet, splits it into preamble/mask/postamble. Then iterates a wordlist substituting payloads.

Generalization: take an `EbcdicCodec` instead of calling `self.get_ascii`.

- [ ] **Step 1: Write failing tests**

Create `hackterm-core/tests/test_inject.py`:

```python
import pytest
from hackterm_core.inject import MaskInjector
from hackterm_core.ebcdic import EbcdicCodec


@pytest.fixture
def codec():
    return EbcdicCodec("cp037")


@pytest.fixture
def injector(codec):
    return MaskInjector(codec, mask_char="*")


def test_capture_finds_mask_run(injector, codec):
    """Packet with **** in the middle splits correctly.

    Packet structure (simplified): [header bytes] **** [trailer bytes]
    EBCDIC '*' is 0x5C.
    """
    pre = b"\x7d\x40\x40\x11\x40\x40"  # AID + cursor + SBA + addr (3270-ish)
    mask = b"\x5c\x5c\x5c\x5c"          # **** in EBCDIC
    post = b"\xff\xef"                   # IAC EOR
    packet = pre + mask + post

    found = injector.capture(packet)
    assert found is True
    assert injector.mask_len == 4
    assert injector.preamble == pre
    assert injector.postamble == post


def test_capture_no_mask_returns_false(injector):
    packet = b"\x7d\x40\x40\xc1\xc2\xc3\xff\xef"  # ABC, no asterisks
    assert injector.capture(packet) is False
    assert injector.mask_len == 0


def test_capture_mask_at_start(injector):
    """Mask at byte 0 — preamble is empty."""
    packet = b"\x5c\x5c\x5c\xff\xef"
    injector.capture(packet)
    assert injector.preamble == b""
    assert injector.mask_len == 3
    assert injector.postamble == b"\xff\xef"


def test_capture_mask_at_end(injector):
    """Mask runs to end of packet — postamble is empty."""
    packet = b"\x7d\x40\x5c\x5c\x5c\x5c"
    injector.capture(packet)
    assert injector.preamble == b"\x7d\x40"
    assert injector.mask_len == 4
    assert injector.postamble == b""


def test_capture_only_first_run(injector):
    """If two mask runs exist, capture the first one (legacy behavior)."""
    packet = b"\xc1\x5c\x5c\xc2\x5c\x5c\x5c\xc3"
    injector.capture(packet)
    assert injector.preamble == b"\xc1"
    assert injector.mask_len == 2
    assert injector.postamble == b"\xc2\x5c\x5c\x5c\xc3"


def test_build_trunc_pads_short_payload(injector, codec):
    """TRUNC mode pads with EBCDIC space (0x40) to mask_len."""
    pre = b"\x7d"
    post = b"\xff\xef"
    injector.capture(pre + b"\x5c" * 6 + post)  # mask_len=6

    result = injector.build("AB", mode="TRUNC")
    payload = codec.to_ebcdic("AB") + b"\x40" * 4  # AB + 4 spaces
    assert result == pre + payload + post


def test_build_trunc_truncates_long_payload(injector):
    pre = b"\x7d"
    post = b"\xff\xef"
    injector.capture(pre + b"\x5c" * 3 + post)  # mask_len=3

    result = injector.build("ABCDEF", mode="TRUNC")
    # Only first 3 chars: ABC = 0xC1 0xC2 0xC3
    assert result == pre + b"\xc1\xc2\xc3" + post


def test_build_skip_returns_none_for_oversized(injector):
    pre = b"\x7d"
    post = b"\xff\xef"
    injector.capture(pre + b"\x5c" * 3 + post)

    assert injector.build("ABCDEF", mode="SKIP") is None


def test_build_skip_returns_packet_for_fitting_payload(injector):
    pre = b"\x7d"
    post = b"\xff\xef"
    injector.capture(pre + b"\x5c" * 6 + post)

    result = injector.build("ABC", mode="SKIP")
    assert result is not None
    # SKIP still pads to mask_len
    assert len(result) == len(pre) + 6 + len(post)


def test_build_overflow_sends_full_payload(injector):
    """OVERFLOW ignores mask_len — tests pre-truncation validation
    (added in hack3270 v2.0.2)."""
    pre = b"\x7d"
    post = b"\xff\xef"
    injector.capture(pre + b"\x5c" * 3 + post)

    result = injector.build("ABCDEF", mode="OVERFLOW")
    # Full payload, packet is now LONGER than original
    assert result == pre + b"\xc1\xc2\xc3\xc4\xc5\xc6" + post


def test_build_without_capture_raises(injector):
    with pytest.raises(RuntimeError):
        injector.build("ABC", mode="TRUNC")


def test_build_invalid_mode_raises(injector):
    pre = b"\x7d"
    injector.capture(pre + b"\x5c\x5c\x5c" + b"\xff\xef")
    with pytest.raises(ValueError):
        injector.build("ABC", mode="BOGUS")


def test_alternate_mask_char():
    """5250 might use a different mask char than '*'."""
    codec = EbcdicCodec()
    inj = MaskInjector(codec, mask_char="#")
    # EBCDIC '#' is 0x7B
    packet = b"\xc1\x7b\x7b\x7b\xc2"
    inj.capture(packet)
    assert inj.mask_len == 3


def test_is_ready(injector):
    assert injector.is_ready() is False
    injector.capture(b"\x5c\x5c\x5c")
    assert injector.is_ready() is True
```

- [ ] **Step 2: Run test, verify failure**

```bash
cd hackterm-core && pytest tests/test_inject.py -v
```

Expected: `ModuleNotFoundError`

- [ ] **Step 3: Implement `inject.py`**

Create `hackterm-core/hackterm_core/inject.py`:

```python
"""
Mask-template field injection.

Operator types a run of mask characters (default '*') into the target
field on the real terminal screen. The proxy intercepts the inbound
packet, finds the EBCDIC mask run, and splits the packet into
preamble/mask/postamble. Then it can rebuild the packet substituting
any payload.

Extracted from capture_mask at hack3270_libs/libhack3270.py:1708-1747.

Generalization: takes an EbcdicCodec rather than calling self.get_ascii,
so it works for both 3270 and 5250 (and any codepage).

Modes (from hack3270 v2.0.2+):
  TRUNC    - pad with EBCDIC space, or truncate, to exactly mask_len
  SKIP     - return None if payload doesn't fit (caller skips this entry)
  OVERFLOW - send full payload regardless of mask_len (tests whether
             the host validates BEFORE truncating to field length)
"""
from typing import Optional, Literal
from hackterm_core.ebcdic import EbcdicCodec

Mode = Literal["TRUNC", "SKIP", "OVERFLOW"]
EBCDIC_SPACE = 0x40


class MaskInjector:
    def __init__(self, codec: EbcdicCodec, mask_char: str = "*"):
        self.codec = codec
        self.mask_char = mask_char
        # The mask byte in EBCDIC for the configured codepage
        self._mask_byte = codec.to_ebcdic(mask_char)[0]

        self.preamble: bytes = b""
        self.postamble: bytes = b""
        self.mask_len: int = 0

    def is_ready(self) -> bool:
        return self.mask_len > 0

    def capture(self, packet: bytes) -> bool:
        """Find the first run of mask bytes and split the packet around it.

        Returns True if a mask run was found.
        Replaces capture_mask (libhack3270.py:1708-1747).
        """
        # Find first occurrence of mask byte
        pre_len = 0
        for b in packet:
            if b == self._mask_byte:
                break
            pre_len += 1
        else:
            # No mask byte found at all
            self.mask_len = 0
            return False

        # Count consecutive mask bytes
        run_len = 0
        for i in range(pre_len, len(packet)):
            if packet[i] == self._mask_byte:
                run_len += 1
            else:
                break

        if run_len == 0:
            self.mask_len = 0
            return False

        self.preamble = packet[:pre_len]
        self.mask_len = run_len
        self.postamble = packet[pre_len + run_len:]
        return True

    def build(self, payload_text: str, mode: Mode = "TRUNC") -> Optional[bytes]:
        """Build a packet with the payload substituted for the mask.

        Returns None in SKIP mode if payload exceeds mask_len.
        Raises RuntimeError if capture() hasn't succeeded yet.
        """
        if not self.is_ready():
            raise RuntimeError("capture() has not found a mask yet")

        payload = self.codec.to_ebcdic(payload_text)

        if mode == "TRUNC":
            if len(payload) > self.mask_len:
                payload = payload[:self.mask_len]
            else:
                payload = payload + bytes([EBCDIC_SPACE]) * (self.mask_len - len(payload))
        elif mode == "SKIP":
            if len(payload) > self.mask_len:
                return None
            payload = payload + bytes([EBCDIC_SPACE]) * (self.mask_len - len(payload))
        elif mode == "OVERFLOW":
            pass  # send as-is, packet length changes
        else:
            raise ValueError(f"unknown mode: {mode!r}")

        return self.preamble + payload + self.postamble
```

- [ ] **Step 4: Run tests, verify pass**

```bash
cd hackterm-core && pytest tests/test_inject.py -v
```

Expected: `14 passed`

- [ ] **Step 5: Re-export**

Append to `hackterm-core/hackterm_core/__init__.py`:

```python
from hackterm_core.inject import MaskInjector
```

- [ ] **Step 6: Commit**

```bash
git add hackterm-core/
git commit -m "feat(core): add MaskInjector with TRUNC/SKIP/OVERFLOW modes"
```

---

## Task 5: ProxyDaemon

**Files:**
- Create: `hackterm-core/hackterm_core/proxy.py`
- Create: `hackterm-core/tests/test_proxy.py`
- Modify: `hackterm-core/hackterm_core/__init__.py`

The big one. Extracted from `client_connect`/`server_connect` (L779-845) and `daemon` (L1329-1471). The legacy `daemon()` has 3270-specific branches mixed in (capture_mask at L1381-1382, aid_spoof at L1384-1399, hack_toggled at L1414-1471). Strip those — they become callbacks/observers.

Key change: **headless**. No QTimer dependency. `tick()` is called by whatever scheduler the caller chooses.

- [ ] **Step 1: Write failing tests**

Create `hackterm-core/tests/test_proxy.py`:

```python
import pytest
import socket
import threading
import time
from hackterm_core.proxy import ProxyDaemon
from hackterm_core.protocol import MutateOpts


@pytest.fixture
def free_port():
    """Bind to port 0 to get a free port from the OS, then release it."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _pump(daemon, n=50, delay=0.01):
    """Drive the select() loop. select() with 0 timeout is non-blocking
    so we tick repeatedly to give bytes time to arrive."""
    for _ in range(n):
        daemon.tick()
        time.sleep(delay)


def test_proxy_passes_bytes_through(mock_protocol, tmp_storage, free_port):
    """End-to-end: server sends bytes, client receives them."""
    server_listener = socket.socket()
    server_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_listener.bind(("127.0.0.1", 0))
    server_listener.listen(1)
    server_port = server_listener.getsockname()[1]

    daemon = ProxyDaemon(
        protocol=mock_protocol,
        storage=tmp_storage,
        listen_addr=("127.0.0.1", free_port),
        target_addr=("127.0.0.1", server_port),
    )

    # Client connect (in a thread because wait_for_client blocks on accept)
    def client_thread():
        time.sleep(0.1)
        c = socket.socket()
        c.connect(("127.0.0.1", free_port))
        client_thread.sock = c
    client_thread.sock = None
    t = threading.Thread(target=client_thread)
    t.start()
    daemon.wait_for_client()
    t.join()

    daemon.connect_to_server()
    server_conn, _ = server_listener.accept()

    # Server sends, client should receive
    server_conn.send(b"hello from MOCK server")
    _pump(daemon)

    client_thread.sock.setblocking(False)
    received = client_thread.sock.recv(1024)
    assert b"hello" in received

    daemon.close()
    client_thread.sock.close()
    server_conn.close()
    server_listener.close()


def test_mutate_applied_to_server_traffic(mock_protocol, tmp_storage, free_port):
    """MockProtocol.mutate() uppercases when unprotect=True. Verify the
    proxy actually calls it on server->client traffic."""
    server_listener = socket.socket()
    server_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_listener.bind(("127.0.0.1", 0))
    server_listener.listen(1)
    server_port = server_listener.getsockname()[1]

    daemon = ProxyDaemon(
        protocol=mock_protocol,
        storage=tmp_storage,
        listen_addr=("127.0.0.1", free_port),
        target_addr=("127.0.0.1", server_port),
    )

    def client_thread():
        time.sleep(0.1)
        c = socket.socket()
        c.connect(("127.0.0.1", free_port))
        client_thread.sock = c
    client_thread.sock = None
    t = threading.Thread(target=client_thread)
    t.start()
    daemon.wait_for_client()
    t.join()

    daemon.connect_to_server()
    server_conn, _ = server_listener.accept()

    # Send handshake first to complete negotiation phase
    server_conn.send(b"MOCK handshake")
    _pump(daemon)
    client_thread.sock.setblocking(False)
    try:
        client_thread.sock.recv(1024)  # drain handshake
    except BlockingIOError:
        pass

    # Now arm the mutation and send data
    daemon.mutate_opts.unprotect = True
    server_conn.send(b"hello world")
    _pump(daemon)

    received = client_thread.sock.recv(1024)
    assert received == b"HELLO WORLD"

    daemon.close()
    client_thread.sock.close()
    server_conn.close()
    server_listener.close()


def test_negotiate_hook_called_before_handshake_complete(
        mock_protocol, tmp_storage, free_port):
    """Until detect() returns True, traffic goes through negotiate_hook
    instead of mutate."""
    server_listener = socket.socket()
    server_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_listener.bind(("127.0.0.1", 0))
    server_listener.listen(1)
    server_port = server_listener.getsockname()[1]

    daemon = ProxyDaemon(
        protocol=mock_protocol,
        storage=tmp_storage,
        listen_addr=("127.0.0.1", free_port),
        target_addr=("127.0.0.1", server_port),
    )

    def client_thread():
        time.sleep(0.1)
        c = socket.socket()
        c.connect(("127.0.0.1", free_port))
        client_thread.sock = c
    client_thread.sock = None
    t = threading.Thread(target=client_thread)
    t.start()
    daemon.wait_for_client()
    t.join()

    daemon.connect_to_server()
    server_conn, _ = server_listener.accept()

    # First server send: doesn't contain "MOCK" so detect()=False,
    # negotiate_hook should be called
    server_conn.send(b"telnet stuff")
    _pump(daemon)
    assert any(d == b"telnet stuff" for d, _ in mock_protocol.negotiate_calls)

    # Second send: contains "MOCK" so detect()=True, handshake complete
    server_conn.send(b"MOCK ready")
    _pump(daemon)
    assert daemon.handshake_complete is True

    daemon.close()
    client_thread.sock.close()
    server_conn.close()
    server_listener.close()


def test_observer_receives_server_traffic(mock_protocol, tmp_storage, free_port):
    """Observers are called for post-handshake server->client traffic.
    This is how ESM passive fingerprinter and IND$FILE detector hook in."""
    server_listener = socket.socket()
    server_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_listener.bind(("127.0.0.1", 0))
    server_listener.listen(1)
    server_port = server_listener.getsockname()[1]

    daemon = ProxyDaemon(
        protocol=mock_protocol,
        storage=tmp_storage,
        listen_addr=("127.0.0.1", free_port),
        target_addr=("127.0.0.1", server_port),
    )

    seen = []
    daemon.add_observer(lambda data, direction: seen.append((data, direction)))

    def client_thread():
        time.sleep(0.1)
        c = socket.socket()
        c.connect(("127.0.0.1", free_port))
        client_thread.sock = c
    client_thread.sock = None
    t = threading.Thread(target=client_thread)
    t.start()
    daemon.wait_for_client()
    t.join()

    daemon.connect_to_server()
    server_conn, _ = server_listener.accept()

    # Complete handshake
    server_conn.send(b"MOCK")
    _pump(daemon)
    # Now send observable traffic
    server_conn.send(b"observable data")
    _pump(daemon)

    assert any(d == b"observable data" and dr == "s2c" for d, dr in seen)

    daemon.close()
    client_thread.sock.close()
    server_conn.close()
    server_listener.close()


def test_storage_logs_unmutated_bytes(mock_protocol, tmp_storage, free_port):
    """Critical: storage gets the ORIGINAL bytes, not the mutated ones.
    Legacy behavior at libhack3270.py:1469-1471 logs the hacked version
    but only on the toggle path — the normal path logs originals. We
    standardize on logging originals so replay is faithful."""
    server_listener = socket.socket()
    server_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_listener.bind(("127.0.0.1", 0))
    server_listener.listen(1)
    server_port = server_listener.getsockname()[1]

    daemon = ProxyDaemon(
        protocol=mock_protocol,
        storage=tmp_storage,
        listen_addr=("127.0.0.1", free_port),
        target_addr=("127.0.0.1", server_port),
    )

    def client_thread():
        time.sleep(0.1)
        c = socket.socket()
        c.connect(("127.0.0.1", free_port))
        client_thread.sock = c
    client_thread.sock = None
    t = threading.Thread(target=client_thread)
    t.start()
    daemon.wait_for_client()
    t.join()

    daemon.connect_to_server()
    server_conn, _ = server_listener.accept()

    server_conn.send(b"MOCK")  # complete handshake
    _pump(daemon)
    daemon.mutate_opts.unprotect = True
    server_conn.send(b"hello")
    _pump(daemon)

    # Storage should have the lowercase original
    rows = tmp_storage.all_logs()
    raw_blobs = [r[5] for r in rows]
    assert b"hello" in raw_blobs
    # And NOT the mutated version
    assert b"HELLO" not in raw_blobs

    daemon.close()
    client_thread.sock.close()
    server_conn.close()
    server_listener.close()


def test_inject_to_server(mock_protocol, tmp_storage, free_port):
    """Direct injection to server. Used by AID fuzzing, field injection."""
    server_listener = socket.socket()
    server_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_listener.bind(("127.0.0.1", 0))
    server_listener.listen(1)
    server_port = server_listener.getsockname()[1]

    daemon = ProxyDaemon(
        protocol=mock_protocol,
        storage=tmp_storage,
        listen_addr=("127.0.0.1", free_port),
        target_addr=("127.0.0.1", server_port),
    )

    def client_thread():
        time.sleep(0.1)
        c = socket.socket()
        c.connect(("127.0.0.1", free_port))
        client_thread.sock = c
    client_thread.sock = None
    t = threading.Thread(target=client_thread)
    t.start()
    daemon.wait_for_client()
    t.join()

    daemon.connect_to_server()
    server_conn, _ = server_listener.accept()

    daemon.inject_to_server(b"injected payload")
    server_conn.setblocking(False)
    time.sleep(0.1)
    received = server_conn.recv(1024)
    assert received == b"injected payload"

    daemon.close()
    client_thread.sock.close()
    server_conn.close()
    server_listener.close()


def test_client_intercept_callback(mock_protocol, tmp_storage, free_port):
    """The c2s intercept replaces inline branches (capture_mask, aid_spoof).
    Returning None means 'don't forward' (e.g. capture mode).
    Returning bytes means 'forward this instead'."""
    server_listener = socket.socket()
    server_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_listener.bind(("127.0.0.1", 0))
    server_listener.listen(1)
    server_port = server_listener.getsockname()[1]

    daemon = ProxyDaemon(
        protocol=mock_protocol,
        storage=tmp_storage,
        listen_addr=("127.0.0.1", free_port),
        target_addr=("127.0.0.1", server_port),
    )

    intercepted = []
    def intercept(data):
        intercepted.append(data)
        return data.replace(b"foo", b"BAR")
    daemon.set_client_intercept(intercept)

    def client_thread():
        time.sleep(0.1)
        c = socket.socket()
        c.connect(("127.0.0.1", free_port))
        client_thread.sock = c
    client_thread.sock = None
    t = threading.Thread(target=client_thread)
    t.start()
    daemon.wait_for_client()
    t.join()

    daemon.connect_to_server()
    server_conn, _ = server_listener.accept()

    client_thread.sock.send(b"foo bar")
    _pump(daemon)

    assert intercepted == [b"foo bar"]
    server_conn.setblocking(False)
    received = server_conn.recv(1024)
    assert received == b"BAR bar"

    daemon.close()
    client_thread.sock.close()
    server_conn.close()
    server_listener.close()


def test_close_idempotent(mock_protocol, tmp_storage, free_port):
    daemon = ProxyDaemon(
        protocol=mock_protocol,
        storage=tmp_storage,
        listen_addr=("127.0.0.1", free_port),
        target_addr=("127.0.0.1", 9),
    )
    daemon.close()
    daemon.close()  # should not raise
```

- [ ] **Step 2: Run test, verify failure**

```bash
cd hackterm-core && pytest tests/test_proxy.py -v
```

Expected: `ModuleNotFoundError`

- [ ] **Step 3: Implement `proxy.py`**

Create `hackterm-core/hackterm_core/proxy.py`:

```python
"""
Headless MITM proxy daemon.

Owns the client+server socket pair and runs the select() event loop.
No GUI dependency — drive via .tick() from any scheduler (QTimer,
asyncio, threading.Timer, while-True loop).

Extracted from hack3270_libs/libhack3270.py:
  - client_connect (L779-801): blocking accept()
  - server_connect (L803-845): outbound connect, optional TLS
  - daemon (L1329-1471): the select() pump

What's stripped vs. legacy daemon():
  - Inline branches at L1381-1399 (capture_mask, aid_fuzzer, aid_spoof)
    become a single set_client_intercept() callback.
  - Inline hack_toggled block at L1414-1471 becomes the standard
    mutate() path — no toggle re-send, just always mutate.
  - API listener (L1334-1372) moves to api_server.py.

What's added:
  - Negotiation phase: until protocol.detect() returns True, traffic
    flows through protocol.negotiate_hook() instead of mutate().
    This is where LU-name spoofing (3270) and IBMRSEED stripping
    (5250) hook in.
  - Observer pattern: ESM passive fingerprinter, IND$FILE detector
    register via add_observer().
"""
import socket
import select
import ssl
import logging
from typing import Callable, Optional

from hackterm_core.protocol import Protocol, MutateOpts, NegotiateOpts
from hackterm_core.storage import Storage

BUFFER_SIZE = 16384  # legacy was 10000; bump slightly but keep modest
Observer = Callable[[bytes, str], None]
ClientIntercept = Callable[[bytes], Optional[bytes]]


class ProxyDaemon:
    """Single-connection MITM proxy.

    Lifecycle:
        d = ProxyDaemon(protocol, storage, listen_addr, target_addr)
        d.wait_for_client()      # blocks until emulator connects
        d.connect_to_server()    # connects to mainframe
        while running:
            d.tick()             # one select() pass, non-blocking
        d.close()
    """

    def __init__(self, protocol: Protocol, storage: Storage,
                 listen_addr: tuple[str, int],
                 target_addr: tuple[str, int],
                 use_tls: bool = False):
        self.protocol = protocol
        self.storage = storage
        self.listen_addr = listen_addr
        self.target_addr = target_addr
        self.use_tls = use_tls

        self.mutate_opts = MutateOpts()
        self.negotiate_opts = NegotiateOpts()
        self.handshake_complete = False

        self._observers: list[Observer] = []
        self._client_intercept: Optional[ClientIntercept] = None

        self._listener: Optional[socket.socket] = None
        self.client: Optional[socket.socket] = None
        self.server: Optional[socket.socket] = None

        self._log = logging.getLogger(__name__)

    # --- Connection lifecycle ----------------------------------------

    def wait_for_client(self) -> None:
        """Blocking accept(). Replaces client_connect (L779-801)."""
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(self.listen_addr)
        self._listener.listen(1)
        self._log.debug("waiting for client on %s", self.listen_addr)
        conn, peer = self._listener.accept()
        self._log.debug("client connected from %s", peer)
        self.client = conn

    def connect_to_server(self) -> None:
        """Connect to the mainframe. Replaces server_connect (L803-845)."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if self.use_tls:
            ctx = ssl._create_unverified_context()
            sock = ctx.wrap_socket(sock, server_hostname=self.target_addr[0])
        sock.connect(self.target_addr)
        self.server = sock
        self._log.debug("connected to server %s", self.target_addr)

    def close(self) -> None:
        for s in (self.client, self.server, self._listener):
            if s:
                try:
                    s.close()
                except OSError:
                    pass
        self.client = None
        self.server = None
        self._listener = None

    # --- Hooks -------------------------------------------------------

    def add_observer(self, fn: Observer) -> None:
        """Register a callback for post-handshake traffic.
        fn(data: bytes, direction: 's2c'|'c2s')
        Used by: ESM passive fingerprinter, IND$FILE detector,
        state-machine recorder.
        """
        self._observers.append(fn)

    def set_client_intercept(self, fn: Optional[ClientIntercept]) -> None:
        """Register a callback for client->server traffic.
        fn(data) -> bytes (modified) | None (drop, don't forward)
        Replaces the inline branches at libhack3270.py:1381-1399.
        Used by: MaskInjector capture, AID spoofing, AID fuzzer.
        """
        self._client_intercept = fn

    def inject_to_server(self, data: bytes) -> None:
        """Send bytes directly to the server. Used by attack modules."""
        if not self.server:
            raise RuntimeError("not connected to server")
        self.storage.log("C", "injected", data)
        self.server.send(data)

    def inject_to_client(self, data: bytes) -> None:
        """Send bytes directly to the client. Used for replay."""
        if not self.client:
            raise RuntimeError("no client connected")
        self.client.send(data)

    # --- Event loop --------------------------------------------------

    def tick(self) -> None:
        """One select() pass, zero timeout. Call repeatedly.
        Replaces daemon (L1329-1471).
        """
        if not (self.client and self.server):
            return

        readable = [self.client, self.server]
        rlist, _, _ = select.select(readable, [], [], 0)

        if self.client in rlist:
            self._handle_client()

        if self.server in rlist:
            self._handle_server()

    def _handle_client(self) -> None:
        data = self.client.recv(BUFFER_SIZE)
        if not data:
            self._log.debug("client disconnected")
            return

        if not self.handshake_complete:
            data = self.protocol.negotiate_hook(data, "c2s", self.negotiate_opts)
            self.storage.log("C", "", data)
            self.server.send(data)
            return

        # Client intercept (capture_mask, aid_spoof, aid_fuzzer all live here)
        if self._client_intercept:
            modified = self._client_intercept(data)
            if modified is None:
                # Intercept consumed it (e.g. capture mode). Still log original.
                self.storage.log("C", "intercepted", data)
                return
            data = modified

        for obs in self._observers:
            obs(data, "c2s")
        self.storage.log("C", "", data)
        self.server.send(data)

    def _handle_server(self) -> None:
        data = self.server.recv(BUFFER_SIZE)
        if not data:
            self._log.debug("server disconnected")
            return

        if not self.handshake_complete:
            data = self.protocol.negotiate_hook(data, "s2c", self.negotiate_opts)
            self.storage.log("S", "", data)
            if self.protocol.detect(data):
                self.handshake_complete = True
                self._log.debug("handshake complete")
            self.client.send(data)
            return

        # Log ORIGINAL bytes before mutation — replay must be faithful
        self.storage.log("S", "", data)
        for obs in self._observers:
            obs(data, "s2c")

        mutated = self.protocol.mutate(data, self.mutate_opts)
        self.client.send(mutated)
```

- [ ] **Step 4: Run tests, verify pass**

```bash
cd hackterm-core && pytest tests/test_proxy.py -v
```

Expected: `8 passed`

If `test_storage_logs_unmutated_bytes` is flaky due to timing: increase `_pump` iterations or add explicit recv-drain after handshake. If `test_negotiate_hook_called_before_handshake_complete` fails: check that MockProtocol's `detect()` correctly returns False for `b"telnet stuff"` (it does — no `b"MOCK"` substring) and True for `b"MOCK ready"`.

- [ ] **Step 5: Re-export**

Append to `hackterm-core/hackterm_core/__init__.py`:

```python
from hackterm_core.proxy import ProxyDaemon
```

- [ ] **Step 6: Commit**

```bash
git add hackterm-core/
git commit -m "feat(core): add ProxyDaemon with negotiate/mutate phases and observers"
```

---

## Task 6: ApiServer

**Files:**
- Create: `hackterm-core/hackterm_core/api_server.py`
- Create: `hackterm-core/tests/test_api_server.py`
- Modify: `hackterm-core/hackterm_core/__init__.py`

Extracted from `api_start` (L847-865) and the API-handling block in `daemon` (L1344-1372). Generalization: handler registry instead of hardcoded `handle_api_request`. The legacy protocol is line-based text (`PING\n` → `PONG\n`, `GET_LAST_SERVER_RAW\n` → `<hex>\n`) — keep that.

- [ ] **Step 1: Write failing tests**

Create `hackterm-core/tests/test_api_server.py`:

```python
import pytest
import socket
import time
from hackterm_core.api_server import ApiServer


@pytest.fixture
def api_server():
    s = ApiServer(port=0)  # port 0 = OS-assigned
    s.start()
    yield s
    s.stop()


def _pump(server, n=20, delay=0.01):
    for _ in range(n):
        server.tick()
        time.sleep(delay)


def test_starts_and_reports_port(api_server):
    assert api_server.port > 0


def test_register_handler_and_dispatch(api_server):
    api_server.register("PING", lambda args: "PONG")

    client = socket.socket()
    client.connect(("127.0.0.1", api_server.port))
    client.send(b"PING\n")
    _pump(api_server)
    client.setblocking(False)
    resp = client.recv(1024)
    assert resp == b"PONG\n"
    client.close()


def test_handler_receives_arguments(api_server):
    received = []
    api_server.register("ECHO", lambda args: (received.append(args), args)[1])

    client = socket.socket()
    client.connect(("127.0.0.1", api_server.port))
    client.send(b"ECHO hello world\n")
    _pump(api_server)
    client.setblocking(False)
    resp = client.recv(1024)
    assert resp == b"hello world\n"
    assert received == ["hello world"]
    client.close()


def test_unknown_command_returns_error(api_server):
    client = socket.socket()
    client.connect(("127.0.0.1", api_server.port))
    client.send(b"NONEXISTENT\n")
    _pump(api_server)
    client.setblocking(False)
    resp = client.recv(1024)
    assert b"ERROR" in resp
    client.close()


def test_multiple_clients(api_server):
    api_server.register("PING", lambda args: "PONG")

    c1 = socket.socket()
    c1.connect(("127.0.0.1", api_server.port))
    c2 = socket.socket()
    c2.connect(("127.0.0.1", api_server.port))
    _pump(api_server)

    c1.send(b"PING\n")
    c2.send(b"PING\n")
    _pump(api_server)

    c1.setblocking(False)
    c2.setblocking(False)
    assert c1.recv(1024) == b"PONG\n"
    assert c2.recv(1024) == b"PONG\n"
    c1.close()
    c2.close()


def test_client_disconnect_handled(api_server):
    """Client closing mid-session shouldn't crash the server."""
    api_server.register("PING", lambda args: "PONG")

    c = socket.socket()
    c.connect(("127.0.0.1", api_server.port))
    _pump(api_server)
    c.close()
    _pump(api_server)  # should not raise

    # Server still works for new clients
    c2 = socket.socket()
    c2.connect(("127.0.0.1", api_server.port))
    c2.send(b"PING\n")
    _pump(api_server)
    c2.setblocking(False)
    assert c2.recv(1024) == b"PONG\n"
    c2.close()


def test_handler_exception_returns_error_not_crash(api_server):
    api_server.register("BOOM", lambda args: 1 / 0)

    client = socket.socket()
    client.connect(("127.0.0.1", api_server.port))
    client.send(b"BOOM\n")
    _pump(api_server)
    client.setblocking(False)
    resp = client.recv(1024)
    assert b"ERROR" in resp
    client.close()


def test_binary_response_via_hex():
    """The legacy API returns binary data hex-encoded (e.g.
    GET_LAST_SERVER_RAW). Verify that hex strings work as responses."""
    s = ApiServer(port=0)
    s.start()
    s.register("RAW", lambda args: b"\xde\xad\xbe\xef".hex())

    client = socket.socket()
    client.connect(("127.0.0.1", s.port))
    client.send(b"RAW\n")
    _pump(s)
    client.setblocking(False)
    resp = client.recv(1024)
    assert resp == b"deadbeef\n"
    client.close()
    s.stop()


def test_stop_idempotent():
    s = ApiServer(port=0)
    s.start()
    s.stop()
    s.stop()  # should not raise
```

- [ ] **Step 2: Run test, verify failure**

```bash
cd hackterm-core && pytest tests/test_api_server.py -v
```

Expected: `ModuleNotFoundError`

- [ ] **Step 3: Implement `api_server.py`**

Create `hackterm-core/hackterm_core/api_server.py`:

```python
"""
Non-blocking TCP API server.

Line-based text protocol on localhost. Each line is:
    COMMAND [args...]\\n
Response is one line ending in \\n. Binary data is hex-encoded.

Extracted from hack3270_libs/libhack3270.py:
  - api_start (L847-865): non-blocking listener setup
  - daemon API block (L1344-1372): accept + dispatch loop

Generalization: handler registry instead of a hardcoded
handle_api_request method with a giant if/elif chain. Both
hack3270 and hack5250 register their own handlers.
"""
import socket
import select
import logging
from typing import Callable, Optional

Handler = Callable[[str], str]


class ApiServer:
    """Localhost-only line-based command server.

    Drive via .tick() alongside ProxyDaemon — same select()-based
    non-blocking pattern.
    """

    def __init__(self, port: int = 31337):
        self._requested_port = port
        self.port: int = 0
        self._listener: Optional[socket.socket] = None
        self._clients: list[socket.socket] = []
        self._handlers: dict[str, Handler] = {}
        self._log = logging.getLogger(__name__)

    def start(self) -> None:
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.setblocking(False)
        self._listener.bind(("127.0.0.1", self._requested_port))
        self._listener.listen(5)
        self.port = self._listener.getsockname()[1]
        self._log.info("API server listening on 127.0.0.1:%d", self.port)

    def stop(self) -> None:
        for c in self._clients:
            try:
                c.close()
            except OSError:
                pass
        self._clients = []
        if self._listener:
            try:
                self._listener.close()
            except OSError:
                pass
        self._listener = None

    def register(self, command: str, handler: Handler) -> None:
        """Register a command handler. handler(args_str) -> response_str."""
        self._handlers[command] = handler

    def tick(self) -> None:
        """One select() pass. Call alongside ProxyDaemon.tick()."""
        if not self._listener:
            return

        readable = [self._listener] + self._clients
        rlist, _, _ = select.select(readable, [], [], 0)

        if self._listener in rlist:
            try:
                conn, _ = self._listener.accept()
                conn.setblocking(False)
                self._clients.append(conn)
            except OSError:
                pass

        for client in list(self._clients):
            if client not in rlist:
                continue
            try:
                data = client.recv(4096)
            except OSError:
                self._drop(client)
                continue
            if not data:
                self._drop(client)
                continue
            self._dispatch(client, data)

    def _dispatch(self, client: socket.socket, data: bytes) -> None:
        try:
            line = data.decode("utf-8", errors="replace").strip()
        except Exception:
            self._send(client, "ERROR: bad encoding")
            return
        if not line:
            return

        parts = line.split(" ", 1)
        cmd = parts[0]
        args = parts[1] if len(parts) > 1 else ""

        handler = self._handlers.get(cmd)
        if not handler:
            self._send(client, f"ERROR: unknown command {cmd!r}")
            return
        try:
            resp = handler(args)
        except Exception as e:
            self._log.exception("handler %s raised", cmd)
            self._send(client, f"ERROR: {e}")
            return
        self._send(client, resp)

    def _send(self, client: socket.socket, resp: str) -> None:
        try:
            client.send((resp + "\n").encode("utf-8"))
        except OSError:
            self._drop(client)

    def _drop(self, client: socket.socket) -> None:
        try:
            client.close()
        except OSError:
            pass
        if client in self._clients:
            self._clients.remove(client)
```

- [ ] **Step 4: Run tests, verify pass**

```bash
cd hackterm-core && pytest tests/test_api_server.py -v
```

Expected: `9 passed`

- [ ] **Step 5: Re-export**

Append to `hackterm-core/hackterm_core/__init__.py`:

```python
from hackterm_core.api_server import ApiServer
```

- [ ] **Step 6: Commit**

```bash
git add hackterm-core/
git commit -m "feat(core): add ApiServer with handler registry"
```

---

## Task 7: Full test suite + final integration

**Files:**
- Modify: `hackterm-core/hackterm_core/__init__.py` (verify exports)

- [ ] **Step 1: Run full suite**

```bash
cd hackterm-core && pytest -v
```

Expected: All tests pass (`13 + 16 + 13 + 14 + 8 + 9 = 73 passed`).

- [ ] **Step 2: Verify final `__init__.py`**

`hackterm-core/hackterm_core/__init__.py` should now read:

```python
"""
hackterm-core: shared MITM proxy infrastructure for tn3270/tn5250 pentesting.
"""
__version__ = "0.1.0"

from hackterm_core.protocol import (
    Protocol, Field, Screen, FieldWrite,
    MutateOpts, NegotiateOpts, StructuredField, QueryLies,
)
from hackterm_core.ebcdic import EbcdicCodec
from hackterm_core.storage import Storage
from hackterm_core.inject import MaskInjector
from hackterm_core.proxy import ProxyDaemon
from hackterm_core.api_server import ApiServer
```

- [ ] **Step 3: Verify everything imports from top-level**

```bash
python -c "
from hackterm_core import (
    Protocol, Screen, Field, FieldWrite, MutateOpts, NegotiateOpts,
    StructuredField, QueryLies, EbcdicCodec, Storage, MaskInjector,
    ProxyDaemon, ApiServer,
)
print('all imports ok')
"
```

Expected: `all imports ok`

- [ ] **Step 4: Verify importable from sibling directory**

This proves Phase 1 (hack3270 wiring) can begin.

```bash
cd /home/kali/hack3270-update && python -c "from hackterm_core import Protocol; print(Protocol)"
```

Expected: `<class 'hackterm_core.protocol.Protocol'>`

- [ ] **Step 5: Commit & tag**

```bash
git add hackterm-core/
git commit -m "feat(core): complete Phase 0 — hackterm-core v0.1.0"
git tag phase0-complete
```

---

## Self-Review

**Spec coverage check** (against §2.1–§2.4 and §5 Phase 0 table):

| Spec item | Plan task | ✓ |
|---|---|---|
| §2.2 Protocol ABC + dataclasses | Task 1 | ✓ |
| §2.4 EbcdicCodec, codepage-aware, fallback | Task 2 | ✓ |
| §2.3 ProxyDaemon, headless, observers, negotiate phase | Task 5 | ✓ |
| §2.1 storage.py, schema-compatible | Task 3 | ✓ |
| §2.1 inject.py, mask-template | Task 4 | ✓ |
| §2.1 api_server.py, handler registry | Task 6 | ✓ |
| §5.0.1 stub TN3270/TN5250 instantiate | Task 1 step 1 (`Minimal` class in test) | ✓ |
| §5.0.2 ebcdic round-trip property test | Task 2 step 1 (`test_round_trip_printable_ascii`) | ✓ |
| §5.0.3 mock protocol uppercase test | Task 5 step 1 (`test_mutate_applied_to_server_traffic`) | ✓ |
| §5.0.4 existing .db opens | Task 3 step 1 (`test_logs_table_schema_matches_legacy`, `test_reopen_existing_db_loads_config`) | ✓ |
| §5.0.5 mask split correct | Task 4 step 1 (`test_capture_finds_mask_run`) | ✓ |
| §5.0.6 echo handler responds | Task 6 step 1 (`test_handler_receives_arguments`) | ✓ |
| §5.0.7 pip install -e | Task 0 step 5 + Task 7 step 4 | ✓ |
| §2.4 EBCDIC legacy divergence documented | Task 2 step 1 (`test_legacy_divergence_documented`) | ✓ |
| §2.3 log BEFORE mutation | Task 5 step 1 (`test_storage_logs_unmutated_bytes`) | ✓ |
| §2.3 client intercept (capture_mask/aid_spoof replacement) | Task 5 step 1 (`test_client_intercept_callback`) | ✓ |

**Type/name consistency check:**
- `Protocol` — used consistently (Tasks 1, 5)
- `Screen.empty()` — defined Task 1, used in conftest
- `MutateOpts` — defined Task 1, used Task 5 (`daemon.mutate_opts.unprotect`)
- `NegotiateOpts` — defined Task 1, used Task 5
- `EbcdicCodec` — defined Task 2, used Task 4
- `Storage` — defined Task 3, used Task 5 conftest fixture
- `MaskInjector.is_ready()` — defined and tested Task 4
- `ProxyDaemon.tick()` — defined and tested Task 5
- `ApiServer.tick()` — defined and tested Task 6

No mismatches found.

**Placeholder scan:** No "TBD"/"TODO"/"implement later" in any task. All steps have complete code. The "If test X fails" notes in steps 4 are debugging guidance, not deferred work.
