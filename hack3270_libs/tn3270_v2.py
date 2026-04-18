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

    def _finish(self, st: "_ParseState", original: bytes) -> Screen:
        st.close_field()
        return Screen(
            rows=st.rows, cols=st.cols,
            fields=st.fields, raw=original,
            rendered=st.grid,
        )

    # --- Stubs for ABC compliance (filled in by 1c/1d) -------------------

    def mutate(self, data: bytes, opts: MutateOpts) -> bytes:
        """In-flight attribute manipulation.

        Walks the datastream the same way parse() does, but instead of
        building a Screen it surgically rewrites attr bytes in place.
        Same flips as legacy manipulate() (libhack3270.py:1240+) but
        context-aware: only flips bytes that are PROVABLY attr bytes.

        Operates on the wire bytes directly — does NOT strip headers/IAC,
        just walks past them. Output is byte-for-byte same length as input.
        """
        if not any([opts.unprotect, opts.reveal_hidden,
                    opts.remove_numeric, opts.high_visibility,
                    opts.color_reveal]):
            return data

        out = bytearray(data)
        n = len(out)
        i = 0

        # Skip TN3270E header (don't remove, just walk past)
        if n >= TN3270E_HDR_LEN + 1 and out[0] <= 0x07:
            peek = out[TN3270E_HDR_LEN]
            if peek in _HAS_WCC or peek == CMD_WSF:
                i = TN3270E_HDR_LEN

        # Limit walk range to exclude trailing IAC EOR
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
                i += 3   # SBA + 2 addr bytes — operands are NOT orders
            elif b == ORD_SA:
                i += 3   # SA + type + value
            elif b == ORD_IC or b == ORD_PT:
                i += 1
            elif b == ORD_RA:
                i += 4   # RA + 2 addr + 1 fill char
            elif b == ORD_EUA:
                i += 3   # EUA + 2 addr
            elif b == ORD_GE:
                i += 2   # GE + 1 graphic byte — that byte is data, never an order
            else:
                i += 1   # data byte

        return bytes(out)

    # --- Datastream layer (terminal → host) ------------------------------

    def build_inbound(self, aid: int, cursor: tuple[int, int],
                      fields: list[FieldWrite]) -> bytes:
        """Construct an inbound (terminal→host) packet.

        Layout (GA23-0059 §3.5.4):
          [TN3270E header(5)] AID cursor-addr(2) (SBA addr(2) data)* IAC EOR

        Field data is IAC-escaped (0xFF → 0xFF 0xFF) so a literal 0xFF
        in EBCDIC content isn't mistaken for telnet IAC.
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
        """Replace the AID byte in a captured inbound packet.

        AID is at offset 0 for plain TN3270, offset 5 for TN3270E
        (after the 5-byte header).
        """
        out = bytearray(original)
        offset = TN3270E_HDR_LEN if self.is_tn3270e else 0
        if len(out) > offset:
            out[offset] = new_aid
        return bytes(out)

    # --- Structured fields ----------------------------------------------

    def build_query_reply(self, lies: QueryLies) -> bytes:
        """Build a Query Reply with operator-chosen lies. See attacks/structured.py."""
        # Late import to avoid circular dependency
        from hack3270_libs.attacks.structured import build_query_reply
        return build_query_reply(lies, tn3270e=self.is_tn3270e, seq=self.last_seq)

    def parse_structured(self, data: bytes):
        """Parse a WSF datastream. Returns StructuredField or None.
        Used by IND$FILE detector."""
        from hack3270_libs.attacks.structured import parse_wsf
        return parse_wsf(data)
