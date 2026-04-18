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
