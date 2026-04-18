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
  - L1888-1892: SF branch flips BEFORE checking hidden → HV inject
    never fires for SF orders. SFE branch (L1915-1917) checks BEFORE
    flipping → HV inject DOES fire. Golden tests lock this in.

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
        _log.debug("Flipping bits in {:02X}".format(tn3270_data))
        # Turn of 'Protected' Flag (Bit 6) if Set
        if flags.hack_prot:
            _log.debug("Flipping Protected bit")
            if value & 0b00100000 == 0b00100000:
                value ^= 0b00100000
        # Turn off 'Non-display' Flag (Bit 4) if Set (i.e. Bits 3 and 4 are on)
        if flags.hack_hf:
            _log.debug("Flipping Non-display bit")
            if value & 0b00001100 == 0b00001100:
        # Flip bit 3 instead of 4 if enable intentisty is selected
                if flags.hack_ei:
                    _log.debug("Flipping intensity bit")
                    value ^= 0b00000100
                else:
                    value ^= 0b00001000
        # Turn off 'Numeric Only' Flag (Bit 5) if Set
        if flags.hack_rnr:
            _log.debug("Flipping Numeric bit")
            if value & 0b00010000 == 0b00010000:
                value ^= 0b00010000
        _log.debug("Flipped bits: {:02X}".format(tn3270_data))
        return(value)

    @staticmethod
    def _check_hidden(tn3270_data):
        """libhack3270.py:1851-1867"""
        #if passed_value & 0b00001100 == 0b00001100:
        if tn3270_data & 12 == 12:
            _log.debug("Hidden TN3270 Flag detected")
            return True
        else:
            _log.debug("Hidden TN3270 Flag not detected")
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
            _log.debug("Received Telnet data, returning")
            return(tn3270_data)

        data = bytearray(len(tn3270_data))
        data[:] = tn3270_data

        _log.debug("Data recieved: {}".format(data.hex()))
        _log.debug("Hack on: {}".format(flags.hack_on))
        # Process hacking of Basic Field Attributes
        if flags.hack_on:
            for x in range(len(data)):
                #self.logger.debug("Current Byte: {}".format(data[x]))

                if flags.hack_sf and data[x] == 0x1d: # Start Field
                    _log.debug("Start Field found")

                    data[x + 1] = cls._flip_bits(data[x + 1], flags)
                    if flags.hack_hf and cls._check_hidden(data[x + 1]):
                        #self.logger.debug("Disabling found Hidden Field")
                        bfa_byte = data[x + 1].to_bytes(1, byteorder='little')
                        if flags.hack_hv:
                            _log.debug("Enabling High Visibility")
                            data2 = bytearray(len(data) + 6)
                            data2 = data[:x] + b'\x29\x03\xc0' + bfa_byte + b'\x41\xf2\x42\xf6' + data[x + 2:]
                            data = data2
                            x = x + 6
                        else:
                            data2 = bytearray(len(data) + 4)
                            data2 = data[:x + 2] + b'\x28\x42\xf6' + data[x + 2:]
                            data2 = data[:x] + b'\x29\x02\xc0' + bfa_byte + b'\x42\xf6' + data[x + 2:]
                            x = x + 4

                elif data[x] == 0x29: # Start Field Extended
                    _log.debug("Start Field Extended found, looping over {} fields".format(data[x + 1]))

                    for y in range(data[x + 1]):

                        if(len(data) < ((x + 3) + (y * 2))):
                            continue
                        if flags.hack_sfe and data[((x + 3) + (y * 2)) - 1] == 0xc0: # Basic 3270 field attributes
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
                elif data[x] == 0x2c: # Modify Field
                    for y in range(data[x + 1]):
                        if(len(data) < ((x + 3) + (y * 2))):
                            continue
                        if flags.hack_mf and data[((x + 3) + (y * 2)) - 1] == 0xc0: # Basic 3270 field attributes
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
        _log.debug("Hack Colors on: {}".format(flags.hack_color_on))
        if flags.hack_color_on:
            for x in range(len(data)):
                if data[x] == 0x29: # Start Field Extended
                    for y in range(data[x + 1]):
                        if(len(data) < ((x + 3) + (y * 2))):
                            continue
                        if flags.hack_color_sfe and data[((x + 3) + (y * 2)) - 1] == 0x42: # Color
                            if data[((x + 3) + (y * 2))] == 0xf8: # Black
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
                elif data[x] == 0x28: # Set Attribute
                    if flags.hack_color_sa and data[x + 1] == 0x42: # Color
                        if data[x + 2] == 0xf8: # Black
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
                elif data[x] == 0x2c: # Modify Field
                    for y in range(data[x + 1]):
                        if(len(data) < ((x + 3) + (y * 2))):
                            continue
                        if flags.hack_color_mf and data[((x + 3) + (y * 2)) - 1] == 0x42: # Color
                            if data[((x + 3) + (y * 2))] == 0xf8: # Black
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

        return(data)
