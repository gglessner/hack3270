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
