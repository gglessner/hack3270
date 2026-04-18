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

        Bytes that decode to characters outside the basic ASCII printable
        range (0x20-0x7E) are rendered as '[0xNN]' to match legacy
        hack3270 behavior — the TELNET_PATTERNS regexes in
        libhack3270.py:66-92 depend on this (e.g. '[0xFF]' -> '[IAC]').
        """
        out = []
        for b in data:
            try:
                ch, _ = self._codec.decode(bytes([b]))
            except UnicodeDecodeError:
                out.append(f"[0x{b:02X}]")
                continue
            # Only show basic ASCII printables. cp037 maps bytes like
            # 0xFF -> 'Ÿ' which str.isprintable() accepts, but the
            # TELNET_PATTERNS regexes need to see '[0xFF]'.
            if " " <= ch <= "~":  # basic ASCII printable (U+0020 to U+007E)
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
