"""
MaskInjector shim tests.

capture_mask must delegate to MaskInjector.capture and copy results
back to legacy attributes that gui.py:3334 reads.
"""
import pytest


def test_shim_creates_injector(legacy_hack3270):
    from hackterm_core import MaskInjector
    h = legacy_hack3270
    assert hasattr(h, "_injector")
    assert isinstance(h._injector, MaskInjector)


def test_capture_mask_finds_run(legacy_hack3270):
    """EBCDIC '*' is 0x5C. Packet: pre + *** + post."""
    h = legacy_hack3270
    h.set_inject_mask("*")
    h.set_inject_setup_capture(1)
    # ENTER + cursor + *** + IAC EOR
    pkt = b"\x7D\x40\x40" + b"\x5C\x5C\x5C" + b"\xFF\xEF"
    h.capture_mask(pkt)
    assert h.inject_mask_len == 3
    assert h.inject_preamble == b"\x7D\x40\x40"
    assert h.inject_postamble == b"\xFF\xEF"
    assert h.inject_config_set == 1
    assert h.inject_setup_capture is False  # cleared after capture


def test_capture_mask_no_run(legacy_hack3270):
    h = legacy_hack3270
    h.set_inject_mask("*")
    h.set_inject_setup_capture(1)
    pkt = b"\x7D\x40\x40\xC8\xC5\xD3\xD3\xD6\xFF\xEF"  # no asterisks
    h.capture_mask(pkt)
    assert h.inject_mask_len == 0
    assert h.inject_config_set == 0


def test_capture_mask_logs(legacy_hack3270):
    """L1740/1746: capture_mask writes to db log."""
    h = legacy_hack3270
    h.set_inject_mask("*")
    h.capture_mask(b"\x7D\x40\x40\x5C\x5C\xFF\xEF")
    rows = h.all_logs()
    assert len(rows) == 1
    assert "Inject setup" in rows[0][3]


def test_get_inject_methods_unchanged(legacy_hack3270):
    """gui.py:3334 reads via getters — they must reflect injector state."""
    h = legacy_hack3270
    h.set_inject_mask("*")
    h.capture_mask(b"\x7D\x40\x40\x5C\x5C\x5C\x5C\xFF\xEF")
    assert h.get_inject_mask_len() == 4
    assert h.get_inject_preamble() == b"\x7D\x40\x40"
    assert h.get_inject_postamble() == b"\xFF\xEF"
    assert h.get_inject_config_set() == 1


def test_set_inject_mask_updates_injector(legacy_hack3270):
    """Changing mask char must propagate to MaskInjector."""
    h = legacy_hack3270
    h.set_inject_mask("#")
    # EBCDIC '#' is 0x7B
    h.capture_mask(b"\x7D\x40\x40\x7B\x7B\xFF\xEF")
    assert h.inject_mask_len == 2


def test_gui_inject_one_line_compat(legacy_hack3270):
    """Mirror exactly what gui.py:3333-3338 does after capture."""
    h = legacy_hack3270
    h.set_inject_mask("*")
    h.capture_mask(b"\x7D\x40\x40\x5C\x5C\x5C\x5C\x5C\xFF\xEF")  # 5 asterisks

    line = "HELLO"  # exactly 5 chars, fits TRUNC mode
    injection_ebcdic = h.get_ebcdic(line)
    bytes_ebcdic = (h.get_inject_preamble() +
                    injection_ebcdic +
                    h.get_inject_postamble())

    assert bytes_ebcdic == b"\x7D\x40\x40" + b"\xC8\xC5\xD3\xD3\xD6" + b"\xFF\xEF"
