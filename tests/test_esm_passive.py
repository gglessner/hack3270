"""
ESM (External Security Manager) passive fingerprinter tests.

The fingerprinter registers as a ProxyDaemon observer and pattern-matches
on parsed screen text. We test against FakeDaemon — fire synthetic
screens, assert findings dict updates.
"""
import pytest
from hackterm_core.ebcdic import EbcdicCodec


@pytest.fixture
def esm():
    from hack3270_libs.attacks.esm_passive import ESMFingerprinter
    from hack3270_libs.tn3270_v2 import TN3270
    return ESMFingerprinter(protocol=TN3270())


def _make_screen_packet(text: str) -> bytes:
    """Build a minimal datastream that renders `text` at row 1.
    Erase/Write + WCC + SF unprotected + EBCDIC text + IAC EOR."""
    codec = EbcdicCodec()
    ebcdic = codec.to_ebcdic(text)
    return bytes([0xF5, 0xC3, 0x1D, 0x40]) + ebcdic + b"\xff\xef"


# ---------------------------------------------------------------------------
# Pattern detection — spec §3.3 inference table
# ---------------------------------------------------------------------------

def test_findings_starts_empty(esm):
    assert esm.findings == {}


def test_dfhce3530_sets_username_enum(esm, fake_daemon):
    """DFHCE3530 = 'Your userid is invalid' — pre-CICS-TS-5.1 oracle."""
    esm.attach(fake_daemon)
    fake_daemon.fire_s2c(_make_screen_packet("DFHCE3530 Your userid is invalid"))
    assert "username_enum" in esm.findings
    assert "DFHCE3530" in esm.findings["username_enum"]["evidence"]


def test_dfhce3532_also_sets_username_enum(esm, fake_daemon):
    """DFHCE3532 = 'Your password is invalid' — confirms differential."""
    esm.attach(fake_daemon)
    fake_daemon.fire_s2c(_make_screen_packet("DFHCE3532 Your password is invalid"))
    assert "username_enum" in esm.findings


def test_dfhce3520_sets_account_state_leak(esm, fake_daemon):
    esm.attach(fake_daemon)
    fake_daemon.fire_s2c(_make_screen_packet("DFHCE3520 Your userid has been revoked"))
    assert "account_state_leak" in esm.findings


def test_dfhce3592_sets_password_expiry(esm, fake_daemon):
    esm.attach(fake_daemon)
    fake_daemon.fire_s2c(_make_screen_packet("DFHCE3592 Your password has expired"))
    assert "password_expiry" in esm.findings


def test_dfhce3543_sets_passphrase(esm, fake_daemon):
    esm.attach(fake_daemon)
    fake_daemon.fire_s2c(_make_screen_packet("DFHCE3543 Sign-on with passphrase"))
    assert "passphrase" in esm.findings


def test_ich408i_sets_racf_confirmed(esm, fake_daemon):
    """ICH408I is the RACF audit message prefix."""
    esm.attach(fake_daemon)
    fake_daemon.fire_s2c(_make_screen_packet("ICH408I USER(BOB) GROUP(SYS1)"))
    assert "racf_confirmed" in esm.findings


def test_acf01_prefix_sets_acf2_confirmed(esm, fake_daemon):
    esm.attach(fake_daemon)
    fake_daemon.fire_s2c(_make_screen_packet("ACF01004 LOGONID NOT FOUND"))
    assert "acf2_confirmed" in esm.findings


def test_tss_prefix_sets_topsecret_confirmed(esm, fake_daemon):
    esm.attach(fake_daemon)
    fake_daemon.fire_s2c(_make_screen_packet("TSS7100E PASSWORD INCORRECT"))
    assert "topsecret_confirmed" in esm.findings


def test_no_match_no_findings(esm, fake_daemon):
    esm.attach(fake_daemon)
    fake_daemon.fire_s2c(_make_screen_packet("WELCOME TO CICS"))
    assert esm.findings == {}


def test_ignores_c2s_traffic(esm, fake_daemon):
    """Only s2c traffic carries server messages — c2s is user keystrokes."""
    esm.attach(fake_daemon)
    fake_daemon.fire_c2s(_make_screen_packet("ICH408I"))   # wrong direction
    assert esm.findings == {}


def test_multiple_findings_accumulate(esm, fake_daemon):
    esm.attach(fake_daemon)
    fake_daemon.fire_s2c(_make_screen_packet("DFHCE3530 invalid userid"))
    fake_daemon.fire_s2c(_make_screen_packet("ICH408I USER(BOB)"))
    assert "username_enum" in esm.findings
    assert "racf_confirmed" in esm.findings


def test_finding_has_severity(esm, fake_daemon):
    """Each finding carries a severity for GUI color-coding."""
    esm.attach(fake_daemon)
    fake_daemon.fire_s2c(_make_screen_packet("DFHCE3530 invalid"))
    assert esm.findings["username_enum"]["severity"] in ("low", "medium", "high")


# ---------------------------------------------------------------------------
# Password field length inference (from Screen.fields, not regex)
# ---------------------------------------------------------------------------

def test_8char_password_field_sets_no_passphrase(esm, fake_daemon):
    """An unprotected hidden field of length 8 → RACF without KDFAES.
    This is a STRUCTURAL inference, not regex — needs Screen.fields."""
    # Build: protected "PASS:" + hidden unprotected 8-byte field
    pkt = bytes([
        0xF5, 0xC3,
        0x1D, 0x60,                          # protected label field
        0xD7, 0xC1, 0xE2, 0xE2, 0x7A,        # "PASS:"
        0x1D, 0x4C,                          # unprotected + hidden (0x4C = bit6+bits3,2)
        0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,  # 8 spaces
        0x1D, 0x60,                          # next field (closes the password field at len 8)
        0xFF, 0xEF,
    ])
    esm.attach(fake_daemon)
    fake_daemon.fire_s2c(pkt)
    assert "no_passphrase" in esm.findings


def test_long_password_field_sets_passphrase_capable(esm, fake_daemon):
    """Hidden unprotected field >8 → passphrase support."""
    pkt = bytes([
        0xF5, 0xC3,
        0x1D, 0x4C,                          # hidden unprotected
    ]) + bytes([0x40] * 20) + bytes([        # 20 spaces
        0x1D, 0x60,                          # close it
        0xFF, 0xEF,
    ])
    esm.attach(fake_daemon)
    fake_daemon.fire_s2c(pkt)
    assert "passphrase_capable" in esm.findings


# ---------------------------------------------------------------------------
# Active probe — replays login with single-char mutations
# ---------------------------------------------------------------------------

def test_active_probe_off_by_default(esm):
    """Active probing is dangerous (account lockout). Must be opt-in."""
    assert esm.active_enabled is False


def test_active_probe_generates_mutations(esm):
    """Given a known-good (user, password), generate test mutations."""
    muts = esm._generate_mutations("IBMUSER", "SYS1")
    # Should include: case-flip, append-char, special-substitute
    names = {m["name"] for m in muts}
    assert "case_flip_0" in names
    assert "append_9th" in names


def test_active_probe_case_flip(esm):
    muts = esm._generate_mutations("IBMUSER", "SYS1")
    case_flip = next(m for m in muts if m["name"] == "case_flip_0")
    # First char of password flipped
    assert case_flip["password"] == "sYS1"
    assert case_flip["expected_if_success"] == "case_insensitive"
