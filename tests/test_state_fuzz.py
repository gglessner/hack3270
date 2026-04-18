"""
Pseudo-conversational state fuzzer tests.

Three phases:
  Task 6 — Record: observer captures (host_screen, user_input) pairs as Steps
  Task 7 — Analyze: find echo-back fields (step N input → step N+1 output)
  Task 8 — Mutate-replay: drive flow to target step, mutate, classify result
"""
import pytest
import sqlite3
from hackterm_core.ebcdic import EbcdicCodec

_codec = EbcdicCodec()


def _screen(text: str) -> bytes:
    """Build a minimal s2c datastream rendering `text`."""
    return bytes([0xF5, 0xC3, 0x1D, 0x40]) + _codec.to_ebcdic(text) + b"\xff\xef"


def _input(text: str) -> bytes:
    """Build a minimal c2s inbound packet (AID=ENTER + text)."""
    # AID + cursor + SBA + addr + EBCDIC text + IAC EOR
    return (b"\x7d\x40\x40\x11\x40\xc1"
            + _codec.to_ebcdic(text) + b"\xff\xef")


# ===========================================================================
# Task 6: Recording
# ===========================================================================

@pytest.fixture
def fuzzer(tmp_path):
    from hack3270_libs.attacks.state_fuzz import StateFuzzer
    from hack3270_libs.tn3270_v2 import TN3270
    db = sqlite3.connect(str(tmp_path / "fuzz.db"))
    return StateFuzzer(protocol=TN3270(), db=db)


def test_step_dataclass():
    from hack3270_libs.attacks.state_fuzz import Step
    from hackterm_core.protocol import Screen
    s = Step(host_screen=Screen.empty(), user_input=b"\x7d", timestamp=0.0)
    assert s.user_input == b"\x7d"


def test_flow_dataclass():
    from hack3270_libs.attacks.state_fuzz import Flow
    f = Flow(id=0, name="login", steps=[])
    assert f.name == "login"
    assert f.steps == []


def test_recorder_starts_not_recording(fuzzer):
    assert fuzzer.recording is False


def test_start_recording(fuzzer, fake_daemon):
    fuzzer.attach(fake_daemon)
    fuzzer.start_recording("login_flow")
    assert fuzzer.recording is True
    assert fuzzer.current_flow.name == "login_flow"


def test_record_s2c_creates_step(fuzzer, fake_daemon):
    """Each s2c packet → parse() → store as new Step.host_screen."""
    fuzzer.attach(fake_daemon)
    fuzzer.start_recording("test")
    fake_daemon.fire_s2c(_screen("ENTER USERID"))
    assert len(fuzzer.current_flow.steps) == 1
    assert "ENTER USERID" in fuzzer.current_flow.steps[0].host_screen.text


def test_record_c2s_attaches_to_previous_step(fuzzer, fake_daemon):
    """Each c2s packet → store as user_input on the PREVIOUS step.
    The pairing is: host shows screen, THEN user responds. So the
    response goes on the step that holds the screen the user saw."""
    fuzzer.attach(fake_daemon)
    fuzzer.start_recording("test")
    fake_daemon.fire_s2c(_screen("ENTER USERID"))
    fake_daemon.fire_c2s(_input("BOB"))
    assert len(fuzzer.current_flow.steps) == 1
    assert fuzzer.current_flow.steps[0].user_input == _input("BOB")


def test_record_full_flow(fuzzer, fake_daemon):
    """Multi-step: screen → input → screen → input → screen."""
    fuzzer.attach(fake_daemon)
    fuzzer.start_recording("login")
    fake_daemon.fire_s2c(_screen("USERID:"))
    fake_daemon.fire_c2s(_input("BOB"))
    fake_daemon.fire_s2c(_screen("PASSWORD:"))
    fake_daemon.fire_c2s(_input("SECRET"))
    fake_daemon.fire_s2c(_screen("WELCOME BOB"))

    flow = fuzzer.current_flow
    assert len(flow.steps) == 3
    assert "USERID" in flow.steps[0].host_screen.text
    assert flow.steps[0].user_input == _input("BOB")
    assert "PASSWORD" in flow.steps[1].host_screen.text
    assert flow.steps[1].user_input == _input("SECRET")
    assert "WELCOME BOB" in flow.steps[2].host_screen.text
    assert flow.steps[2].user_input == b""  # no input yet


def test_record_ignores_when_not_recording(fuzzer, fake_daemon):
    fuzzer.attach(fake_daemon)
    fake_daemon.fire_s2c(_screen("hello"))
    assert fuzzer.current_flow is None


def test_record_c2s_before_any_screen_is_ignored(fuzzer, fake_daemon):
    """Recording started mid-conversation: c2s arrives but no step exists yet.
    Don't crash — just drop it."""
    fuzzer.attach(fake_daemon)
    fuzzer.start_recording("mid")
    fake_daemon.fire_c2s(_input("ORPHAN"))
    assert len(fuzzer.current_flow.steps) == 0
    # Subsequent s2c should still work
    fake_daemon.fire_s2c(_screen("HELLO"))
    assert len(fuzzer.current_flow.steps) == 1


def test_stop_recording_persists_to_db(fuzzer, fake_daemon):
    """stop_recording() writes Flow + Steps to SQLite, returns flow_id."""
    fuzzer.attach(fake_daemon)
    fuzzer.start_recording("login")
    fake_daemon.fire_s2c(_screen("USERID:"))
    fake_daemon.fire_c2s(_input("BOB"))

    flow_id = fuzzer.stop_recording()
    assert flow_id > 0
    assert fuzzer.recording is False

    # Verify it's in the DB
    cur = fuzzer.db.cursor()
    cur.execute("SELECT name FROM Flows WHERE id = ?", (flow_id,))
    assert cur.fetchone()[0] == "login"
    cur.execute("SELECT COUNT(*) FROM Steps WHERE flow_id = ?", (flow_id,))
    assert cur.fetchone()[0] == 1


def test_load_flow_from_db(fuzzer, fake_daemon):
    """Round-trip: record → stop → load."""
    fuzzer.attach(fake_daemon)
    fuzzer.start_recording("login")
    fake_daemon.fire_s2c(_screen("USERID:"))
    fake_daemon.fire_c2s(_input("BOB"))
    fake_daemon.fire_s2c(_screen("WELCOME"))
    flow_id = fuzzer.stop_recording()

    loaded = fuzzer.load_flow(flow_id)
    assert loaded.name == "login"
    assert len(loaded.steps) == 2
    assert "USERID" in loaded.steps[0].host_screen.text
    assert loaded.steps[0].user_input == _input("BOB")


# ===========================================================================
# Task 7: Echo-back analysis
# ===========================================================================

def test_echotarget_dataclass():
    from hack3270_libs.attacks.state_fuzz import EchoTarget
    t = EchoTarget(step_idx=2, field_idx=0, source_step=0, confidence=1.0)
    assert t.confidence == 1.0


def test_analyze_finds_simple_echo(fuzzer, fake_daemon):
    """Step 0 input contains 'BOBSMITH'. Step 1 screen contains 'BOBSMITH'.
    → EchoTarget(step_idx=1, source_step=0)."""
    fuzzer.attach(fake_daemon)
    fuzzer.start_recording("echo_test")
    fake_daemon.fire_s2c(_screen("USERID:"))
    fake_daemon.fire_c2s(_input("BOBSMITH"))
    # The next screen echoes the input back
    fake_daemon.fire_s2c(_screen("WELCOME BOBSMITH"))
    flow_id = fuzzer.stop_recording()

    targets = fuzzer.analyze(flow_id)
    assert len(targets) >= 1
    t = targets[0]
    assert t.step_idx == 1       # echo appears in step 1
    assert t.source_step == 0    # input came from step 0


def test_analyze_no_echo_no_targets(fuzzer, fake_daemon):
    """No relationship between input and next screen → no targets."""
    fuzzer.attach(fake_daemon)
    fuzzer.start_recording("no_echo")
    fake_daemon.fire_s2c(_screen("USERID:"))
    fake_daemon.fire_c2s(_input("BOBSMITH"))
    fake_daemon.fire_s2c(_screen("ACCESS DENIED"))   # no echo
    flow_id = fuzzer.stop_recording()

    targets = fuzzer.analyze(flow_id)
    assert targets == []


def test_analyze_minimum_match_length(fuzzer, fake_daemon):
    """Matches shorter than 4 bytes are noise — ignored.
    'AB' appearing in both screens shouldn't count."""
    fuzzer.attach(fake_daemon)
    fuzzer.start_recording("short")
    fake_daemon.fire_s2c(_screen("ENTER:"))
    fake_daemon.fire_c2s(_input("AB"))   # only 2 chars
    fake_daemon.fire_s2c(_screen("HELLO AB WORLD"))   # contains "AB" but too short
    flow_id = fuzzer.stop_recording()

    targets = fuzzer.analyze(flow_id)
    assert targets == []


def test_analyze_confidence_full_match(fuzzer, fake_daemon):
    """When field content == input text exactly, confidence = 1.0."""
    fuzzer.attach(fake_daemon)
    fuzzer.start_recording("conf")
    fake_daemon.fire_s2c(_screen("ENTER:"))
    fake_daemon.fire_c2s(_input("EXACTMATCH"))
    # Build a screen where one field's content is EXACTLY "EXACTMATCH"
    # SF + EBCDIC "EXACTMATCH" + SF (closes the field at exactly that length)
    pkt = (bytes([0xF5, 0xC3, 0x1D, 0x40])
           + _codec.to_ebcdic("EXACTMATCH")
           + bytes([0x1D, 0x60, 0xFF, 0xEF]))
    fake_daemon.fire_s2c(pkt)
    flow_id = fuzzer.stop_recording()

    targets = fuzzer.analyze(flow_id)
    assert len(targets) >= 1
    assert targets[0].confidence == 1.0


def test_analyze_confidence_partial_match(fuzzer, fake_daemon):
    """Field content partially matches input → confidence < 1.0."""
    fuzzer.attach(fake_daemon)
    fuzzer.start_recording("partial")
    fake_daemon.fire_s2c(_screen("ENTER:"))
    fake_daemon.fire_c2s(_input("ABCDEFGH"))
    # Field contains "ABCDE   " (5 of 8 chars match, padded to 8)
    pkt = (bytes([0xF5, 0xC3, 0x1D, 0x40])
           + _codec.to_ebcdic("ABCDE   ")
           + bytes([0x1D, 0x60, 0xFF, 0xEF]))
    fake_daemon.fire_s2c(pkt)
    flow_id = fuzzer.stop_recording()

    targets = fuzzer.analyze(flow_id)
    assert len(targets) >= 1
    # Field is 8 chars, 5 matched → confidence = 5/8
    assert 0.5 < targets[0].confidence < 1.0


def test_analyze_multi_step_echo(fuzzer, fake_daemon):
    """Echo can come from ANY earlier step, not just the immediately
    preceding one (e.g. login userid echoed on screen 5)."""
    fuzzer.attach(fake_daemon)
    fuzzer.start_recording("multi")
    fake_daemon.fire_s2c(_screen("USERID:"))
    fake_daemon.fire_c2s(_input("ALICE"))         # step 0
    fake_daemon.fire_s2c(_screen("PASSWORD:"))
    fake_daemon.fire_c2s(_input("SECRET"))        # step 1
    fake_daemon.fire_s2c(_screen("MENU"))
    fake_daemon.fire_c2s(_input("OPTION1"))       # step 2
    fake_daemon.fire_s2c(_screen("HELLO ALICE"))  # step 3 echoes step 0!
    flow_id = fuzzer.stop_recording()

    targets = fuzzer.analyze(flow_id)
    # Should find at least the ALICE echo at step 3 from source step 0
    alice_targets = [t for t in targets if t.step_idx == 3 and t.source_step == 0]
    assert len(alice_targets) >= 1


def test_analyze_field_idx_correct(fuzzer, fake_daemon):
    """When a screen has multiple fields, field_idx points to the right one."""
    fuzzer.attach(fake_daemon)
    fuzzer.start_recording("fieldidx")
    fake_daemon.fire_s2c(_screen("ENTER:"))
    fake_daemon.fire_c2s(_input("FINDME"))
    # Screen with 3 fields: "AAAA", "FINDME", "ZZZZ"
    pkt = (bytes([0xF5, 0xC3])
           + bytes([0x1D, 0x40]) + _codec.to_ebcdic("AAAA")
           + bytes([0x1D, 0x40]) + _codec.to_ebcdic("FINDME")
           + bytes([0x1D, 0x40]) + _codec.to_ebcdic("ZZZZ")
           + b"\xff\xef")
    fake_daemon.fire_s2c(pkt)
    flow_id = fuzzer.stop_recording()

    targets = fuzzer.analyze(flow_id)
    findme = [t for t in targets if t.confidence == 1.0]
    assert len(findme) == 1
    assert findme[0].field_idx == 1   # second field (0-indexed)


# ===========================================================================
# Task 8: Mutate-replay
# ===========================================================================

# --- Mutation generation (pure functions — fully unit-testable) ---

def test_mutate_length_plus_1():
    """Original input + 1 byte. Tests EIBCALEN check."""
    from hack3270_libs.attacks.state_fuzz import mutate_input
    original = b"\x7d\x40\x40\x11\x40\xc1\xc1\xc2\xc3\xff\xef"  # ENTER + "ABC"
    out = mutate_input(original, "length_plus_1")
    # One byte longer than original (excluding IAC EOR which stays at end)
    assert len(out) == len(original) + 1
    assert out.endswith(b"\xff\xef")
    # Original data still present
    assert b"\xc1\xc2\xc3" in out


def test_mutate_length_double():
    from hack3270_libs.attacks.state_fuzz import mutate_input
    original = b"\x7d\x40\x40\x11\x40\xc1\xc1\xc2\xc3\xff\xef"
    out = mutate_input(original, "length_double")
    # Data portion doubled (3 bytes → 6 bytes)
    assert b"\xc1\xc2\xc3\xc1\xc2\xc3" in out
    assert out.endswith(b"\xff\xef")


def test_mutate_type_confusion_numeric_to_alpha():
    """All-numeric input (0xF0-0xF9) → replaced with alpha."""
    from hack3270_libs.attacks.state_fuzz import mutate_input
    # Input data is "123" = F1 F2 F3
    original = b"\x7d\x40\x40\x11\x40\xc1\xf1\xf2\xf3\xff\xef"
    out = mutate_input(original, "type_confusion")
    # Should NOT contain the original digits
    assert b"\xf1\xf2\xf3" not in out
    # Should contain alpha bytes instead (0xC1+ range)
    data = out[6:-2]  # strip header + IAC EOR
    assert all(0xC1 <= b <= 0xE9 for b in data)


def test_mutate_type_confusion_non_numeric_unchanged():
    """If input wasn't numeric, type_confusion is a no-op."""
    from hack3270_libs.attacks.state_fuzz import mutate_input
    original = b"\x7d\x40\x40\x11\x40\xc1\xc1\xc2\xc3\xff\xef"  # alpha
    out = mutate_input(original, "type_confusion")
    assert out == original


def test_mutate_extra_sba():
    """Append SBA + addr + data the original screen didn't have.
    Tests if host validates field count vs. screen layout."""
    from hack3270_libs.attacks.state_fuzz import mutate_input
    original = b"\x7d\x40\x40\x11\x40\xc1\xc1\xc2\xff\xef"
    out = mutate_input(original, "extra_sba")
    # Should have 2 SBA orders now (original + injected)
    assert out.count(0x11) >= 2
    assert out.endswith(b"\xff\xef")


def test_mutate_step_swap():
    """step_swap needs the OTHER step's input — pass it as kwarg."""
    from hack3270_libs.attacks.state_fuzz import mutate_input
    original = b"\x7d\x40\x40\x11\x40\xc1\xc1\xff\xef"
    other = b"\x7d\x40\x40\x11\x40\xc1\xe9\xe9\xe9\xff\xef"   # different data
    out = mutate_input(original, "step_swap", swap_with=other)
    assert out == other  # entire packet replaced


def test_mutate_unknown_raises():
    from hack3270_libs.attacks.state_fuzz import mutate_input
    with pytest.raises(ValueError):
        mutate_input(b"\x7d\xff\xef", "not_a_real_mutation")


# --- Result classification ---

def test_classify_identical():
    """Response matches recorded screen byte-for-byte → IDENTICAL."""
    from hack3270_libs.attacks.state_fuzz import classify_result
    from hack3270_libs.tn3270_v2 import TN3270
    p = TN3270()
    expected = p.parse(_screen("WELCOME BOB"))
    actual = _screen("WELCOME BOB")
    assert classify_result(actual, expected, p) == "IDENTICAL"


def test_classify_screen_differs():
    from hack3270_libs.attacks.state_fuzz import classify_result
    from hack3270_libs.tn3270_v2 import TN3270
    p = TN3270()
    expected = p.parse(_screen("WELCOME BOB"))
    actual = _screen("ERROR INVALID INPUT")
    assert classify_result(actual, expected, p) == "SCREEN_DIFFERS"


def test_classify_abend():
    """ABEND messages have known prefixes: DFHAC, ASRA, etc."""
    from hack3270_libs.attacks.state_fuzz import classify_result
    from hack3270_libs.tn3270_v2 import TN3270
    p = TN3270()
    expected = p.parse(_screen("WELCOME"))
    actual = _screen("DFHAC2206 TRANSACTION ABEND ASRA")
    assert classify_result(actual, expected, p) == "ABEND"


def test_classify_disconnect():
    """Empty response → host closed the connection."""
    from hack3270_libs.attacks.state_fuzz import classify_result
    from hack3270_libs.tn3270_v2 import TN3270
    p = TN3270()
    expected = p.parse(_screen("WELCOME"))
    assert classify_result(b"", expected, p) == "DISCONNECT"
    assert classify_result(None, expected, p) == "DISCONNECT"


def test_classify_abend_takes_priority():
    """Even if screen differs in other ways, ABEND wins."""
    from hack3270_libs.attacks.state_fuzz import classify_result
    from hack3270_libs.tn3270_v2 import TN3270
    p = TN3270()
    expected = p.parse(_screen("X"))
    actual = _screen("SOMETHING DIFFERENT DFHAC2206 ASRA")
    assert classify_result(actual, expected, p) == "ABEND"


# --- Fuzzy screen comparison (timestamps differ but it's the "same" screen) ---

def test_screens_match_fuzzy_ignores_field_content():
    """Two screens with same field STRUCTURE but different content
    are 'fuzzy equal' — needed because timestamps in fields change."""
    from hack3270_libs.attacks.state_fuzz import screens_match_fuzzy
    from hack3270_libs.tn3270_v2 import TN3270
    p = TN3270()
    # Same structure: 1 protected field, 1 unprotected, both same length
    a = p.parse(bytes([0xF5, 0xC3, 0x1D, 0x60, 0xC1, 0xC2, 0xC3,
                       0x1D, 0x40, 0xF1, 0xF2, 0xF3, 0xFF, 0xEF]))
    b = p.parse(bytes([0xF5, 0xC3, 0x1D, 0x60, 0xE7, 0xE8, 0xE9,
                       0x1D, 0x40, 0xF7, 0xF8, 0xF9, 0xFF, 0xEF]))
    assert screens_match_fuzzy(a, b) is True


def test_screens_match_fuzzy_rejects_different_structure():
    """Different field count → not fuzzy equal."""
    from hack3270_libs.attacks.state_fuzz import screens_match_fuzzy
    from hack3270_libs.tn3270_v2 import TN3270
    p = TN3270()
    a = p.parse(bytes([0xF5, 0xC3, 0x1D, 0x60, 0xC1, 0xFF, 0xEF]))           # 1 field
    b = p.parse(bytes([0xF5, 0xC3, 0x1D, 0x60, 0xC1, 0x1D, 0x40, 0xC2, 0xFF, 0xEF]))  # 2 fields
    assert screens_match_fuzzy(a, b) is False
