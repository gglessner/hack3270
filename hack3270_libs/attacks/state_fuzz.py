"""
Pseudo-conversational state fuzzer.

The hardest attack. Three phases (spec §3.5):

  RECORD (Task 6): observer captures (host_screen, user_input) pairs.
    Each s2c → parse → new Step.host_screen.
    Each c2s → goes on PREVIOUS step's user_input (the response to
    that screen).

  ANALYZE (Task 7): find echo-back fields. If step N's screen contains
    text that appeared in step M's input (M < N), that field echoes
    user input — a fuzzing target.

  MUTATE-REPLAY (Task 8): drive a fresh session through the flow up to
    a target step, send mutated input, classify the result.

CICS pseudo-conversational apps do `SEND MAP` → `RETURN TRANSID(next)
COMMAREA(state)` → user input → `RECEIVE MAP`. The state often
round-trips through hidden screen fields. If we can find which inbound
bytes echo back in outbound screens, we've found the COMMAREA — and
we can fuzz it.

Reference: DEF CON 30 — Labelle, "Mainframe Buffer Overflows" — the
COMMAREA echo-back pattern this exploits.
"""
import re
import time
import sqlite3
from dataclasses import dataclass, field
from typing import Optional, Literal

from hackterm_core.protocol import Protocol, Screen
from hack3270_libs.tn3270_v2 import IAC_EOR, ORD_SBA, encode_addr


# ===========================================================================
# Data model — spec §3.5
# ===========================================================================

@dataclass
class Step:
    """One round-trip: host shows a screen, user responds."""
    host_screen: Screen
    user_input: bytes = b""
    timestamp: float = 0.0


@dataclass
class Flow:
    """A recorded sequence of Steps. Persisted to SQLite."""
    id: int
    name: str
    steps: list[Step] = field(default_factory=list)


@dataclass
class EchoTarget:
    """A field in step N that echoes input from step M < N."""
    step_idx: int       # which step's screen has the echo
    field_idx: int      # index into steps[step_idx].host_screen.fields
    source_step: int    # which earlier step's input was echoed
    confidence: float   # match_len / field_len, 0.0–1.0


# ===========================================================================
# StateFuzzer
# ===========================================================================

class StateFuzzer:
    """Pseudo-conversational fuzzer: record → analyze → mutate-replay."""

    def __init__(self, protocol: Protocol, db: sqlite3.Connection):
        self.protocol = protocol
        self.db = db
        self.recording = False
        self.current_flow: Optional[Flow] = None
        self._init_schema()

    def _init_schema(self) -> None:
        """Create Flows + Steps tables. Idempotent."""
        cur = self.db.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS Flows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                created REAL NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS Steps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                flow_id INTEGER NOT NULL,
                step_idx INTEGER NOT NULL,
                host_raw BLOB NOT NULL,
                user_input BLOB NOT NULL,
                timestamp REAL NOT NULL,
                FOREIGN KEY (flow_id) REFERENCES Flows(id)
            )
        """)
        self.db.commit()

    def attach(self, daemon) -> None:
        daemon.add_observer(self._observe)

    # --- Phase 1: Record (Task 6) ---------------------------------------

    def start_recording(self, name: str) -> None:
        self.current_flow = Flow(id=0, name=name, steps=[])
        self.recording = True

    def stop_recording(self) -> int:
        """Persist current_flow to SQLite. Returns the flow_id."""
        if not self.recording or self.current_flow is None:
            raise RuntimeError("not recording")
        self.recording = False

        cur = self.db.cursor()
        cur.execute("INSERT INTO Flows (name, created) VALUES (?, ?)",
                    (self.current_flow.name, time.time()))
        flow_id = cur.lastrowid

        for idx, step in enumerate(self.current_flow.steps):
            cur.execute(
                "INSERT INTO Steps (flow_id, step_idx, host_raw, user_input, timestamp) "
                "VALUES (?, ?, ?, ?, ?)",
                (flow_id, idx, step.host_screen.raw, step.user_input, step.timestamp)
            )
        self.db.commit()

        self.current_flow.id = flow_id
        return flow_id

    def load_flow(self, flow_id: int) -> Flow:
        """Reconstruct a Flow from SQLite. Re-parses host_raw → Screen."""
        cur = self.db.cursor()
        cur.execute("SELECT name FROM Flows WHERE id = ?", (flow_id,))
        row = cur.fetchone()
        if not row:
            raise KeyError(f"flow {flow_id} not found")
        flow = Flow(id=flow_id, name=row[0], steps=[])

        cur.execute(
            "SELECT host_raw, user_input, timestamp FROM Steps "
            "WHERE flow_id = ? ORDER BY step_idx",
            (flow_id,)
        )
        for host_raw, user_input, ts in cur.fetchall():
            screen = self.protocol.parse(bytes(host_raw))
            flow.steps.append(Step(host_screen=screen,
                                   user_input=bytes(user_input),
                                   timestamp=ts))
        return flow

    def _observe(self, data: bytes, direction: str) -> None:
        if not self.recording or self.current_flow is None:
            return

        if direction == "s2c":
            # Host sent a screen → new Step
            screen = self.protocol.parse(data)
            self.current_flow.steps.append(
                Step(host_screen=screen, user_input=b"", timestamp=time.time())
            )
        elif direction == "c2s":
            # User responded → attach to PREVIOUS step (the screen they
            # were responding to). If no step exists yet (recording
            # started mid-conversation), drop silently.
            if self.current_flow.steps:
                self.current_flow.steps[-1].user_input = data

    # --- Phase 2: Analyze (Task 7) --------------------------------------

    MIN_MATCH_LEN = 4   # ignore echoes shorter than this — too noisy

    def analyze(self, flow_id: int) -> list[EchoTarget]:
        """Find echo-back fields: places where step N's screen contains
        bytes that step M < N's input contained.

        The COMMAREA echo-back signature: user types X at step M, X
        appears verbatim (or truncated/padded) inside a field at step N.
        We use longest-common-substring against the raw inbound packet —
        the EBCDIC field data lives somewhere in there past the
        AID/cursor/SBA header, and the LCS finds it without us having
        to parse the inbound format precisely.

        O(steps² × fields × content²) but flows are 5–15 steps with
        small fields, so it's microseconds.

        Returns targets sorted by confidence descending.
        """
        flow = self.load_flow(flow_id)
        targets: list[EchoTarget] = []

        for n in range(1, len(flow.steps)):
            screen = flow.steps[n].host_screen
            for f_idx, fld in enumerate(screen.fields):
                content = fld.content
                if len(content) < self.MIN_MATCH_LEN:
                    continue

                for m in range(n):
                    user_input = flow.steps[m].user_input
                    if not user_input:
                        continue
                    match_len = _longest_common_substring(content, user_input)
                    if match_len >= self.MIN_MATCH_LEN:
                        targets.append(EchoTarget(
                            step_idx=n, field_idx=f_idx,
                            source_step=m,
                            confidence=match_len / len(content),
                        ))

        targets.sort(key=lambda t: t.confidence, reverse=True)
        return targets

    # --- Phase 3: Mutate & Replay (Task 8) ------------------------------
    #
    # The replay loop needs a live host. This method orchestrates;
    # the building blocks (mutate_input, classify_result,
    # screens_match_fuzzy) are module-level pure functions covered
    # by unit tests. fuzz_target() itself is integration-tested
    # against DVCA only.

    def fuzz_target(self, daemon, flow_id: int, target: EchoTarget,
                    mutation: "Mutation",
                    swap_step: Optional[int] = None,
                    timeout: float = 5.0) -> dict:
        """Drive a fresh session through a recorded flow, mutate at the
        target step, classify the result.

        The daemon must be a freshly-connected ProxyDaemon — we replay
        the recorded inputs verbatim from step 0 up to the target's
        source_step, verify each response fuzzy-matches the recording,
        then send the mutated input and classify what comes back.

        Args:
          daemon:     ProxyDaemon, freshly connected past handshake
          flow_id:    which recorded flow to replay
          target:     which step to mutate at (from analyze())
          mutation:   one of the five Mutation literals
          swap_step:  for "step_swap", which other step's input to send
          timeout:    seconds to wait for each host response

        Returns a dict with keys: mutation, target_step, classification,
        response_text, diverged_at (None if replay tracked the recording
        all the way to the target).
        """
        flow = self.load_flow(flow_id)

        # 1. Replay verbatim up to target.source_step. The first screen
        #    (step 0) was already received when the daemon connected;
        #    we send step 0's input and expect step 1's screen back, etc.
        for idx in range(target.source_step):
            step = flow.steps[idx]
            if not step.user_input:
                continue   # screen with no input recorded — skip
            daemon.inject_to_server(step.user_input)
            response = self._wait_for_response(daemon, timeout)
            if response is None:
                return {"mutation": mutation, "target_step": target.source_step,
                        "classification": "DISCONNECT", "response_text": "",
                        "diverged_at": idx}
            # Verify we're still on track — the response should look
            # structurally like the next recorded screen.
            if idx + 1 < len(flow.steps):
                expected = flow.steps[idx + 1].host_screen
                actual = self.protocol.parse(response)
                if not screens_match_fuzzy(actual, expected):
                    return {"mutation": mutation, "target_step": target.source_step,
                            "classification": "SCREEN_DIFFERS",
                            "response_text": actual.text,
                            "diverged_at": idx}

        # 2. At the target step: mutate and send.
        original_input = flow.steps[target.source_step].user_input
        swap_with = (flow.steps[swap_step].user_input
                     if swap_step is not None else None)
        mutated = mutate_input(original_input, mutation, swap_with=swap_with)
        daemon.inject_to_server(mutated)

        # 3. Capture the host's reaction and classify it.
        response = self._wait_for_response(daemon, timeout)
        next_idx = target.source_step + 1
        expected_next = (flow.steps[next_idx].host_screen
                         if next_idx < len(flow.steps)
                         else Screen.empty())
        cls = classify_result(response, expected_next, self.protocol)

        return {
            "mutation": mutation,
            "target_step": target.source_step,
            "classification": cls,
            "response_text": (self.protocol.parse(response).text
                              if response else ""),
            "diverged_at": None,
        }

    @staticmethod
    def _wait_for_response(daemon, timeout: float) -> Optional[bytes]:
        """Pump daemon.tick() until s2c traffic arrives or timeout.

        Returns the raw bytes or None on timeout/disconnect.

        Simple polling loop — adequate for fuzzing where we control
        timing and reconnect between runs anyway. Not for production
        traffic forwarding.
        """
        captured: list[bytes] = []

        def _grab(data: bytes, direction: str) -> None:
            if direction == "s2c":
                captured.append(data)

        daemon.add_observer(_grab)
        try:
            deadline = time.time() + timeout
            while time.time() < deadline:
                if hasattr(daemon, "tick"):
                    daemon.tick()
                if captured:
                    return captured[0]
                time.sleep(0.01)
            return None
        finally:
            # ProxyDaemon.remove_observer() is idempotent (baf7b92).
            # FakeDaemon may not have it — fall back gracefully.
            if hasattr(daemon, "remove_observer"):
                daemon.remove_observer(_grab)
            else:
                try:
                    daemon._observers.remove(_grab)
                except (AttributeError, ValueError):
                    pass


# ===========================================================================
# Module-level helpers
# ===========================================================================

def _longest_common_substring(a: bytes, b: bytes) -> int:
    """Length of the longest substring of `a` that also appears in `b`.

    Naive O(|a|² × |b|) — fine for the short EBCDIC fields we compare
    (typically < 80 bytes). Walks each starting offset in `a` and
    extends until the prefix no longer appears in `b`.
    """
    if not a or not b:
        return 0
    best = 0
    for i in range(len(a)):
        # Only check lengths greater than current best — early exit
        # the moment a[i:i+length] isn't in b (longer can't be either).
        for length in range(best + 1, len(a) - i + 1):
            if a[i:i + length] in b:
                best = length
            else:
                break
    return best


def _longest_prefix_in(needle: bytes, haystack: bytes) -> int:
    """Length of the longest prefix of `needle` that appears in `haystack`.

    Cheaper than _longest_common_substring when you know the echo
    starts at offset 0 (e.g. a left-justified, right-padded field).
    """
    for length in range(len(needle), 0, -1):
        if needle[:length] in haystack:
            return length
    return 0


# ===========================================================================
# Mutation engine (Task 8) — pure functions, no daemon needed
# ===========================================================================

Mutation = Literal["length_plus_1", "length_double", "type_confusion",
                   "extra_sba", "step_swap"]

# EBCDIC numeric range: F0-F9
_EBCDIC_DIGIT_LO, _EBCDIC_DIGIT_HI = 0xF0, 0xF9


def _split_inbound(pkt: bytes) -> tuple[bytes, bytes, bytes]:
    """Split an inbound packet into (header, data, trailer).

    Inbound layout (GA23-0059 §3.5.6):
      AID(1) + cursor_addr(2) + [SBA(1) + addr(2) + field_data]* + IAC EOR

    header  = everything up to and including the LAST SBA's address bytes
    data    = the EBCDIC field content after that
    trailer = IAC EOR (or empty if not present)

    Cheap heuristic: data starts 3 bytes after the LAST SBA. Works for
    single-field inputs — the common case for COMMAREA echo-backs.
    Multi-field inputs get their last field as `data`; mutations land
    there which is fine for fuzzing purposes.
    """
    if pkt.endswith(IAC_EOR):
        body, trailer = pkt[:-2], IAC_EOR
    else:
        body, trailer = pkt, b""

    last_sba = body.rfind(bytes([ORD_SBA]))
    if last_sba >= 0 and last_sba + 3 <= len(body):
        return body[:last_sba + 3], body[last_sba + 3:], trailer

    # No SBA — short read (e.g. PA1/CLEAR keys send AID only).
    # Treat first 3 bytes (AID + cursor) as header.
    if len(body) >= 3:
        return body[:3], body[3:], trailer
    return body, b"", trailer


def mutate_input(original: bytes, mutation: Mutation,
                 swap_with: Optional[bytes] = None) -> bytes:
    """Apply a mutation to a captured inbound packet.

    Mutations (spec §3.5 table):
      length_plus_1  — append 1 byte; tests EIBCALEN check
      length_double  — duplicate data; tests buffer overflow
      type_confusion — numeric → alpha; tests COBOL PIC type validation
      extra_sba      — inject phantom field; tests RECEIVE MAP field-count
      step_swap      — replay other step's input here; tests state desync
    """
    if mutation == "step_swap":
        if swap_with is None:
            raise ValueError("step_swap requires swap_with=")
        return swap_with

    header, data, trailer = _split_inbound(original)

    if mutation == "length_plus_1":
        # Append one EBCDIC 'A'. CICS apps that check EIBCALEN ==
        # expected length will reject; apps that don't will read past
        # the COMMAREA boundary.
        return header + data + b"\xc1" + trailer

    elif mutation == "length_double":
        return header + data + data + trailer

    elif mutation == "type_confusion":
        # If the field was all-numeric (EBCDIC F0-F9), the host's
        # COBOL probably declared it PIC 9. Send alpha instead and
        # see if RECEIVE MAP / unstring blows up.
        if data and all(_EBCDIC_DIGIT_LO <= b <= _EBCDIC_DIGIT_HI for b in data):
            # Map digits to letters: F0→C1 (special-cased to avoid 0xC0
            # which isn't a valid EBCDIC letter), F1→C1, F2→C2, ... F9→C9
            alpha = bytes((b - 0xF0) + 0xC0 if b != 0xF0 else 0xC1 for b in data)
            return header + alpha + trailer
        return original  # not numeric — no-op

    elif mutation == "extra_sba":
        # Append a phantom SBA at addr 1900 (row 24-ish) with "HACK".
        # The original screen didn't have an unprotected field there.
        # If the host's RECEIVE MAP doesn't validate field positions
        # against the BMS map, it may copy this into unmapped storage.
        phantom = bytes([ORD_SBA]) + encode_addr(1900) + b"\xc8\xc1\xc3\xd2"
        return header + data + phantom + trailer

    raise ValueError(f"unknown mutation: {mutation!r}")


# ===========================================================================
# Result classification (Task 8)
# ===========================================================================

ResultClass = Literal["ABEND", "DISCONNECT", "SCREEN_DIFFERS", "IDENTICAL"]

# CICS abend message patterns. DFHACnnnn = transaction abend message.
# ASRA = 0C4 program check (the classic buffer overflow tell). ASRB = 0C1.
# AICA = runaway task. AEY9 = invalid EXEC CICS. AEXZ = storage violation.
_ABEND_RE = re.compile(
    r"\b(DFHAC\d{4}|ASRA|ASRB|AICA|AEY9|AEXZ|ABEND|0C[1-9A-F])\b"
)


def classify_result(actual_raw: Optional[bytes], expected_screen: Screen,
                    protocol: Protocol) -> ResultClass:
    """Classify the host's response to a mutated input.

    Priority order:
      DISCONNECT      — socket closed / no response. Host crashed or
                        CICS terminated the session. Highest signal.
      ABEND           — transaction abend message in screen text. We
                        broke something. Almost as good as a crash.
      IDENTICAL       — same screen as the recorded flow. Mutation had
                        no observable effect (host validated, or the
                        mutated bytes weren't load-bearing).
      SCREEN_DIFFERS  — something else. Could be a validation error
                        message, could be we landed in a different
                        state. Needs human triage.
    """
    if not actual_raw:
        return "DISCONNECT"

    actual_screen = protocol.parse(actual_raw)

    if _ABEND_RE.search(actual_screen.text):
        return "ABEND"

    if actual_screen.text == expected_screen.text:
        return "IDENTICAL"

    return "SCREEN_DIFFERS"


def screens_match_fuzzy(a: Screen, b: Screen) -> bool:
    """Are two screens structurally equivalent?

    'Fuzzy' = same field count, same protect/hidden/numeric flags per
    field, same field positions. Content IGNORED — timestamps and
    sequence numbers in field content cause false negatives otherwise.

    Used by the replay driver to verify each pre-target step landed
    on the expected screen before sending the next input. We can't
    demand byte-identical screens because the same CICS map renders
    differently across sessions (date/time fields, terminal IDs, etc).
    """
    if len(a.fields) != len(b.fields):
        return False
    for fa, fb in zip(a.fields, b.fields):
        if (fa.row, fa.col) != (fb.row, fb.col):
            return False
        if fa.protected != fb.protected:
            return False
        if fa.hidden != fb.hidden:
            return False
        if fa.numeric != fb.numeric:
            return False
    return True
