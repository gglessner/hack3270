"""
ESM (External Security Manager) passive fingerprinter.

Registers as a ProxyDaemon observer. Watches server→client screens for
known message codes that leak ESM type and configuration.

Spec: docs/superpowers/specs/2026-04-07-hackterm-design.md §3.3
Reference: IBM APAR PM80209 (DFHCE3530/3532 disclosure)

This is the CHEAPEST attack — pure regex on Screen.text. Ships first
to validate the observer wiring works before building anything complex.
"""
import re
import time
from typing import Any

from hackterm_core.protocol import Protocol, Screen


# Inference rules — spec §3.3 table.
# Each rule: (compiled regex, finding_key, severity, human description)
_RULES = [
    (re.compile(r"\bDFHCE3530\b"), "username_enum", "high",
     "Pre-CICS-TS-5.1 or unpatched — distinguishes invalid userid from invalid password"),
    (re.compile(r"\bDFHCE3532\b"), "username_enum", "high",
     "Confirms differential — userid valid, password wrong"),
    (re.compile(r"\bDFHCE3520\b"), "account_state_leak", "medium",
     "Distinguishes revoked account from bad credential"),
    (re.compile(r"\bDFHCE3592\b"), "password_expiry", "low",
     "RACF INTERVAL is non-zero — password expiry enforced"),
    (re.compile(r"\bDFHCE3543\b"), "passphrase", "low",
     "Passphrase support enabled"),
    (re.compile(r"\bICH408I\b"), "racf_confirmed", "low",
     "ESM is RACF (not ACF2/TopSecret)"),
    (re.compile(r"\bACF01\d{3}\b"), "acf2_confirmed", "low",
     "ESM is CA-ACF2"),
    (re.compile(r"\bTSS\d{4}[EWI]\b"), "topsecret_confirmed", "low",
     "ESM is CA-TopSecret"),
]


class ESMFingerprinter:
    """Passive ESM type & configuration inference.

    Usage:
        esm = ESMFingerprinter(protocol=tn3270_instance)
        esm.attach(daemon)            # registers as observer
        ...                           # traffic flows
        print(esm.findings)           # dict of {key: {evidence, severity, ...}}
    """

    def __init__(self, protocol: Protocol):
        self.protocol = protocol
        self.findings: dict[str, dict[str, Any]] = {}
        self.active_enabled = False    # active probing is opt-in (lockout risk)

    def attach(self, daemon) -> None:
        """Register as observer on the proxy daemon."""
        daemon.add_observer(self._observe)

    def _observe(self, data: bytes, direction: str) -> None:
        if direction != "s2c":
            return  # user keystrokes don't carry server messages
        screen = self.protocol.parse(data)
        self._check_text(screen)
        self._check_fields(screen)

    def _check_text(self, screen: Screen) -> None:
        text = screen.text
        for pattern, key, severity, desc in _RULES:
            m = pattern.search(text)
            if m:
                self._record(key, severity, desc, evidence=m.group(0))

    def _check_fields(self, screen: Screen) -> None:
        """Structural inference: hidden+unprotected = password field.
        Length 8 → no passphrase. Length >8 → passphrase-capable."""
        for f in screen.fields:
            if f.hidden and not f.protected:
                if f.length == 8:
                    self._record("no_passphrase", "medium",
                                 "Password field exactly 8 chars — RACF without KDFAES",
                                 evidence=f"hidden field at ({f.row},{f.col}) len=8")
                elif f.length > 8:
                    self._record("passphrase_capable", "low",
                                 "Password field >8 chars — MIXEDCASE likely too",
                                 evidence=f"hidden field at ({f.row},{f.col}) len={f.length}")

    def _record(self, key: str, severity: str, desc: str, evidence: str) -> None:
        if key not in self.findings:
            self.findings[key] = {
                "severity": severity,
                "description": desc,
                "evidence": [],
                "first_seen": time.time(),
            }
        if evidence not in self.findings[key]["evidence"]:
            self.findings[key]["evidence"].append(evidence)

    # --- Active probe (off by default — account lockout risk) -----------

    def _generate_mutations(self, user: str, password: str) -> list[dict]:
        """Build the mutation list for active probing.

        Each mutation is a dict:
          {name, user, password, expected_if_success, expected_if_fail}

        The actual drive (sending these to the host) needs a live daemon
        and is left as an integration concern. Unit tests verify only
        the mutation generation.
        """
        muts = []

        # Case-flip first char of password — tests case sensitivity
        if password:
            flipped = password[0].swapcase() + password[1:]
            muts.append({
                "name": "case_flip_0",
                "user": user, "password": flipped,
                "expected_if_success": "case_insensitive",
                "expected_if_fail": "case_sensitive",
            })

        # Append a 9th character — tests 8-char truncation (legacy RACF)
        muts.append({
            "name": "append_9th",
            "user": user, "password": password + "X",
            "expected_if_success": "host_truncates",
            "expected_if_fail": "length_validated",
        })

        # Special-char substitution — tests RACF special-char rules
        if "$" in password:
            muts.append({
                "name": "special_swap",
                "user": user, "password": password.replace("$", "!"),
                "expected_if_success": "liberal_specials",
                "expected_if_fail": "restricted_specials",
            })

        return muts
