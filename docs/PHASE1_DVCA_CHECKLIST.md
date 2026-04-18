# Phase 1 — DVCA Manual Verification Checklist

**Tag:** `phase1-extraction-complete` @ `5d7e828`
**Automated tests:** 70/70 passing — golden bytes-in-bytes-out prove `manipulate()` is bit-identical.
**What can't be automated:** End-to-end through PySide6 GUI against a live mainframe.

## Setup

```bash
# Start DVCA (or your test mainframe)
# Then:
cd /home/kali/hack3270-update
/home/kali/hack3270-update/.venv/bin/python hack3270.py -i <DVCA_IP> -p 23 -n dvca_phase1_test
# In another terminal, point x3270 at 127.0.0.1:3271
```

## Per-tab checks

### 1. Connection / Logs tab
- [ ] Proxy accepts x3270 connection
- [ ] Mainframe handshake completes (telnet negotiation visible in log)
- [ ] Login screen appears in x3270
- [ ] Log rows accumulate as you navigate
- [ ] Click a server-row → screen replays in x3270 (`play_record` → `Storage.get_raw` → `inject_to_client`)

### 2. Hack Field Attributes tab
- [ ] Toggle "Remove Field Protection" → protected fields become editable in x3270
- [ ] Toggle "Reveal Hidden Fields" → non-display fields become visible
- [ ] Toggle off → next screen refresh shows fields normal again
- [ ] **CRITICAL:** Toggle ON while a screen is already displayed → screen re-renders with hacks (this exercises `hack_toggled` resend via `inject_to_client`)

### 3. Hack Text Color tab
- [ ] Toggle SA color hack → black-on-black text becomes yellow
- [ ] (DVCA may not have black-on-black — check the SA branch by inspecting log hex)

### 4. Inject Key Presses tab
- [ ] Send PF3 → mainframe responds (this exercises `send_key` → direct `self.server.send`)
- [ ] Send CLEAR → blank tranid screen
- [ ] Auto-disable: PF keys whose label is on screen are unchecked (`refresh_aids` via the s2c observer)

### 5. AID Spoofing tab — Manual mode
- [ ] Set spoof to PF12, type something, press ENTER in x3270
- [ ] Mainframe receives PF12 (not ENTER) — this exercises the client-intercept callback
- [ ] Log row shows "AID Spoofed: ENTER -> PF12"

### 6. AID Spoofing tab — Fuzzer mode
- [ ] Arm fuzzer, type something, press ENTER
- [ ] Fuzzer captures the transmission, starts iterating 0x00-0xFF
- [ ] Progress callback fires (GUI progress bar updates)
- [ ] This exercises `aid_fuzzer_armed` → intercept returns None → fuzzer drives

### 7. Inject Into Fields tab
- [ ] Click "Setup", type `****` in a field, press ENTER
- [ ] Status shows "Mask found (length: 4)" — this exercises `capture_mask` → `MaskInjector.capture`
- [ ] Pick a wordlist, click "Inject" → entries iterate through the field
- [ ] **gui.py:3334 path:** `hack3270.get_inject_preamble() + ebcdic_payload + hack3270.get_inject_postamble()` builds the packet

### 8. Field Fuzzing / Order Fuzzing tabs
- [ ] These call `api_send_raw` → `self.server.send` directly. Verify a fuzz iteration sends.

### 9. Statistics / Analysis tabs
- [ ] These read from SQLite via `all_logs`. Numbers populate.

## What changed under the hood (for diagnosis)

| What you do | Old code path | New code path |
|---|---|---|
| Toggle a hack flag | `daemon()` L1414 inline resend | `daemon()` → `inject_to_client(manipulate(server_data))` |
| Press ENTER in x3270 | `daemon()` L1374 → `server.send` | `_client_intercept(data)` → return `data` → `ProxyDaemon._handle_client` → `server.send` |
| Mainframe sends screen | `daemon()` L1405 → `handle_server` → `manipulate` | `ProxyDaemon._handle_server` → `TN3270Legacy.mutate` → s2c observer fires `refresh_aids` |
| Type `****` + ENTER (Inject Setup) | `daemon()` L1381 → `capture_mask` | `_client_intercept(data)` → `capture_mask(data)` → `MaskInjector.capture` → return `None` (drop) |
| Click a log row | `play_record` → `client.send(row[5])` | `play_record` → `Storage.get_raw` → `client.send` |

## If something fails

The 70 automated tests prove the EXTRACTION is correct — `manipulate()` produces identical bytes, all GUI-called methods exist. A failure here means the **integration** is wrong — likely:
- Socket aliasing (`self.client = self._daemon.client`) didn't propagate
- The s2c observer fires at a different point than legacy `handle_server`
- `hack_toggled` resend grabs stale `server_data`

Diagnose by adding `print()` to `daemon()` and `_client_intercept()` — they're now thin enough to trace.
