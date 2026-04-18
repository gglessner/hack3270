# New Attacks — Quick Reference

What changed since upstream hack3270 v2.8.1. Three new GUI tabs, one dock widget, and a sibling tool.

---

## hack3270 — three new tabs + ESM dock

### Negotiation tab (LU-name spoofing)

**What it tests:** RFC 2355 preset-terminal security. If the CICS region binds USERID→TERMID/LU, spoofing a known LU name = automatic sign-on without credentials.

**Workflow:**
1. **Harvest mode** first — passive. Disconnect/reconnect c3270, watch the "Harvested LUs" list populate with whatever VTAM assigned. Build your wordlist.
2. **Single mode** — type an LU name (`CONSOLE`, `CICSA01`, anything from the harvest), hit "Set Target", reconnect c3270. The proxy splices that name into `DEVICE-TYPE REQUEST` before the host sees it.
3. **Wordlist mode** — `injections/lu-names.txt` has 686 common patterns. "Try Next" iterates. Each attempt: reconnect, see what screen you land on. Anything that's NOT the login screen = win.

**Win condition:** Results table shows `<luname> → MAIN MENU` instead of `<luname> → CESN`.

### Structured Fields tab (Query Reply lying + IND\$FILE)

**Query Reply (left half) — zero prior public research:**

Tests what happens when you lie to BMS about your terminal capabilities.

1. Set **Alt Rows: 62, Alt Cols: 160** (way bigger than any real 3270)
2. Check **Deny Color** + **Deny Highlighting** (breaks black-on-black hiding)
3. Check **Arm Query Reply Liar**
4. Reconnect — when CICS sends Read Partition Query, the proxy answers FOR YOU with the lies

**What can break:** BMS allocates buffers based on Usable Area. 62×160 = 9,920 bytes. If the app does fixed-size formatting, you may see overflow garbage or `ASRA`.

**IND\$FILE (right half):**

Set mode to **Carbon Copy** before anyone runs `IND$FILE GET <dataset>` from TSO. Captures land in `<project>_captures/`. You'll see the transfer in the table even if it's not your session.

### State Fuzzer tab (pseudo-conversational COMMAREA fuzzing)

**The deepest attack. No tool has done this before.**

CICS pseudo-conversational apps round-trip state through hidden screen fields between `RETURN TRANSID` calls. Find the round-trip, mutate it, see what breaks.

**Workflow:**
1. Type a flow name → **Record**
2. In c3270: walk a multi-screen flow (login → menu → lookup → result). Whatever you'd normally do.
3. **Stop** → flow saved to `<project>_flows.db`
4. Click the flow in the tree → **Analyze Selected Flow**
5. Targets table populates: each row is a field whose content appeared in *earlier* user input (= COMMAREA echo)
6. Select a target → pick a mutation → **Fuzz Selected Target**

**Mutations:**

| | What it sends | What it tests |
|---|---|---|
| `length_plus_1` | Original + 1 byte | Does the app check `EIBCALEN`? |
| `length_double` | Original × 2 | Buffer overflow in `RECEIVE MAP` |
| `type_confusion` | Numeric → alpha | Does COBOL re-validate `PIC 9`? |
| `extra_sba` | Phantom field appended | Does BMS validate field count? |
| `step_swap` | Replay step 0's input at step N | State desync — app expects N's data |

**Result colors:**
- 🟥 **ABEND** (red) = win. `DFHAC*`/`ASRA`/`0C4` etc. You crashed it.
- 🟧 **DISCONNECT** = host hung up. Interesting — what did it not like?
- 🟨 **SCREEN_DIFFERS** = something changed. Could be an error message, could be noise.
- ⬜ **IDENTICAL** = boring, mutation had no effect.

**If you get `diverged at step 0`:** You're not at the same screen the recording started from. CLEAR back to it and retry.

### ESM Findings dock (right side, always visible)

Passive — watches every screen for ESM-revealing patterns. Populates as you navigate:

| What you see | What it means |
|---|---|
| `[!] username_enum: DFHCE3530 seen` | **Pre-CICS-TS-5.1** — CESN tells you "userid invalid" vs "password invalid" separately. Username oracle. |
| `racf_confirmed: ICH408I` | It's RACF (not ACF2/TopSecret) |
| `no_passphrase: 8-char hidden field` | RACF without KDFAES — passwords are 8 chars max, no mixedcase |
| `account_state_leak: DFHCE3520` | Distinguishes "revoked" from "bad password" — leaks account state |

---

## hack5250 — sibling tool, separate entry point

```bash
.venv/bin/python hack5250/hack5250.py <ibmi_ip> 23 -n ibmi_test
# Point tn5250/x5250/ACS at 127.0.0.1:5251
```

5 tabs:

| Tab | Attack | Mechanic |
|---|---|---|
| Hack FFW | Field Format Word manipulation | First ever public 5250 field-attribute attack. Clears `FFW_BYPASS` (0x2000) → protected fields become editable. Rewrites screen-attr `0x27` (NONDISP) → green. |
| Inject AID | F1-24 + ATTN | Big red ATTN button = Silent Signal escape (ATTN → Operational Assistant → F9 → CL command line). "Send All Masked Keys" fires every F-key the SOH bitmap said was invalid. |
| Negotiation | IBMRSEED downgrade | Strip the RFC 2877 server seed → emulator falls back to CLEARTEXT password → captured-creds dock turns red. DEVNAME spoof = 5250's LU-name analog. |
| Inject Into Fields | Mask-template | Same `****` trick as 3270. Wordlists: 91 CL commands, 54 default Q* users. |
| Logs | SQLite viewer | Same as hack3270. |

**Captured creds dock** (right side, always visible): goes bright red when IBMRSEED downgrade succeeds. `QSECOFR : whatever`.

---

## API surfaces

| Tool | Port | Sample |
|---|---|---|
| hack3270 | `:31337` | `echo "SEND_AID CLEAR" \| nc -q1 127.0.0.1 31337` |
| hack5250 | `:52500` | `echo "ffw_unprotect on" \| nc -q1 127.0.0.1 52500` |

Both line-based, one command per line, response per line. JSON for structured data.

**hack3270 :31337 new handlers** (Phase 3):
```
esm_get_findings, lu_spoof_single, lu_get_harvested, lu_get_results,
qr_arm, qr_disarm, indfile_set_mode, indfile_get_captures,
flow_record_start, flow_record_stop, flow_analyze, flow_list_mutations
```

**hack5250 :52500 (21 handlers):**
```
ping, get_screen_text, get_fields, get_pf_mask, list_aids,
send_aid, send_attn,
ffw_unprotect, ffw_reveal_hidden, ffw_remove_numeric, ffw_high_visibility, ffw_status,
ibmrseed_downgrade, devname_spoof, nego_status, get_captured_creds,
mask_arm, mask_status, inject_word,
log_count
```

---

## Project artifacts per engagement

| File | Tool | What |
|---|---|---|
| `<project>.db` | both | SQLite packet log (Logs + Config tables) |
| `<project>_flows.db` | hack3270 | State fuzzer recordings (Flows + Steps tables) |
| `<project>_captures/` | hack3270 | IND\$FILE carbon-copies |

All three are gitignored. Back them up together.

---

## Common gotchas

**"Already in use" on TSO:** `LOGON <userid> RECONNECT` to grab the existing session, or `LOGON <userid> HERE` to kick the other terminal.

**Clear key in c3270:** Default is `Ctrl+C` (eaten by terminal as SIGINT) or `Esc` → c3270 prompt → `Clear()`. Easier: Inject Key Presses tab → CLEAR button.

**Stats tab negotiation count = 0:** Fixed in `4367e37` — it now matches both `tn3270 negotiation` (legacy DBs) and `telnet negotiation` (new).

**State fuzzer "diverged at step 0":** You're not at the recording's starting screen. CLEAR or navigate back.

**hack5250 IBMRSEED only triggers on RECONNECT:** The seed exchange happens during telnet negotiation. Arm it, then disconnect/reconnect the emulator.
