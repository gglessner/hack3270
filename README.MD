# hack3270

A Python 3 toolkit for manipulating TN3270 data streams, specifically designed for application penetration testing of mainframe CICS applications.

## Version 2.5.2 Changelog

### API Bug Fixes
- **Fixed `send_command()` for IBM mainframes**: Added SBA (Set Buffer Address) order to packet structure for TN3270E compatibility. The function now works correctly on both TK4 emulators and real IBM mainframes.

### GUI Improvements
- **Field Fuzzing tab layout**: Added width constraints to Options (max 300px) and Controls (max 400px) boxes for better visual balance

---

## Version 2.5.1 Changelog

### Redesigned Statistics Tab
Complete overhaul of the Statistics tab with a 3x3 grid layout providing comprehensive session metrics:

#### Connection & Traffic
- Server address, TLS status, protocol mode
- TCP sessions, session duration
- Server/client message and byte counts
- Average response/request sizes

#### Hack Operations & Hidden Fields
- Field hack and color hack enable counts
- Hack toggle events, TN3270 negotiations
- Hidden fields detected and fields with data
- Screens containing hidden fields

#### AID & Field Injection
- Inject Keys tab usage
- AID Spoofing (manual mode) count
- AID Fuzzer test count
- API: Send AID, Send Field, Send Command counts
- Mask captures, replay operations
- Total injection counts

#### Fuzzing Activity & Results
- Field fuzzing and order fuzzing test counts
- Brute force attempts
- GUI fuzz packets sent
- ABENDs triggered, errors detected
- Unique crash payloads, ABEND rate
- Top ABEND causes summary

### Window Height Fixes
- Fixed issue where switching from taller tabs wouldn't reset window height
- All tabs now properly resize to their correct height
- Logs, Analysis, and Statistics tabs share the same unified height
- Field Fuzzing and Order Fuzzing tabs share the same height (700px)

---

## Version 2.5.0 Changelog

### New Fuzzing Tabs
Two comprehensive fuzzing tabs have been added to the GUI between AID Spoofing and Logs:

#### Field Fuzzing Tab
- **Redesigned Layout**: Left panel for discovered fields (full height), right panel for controls and findings
- **Field Discovery**: Automatically discovers input, protected, and hidden fields from the current screen
- **Field Value Display**: Shows current EBCDIC→ASCII converted values for each discovered field
- **Field Selection**: All/None buttons to quickly select/deselect fields for fuzzing
- **Configurable Payload Categories** (default unchecked for safety):
  - Buffer Overflow
  - Packed Decimal (COMP-3)
  - Zoned Decimal
  - Date/Time Edge Cases
  - EBCDIC Control Characters
  - CICS Transaction Injection
  - SQL/DB2 Injection
  - COBOL Special Values (LOW-VALUES, HIGH-VALUES)
  - Random Binary
  - Boundary Testing

#### Order Fuzzing Tab
- **TN3270 Protocol Order Injection**: Tests SBA, SF, SFE, RA, EUA, IC, PT, GE order handling
- **Extended Payloads**: Invalid addresses, nested orders, Telnet escapes, random sequences
- **Separate Interface**: Dedicated tab for protocol-level fuzzing

#### Common Features
- **Safety Controls**: Dual confirmation warning ("I understand and have permission!")
- **Real-time Monitoring**: Stop on ABEND detection, stop on connection loss
- **Controls**: Start, Stop, Pause, Resume with progress display
- **Findings Table**: Color-coded results (red=ABEND, orange=warning, yellow=error)
- **Numeric Sorting**: Findings tables sort numerically by # and Response Length columns
- **CSV Export**: Export findings to CSV file

#### New Internal Methods
- `api_send_raw(data, description)` - Direct packet sending from GUI
- `get_last_server_raw()` - Get raw server response bytes
- `get_last_server()` - Get ASCII-converted server response

---

## Version 2.4.6 Changelog

### Improved Logging Descriptions
- `send_raw()` now accepts optional `description` parameter for custom log messages
- `send_field()` logs as `API: Send field "text"`
- `send_command()` logs as `API: Send command "text"`
- `send_client_data()` logs as `API: Replay client data (ID X)`
- `inject()` logs as `API: Inject "value"`

### Standardized Fuzzing Log Format
- All fuzzers now use consistent `Fuzz: target/payload` format
- Enables unified analysis across fuzz.py, fuzz2.py, fuzz3.py, order_fuzz.py
- Brute force scripts use `Brute: value` format

### Analysis Tab Enhancements
- New "Fuzz" detection type for API fuzzing results
- Automatically detects abends (SOC7, ASRA, APCT, AICA, etc.) in fuzzing responses
- Detects error patterns (NOT FOUND, UNDEFINED, UNKNOWN TRANSACTION)
- Status shows fuzz abend and error counts

### Standalone Analysis Script (`analyze.py`)
- Added `analyze_fuzzing()` function for processing Fuzz:/Brute: entries
- Groups fuzzing by timing sequences
- Reports abends, errors, and length anomalies

---

## Version 2.4.5 Changelog

### New API Functions for Screen Parsing
- `decode_buffer_address(b1, b2)` - Decode 12-bit/14-bit buffer addresses
- `encode_buffer_address(addr)` - Encode position to 2-byte address
- `parse_screen_fields()` - Parse 3270 data stream to discover all fields
- `get_input_fields()` - Get editable (unprotected) fields
- `get_protected_fields()` - Get read-only fields
- `get_hidden_fields()` - Get hidden fields
- `is_field_protected(attr)`, `is_field_numeric(attr)`, `is_field_hidden(attr)` - Attribute helpers
- `check_abend()` - Detect mainframe abend/error patterns
- `test_connection()` - Verify API is responsive
- `build_raw_packet()` - Build TN3270 packets with proper headers

### New API Constants
- `ADDR_TABLE` - 12-bit address encoding table
- `ORDERS` - TN3270 order byte reference (SBA, SF, SFE, etc.)
- `WRITE_COMMANDS` - Write command reference
- `ABEND_PATTERNS` - Mainframe error patterns

### Fuzzing Scripts
Added comprehensive fuzzing tools for mainframe penetration testing:

- **`fuzz.py`** - CICS/COBOL-specific fuzzer with hardcoded fields
  - Packed decimal (COMP-3) attacks
  - Zoned decimal invalid data
  - CICS command injection
  - SQL/DB2 injection attempts
  - TN3270 order injection

- **`fuzz2.py`** - Dynamic field discovery fuzzer
  - Automatically discovers input fields on current screen
  - No field configuration required
  - Uses API screen parsing functions

- **`fuzz3.py`** - Protected & hidden field fuzzer
  - Tests server-side validation of "read-only" data
  - Detects if server trusts protected field data
  - Corruption detection and auto-stop

- **`order_fuzz.py`** - TN3270 protocol order injection
  - Tests SBA, SF, SFE, RA, EUA order handling
  - Telnet control sequence injection
  - Protocol parsing vulnerability detection

### Documentation
- Created tutorials: `fuzz.md`, `fuzz2.md`, `fuzz3.md`, `order_fuzz.md`
- Updated `API_Documentation.md` with new screen parsing functions

---

## Version 2.4.4 Changelog

### TN3270E Protocol Fixes
- Fixed AID handling for TN3270E mode (IBM mainframes vs TK4)
- API functions now correctly prepend 5-byte TN3270E header when required
- Added `is_tn3270e()` API function to query proxy mode

#### Functions Updated
- `send_aid()` - now adds TN3270E header automatically
- `send_field()` - now adds TN3270E header automatically  
- `send_command()` - now adds TN3270E header automatically
- AID Fuzzer and AID Spoofing - fixed byte position for TN3270E

---

## Version 2.4.3 Changelog

### New API Functions
- Added `send_field()` - send text to a specific field with automatic EBCDIC conversion
- Added `send_command()` - send commands on unformatted screens

### New Scripts (No Database Required)
- `login2.py` - Login using raw packet construction (no .db file)
- `login3.py` - Login with automatic reconnect handling for "USERID IN USE" scenarios
- `brute2.py` - Brute force using raw packets with form data defined in ASCII

### Documentation
- Created in-depth tutorials for all scripts:
  - `login.md`, `login2.md`, `login3.md`
  - `check_hidden.md`, `aid_scan.md`
  - `brute.md`, `brute2.md`
- Updated `API-Examples.md` with all new scripts
- Updated `API_Documentation.md` with new functions

### Cleanup
- Removed redundant scripts (`inject_loop.py`, `login-reconnect.py`)

---

## Version 2.4.2 Changelog

### API Client Library Fix
- Fixed `get_inject_template()` to use local database instead of server's database
- Injection scripts now work with custom `.db` files (e.g., `dvca-brute.db`)

### Code Organization
- Moved all API example scripts to `API-DVCA-Code/` directory
- Added `API-Examples.md` with step-by-step DVCA demo instructions

---

## Version 2.4.1 Changelog

### Offline Mode Fix
- Web API no longer starts in offline mode (`-o` flag)
- Prevents unnecessary port binding when replaying sessions

### Security Fix
- Web API now binds to `127.0.0.1` (localhost) only
- Prevents remote access to the API port (31337)

---

## Version 2.4.0 Changelog

### New Feature: Web API for Automation

Added a **TCP Web API** on port 31337 for scripting and automation of penetration tests.

#### Python Client Library (`hack3270_api.py`)
- Full-featured client library for API interaction
- Direct SQLite3 database access for session replay
- Context manager support for clean resource handling

#### API Capabilities
- **Connection Management**: `connect()`, `disconnect()`, `is_connected()`, `reconnect()`, `is_tn3270e()`
- **Response Handling**: `get_last_server()`, `get_last_server_raw()`, `wait_for(pattern)`, `wait_for_change()`
- **Screen Analysis**: `get_screen_text()`, `find_text()`, `find_field()`, `get_text_at()`
- **Data Conversion**: `ascii_to_ebcdic()`, `ebcdic_to_ascii()`
- **AID Keys**: `send_aid()` - send ENTER, PF1-24, PA1-3, CLEAR, etc.
- **Raw Data**: `send_raw()`, `send_client_data()`
- **Field Injection**: `get_inject_template()`, `inject()`, `load_injection_file()`
- **Hidden Fields**: `analyze_hidden()` - detect data in hidden fields
- **Automation**: `replay_sequence()`, `record_start()`, `record_stop()`, `playback()`

#### Documentation
- Full API documentation in `API_Documentation.md`
- Example code for all methods
- Step-by-step automation tutorials

---

## Version 2.3.2 Changelog

### Analysis Tab Export
- **Export CSV**: New button exports analysis results to CSV file
- Exports all columns: Type, Request ID, Response ID, Value/Key, Length, Finding
- UTF-8 encoding for proper character handling

---

## Version 2.3.1 Changelog

### Analysis Tab Improvements
- **AID Fuzzer Detection**: Now detects `AID Fuzz:` and `AID Spoofed:` patterns in addition to `Sending key:`
- **Numeric Sorting**: Results sorted numerically by Request ID (same as Logs tab)
- All three AID sources detected: Inject Keys, AID Fuzzer, AID Spoof Manual

---

## Version 2.3.0 Changelog

### Redesigned Analysis Tab

Completely rebuilt **Analysis Tab** with three distinct detection methods:

#### 1. Hidden Field Detection
- Scans server responses for hidden fields revealed by Hack Fields mode
- Detects the `[Highlighting - Reverse][Color - Yellow]` pattern that indicates hidden content
- **Requires**: Hack Field Attributes enabled with "Show Hidden: 1"
- Distinguishes between:
  - **Hidden Labels**: Field names that were hidden (yellow)
  - **Hidden Values**: Actual data in hidden fields (red - critical)
- Example findings: `Purchaseable: Y`, `99) Delete Order History`

#### 2. AID Key Injection Analysis
- Detects screen transitions during automated key injection attacks
- Uses **response length mode** as baseline (most common length = normal response)
- Flags any key that produces a different response length
- Shows transition with before/after: `PA2(1567) -> PA3(1889) [+322]`
- Works regardless of Hack Fields mode

#### 3. Field Injection Analysis
- Detects content changes during field injection attacks (e.g., PIN/password brute force)
- **Normalizes responses** by removing echoed injected values before comparison
- Uses **content mode** as baseline (most common response content)
- Flags when response content differs (even if length is identical)
- Shows transition: `1336 -> 1337 (content changed)`

#### Concise Results Display
- **Type**: Hidden, AID, or Field
- **Req/Resp**: Request and response log IDs
- **Value/Key**: The injected value or AID key
- **Len**: Response length
- **Finding**: Concise description of the finding

#### Replay Functionality
- Click any finding to view full request/response detail
- **Auto Send Server**: Replays response to terminal
- **Auto Send Client**: Replays request to mainframe

#### Status Summary
Shows counts: "Found: 3 hidden values, 2 hidden labels, 1 AID transitions, 1 field transitions"

---

## Version 2.2.0 Changelog

### Initial Analysis Tab
- First implementation of Analysis Tab with threshold-based detection

---

## Version 2.1.2 Changelog

### Export Enhancements
- **Export Visible**: New button exports only filtered/visible log entries to a user-specified CSV file
- Renamed "Export to CSV" to "Export All" for clarity
- Fixed UTF-8 encoding for CSV export to handle special characters

---

## Version 2.1.1 Changelog

### Enhanced Logs Tab

- **Delta (ms) Column**: New column showing the time difference in milliseconds between consecutive log entries - useful for timing analysis (e.g., detecting valid vs. invalid credentials based on response time)
- **Follow Mode**: New "Follow" button auto-scrolls to and selects the newest log entry in real-time - perfect for monitoring live injection attacks
- **Log Search**: New search field converts ASCII input to EBCDIC and filters log entries containing that data - click "Search" or press Enter to filter
- **Clear Button**: Restores all log entries and scrolls to the last entry
- **Auto-scroll on First Visit**: Logs tab now automatically scrolls to and selects the last entry when first opened

---

## Version 2.1.0 Changelog

### New Feature: AID Spoofing

Added new **AID Spoofing** tab with Attention Identifier manipulation capabilities:

#### Manual Mode
- Toggle to enable/disable AID spoofing
- Select any AID value (ENTER, PF1-24, PA1-3, CLEAR, etc.) to replace outgoing AIDs
- All transmissions from the terminal will have their AID replaced with the selected value
- Attack scenario: Send form data but report it as CLEAR to bypass validation routines

#### Fuzzer Mode
- **ARM** button captures the next terminal transmission
- Automatically replays the captured data 256 times (0x00-0xFF)
- Tests all possible AID values including invalid/undefined ones
- **STOP** button pauses fuzzing at current progress
- **RESUME** button continues fuzzing from where it paused
- All responses logged to SQLite database for analysis
- Progress updates shown in status area
- Check Logs tab to analyze response differences, timing, and errors

#### Attack Scenarios
- **Bypass input validation**: Send user data with PF12 (Cancel) AID to skip validation
- **State machine confusion**: Send data with unexpected AID to trigger wrong code path
- **Error handler exploitation**: Invalid AIDs may trigger poorly-tested error handlers
- **Edge case testing**: PA keys "shouldn't" have data, but your data is still sent

#### Real-World Testing Notes

**TSO/VTAM (TK4- tested):** When sending login data with AID set to "NO" (0x60), TSO's TGET routine detected the unusual AID and displayed a debug message:
```
IKTXLOG TGET RC=X'18',LEN=X'00B4',DATA=X'60000E81808081848586878895A1A600'
```
This shows TSO has protection - it flagged the spoofed AID with return code 0x18. The raw data stream shows the 0x60 (NO) AID was received along with the field data.

**CICS Applications:** Many CICS programs lack this level of TGET protection and rely purely on EIBAID checks in COBOL. These are more vulnerable to AID spoofing attacks because:
- No system-level validation of expected AIDs
- Application code must explicitly check EIBAID
- Missing or incomplete EVALUATE statements allow unexpected code paths

**Recommendation:** Test AID spoofing against CICS transaction programs rather than TSO login screens for higher success rates.

---

## Version 2.0.2 Changelog

### New Features: Field Overflow Mode
- Added **OVERFLOW** option to injection Mode dropdown (alongside SKIP and TRUNC)
- OVERFLOW mode sends the full wordlist entry regardless of the field's defined length
- Bypasses terminal's field length enforcement at the proxy level
- Status shows `[OVERFLOW]` indicator when sending oversized data
- Attack scenario: Test if COBOL validation checks occur before or after data truncation

---

## Version 2.0.1 Changelog

### Bug Fixes
- Fixed AID checkboxes in Inject Key Presses tab being unresponsive - `aid_refresh()` was resetting all checkboxes every 10ms

### New Features
- Added **CLEAR ALL** button to Inject Key Presses tab - unchecks all AID checkboxes
- Added **DEFAULTS** button to Inject Key Presses tab - restores default checkbox states

---

## Version 2.0.0 Changelog

### GUI Rewrite - PySide6 (Qt6)
- Complete GUI rewrite from Tkinter to PySide6 (Qt6)
- Modern dark theme with professional styling and color-coded status indicators
- Dynamic window sizing - compact tabs auto-fit to content height
- Logs and Help tabs use 2/3 screen height and remember user's preferred size
- Merged "Hack Text Color" controls into "Hack Field Attributes" tab for streamlined workflow
- Markdown rendering in Help tab for better documentation display
- Renamed `tk.py` to `gui.py` to reflect the new toolkit

### Enhanced Injection Controls
- Added **STEP** button to Inject Into Fields tab for single-entry injection (step through wordlist one entry at a time)
- Added **PAUSE** and **RESUME** buttons to Inject Into Fields tab for better control during brute forcing
- Added **STOP** button to Inject Into Fields tab to halt injection mid-operation
- Added **STOP** button to Inject Key Presses tab to halt key sending mid-operation
- Real-time status updates show current injection state (Sending, Paused, Stopped, Stepped, Ready)
- Status message now shows "Mask set! Field length: X" when injection field is captured

### New Injection Wordlists
Added 18 new injection files for comprehensive mainframe penetration testing:
- `tso-commands.txt` - Common TSO commands (70 entries)
- `ispf-panels.txt` - ISPF panel names and navigation paths (133 entries)
- `ims-transactions.txt` - IMS transaction codes (96 entries)
- `vtam-commands.txt` - VTAM network commands (58 entries)
- `common-userids.txt` - Common mainframe user IDs (132 entries)
- `default-passwords.txt` - Default/weak mainframe passwords (133 entries)
- `racf-groups.txt` - Common RACF security group names (89 entries)
- `cics-programs.txt` - CICS program names (116 entries)
- `dataset-names.txt` - Common dataset name patterns (119 entries)
- `jcl-injections.txt` - JCL syntax injection attempts (53 entries)
- `db2-tables.txt` - DB2 system table names (80 entries)
- `db2-commands.txt` - DB2 SQL commands and injection payloads (63 entries)
- `special-chars.txt` - Special characters for fuzzing (93 entries)
- `overflow-strings.txt` - Long strings for buffer testing (26 entries)
- `ebcdic-edge-cases.txt` - EBCDIC edge case characters (56 entries)
- `pin-common.txt` - Most common 4-digit PINs (167 entries)
- `numeric-5.txt` - 5-digit numeric codes (100,000 entries)
- `numeric-6.txt` - 6-digit numeric codes (1,000,000 entries)

### Bug Fixes
- Fixed offline mode (`-o`) incorrectly requiring IP/PORT arguments
- Fixed `TypeError` when `server_port` is `None` in offline mode
- Fixed `AttributeError` for uninitialized `server_data` in daemon()
- Improved error message when offline mode project database file doesn't exist
- Fixed `logger_formatter` using undefined `self.filename` variable

### Performance Optimizations
- Created module-level reverse lookup dictionary (`a2e`) for ASCII-to-EBCDIC conversion - O(n) instead of O(n²)
- Changed `get_ascii()` to use `str.join()` instead of repeated string concatenation
- Pre-compiled regex patterns as module-level constants (`TELNET_PATTERNS`, `PATTERNS_3270`)
- Refactored `send_keys()` from 35+ individual if statements to loop using `AIDS` dictionary
- Refactored `aid_refresh()`/`aid_setdef()` using helper method `_get_pf_vars()`
- Extracted common shutdown logic into `_shutdown()` method

### Code Cleanup
- Removed 16 unused `toggle_*` methods
- Removed unused `reset_hack_variables_state()` method
- Removed unused `set_offline()` method
- Removed duplicate `self.offline` variable (now uses `self.offline_mode` consistently)
- Removed unused `inject_enter` and `inject_clear` variables
- Added author and license metadata to all source files

## Features

- **Man-in-the-Middle Proxy** - Intercepts and logs all TN3270 traffic between your terminal emulator and the mainframe
- **Field Attribute Hacking** - Disable field protection, reveal hidden fields, remove numeric-only restrictions
- **Color Attribute Hacking** - Expose hidden text by manipulating color attributes
- **Key Injection** - Automatically send PF keys, PA keys, and other attention identifiers
- **Field Injection** - Brute force input fields with wordlists
- **Session Logging** - SQLite database captures all traffic for later analysis
- **Offline Replay** - Review captured sessions without connecting to the mainframe
- **CSV Export** - Export logs for reporting and documentation

## How It Works

### Architecture

```
[Your Terminal Emulator] <---> [hack3270 Proxy] <---> [Mainframe]
      (x3270/wx3270)           (localhost:3271)        (TN3270)
```

You point your terminal emulator at the hack3270 proxy instead of directly at the mainframe. The proxy intercepts all traffic in both directions, allowing real-time manipulation of the 3270 data stream before it reaches your terminal.

### Exposing Hidden Fields

Mainframe applications use 3270 field attributes to hide sensitive data such as passwords, internal values, and debug information. The "non-display" bit (bits 3+4 of the field attribute byte) makes fields invisible to the user. hack3270 clears this bit in real-time as data passes through, revealing all hidden content on your screen.

### Removing Field Protection

Protected fields (bit 6 of the field attribute) are read-only - the terminal won't allow typing in them. These are often used for pre-populated values like account numbers, transaction IDs, or system-generated data. hack3270 clears this protection bit, allowing you to modify fields that should be locked and test for authorization bypass vulnerabilities.

### Removing Numeric-Only Restrictions

Some input fields enforce numeric-only input (bit 5), rejecting alphabetic characters at the terminal level. Clearing this restriction allows injection of unexpected characters, potentially triggering SQL injection, buffer overflows, or application errors that reveal useful information.

### Exposing Color-Hidden Text

Some applications hide sensitive data by setting the text color to match the background (typically black text on a black background - color code `0xF8`). hack3270 detects these color attributes and changes them to visible colors, exposing the hidden content.

### PF Key Fuzzing

Many mainframe applications have hidden administrative functions, debug menus, or undocumented features accessible via specific PF keys (PF1-PF24), PA keys (PA1-PA3), or other attention identifiers. hack3270 automatically sends all possible keys and logs the responses, making it easy to discover hidden functionality by identifying responses with unusual sizes or content.

### Field Injection and Brute Forcing

hack3270 can automate the injection of wordlist entries into input fields. This enables brute-forcing of supervisor codes, transaction identifiers, passwords, or any other input. The mask character system allows precise targeting of specific fields on the screen.

### Session Logging and Replay

Every packet exchanged between the terminal and mainframe is logged to a SQLite database with timestamps and metadata. Sessions can be replayed offline for analysis, exported to CSV for reporting, and reviewed to identify exactly what actions were taken during testing.

## Why This Matters

CICS and legacy mainframe applications were often designed with the assumption that the 3270 terminal was a trusted, "dumb" device. Security was frequently "enforced" by simply hiding fields or making them read-only at the presentation layer. This is security through obscurity - the actual data still traverses the network in the 3270 data stream.

hack3270 demonstrates that these client-side controls provide no real security. By intercepting and modifying the data stream, all hidden fields become visible, all protected fields become editable, and all "enforced" restrictions can be bypassed. True security must be implemented on the server side with proper authorization checks.

## Requirements

- Python 3.11+
- PySide6 (Qt6 bindings for Python)
- A TN3270 terminal emulator (x3270, c3270, or wx3270)

## Installation

```bash
git clone https://github.com/gglessner/hack3270.git
cd hack3270
pip install -r requirements.txt
```

## Usage

```
usage: hack3270.py [options] IP PORT

positional arguments:
  IP                    TN3270 server IP address
  PORT                  TN3270 server port

options:
  -h, --help            show this help message and exit
  -n NAME, --name NAME  Project name (default: pentest)
  -p PROXY_PORT, --proxy_port PROXY_PORT
                        Local TN3270 proxy port (default: 3271)
  --proxy_ip PROXY_IP   Local TN3270 proxy IP (default: 127.0.0.1)
  -t, --tls             Enable TLS encryption for server connection
  -o, --offline         Offline log analysis mode
  -d, --debug           Enable debug logging
```

### Examples

```bash
# Basic connection
python hack3270.py 10.10.10.10 3270

# Named project with TLS
python hack3270.py -n prod_test -t 10.10.10.10 992

# Expose proxy on all interfaces (for remote testing)
python hack3270.py --proxy_ip 0.0.0.0 -p 31337 10.10.10.10 3270

# Offline analysis of a previous session
python hack3270.py -n myproject -o
```

## Quick Start

1. **Start hack3270** pointing to your mainframe:
   ```bash
   python hack3270.py 10.10.10.10 3270 -n mytest
   ```

2. **Connect your terminal emulator** to the local proxy:
   - Host: `127.0.0.1`
   - Port: `3271` (default)

3. **Click "Continue"** when the connection is received

4. **Use the GUI tabs** to perform testing while interacting with the mainframe through your terminal

## Command Line Options

| Option | Description |
|--------|-------------|
| `-n, --name` | Project name for the SQLite log database. Each project creates a `.db` file that persists across sessions. |
| `-p, --proxy_port` | Local port for the TN3270 proxy (default: 3271). Traffic on this port is unencrypted. |
| `--proxy_ip` | Local IP to bind the proxy (default: 127.0.0.1). Use `0.0.0.0` to allow remote connections. |
| `-t, --tls` | Enable TLS for the connection to the mainframe. |
| `-o, --offline` | Replay mode - review logged sessions without connecting to the mainframe. |
| `-d, --debug` | Enable verbose debug output to console. |

## GUI Tabs

### Hack Field Attributes
Manipulate 3270 field attributes in real-time:
- Disable field protection (make read-only fields editable)
- Reveal hidden/non-display fields
- Remove numeric-only restrictions
- Apply to Start Field, Start Field Extended, and Modify Field orders
- Expose text hidden using color attributes (e.g., black text on black background)

### Inject Into Fields
Brute force input fields using wordlists:
1. Click **FILE** to select a wordlist from the `injections/` directory
2. Click **SETUP** and enter your mask character in the target field
3. Click **INJECT** to iterate through the entire wordlist automatically
   - Or click **STEP** to inject just one entry at a time (for manual stepping through the wordlist)
4. Use **PAUSE**/**RESUME** to temporarily halt and continue injection
5. Click **STOP** to abort the injection at any time
6. Click **RESET** to clear the configuration and start over

**Tip:** Use **STEP** when you want fine-grained control - click it repeatedly to test entries one by one. Use **INJECT** when you want to run through the entire wordlist automatically.

### Inject Key Presses
Send attention identifier keys (PF1-PF24, PA1-PA3, CLEAR, etc.) to discover hidden functions.
- Click **Send Keys** to send all checked keys
- Click **STOP** to halt key sending mid-operation
- Click **CLEAR ALL** to uncheck all AID checkboxes
- Click **DEFAULTS** to restore default checkbox states

### AID Spoofing (new in v2.1.0)
Manipulate the Attention Identifier byte in outgoing transmissions:

**Manual Mode:**
- Toggle to enable AID spoofing
- Select any AID value (ENTER, PF1-24, PA1-3, CLEAR, etc.)
- All transmissions will have their AID replaced with the selected value
- Attack scenario: Send form data but report it as CLEAR to bypass validation

**Fuzzer Mode:**
- Click **ARM** to prepare for fuzzing
- Send any transmission from your terminal
- The tool captures it and replays 256 times with all AID values (0x00-0xFF)
- Click **STOP** to pause fuzzing, **RESUME** to continue
- All responses logged to database for analysis
- Check Logs tab to find response differences, errors, or timing anomalies

### Logs
- View all captured traffic with timestamps and data sizes
- Click any entry to replay it to your terminal
- Identify anomalies by comparing response sizes
- Export to CSV for reporting

### Statistics
View session metrics: connection count, message counts, bytes transferred, and total test time.

## Terminal Emulator Setup

Recommended settings for x3270/c3270/wx3270:

1. **Screen Size**: Model 5 (132x27) recommended for best visibility
2. **Font**: Choose a monospace font appropriate for your display
3. **Save settings** after configuration

Keep your screen size consistent to ensure offline replay renders correctly.

## Testing with DVCA

[DVCA](https://github.com/mainframed/DVCA) (Damn Vulnerable CICS Application) is a great way to learn the toolkit.

### Initial Setup

1. Start the DVCA docker container:
   ```bash
   sudo docker run -p 3270:3270 --expose=3270 mainframed767/dvca
   ```

2. Launch hack3270 with a project name:
   ```bash
   python hack3270.py 127.0.0.1 3270 -n dvca
   ```

3. A window will appear saying the tool is waiting for a connection on port 3271

4. Use x3270 and connect to `127.0.0.1` port `3271`

5. The window will show "Connection received" - click the button to launch the full GUI

6. The x3270 terminal will display the logon screen. Login with `dvca` / `dvca`
   - If already logged in, type `LOGON DVCA RECONNECT` then enter the password

7. Click CLEAR on the x3270 keyboard, type `MCGM` to launch the DVCA application, then press PF5

8. To exit DVCA: press F3, type `KSSF`, press Enter, then type `LOGOFF`

### Demo: Hack Field Attributes

1. Go to the **Hack Field Attributes** tab and turn the Hack Fields button ON
2. Additional previously-hidden options will appear on screen
3. Click on the **Logs** tab and scroll to the bottom
4. The last entries show data received from the server - the bottom one will say "TOGGLED ON" with the set options
5. Click on any Server log line to replay that data to your terminal, rendering the display as it appeared at that moment
6. This allows auditors to review exactly what the tester saw during testing
7. Response sizes are shown, making it easy to identify when injected data causes unique responses

### Demo: Inject Key Presses

1. Go to the **Inject Key Presses** tab
2. The tool auto-disables any PF key that appears in the screen text
3. Click **Send Keys** to send all enabled function keys
4. A hidden display will be revealed
5. Click **Send Keys** again - another hidden option will briefly appear
6. Check the **Logs** tab - look for entries with different response sizes
7. Click those lines to display the hidden messages
8. Look at the preceding Client log entry to see which key triggered the response
9. Use arrow keys to scroll through log entries while watching the x3270 screen update in real-time

### Demo: Brute Force Supervisor Code

1. From the DVCA main menu, select option 2 (Shipping Address)
2. Go to the **Inject into Fields** tab
3. Click **FILE** and select `dvca-demo-numeric-4.txt`
4. Click **SETUP** - it will show your mask character (default: `*`)
5. In the supervisor code field, type `****` (four mask characters) and press Enter
6. Click **INJECT** to brute force the 4-digit supervisor password

### Demo: Discover Transaction Codes

1. Exit DVCA and click CLEAR in the x3270 keyboard
2. Go to **Inject into Fields** tab
3. Click **FILE** and select `dvca-demo-transactions.txt`
4. Click **SETUP**, type `****` (four mask characters), and press Enter
5. Change the **Keys** option to `ENTER+CLEAR` (clears screen between attempts)
   - For apps requiring PF3 to exit, use `ENTER+PF3+CLEAR`
6. Click **INJECT** to test transaction codes
7. Review the **Logs** tab - look for Server responses with unusual lengths to identify valid transactions

## Injection Wordlists

The `injections/` directory contains wordlists for brute forcing and fuzzing:

| Category | Files | Description |
|----------|-------|-------------|
| **Numeric** | `numeric-1.txt` through `numeric-6.txt` | All numeric combinations (1-6 digits) |
| **Alpha** | `alpha-1.txt` through `alpha-4.txt` | Uppercase letter combinations (A-Z) |
| **Alphanumeric** | `alphanumeric-1.txt` through `alphanumeric-4.txt` | Letters + numbers (A-Z, 0-9) |
| **Common PINs** | `pin-common.txt` | Most frequently used 4-digit PINs |
| **Transactions** | `cics-default-transactions.txt`, `ims-transactions.txt` | Known CICS/IMS transaction codes |
| **Commands** | `tso-commands.txt`, `vtam-commands.txt`, `db2-commands.txt` | System commands |
| **User Enumeration** | `common-userids.txt`, `default-passwords.txt` | Common mainframe credentials |
| **Security Groups** | `racf-groups.txt` | RACF group names |
| **System Resources** | `dataset-names.txt`, `cics-programs.txt`, `db2-tables.txt` | Common resource names |
| **Fuzzing** | `special-chars.txt`, `overflow-strings.txt`, `ebcdic-edge-cases.txt` | Edge case testing |
| **SQL Injection** | `db2-injections.txt` | DB2-specific SQL injection payloads |
| **JCL** | `jcl-injections.txt` | JCL syntax injection attempts |
| **DVCA Demos** | `dvca-demo-*.txt` | Quick demo wordlists for DVCA testing |

## Security Considerations

- The local proxy port is **unencrypted** by design (enables packet capture with Wireshark)
- When testing over a network, keep the proxy bound to `127.0.0.1` unless remote access is required
- Use `-t` for TLS connections to the mainframe

## License

GNU General Public License v3.0 - see [LICENSE](LICENSE) for details.

## Authors

- **Garland Glessner** - Original author (gglessner@gmail.com)
- **Phil Young** (Soldier of FORTRAN) - Rewrite contributor ([@mainframed](https://github.com/mainframed))

## Contributing

Issues and pull requests welcome at https://github.com/gglessner/hack3270
