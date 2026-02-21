# Changelog

## Version 2.8.1

### Endevor-MCP Skill: Source Code Discovery Guidance

Updated `skills/endevor-mcp.md` with practical guidance for finding source code in enterprise Endevor environments:

- **Element path from app team is the primary workflow** — the tester should provide the Endevor element path (environment, stage, system, subsystem, type) supplied by the application team, and the AI jumps straight to listing/retrieving
- **Search by name as secondary** — use wildcards with context from the pen test (transaction names, program names from screens) to search directly
- **Hierarchy walk requires human approval** — the AI must explicitly ask the user for permission before browsing the Endevor inventory top-down, since large enterprises have thousands of systems and unbounded walks waste time

---

## Version 2.8.0

### Endevor-MCP v1.1.0: Auto-Connect, API Fixes, and Debug Toggle

Streamlined the Endevor-MCP server for zero-configuration usage and fixed compatibility with real Endevor REST API servers.

#### Auto-Connect at Startup
- Connection and JWT authentication now happen automatically when the MCP starts — no `endevor_connect` or `endevor_authenticate` calls needed
- All 22 tools default `conn_id` to `"auto"`, so the AI can call tools directly without specifying a connection
- `endevor_connect` demoted to advanced use (connecting to a second Endevor instance)
- MCP server instructions rewritten to tell AI agents: "just start using tools"

#### Endevor REST API v2 Compatibility Fixes
- **Wildcard path fix**: List endpoints now include `*` in the URL path (e.g. `/env/*` instead of `/env`), matching the Broadcom API spec — fixes HTTP 500 / RC 0020 RSN 0033 on real servers
- **Token parsing fix**: `authenticate()` correctly handles `{"data": [{"token": "..."}]}` response format from real Endevor servers
- **Bearer token persistence**: JWT token explicitly injected into per-request headers, surviving redirects and session state changes
- **Basic Auth cleanup**: Cleared from session after JWT obtained to prevent sending both auth types
- **Credential passthrough**: `endevor_authenticate` accepts `username`/`password` for cases where credentials weren't provided at connect time

#### Debug Toggle
- `ENDEVOR_DEBUG=true` in `mcp.json` enables full HTTP request/response logging to stderr — no source code edits needed
- Logs method, URL, parameters, auth headers, response status, body length, and content
- Startup diagnostic output (config dump, auth result details, tracebacks) gated behind the same toggle

#### File Reorganization
- Moved `MCPs/run_endevor_mcp.py` into `MCPs/endevor_mcp/run.py` for cleaner project structure
- Updated `.cursor/mcp.json` and `.vscode/mcp.json` to match

#### AI Skill Updates
- Rewrote `skills/endevor-mcp.md` with prominent "DO NOT call endevor_connect" guidance and step-by-step inventory browsing walkthrough
- Updated `.cursor/skills/endevor-mcp/SKILL.md` pointer with same guidance

---

## Version 2.7.0

### Endevor-MCP Integration: Source-Informed Pen Testing

Added a companion **Endevor-MCP** server that provides read-only access to Broadcom Endevor SCM, enabling AI agents to retrieve COBOL source, BMS maps, and system tables during live pen testing. When used alongside hack3270, this transforms the assessment methodology from blind black-box testing to **source-informed, live-verified** testing.

#### Endevor-MCP Server
- Read-only interaction with Endevor REST API v2
- Browse inventory: environments, systems, subsystems, types, elements
- Retrieve source code for COBOL programs, BMS maps, system tables (PCT, PPT, FCT), CLISTs
- Pre-configured `auto` connection when `ENDEVOR_HOST` environment variables are set
- MCP configuration included in `.cursor/mcp.json` and `.vscode/mcp.json`

#### hack3270 Skill Updates
- **New Phase 2A: Endevor-Enhanced Testing** -- complete methodology for parallel source analysis and live verification. Retrieve COBOL, BMS, and system tables while navigating screens with hack3270. Verify every source-code finding live.
- **Deferred TSO escape** -- documented that routing field corruption may not trigger immediately; pressing navigation PF keys (PF5, PF3) after field modification can produce a deferred `READY` prompt
- **TIME output buffering** -- added guidance that TSO `TIME` output may require CLEAR to display
- **KICKS recovery sequence** -- explicit steps to return from TSO to KICKS without using LOGOFF (which strands the terminal)
- **`send_fields_data` field inclusion warning** -- critical note that only explicitly specified fields are sent; FSET/PROT fields must be manually included in the payload
- **`fuzz_field` category filter caveat** -- warning that the tool may send payloads from all categories regardless of the `categories` parameter
- **CLEAR key trapping** -- note that some COBOL programs intercept CLEAR and redisplay; suggests PF3 as alternative exit

#### Performance Impact
Endevor-enhanced methodology reduced a full DVCA application pen test from ~8.5 minutes to ~4.5 minutes (46% faster) with identical vulnerability coverage (8 findings, 3 positive controls). Source analysis eliminates blind brute forcing, systematic AID key scanning, and guess-and-check fuzzing -- the AI reads the vulnerability in source and verifies it in one shot.

---

## Version 2.6.7

### Bug Fixes and New Features

- **Fixed "Auto Send Server" and "Auto Send Client" in the GUI log viewer**: Clicking a log entry with either auto-send checkbox enabled now correctly replays the packet. The bug was caused by reading the wrong tree column index (`Delta` instead of `Sender`) after the Delta column was added, so the sender check never matched "Server" or "Client".
- **New `send_field_data` `aid` parameter**: Send field data with any AID key (PF1-PF24, PA1-PA3, CLEAR, SYSREQ, or hex) instead of just ENTER. Defaults to ENTER for backward compatibility.
- **New `send_fields_data` MCP tool**: Fill multiple fields in a single packet and submit once. Accepts a JSON array of `{address, text}` objects. Useful for login forms (username + password) and multi-field searches.
- **New `send_fields()` API method**: Low-level counterpart in `hack3270_api.py` that constructs a multi-SBA packet with configurable AID byte.
- **Refactored AID resolution**: Extracted `_resolve_aid()` helper in the MCP server, eliminating duplicated AID mapping code.
- **AI Skills Restructure**: Created `skills/` directory with comprehensive, tutorial-first skill files:
  - `hack3270-mcp-tutorial.md` -- Complete tutorial covering all 53 MCP tools with examples, decision trees, recipes, gotchas, and TN3270 protocol reference
  - `hack3270.md` -- Guardrailed pen testing skill with TOC and prerequisite pointer
  - `tn3270-pentest.md` -- Unrestricted pen testing skill with TOC and prerequisite pointer
  - `README.md` -- Index of available skills
- **VS Code auto-discovery**: Added `.github/copilot-instructions.md` so GitHub Copilot automatically knows about the skills directory.
- **Cursor pointer skills**: `.cursor/skills/` converted to thin pointers referencing `skills/` directory.

---

## Version 2.6.6

### AI Skills Restructure: Tutorial-First Skill Files

Major restructuring of AI skill files to make them accessible to all AI models (including weaker ones like GPT-4.1) and all IDEs.

- **New `skills/` directory at project root**: All skill content now lives here as the single source of truth, accessible from any IDE or AI tool.
- **New `skills/hack3270-mcp-tutorial.md`**: Comprehensive "driver's ed" tutorial for AI assistants. Covers all 53 MCP tools with practical examples, decision trees for choosing the right tool, common patterns and recipes, gotchas and troubleshooting, and a TN3270 protocol cheat sheet. Written for the lowest-common-denominator AI model.
- **Restructured `skills/hack3270.md`**: Guardrailed pen testing skill with table of contents and prerequisite pointer to the tutorial.
- **Restructured `skills/tn3270-pentest.md`**: Unrestricted pen testing skill with table of contents and prerequisite pointer to the tutorial.
- **New `skills/README.md`**: Index file explaining which skill to use when.
- **New `.github/copilot-instructions.md`**: VS Code + GitHub Copilot auto-discovery. Automatically tells Copilot about the skills directory in every chat session.
- **`.cursor/skills/` converted to thin pointers**: Cursor's skill files now point to `skills/` directory, maintaining auto-load functionality while eliminating content duplication.
- **New `.cursor/skills/hack3270-mcp-tutorial/SKILL.md`**: Cursor auto-load pointer for the tutorial.

---

## Version 2.6.5

### New Features: Multi-Field Submission and AID Key Selection

- **`send_field_data` now accepts an `aid` parameter**: Previously hardcoded to ENTER, you can now specify any AID key (PF1-PF24, PA1-PA3, CLEAR, SYSREQ, or hex) when sending field data. Defaults to ENTER for backward compatibility.
- **New `send_fields_data` MCP tool**: Send data to multiple fields in a single packet. Accepts a JSON array of `{address, text}` objects and submits them all with one AID key press. Useful for filling out login forms (username + password), multi-field searches, or any screen with multiple inputs.
- **New `send_fields()` API method**: Low-level counterpart in `hack3270_api.py` that constructs a multi-SBA packet with configurable AID byte.
- **Refactored AID resolution**: Extracted `_resolve_aid()` helper in the MCP server, eliminating duplicated AID mapping code across tools.

---

## Version 2.6.4

### Project Reorganization and VS Code MCP Support

- **Directory restructuring**: Reorganized the project for clarity and maintainability:
  - `hack3270_libs/` -- core libraries (`gui.py`, `hack3270_api.py`, `libhack3270.py`)
  - `MCPs/hack3270_mcp/` -- MCP server (`hack3270_mcp.py`, renamed from `mcp_server.py`)
  - `Documentation/` -- all documentation (`API_Documentation.md`, `MCP_SETUP.md`, `MCP_PENTEST_REPORT.md`, `API-DVCA-Code/`)
  - Root now contains only the entry point (`hack3270.py`), metadata files, and config
- **VS Code MCP support**: Added `.vscode/mcp.json` with OS-agnostic configuration using `${command:python.interpreterPath}` for the Python interpreter and `${workspaceFolder}` for the working directory.
- **Separated CHANGELOG.md**: Version history moved from `README.md` into its own `CHANGELOG.md` file.
- **README.md AI section**: Added comprehensive "AI-Assisted Pen Testing" section covering architecture, skill files, quick start, and capabilities.
- **Python command standardized**: Cursor MCP config changed from `python` to `python3` for cross-platform compatibility.
- **Import paths updated**: All Python files updated with absolute path resolution for imports after library relocation.

---

## Version 2.6.3

### New AI Skill: hack3270 (Guardrailed Pen Testing)

- **Added `.cursor/skills/hack3270/SKILL.md`**: A production-safe AI skill for pen testing scoped CICS/KICKS applications. Unlike the unrestricted `tn3270-pentest` skill (designed for lab/CTF use), `hack3270` enforces strict guardrails to prevent scope creep, denial of service, and account lockout during authorized engagements.
- **Transaction scope locking**: AI testing is automatically confined to the 2-character prefix of the entry-point transaction (e.g., `MC**` for `MCGM`). System transactions, out-of-scope codes, and wide enumeration are prohibited.
- **8 hard guardrails**: No system transaction execution, TSO escape test-only (validate with `TIME`, no post-exploitation), no JCL submission, no RACF brute force, graduated overflow fuzzing (human approval required), stop-on-abend, no wide transaction enumeration, and sensitive data masking in reports.
- **Escalation protocol**: High-risk actions (overflow fuzzing, data modification, out-of-prefix testing) require explicit human approval with risk-level justification.
- **11-step safe methodology**: Observation-first approach with baseline establishment, full screen mapping, hidden/protected field analysis, conservative AID key scanning, input validation testing, and structured reporting with positive security control documentation.
- **Recovery procedures**: Handles accidental app exit, system transaction screen landing, abends, account lockout, TSO prompts, TN3270 integrity detection, and unresponsive applications.
- **Tool-specific guardrails**: Per-tool restrictions annotated in the MCP tools quick reference, cross-referencing guardrail numbers.

---

## Version 2.6.2

### Auto-Reconnect on hack3270 Restart

- **MCP server now auto-reconnects when hack3270 is restarted**: Previously, restarting the hack3270 proxy caused a broken pipe error in the MCP server that required manually calling `reconnect_api`. Now, `_ensure_connected()` performs a lightweight ping health check before every tool call and silently reconnects if the connection is dead.
- **`_send()` / `_recv()` broken pipe handling**: Connection errors (`BrokenPipeError`, `ConnectionResetError`, `ConnectionAbortedError`) are now caught and cleanly tear down the dead socket, clearing both `_sock` and the `_is_tn3270e` protocol cache so the next reconnect starts fresh.

---

## Version 2.6.1

### Bug Fix: TN3270E Protocol Detection Cache

- **Fixed `is_tn3270e()` stale cache bug**: The `_is_tn3270e` flag was cached forever and never cleared on `disconnect()` or `reconnect()`. If the proxy was restarted or the protocol mode changed, the stale cache caused `send_command()` to add a spurious 5-byte TN3270E header to plain TN3270 packets, corrupting transaction codes and causing APCT abends on KICKS/CICS.
- **`disconnect()` now clears protocol cache**: Ensures protocol mode is re-detected on next connection.
- **`reconnect()` now clears protocol cache**: Prevents stale TN3270E state from persisting across proxy restarts.
- **`is_tn3270e()` error handling**: Now defaults to plain TN3270 mode on detection errors instead of potentially caching an incorrect `True` value.

---

## Version 2.6.0

### New Feature: MCP Server for AI-Assisted Pen Testing (`hack3270_mcp.py`)

Added a **Model Context Protocol (MCP) server** that exposes the full hack3270 API as 52 tools, enabling AI coding assistants (Cursor, VS Code + Copilot) to autonomously pen test mainframes through natural language interaction.

#### Architecture
```
[AI Agent] <--stdio/JSON-RPC--> [hack3270_mcp.py] <--TCP:31337--> [hack3270 Proxy] <--TN3270--> [Mainframe]
```

#### 52 MCP Tools in 9 Categories

| Category | Tools | Description |
|----------|-------|-------------|
| **Connection** | `connect_api`, `disconnect_api`, `reconnect_api`, `ping`, `check_connection`, `test_mainframe_connection` | API and mainframe connectivity |
| **Screen Reading** | `get_screen`, `get_screen_raw`, `get_screen_raw_hex`, `find_text`, `find_field_value`, `get_text_at` | Read and search terminal content |
| **Field Analysis** | `analyze_screen_fields`, `get_input_fields`, `get_hidden_fields`, `analyze_hidden`, `check_abend` | Discover input, protected, and hidden fields |
| **Input/AID Keys** | `send_enter`, `send_aid_key`, `send_pf_key`, `send_clear` | Send attention identifier keys |
| **Data Sending** | `send_command`, `send_field_data`, `send_raw_hex`, `build_and_send_packet` | Type text, send to fields, craft raw packets |
| **Waiting** | `wait_for_text`, `wait_for_screen_change` | Wait for screen responses |
| **Database/Replay** | `load_database`, `close_database`, `list_databases`, `get_logs`, `get_log_entry`, `replay_client_data`, `replay_sequence` | Session capture and replay |
| **Injection/Brute Force** | `list_wordlists`, `load_wordlist`, `get_wordlist_contents`, `setup_injection`, `inject_value`, `brute_force_field` | Credential brute forcing and field injection |
| **Fuzzing/Scanning** | `scan_aid_keys`, `fuzz_field`, `fuzz_all_input_fields`, `fuzz_transaction_codes` | AID key scanning, field fuzzing, transaction enumeration |
| **Utilities** | `convert_ascii_to_ebcdic`, `convert_ebcdic_to_ascii`, `encode_buffer_address`, `decode_buffer_address`, `get_protocol_info` | Encoding, addressing, and protocol info |
| **Recording** | `start_recording`, `stop_recording`, `playback_recording` | Action recording and playback |

#### Setup
- Works with **Cursor** (`.cursor/mcp.json`) and **VS Code** (`settings.json`)
- Communicates via JSON-RPC 2.0 over stdio
- See `MCP_SETUP.md` for detailed installation instructions

#### Dependencies
- Added `mcp>=1.26.0` to `requirements.txt`

---

## Version 2.5.2

### API Bug Fixes
- **Fixed `send_command()` for IBM mainframes**: Added SBA (Set Buffer Address) order to packet structure for TN3270E compatibility. The function now works correctly on both TK4 emulators and real IBM mainframes.

### GUI Improvements
- **Field Fuzzing tab layout**: Added width constraints to Options (max 300px) and Controls (max 400px) boxes for better visual balance

---

## Version 2.5.1

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

## Version 2.5.0

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

## Version 2.4.6

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

## Version 2.4.5

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

## Version 2.4.4

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

## Version 2.4.3

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

## Version 2.4.2

### API Client Library Fix
- Fixed `get_inject_template()` to use local database instead of server's database
- Injection scripts now work with custom `.db` files (e.g., `dvca-brute.db`)

### Code Organization
- Moved all API example scripts to `API-DVCA-Code/` directory
- Added `API-Examples.md` with step-by-step DVCA demo instructions

---

## Version 2.4.1

### Offline Mode Fix
- Web API no longer starts in offline mode (`-o` flag)
- Prevents unnecessary port binding when replaying sessions

### Security Fix
- Web API now binds to `127.0.0.1` (localhost) only
- Prevents remote access to the API port (31337)

---

## Version 2.4.0

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

## Version 2.3.2

### Analysis Tab Export
- **Export CSV**: New button exports analysis results to CSV file
- Exports all columns: Type, Request ID, Response ID, Value/Key, Length, Finding
- UTF-8 encoding for proper character handling

---

## Version 2.3.1

### Analysis Tab Improvements
- **AID Fuzzer Detection**: Now detects `AID Fuzz:` and `AID Spoofed:` patterns in addition to `Sending key:`
- **Numeric Sorting**: Results sorted numerically by Request ID (same as Logs tab)
- All three AID sources detected: Inject Keys, AID Fuzzer, AID Spoof Manual

---

## Version 2.3.0

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

## Version 2.2.0

### Initial Analysis Tab
- First implementation of Analysis Tab with threshold-based detection

---

## Version 2.1.2

### Export Enhancements
- **Export Visible**: New button exports only filtered/visible log entries to a user-specified CSV file
- Renamed "Export to CSV" to "Export All" for clarity
- Fixed UTF-8 encoding for CSV export to handle special characters

---

## Version 2.1.1

### Enhanced Logs Tab

- **Delta (ms) Column**: New column showing the time difference in milliseconds between consecutive log entries - useful for timing analysis (e.g., detecting valid vs. invalid credentials based on response time)
- **Follow Mode**: New "Follow" button auto-scrolls to and selects the newest log entry in real-time - perfect for monitoring live injection attacks
- **Log Search**: New search field converts ASCII input to EBCDIC and filters log entries containing that data - click "Search" or press Enter to filter
- **Clear Button**: Restores all log entries and scrolls to the last entry
- **Auto-scroll on First Visit**: Logs tab now automatically scrolls to and selects the last entry when first opened

---

## Version 2.1.0

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

## Version 2.0.2

### New Features: Field Overflow Mode
- Added **OVERFLOW** option to injection Mode dropdown (alongside SKIP and TRUNC)
- OVERFLOW mode sends the full wordlist entry regardless of the field's defined length
- Bypasses terminal's field length enforcement at the proxy level
- Status shows `[OVERFLOW]` indicator when sending oversized data
- Attack scenario: Test if COBOL validation checks occur before or after data truncation

---

## Version 2.0.1

### Bug Fixes
- Fixed AID checkboxes in Inject Key Presses tab being unresponsive - `aid_refresh()` was resetting all checkboxes every 10ms

### New Features
- Added **CLEAR ALL** button to Inject Key Presses tab - unchecks all AID checkboxes
- Added **DEFAULTS** button to Inject Key Presses tab - restores default checkbox states

---

## Version 2.0.0

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
