# hack3270

A Python 3 toolkit for manipulating TN3270 data streams, specifically designed for application penetration testing of mainframe CICS applications.

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
- Added **PAUSE** and **RESUME** buttons to Inject Into Fields tab for better control during brute forcing
- Added **STOP** button to Inject Into Fields tab to halt injection mid-operation
- Added **STOP** button to Inject Key Presses tab to halt key sending mid-operation
- Real-time status updates show current injection state (Sending, Paused, Stopped, Ready)
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
- Created module-level reverse lookup dictionary (`a2e`) for ASCII-to-EBCDIC conversion - O(n) instead of O(n squared)
- Changed `get_ascii()` to use `str.join()` instead of repeated string concatenation
- Pre-compiled regex patterns as module-level constants
- Refactored `send_keys()` from 35+ individual if statements to loop using `AIDS` dictionary
- Extracted common shutdown logic into `_shutdown()` method

### Code Cleanup
- Removed 16 unused `toggle_*` methods
- Removed unused methods and variables
- Added author and license metadata to all source files

## Features

- **Man-in-the-Middle Proxy** - Intercepts and logs all TN3270 traffic
- **Field Attribute Hacking** - Disable field protection, reveal hidden fields
- **Color Attribute Hacking** - Expose hidden text by manipulating color attributes
- **Key Injection** - Send PF keys, PA keys, and other attention identifiers
- **Field Injection** - Brute force input fields with wordlists
- **Session Logging** - SQLite database captures all traffic
- **Offline Replay** - Review captured sessions without connecting
- **CSV Export** - Export logs for reporting

## Requirements

- Python 3.11+
- PySide6 (Qt6 bindings for Python)
- A TN3270 terminal emulator (x3270, c3270, or wx3270)

## Installation

    git clone https://github.com/gglessner/hack3270.git
    cd hack3270
    pip install -r requirements.txt

## Usage

    python hack3270.py [options] IP PORT

Options:
  -n NAME    Project name (default: pentest)
  -p PORT    Local proxy port (default: 3271)
  -t         Enable TLS for server connection
  -o         Offline log analysis mode
  -d         Enable debug logging

## GUI Tabs

### Inject Into Fields
1. Click **FILE** to select a wordlist
2. Click **SETUP** and enter mask character in target field
3. Click **INJECT** to iterate through wordlist
4. Use **PAUSE**/**RESUME** to control injection
5. Click **STOP** to abort at any time
6. Click **RESET** to clear configuration

### Inject Key Presses
- Click **Send Keys** to send all checked keys
- Click **STOP** to halt key sending mid-operation

## Injection Wordlists

The injections/ directory contains wordlists for brute forcing:
- Numeric (1-6 digits), Alpha, Alphanumeric combinations
- Common PINs, CICS/IMS transactions, TSO/VTAM commands
- User IDs, passwords, RACF groups
- SQL injection payloads, JCL injections
- Fuzzing: special chars, overflow strings, EBCDIC edge cases

## License

GNU General Public License v3.0

## Authors

- **Garland Glessner** - Original author (gglessner@gmail.com)
- **Phil Young** (Soldier of FORTRAN) - Rewrite contributor
