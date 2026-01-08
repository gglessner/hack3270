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
- Created module-level reverse lookup dictionary (`a2e`) for ASCII-to-EBCDIC conversion - O(n) instead of O(n squared)
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
