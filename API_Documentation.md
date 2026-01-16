# hack3270 Web API Documentation

The hack3270 Web API allows you to automate TN3270 penetration testing through a TCP interface on port 31337. This document covers the Python client library and all available methods.

## Table of Contents

- [Getting Started](#getting-started)
- [Connection Management](#connection-management)
- [Database Access](#database-access)
- [Server Response Methods](#server-response-methods)
- [Sending Data](#sending-data)
- [Screen Analysis](#screen-analysis)
- [Data Conversion](#data-conversion)
- [Field Injection](#field-injection)
- [Automation](#automation)
- [Complete Examples](#complete-examples)

---

## Getting Started

### Prerequisites

1. Start hack3270 connected to a mainframe:
   ```bash
   python hack3270.py 10.10.10.10 3270 -n myproject
   ```

2. Connect your terminal emulator to the proxy (port 3271)

3. The API automatically starts on port 31337

### Basic Usage

```python
from hack3270_api import Hack3270API

# Create client and connect
api = Hack3270API()
api.connect()

# Do something
response = api.get_last_server()
print(response)

# Clean up
api.disconnect()
```

### Using Context Manager (Recommended)

```python
from hack3270_api import Hack3270API

with Hack3270API() as api:
    api.load_db('pentest.db')
    response = api.get_last_server()
    print(response)
# Automatically disconnects and closes database
```

### Quick Connect Function

```python
from hack3270_api import connect

api = connect()  # Creates and connects in one call
api.ping()
api.disconnect()
```

---

## Connection Management

### `Hack3270API(host=None, port=None, timeout=None)`

Create an API client instance.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `host` | str | `'127.0.0.1'` | API server address |
| `port` | int | `31337` | API server port |
| `timeout` | float | `10.0` | Socket timeout in seconds |

```python
# Default connection (localhost:31337)
api = Hack3270API()

# Remote connection
api = Hack3270API(host='192.168.1.100', port=31337, timeout=30.0)
```

### `connect()`

Establish connection to the API server.

```python
api = Hack3270API()
api.connect()
```

**Raises:** `Hack3270APIError` if connection fails.

### `disconnect()`

Close the connection to the API server.

```python
api.disconnect()
```

### `is_connected()`

Check if the API connection is alive.

```python
if api.is_connected():
    print("Connected!")
else:
    print("Connection lost")
```

**Returns:** `bool`

### `reconnect()`

Disconnect and reconnect to the API.

```python
api.reconnect()
```

### `ping()`

Test API connectivity.

```python
response = api.ping()
print(response)  # "pong"
```

**Returns:** `str` - Server response

---

## Database Access

The API provides direct SQLite3 access to session data stored in `.db` files.

### `load_db(filename)`

Load a hack3270 session database.

```python
api.load_db('pentest.db')
```

**Raises:** `Hack3270APIError` if file cannot be opened.

### `close_db()`

Close the currently loaded database.

```python
api.close_db()
```

### `db_get_logs(direction=None, limit=None)`

Get log entries from the database.

| Parameter | Type | Description |
|-----------|------|-------------|
| `direction` | str | `'C'` for client, `'S'` for server, `None` for all |
| `limit` | int | Maximum entries to return |

```python
# Get all logs
logs = api.db_get_logs()

# Get only client requests
client_logs = api.db_get_logs(direction='C')

# Get last 10 server responses
server_logs = api.db_get_logs(direction='S', limit=10)

# Each log is a tuple: (ID, TIMESTAMP, C_S, NOTES, DATA_LEN)
for log in logs:
    print(f"ID: {log[0]}, Direction: {log[2]}, Length: {log[4]}")
```

**Returns:** `list` of tuples

### `db_get_log(log_id)`

Get a specific log entry by ID.

```python
log = api.db_get_log(42)
if log:
    id, timestamp, direction, notes, data_len, raw_data = log
    print(f"Entry {id}: {data_len} bytes")
```

**Returns:** Tuple `(ID, TIMESTAMP, C_S, NOTES, DATA_LEN, RAW_DATA)` or `None`

### `db_get_raw(log_id)`

Get raw binary data from a log entry.

```python
raw_bytes = api.db_get_raw(42)
print(f"Got {len(raw_bytes)} bytes")
print(raw_bytes.hex())
```

**Returns:** `bytes` or `None`

---

## Server Response Methods

### `get_last_server()`

Get the last server response converted to ASCII text.

```python
screen = api.get_last_server()
print(screen)
```

**Returns:** `str` - ASCII representation of the screen

### `get_last_server_raw()`

Get the last server response as raw bytes.

```python
raw = api.get_last_server_raw()
print(f"Raw data: {len(raw)} bytes")
print(raw.hex())
```

**Returns:** `bytes` - Raw TN3270 data

### `wait_for(pattern, timeout=None, poll_interval=0.2)`

Wait until a pattern appears in the server response.

| Parameter | Type | Description |
|-----------|------|-------------|
| `pattern` | str or regex | Text or regex pattern to match |
| `timeout` | float | Max seconds to wait (default: client timeout) |
| `poll_interval` | float | Seconds between checks |

```python
import re

# Wait for text
api.send_aid('ENTER')
if api.wait_for('READY', timeout=5):
    print("System ready!")
else:
    print("Timeout waiting for READY")

# Wait for regex pattern
if api.wait_for(re.compile(r'USER.*LOGGED'), timeout=10):
    print("Login successful!")
```

**Returns:** `bool` - `True` if pattern found, `False` if timeout

### `wait_for_change(timeout=None, poll_interval=0.2)`

Wait for the screen to change from its current state.

```python
api.send_aid('PF3')
new_screen = api.wait_for_change(timeout=5)
if new_screen:
    print("Screen changed!")
    print(new_screen[:100])
else:
    print("No change detected")
```

**Returns:** `str` (new response) or `None` (timeout)

---

## Sending Data

### `send_aid(aid)`

Send an Attention Identifier (AID) key.

| AID Values | Description |
|------------|-------------|
| `'ENTER'` | Enter key |
| `'CLEAR'` | Clear key |
| `'PF1'` - `'PF24'` | Program Function keys |
| `'PA1'` - `'PA3'` | Program Attention keys |
| `'SYSREQ'` | System Request |

```python
# Send Enter key
api.send_aid('ENTER')

# Send PF3 to exit
api.send_aid('PF3')

# Send Clear
api.send_aid('CLEAR')

# Send by hex value
api.send_aid('0x7d')  # ENTER as hex
```

**Returns:** `str` - API response

**Raises:** `Hack3270APIError` if AID not recognized

### `send_raw(data)`

Send raw bytes directly to the mainframe.

```python
# Send raw EBCDIC data
raw_data = api.ascii_to_ebcdic('LOGON MYUSER')
api.send_raw(raw_data)
```

**Returns:** `str` - API response

### `send_field(text, cursor_addr, field_addr, add_space=False)`

Send text to a specific field on a formatted screen. Automatically converts ASCII to EBCDIC and builds the TN3270 packet.

```python
# Screen positions from captured packets
USERNAME_CURSOR = bytes([0x5B, 0xF4])
USERNAME_FIELD = bytes([0x5B, 0xF0])

# Send username to field
api.send_field('DVCA', USERNAME_CURSOR, USERNAME_FIELD, add_space=True)
```

**Parameters:**
- `text` - ASCII text to send (converted to EBCDIC)
- `cursor_addr` - 2-byte cursor address (from captured packet)
- `field_addr` - 2-byte field address (from captured packet)
- `add_space` - Add trailing space after text (default: False)

**Returns:** `str` - API response

### `send_command(text, cursor_addr=None)`

Send a command on an unformatted screen (e.g., transaction codes like CICS transactions).

```python
# Send MCGM transaction
api.send_command('MCGM')

# With custom cursor position
api.send_command('CESF LOGOFF', cursor_addr=bytes([0x40, 0xC4]))
```

**Parameters:**
- `text` - ASCII command text (converted to EBCDIC)
- `cursor_addr` - Optional 2-byte cursor address (default: 0x40, 0xC4)

**Returns:** `str` - API response

### `send_client_data(log_id)`

Replay client data from a database log entry.

```python
api.load_db('pentest.db')

# Replay the exact packet from log ID 42
api.send_client_data(42)
```

**Returns:** `str` - API response

**Raises:** `Hack3270APIError` if log entry not found

---

## Screen Analysis

### `get_screen_text()`

Get the screen as plain text with control codes removed.

```python
lines = api.get_screen_text()
# Returns list of 24 lines, 80 chars each

for i, line in enumerate(lines):
    print(f"{i+1:2}: {line}")
```

**Returns:** `list` of 24 strings (80 chars each)

### `find_text(pattern)`

Find text on the screen.

```python
import re

# Find literal text
results = api.find_text('ERROR')
for row, col, match in results:
    print(f"Found '{match}' at row {row+1}, col {col+1}")

# Find with regex
results = api.find_text(re.compile(r'PF\d+'))
for row, col, match in results:
    print(f"Found '{match}' at ({row}, {col})")
```

**Returns:** `list` of `(row, col, match)` tuples (0-indexed)

### `find_field(label)`

Find a field value by its label.

```python
# Screen shows: "USERID: ADMIN"
userid = api.find_field('USERID')
print(userid)  # "ADMIN"

# Screen shows: "Balance . . . 1234.56"
balance = api.find_field('Balance')
print(balance)  # "1234.56"
```

**Returns:** `str` (field value) or `None`

### `get_text_at(row, col, length=None)`

Get text at a specific screen position.

```python
# Get text starting at row 5, column 10
text = api.get_text_at(4, 9)  # 0-indexed
print(text)

# Get exactly 8 characters
text = api.get_text_at(0, 0, 8)
print(text)
```

**Returns:** `str`

### `analyze_hidden()`

Analyze the current screen for hidden fields.

```python
result = api.analyze_hidden()

print(f"Hidden fields found: {result['hidden_count']}")

for field in result['hidden_fields']:
    print(f"  Type: {field['type']}")
    print(f"  Position: {field['position']}")
    print(f"  Data: {field['data']}")
```

**Returns:** `dict` with keys:
- `status`: `'ok'` or `'error'`
- `total_bytes`: Screen data size
- `hidden_count`: Number of hidden fields
- `hidden_fields`: List of field details

---

## Data Conversion

### `ascii_to_ebcdic(s)`

Convert ASCII string to EBCDIC bytes.

```python
ebcdic = api.ascii_to_ebcdic('HELLO')
print(ebcdic.hex())  # c8c5d3d3d6
```

**Returns:** `bytes`

### `ebcdic_to_ascii(data)`

Convert EBCDIC bytes to ASCII string.

```python
raw = bytes.fromhex('c8c5d3d3d6')
text = api.ebcdic_to_ascii(raw)
print(text)  # "HELLO"
```

**Returns:** `str`

---

## Field Injection

Automate brute-force attacks on input fields.

### `get_inject_template(log_id, mask='*')`

Get injection template from a captured packet. Uses the **local database** loaded via `load_db()`.

First, capture a packet with mask characters in the target field:
1. In the terminal, type `****` in the field you want to inject
2. Press Enter to send
3. Note the log ID from the Logs tab

```python
# Load the database containing your captured packet
api.load_db('my_session.db')

# Get template from log ID 42 (where you typed '****')
template = api.get_inject_template(42, '*')

if template['status'] == 'ok':
    print(f"Mask length: {template['mask_length']}")
    print(f"Preamble: {len(template['preamble'])} bytes")
    print(f"Postamble: {len(template['postamble'])} bytes")
```

**Note:** You must call `load_db()` before using this function. The template is extracted from your local `.db` file, not the server's active session.

**Returns:** `dict` with `preamble`, `postamble`, `mask_length`

### `load_injection_file(filename)`

Load injection values from a file.

```python
values = api.load_injection_file('injections/numeric-4.txt')
print(f"Loaded {len(values)} values")
```

**Returns:** `list` of strings

### `inject(template, value, mode='TRUNC')`

Build and send an injection packet.

| Mode | Description |
|------|-------------|
| `'TRUNC'` | Truncate/pad to exact field length |
| `'SKIP'` | Skip if value is too long |
| `'OVERFLOW'` | Send full value (may overflow field) |

```python
template = api.get_inject_template(42, '*')

# Single injection
api.inject(template, '1234')

# Brute force loop
values = api.load_injection_file('injections/pin-common.txt')
for value in values:
    api.inject(template, value)
    response = api.get_last_server()
    
    if 'INVALID' not in response:
        print(f"Found valid value: {value}")
        break
```

**Returns:** API response or `None` (if skipped)

---

## Automation

### `replay_sequence(log_ids, delay=0.5)`

Replay multiple log entries in sequence.

```python
api.load_db('pentest.db')

# Replay a login sequence
responses = api.replay_sequence([7, 9, 11], delay=1.0)

for r in responses:
    print(f"ID {r['id']}: {r['response'][:50]}")
```

**Returns:** `list` of `{'id': int, 'response': str}` dicts

### `record_start()`

Start recording actions for later playback.

```python
api.record_start()

# These actions will be recorded
api.send_aid('ENTER')
api.send_aid('PF3')
api.send_client_data(42)

actions = api.record_stop()
print(f"Recorded {len(actions)} actions")
```

### `record_stop()`

Stop recording and return the recorded actions.

```python
actions = api.record_stop()
# Returns: [('AID', 'ENTER'), ('AID', 'PF3'), ('LOG', 42)]
```

**Returns:** `list` of `(action_type, data)` tuples

### `playback(actions, delay=0.5)`

Playback recorded actions.

```python
# Record once
api.record_start()
api.send_aid('ENTER')
api.send_aid('PF3')
actions = api.record_stop()

# Playback multiple times
for i in range(5):
    print(f"Playback {i+1}")
    api.playback(actions, delay=0.5)
```

---

## Complete Examples

### Example 1: Simple Screen Check

```python
from hack3270_api import Hack3270API

with Hack3270API() as api:
    # Get current screen
    screen = api.get_last_server()
    print("Current screen:")
    print(screen[:500])
    
    # Check for specific text
    if 'LOGON' in screen:
        print("\nAt login screen")
    elif 'READY' in screen:
        print("\nSystem ready")
```

### Example 2: Automated Login Sequence

```python
from hack3270_api import Hack3270API
import time

with Hack3270API() as api:
    api.load_db('pentest.db')
    
    # Replay login packets
    login_ids = [7, 9, 11]  # Your captured login sequence
    
    for log_id in login_ids:
        print(f"Sending packet {log_id}...")
        api.send_client_data(log_id)
        time.sleep(1.0)
    
    # Verify login
    if api.wait_for('READY', timeout=5):
        print("Login successful!")
    else:
        screen = api.get_last_server()
        print(f"Login may have failed: {screen[:100]}")
```

### Example 3: AID Key Discovery

```python
from hack3270_api import Hack3270API
import time

AIDS = ['PA1', 'PA2', 'PA3', 'PF1', 'PF2', 'PF3', 'PF4', 
        'PF6', 'PF7', 'PF8', 'PF9', 'PF10', 'PF11', 'PF12']

with Hack3270API() as api:
    # Get baseline screen
    baseline = api.get_last_server()
    baseline_len = len(baseline)
    
    print(f"Baseline screen: {baseline_len} chars")
    print("Scanning AIDs...\n")
    
    for aid in AIDS:
        api.send_aid(aid)
        time.sleep(0.5)
        
        response = api.get_last_server()
        
        if len(response) != baseline_len:
            print(f"*** {aid}: NEW SCREEN ({len(response)} chars) ***")
        else:
            print(f"    {aid}: same")
```

### Example 4: Field Brute Force

```python
from hack3270_api import Hack3270API
import time

with Hack3270API() as api:
    api.load_db('pentest.db')
    
    # Get template (log ID where you typed '****' in target field)
    template = api.get_inject_template(42, '*')
    
    if template['status'] != 'ok':
        print(f"Error: {template.get('message')}")
        exit(1)
    
    print(f"Field length: {template['mask_length']}")
    
    # Load wordlist
    values = api.load_injection_file('injections/numeric-4.txt')
    print(f"Testing {len(values)} values...")
    
    for i, value in enumerate(values):
        api.inject(template, value)
        time.sleep(0.2)
        
        response = api.get_last_server()
        
        if 'INVALID' not in response:
            print(f"\n*** FOUND: {value} ***")
            break
        
        if (i + 1) % 100 == 0:
            print(f"Progress: {i + 1}/{len(values)}")
```

### Example 5: Hidden Field Detection

```python
from hack3270_api import Hack3270API

with Hack3270API() as api:
    result = api.analyze_hidden()
    
    print(f"Screen size: {result['total_bytes']} bytes")
    print(f"Hidden fields: {result['hidden_count']}")
    
    if result['hidden_count'] > 0:
        print("\nHidden field contents:")
        for field in result['hidden_fields']:
            data = field.get('data', '').strip()
            if data:
                print(f"  [{field['type']}] {data}")
```

### Example 6: Wait and React

```python
from hack3270_api import Hack3270API
import re

with Hack3270API() as api:
    # Send a command
    api.send_aid('ENTER')
    
    # Wait for one of several possible responses
    patterns = [
        ('success', re.compile(r'COMPLETE|SUCCESS|READY')),
        ('error', re.compile(r'ERROR|FAILED|INVALID')),
        ('timeout', re.compile(r'TIMEOUT|EXPIRED')),
    ]
    
    for name, pattern in patterns:
        if api.wait_for(pattern, timeout=2):
            print(f"Got response: {name}")
            break
    else:
        print("No expected response received")
        screen = api.get_last_server()
        print(f"Screen shows: {screen[:200]}")
```

---

## Error Handling

All API methods can raise `Hack3270APIError`:

```python
from hack3270_api import Hack3270API, Hack3270APIError

try:
    api = Hack3270API()
    api.connect()
    api.send_client_data(99999)  # Non-existent ID
except Hack3270APIError as e:
    print(f"API Error: {e}")
finally:
    api.disconnect()
```

---

## API Protocol Reference

The TCP API uses simple text commands on port 31337:

| Command | Description |
|---------|-------------|
| `ping` | Test connectivity |
| `GET_LAST_SERVER` | Get ASCII screen |
| `GET_LAST_SERVER_RAW` | Get raw bytes (base64 JSON) |
| `SEND_AID:<aid>` | Send AID key |
| `SEND_RAW:<len>\n<data>` | Send raw bytes |
| `ANALYZE_HIDDEN` | Analyze hidden fields (JSON) |
| `GET_INJECT_TEMPLATE:<id>:<mask>` | Get injection template (JSON) |

The Python client library handles all protocol details automatically.
