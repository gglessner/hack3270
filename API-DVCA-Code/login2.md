# login2.py - Raw Packet Construction Tutorial

This script automates DVCA login by building TN3270 packets programmatically, with no database required.

## Overview

Unlike `login.py` which replays captured packets, `login2.py` constructs packets from scratch. Credentials are defined as ASCII strings and converted to EBCDIC at runtime.

## Prerequisites

- `hack3270` running and connected to DVCA
- No database file needed!
- Terminal connected through hack3270 proxy

## Key Concept: TN3270 Packet Structure

A TN3270 client-to-server packet for field entry has this structure:

```
[AID] [Cursor Addr] [SBA] [Field Addr] [EBCDIC Data] [IAC EOR]
 1B      2B          1B      2B          N bytes       2B
```

| Component | Bytes | Description |
|-----------|-------|-------------|
| AID | 1 | Attention Identifier (ENTER = 0x7D) |
| Cursor Addr | 2 | Current cursor position |
| SBA | 1 | Set Buffer Address order (0x11) |
| Field Addr | 2 | Address of the field |
| EBCDIC Data | N | The text, converted from ASCII |
| IAC EOR | 2 | Telnet End-of-Record (0xFF 0xEF) |

## How The Code Works

### Configuration

```python
USERNAME = 'DVCA'
PASSWORD = 'DVCA'
TRANSACTION = 'MCGM'
```

Credentials are plain ASCII strings - easy to read and modify.

### Field Addresses

```python
USERNAME_CURSOR = bytes([0x5B, 0xF4])
USERNAME_FIELD = bytes([0x5B, 0xF0])
PASSWORD_CURSOR = bytes([0xC1, 0xD5])
PASSWORD_FIELD = bytes([0xC1, 0xD1])
```

These 2-byte addresses specify screen positions. They're extracted from captured packets:
1. Capture a login packet in hack3270
2. Look at the hex: `7d 5b f4 11 5b f0 c4 e5 c3 c1...`
3. Bytes 2-3 after AID = cursor (5B F4)
4. Bytes after SBA (11) = field address (5B F0)

### The send_field() API Function

```python
api.send_field(USERNAME, USERNAME_CURSOR, USERNAME_FIELD, add_space=True)
```

This API function:
1. Converts ASCII text to EBCDIC
2. Builds the full packet structure
3. Sends via `send_raw()`

Internal implementation:
```python
def send_field(self, text, cursor_addr, field_addr, add_space=False):
    AID_ENTER = 0x7D
    SBA = 0x11
    IAC_EOR = bytes([0xFF, 0xEF])
    
    ebcdic_text = self.ascii_to_ebcdic(text)
    if add_space:
        ebcdic_text += self.ascii_to_ebcdic(' ')
    
    packet = bytes([AID_ENTER]) + cursor_addr + bytes([SBA]) + \
             field_addr + ebcdic_text + IAC_EOR
    return self.send_raw(packet)
```

### The send_command() API Function

```python
api.send_command(TRANSACTION)
```

For unformatted screens (like after CLEAR), use `send_command()`:

```python
def send_command(self, text, cursor_addr=None):
    # Simpler packet: AID + Cursor + Data + IAC_EOR
    # (no SBA/field address needed)
```

### ASCII to EBCDIC Conversion

The API handles character encoding automatically:

```python
A2E = {
    'A': 0xC1, 'B': 0xC2, 'C': 0xC3, 'D': 0xC4, ...
    '0': 0xF0, '1': 0xF1, '2': 0xF2, ...
    ' ': 0x40, '*': 0x5C, ...
}
```

So `'DVCA'` becomes `bytes([0xC4, 0xE5, 0xC3, 0xC1])`.

## Login Flow

```
1. Check splash screen → send CLEAR if needed
2. Send username field → USERNAME + ENTER
3. Send password field → PASSWORD + ENTER
4. Handle *** prompts → ENTER, then CLEAR
5. Send CLEAR → get to command mode
6. Send MCGM → launch transaction
7. Send PF5 → navigate to Options
8. Verify "Option" in response
```

## Finding Field Addresses

To adapt this for other applications:

1. **Capture the packet**: Perform the action manually, check Logs tab
2. **Get the hex**: Click the log entry, view raw data
3. **Parse the structure**:
   ```
   7d c6e7 11 c6e7 d7888993...
   ^  ^    ^  ^    ^
   |  |    |  |    EBCDIC data
   |  |    |  Field address
   |  |    SBA order
   |  Cursor address
   AID (ENTER)
   ```

## Advantages Over Database Replay

| Aspect | login.py (DB) | login2.py (Raw) |
|--------|---------------|-----------------|
| Database required | Yes | No |
| Portable | No (session-specific) | Yes |
| Flexible data | No | Yes (change USERNAME) |
| Complexity | Lower | Higher |

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "May not be at login screen" | Wrong initial state, restart DVCA |
| Login fails silently | Check field addresses match your screen |
| Garbled text | EBCDIC conversion issue |

## Code Structure

```
login2.py
├── Configuration
│   ├── Credentials (ASCII)
│   └── Field addresses (bytes)
├── main()
│   ├── Connect to API
│   ├── Handle splash screen
│   ├── send_field(USERNAME)
│   ├── send_field(PASSWORD)
│   ├── Handle *** prompts
│   ├── send_command(MCGM)
│   ├── send_aid(PF5)
│   └── Verify success
└── Cleanup
```

## See Also

- `login.py` - Simpler database replay approach
- `login3.py` - Adds reconnect handling to this approach
