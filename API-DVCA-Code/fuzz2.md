# fuzz2.py - Dynamic Field Discovery Fuzzer Tutorial

This tutorial explains `fuzz2.py`, which automatically discovers input fields on the current screen before fuzzing them.

## Overview

Unlike `fuzz.py` which requires hardcoded field addresses, `fuzz2.py` dynamically parses the 3270 data stream to find all input fields. This makes it ideal for quickly testing new screens without prior configuration.

## Key Feature: Dynamic Field Discovery

The fuzzer uses the API's screen parsing functions:

```python
# Get all fields from current screen
all_fields = api.parse_screen_fields(raw_data)

# Filter to input fields only
input_fields = api.get_input_fields(raw_data)
```

Each field includes:
- `address` - Buffer position where data starts
- `protected` - True if read-only
- `numeric` - True if numeric-only
- `hidden` - True if invisible
- `length` - Field length
- `value` - Current EBCDIC content

## How Screen Parsing Works

The API's `parse_screen_fields()` function:

1. **Skips command bytes** - F1 (Write), F5 (Erase/Write), etc.
2. **Tracks buffer position** - SBA orders update current address
3. **Detects field starts** - SF (0x1D) and SFE (0x29) mark new fields
4. **Parses attributes** - Protected, numeric, hidden bits
5. **Collects field data** - Bytes between field definitions

```python
# Simplified parsing logic
while i < len(raw_data):
    if byte == 0x11:  # SBA
        current_addr = api.decode_buffer_address(b1, b2)
    elif byte == 0x1D:  # SF
        attr = raw_data[i+1]
        field = {
            'address': current_addr + 1,  # Data after attribute
            'protected': (attr & 0x20) != 0,
            'numeric': (attr & 0x10) != 0,
            'hidden': (attr & 0x0C) == 0x0C,
        }
        fields.append(field)
```

## 12-Bit Address Encoding

TN3270 uses a special encoding for buffer addresses:

```python
ADDR_TABLE = [0x40, 0xC1, 0xC2, 0xC3, ...]  # 64 values

def encode_buffer_address(addr):
    high = (addr >> 6) & 0x3F
    low = addr & 0x3F
    return bytes([ADDR_TABLE[high], ADDR_TABLE[low]])

def decode_buffer_address(b1, b2):
    high = ADDR_TABLE.index(b1)
    low = ADDR_TABLE.index(b2)
    return (high << 6) | low
```

Example:
- Position 423 = `(6 << 6) | 39` = `c6e7`
- Position 583 = `(9 << 6) | 7` = `c9c7`

## Payload Generation

Generates payloads based on field characteristics:

```python
def generate_payloads(field_length, is_numeric):
    payloads = []
    
    # Overflow - always test
    payloads.append(('overflow_2x', 'A' * (field_length * 2), False))
    
    # Numeric-specific
    if is_numeric:
        payloads.append(('alpha_in_num', 'ABCD', False))
    
    # Binary injection
    payloads.append(('sba_inject', b'\x11\x11\x11\x11', True))
    
    return payloads
```

## Packet Building

Builds packets using API encoding functions:

```python
def build_fuzz_packet(api, fields, fuzz_idx, fuzz_data, is_binary):
    # TN3270E header if needed
    if api.is_tn3270e():
        packet = bytes([0x00, 0x00, 0x00, 0x00, 0x01, AID_ENTER])
    else:
        packet = bytes([AID_ENTER])
    
    # Cursor at first input field
    cursor_addr = api.encode_buffer_address(input_fields[0]['address'])
    packet += cursor_addr
    
    # Add each field
    for idx, field in enumerate(input_fields):
        field_addr = api.encode_buffer_address(field['address'])
        
        if idx == fuzz_idx:
            # Fuzz payload
            if is_binary:
                field_data = fuzz_data
            else:
                field_data = api.ascii_to_ebcdic(fuzz_data)
        else:
            # Original value
            field_data = field['value'] or api.ascii_to_ebcdic(' ')
        
        packet += bytes([SBA]) + field_addr + field_data
    
    packet += IAC_EOR
    return packet
```

## Running the Fuzzer

```bash
cd API-DVCA-Code
python fuzz2.py --yes
```

### Interactive Mode (default)

```
============================================================
Dynamic Field Discovery Fuzzer
============================================================
[+] Connected to API

[*] Analyzing current screen...
[+] Found 67 total fields
[+] Found 7 input fields:

  [0] Addr: 0423 (c6e7)  Len:  44 = 'Philip Young'
  [1] Addr: 0583 (c9c7)  Len:  44 = '100 Adelaide St W'
  [2] Addr: 0743 (4be7)  Len:  44 = 'Toronto'
  ...

[!] WARNING: Fuzzing may cause application crashes or abends.
    Continue? (y/N):
```

### Non-Interactive Mode

Use `--yes` to skip confirmation:

```bash
python fuzz2.py --yes
```

## Output Format

```
[*] Fuzzing field 0 (addr 423, len 44)
  [.] overflow_2x: OK
  [.] overflow_10x: OK
  [.] nulls: OK
  [!] ABEND SOC7 with payload: packed_invalid
```

## Debug Mode

Enable debug output to see packet details:

```python
DEBUG = True  # In configuration section
```

Output:
```
[DEBUG] Cursor addr bytes: c6e7
[DEBUG] Field 0: addr=423 -> bytes=c6e7, data_len=88
[DEBUG] Total packet: 338 bytes
[DEBUG] First 50 bytes: 7dc6e711c6e7c1c1c1c1...
```

## Crash Detection and Recovery

The fuzzer handles connection loss:

```python
except socket.error as e:
    print(f"[!!!] CONNECTION LOST during {payload_name}")
    crashes_found.append({
        'field': field_idx,
        'payload': payload_name,
        'error': str(e)
    })
    
    # Attempt reconnect
    api.disconnect()
    time.sleep(2)
    api.connect()
    
    # Re-parse screen (may have changed)
    raw_data = api.get_last_server_raw()
    all_fields = api.parse_screen_fields(raw_data)
```

## API Functions Used

| Function | Purpose |
|----------|---------|
| `parse_screen_fields()` | Discover all fields on screen |
| `get_input_fields()` | Filter to editable fields |
| `encode_buffer_address()` | Convert position to bytes |
| `check_abend()` | Detect mainframe errors |
| `is_tn3270e()` | Check for TN3270E mode |
| `ascii_to_ebcdic()` | Convert text payloads |
| `send_raw(data, desc)` | Send packet with log description |

## Comparison: fuzz.py vs fuzz2.py

| Aspect | fuzz.py | fuzz2.py |
|--------|---------|----------|
| Field configuration | Hardcoded | Dynamic |
| Setup required | Extract addresses | None |
| Payload variety | Comprehensive | Basic |
| Best for | Known forms | Quick testing |

## Workflow

```
┌─────────────────────────────────────────┐
│ 1. Connect to API                       │
├─────────────────────────────────────────┤
│ 2. Get raw screen data                  │
├─────────────────────────────────────────┤
│ 3. Parse 3270 data stream               │
│    └── Find SF/SFE orders               │
│    └── Extract field attributes         │
│    └── Calculate addresses/lengths      │
├─────────────────────────────────────────┤
│ 4. Filter to input fields               │
├─────────────────────────────────────────┤
│ 5. For each field:                      │
│    └── Generate payloads                │
│    └── Build packet                     │
│    └── Send and check response          │
│    └── Detect abends/crashes            │
├─────────────────────────────────────────┤
│ 6. Report findings                      │
└─────────────────────────────────────────┘
```

## Common Issues

| Issue | Solution |
|-------|----------|
| "No screen data" | Ensure terminal is connected and showing a form |
| "No input fields" | Screen may have only protected fields |
| Wrong addresses | May need to adjust address offset |
| TN3270E issues | Check `api.is_tn3270e()` is working |

## See Also

- `fuzz.py` - Comprehensive CICS fuzzer with hardcoded fields
- `fuzz3.py` - Protected/hidden field fuzzer
- `order_fuzz.py` - TN3270 protocol order fuzzer
- `API_Documentation.md` - Full API reference
