# fuzz.py - Comprehensive CICS Form Fuzzer Tutorial

This tutorial explains `fuzz.py`, a comprehensive fuzzer targeting CICS/COBOL mainframe applications with hardcoded field definitions.

## Overview

`fuzz.py` is designed for **known forms** where you've already captured field addresses. It tests each field with a comprehensive set of CICS-specific payloads designed to trigger mainframe-specific vulnerabilities.

## When to Use This Fuzzer

Use `fuzz.py` when:
- You have captured field addresses from a specific form
- You want thorough CICS/COBOL-specific testing
- You need to test packed decimal, zoned decimal, and other mainframe data types

Use `fuzz2.py` instead when:
- You want to discover fields dynamically
- You're testing a new screen without prior knowledge

## Payload Categories

### 1. Buffer Overflow

```python
def generate_overflow_payloads(field_length):
    sizes = [length + 1, length * 2, 128, 256, 1000]
    return [('A' * size, f"OVF-{size}", False) for size in sizes]
```

Tests how the application handles data exceeding field boundaries. COBOL typically truncates, but bugs can cause memory corruption.

### 2. Packed Decimal (COMP-3)

```python
def generate_packed_decimal_payloads():
    return [
        (b'\xFF\xFF\xFF\xFF', 'PD-ALLF', True),  # Invalid sign
        (b'\x00\x00\x00\x0C', 'PD-ZERO-POSITIVE', True),
        (b'\x99\x99\x99\x9C', 'PD-MAX-POS', True),
        (b'\xAB\xCD\xEF\x0C', 'PD-INVALID', True),  # Non-digit nibbles
    ]
```

Packed decimal stores two digits per byte with the sign in the last nibble. Invalid packed data causes **SOC7 (Data Exception)** abends.

### 3. Zoned Decimal

```python
def generate_zoned_decimal_payloads():
    return [
        ('A123', 'ZD-ALPHA-START', False),  # Non-numeric
        ('12-3', 'ZD-MID-SIGN', False),     # Sign in wrong position
        (b'\xF0\xF1\xC2', 'ZD-POS-SIGN', True),  # Positive signed
    ]
```

Zoned decimal uses one byte per digit. Testing invalid formats helps find input validation gaps.

### 4. CICS Command Injection

```python
def generate_cics_injection_payloads():
    return [
        ('EXEC CICS RETURN', 'CICS-RETURN', False),
        ('EXEC CICS XCTL PROGRAM(HACK)', 'CICS-XCTL', False),
        ("EXEC CICS SEND TEXT FROM('HACKED')", 'CICS-SEND', False),
    ]
```

Attempts to inject CICS commands. Rarely successful but worth testing for improper input handling.

### 5. SQL/DB2 Injection

```python
def generate_sql_injection_payloads():
    return [
        ("' OR '1'='1", 'SQL-OR', False),
        ("'; DELETE FROM--", 'SQL-DELETE', False),
        ("EXEC SQL SELECT * FROM SYSIBM.SYSTABLES", 'SQL-EXEC', False),
    ]
```

Tests for SQL injection if the CICS application interfaces with DB2.

### 6. TN3270 Order Injection

```python
def generate_tn3270_order_payloads():
    return [
        (b'\x11\x11\x11\x11', 'TN-SBA-REPEAT', True),  # Repeated SBA
        (b'\x1D\x00\x1D\xFF', 'TN-SF-CHAIN', True),    # Chained SF
        (b'\x29\xFF', 'TN-SFE-MAXCOUNT', True),        # Invalid SFE
    ]
```

Injects 3270 order bytes into data fields to test parsing vulnerabilities.

## Form Field Configuration

```python
FORM_FIELDS = [
    (bytes([0xC6, 0xE7]), 'Name', 'Phillip Young', 44),
    (bytes([0xC9, 0xC7]), 'Address', '101 Adelaide St W', 44),
    (bytes([0x4B, 0xE7]), 'City', 'Toronto', 44),
    (bytes([0x4E, 0xC7]), 'State', 'Ontario', 44),
    (bytes([0x50, 0xE7]), 'Zip', 'M5H 0B3', 44),
    (bytes([0xD3, 0xC7]), 'Country', 'Canada', 44),
    (bytes([0xD5, 0xE7]), 'Code', '1234', 4),
]
```

Each field definition:
- **Address**: 2-byte encoded buffer address
- **Name**: Human-readable field name
- **Default**: Value to use when not fuzzing this field
- **Length**: Maximum field length

## Packet Building

```python
def build_fuzz_packet(api, fuzz_field_idx, fuzz_data, is_binary):
    # TN3270E header if needed
    if api.is_tn3270e():
        packet = bytes([0x00, 0x00, 0x00, 0x00, 0x01, AID_ENTER]) + CURSOR_ADDR
    else:
        packet = bytes([AID_ENTER]) + CURSOR_ADDR
    
    for idx, (field_addr, name, default_val, max_len) in enumerate(FORM_FIELDS):
        if idx == fuzz_field_idx:
            # Inject fuzz payload
            field_data = fuzz_data if is_binary else api.ascii_to_ebcdic(fuzz_data)
        else:
            # Use default value
            field_data = api.ascii_to_ebcdic(default_val.ljust(max_len))
        
        packet += bytes([SBA]) + field_addr + field_data
    
    packet += IAC_EOR
    return packet
```

## Abend Detection

Uses both API built-in patterns and extended patterns:

```python
def check_for_abend(api, response):
    # API patterns: DFHAC2, ABEND, ASRA, AICA, AEY7, APCT, SOC7, SOC4
    abend = api.check_abend(response)
    if abend:
        return abend
    
    # Extended patterns
    for pattern in EXTENDED_ABEND_PATTERNS:
        if pattern in response.upper():
            return pattern
    return None
```

## Running the Fuzzer

```bash
cd API-DVCA-Code
python fuzz.py
```

### Prerequisites

1. `hack3270` connected to mainframe
2. Terminal emulator at the target form
3. Field addresses configured in `FORM_FIELDS`

### Output

```
[1/500] Name/OVF-45: AAAAAAAAAAAAAAAAAAA... OK
[2/500] Name/OVF-88: AAAAAAAAAAAAAAAAAAA... OK
[3/500] Name/PD-ALLF: ffffffff OK
...
[47/500] Name/TN-SBA-REPEAT: 11111111 *** CONNECTION LOST ***

!!! CRASH DETECTED !!!
Field: Name
Payload: TN-SBA-REPEAT
Data: 0x11111111
Previous successful: TN-SF-CHAIN
```

## Crash Detection

The fuzzer detects two types of issues:

### 1. Abends (Application Errors)
- SOC7 - Data Exception (packed decimal)
- ASRA - Program Check
- APCT - Program Not Found

### 2. Crashes (Connection Loss)
- Connection reset
- Connection aborted
- Identifies the payload that caused the crash

## Customizing for Your Application

### Step 1: Capture Field Addresses

Navigate to your form, submit it, and examine the Logs tab in hack3270. Find the client entry with your submission.

### Step 2: Parse the Packet

```python
# Extract addresses from captured packet
raw = cursor.execute('SELECT RAW_DATA FROM Logs WHERE ID = ?', (id,)).fetchone()[0]
i = 3  # Skip AID + cursor
while i < len(raw) - 2:
    if raw[i] == 0x11:  # SBA
        addr = bytes([raw[i+1], raw[i+2]])
        print(f"Field at {addr.hex()}")
        i += 3
    else:
        i += 1
```

### Step 3: Update FORM_FIELDS

Replace the default entries with your application's fields.

## Security Findings

Common vulnerabilities detected:

| Payload Type | Abend | Meaning |
|-------------|-------|---------|
| Packed Decimal | SOC7 | Invalid numeric data not validated |
| Overflow | ASRA | Buffer overflow caused program check |
| TN3270 Orders | Crash | Protocol parsing vulnerability |
| SQL Injection | None | May still work silently |

## API Functions Used

| Function | Purpose |
|----------|---------|
| `is_tn3270e()` | Check for TN3270E mode |
| `encode_buffer_address()` | Convert position to bytes |
| `ascii_to_ebcdic()` | Convert text payloads |
| `check_abend()` | Detect mainframe errors |
| `send_raw(data, desc)` | Send packet with log description |

## See Also

- `fuzz2.py` - Dynamic field discovery fuzzer
- `fuzz3.py` - Protected/hidden field fuzzer
- `order_fuzz.py` - TN3270 protocol fuzzer
- `API_Documentation.md` - Full API reference
