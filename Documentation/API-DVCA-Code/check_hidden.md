# check_hidden.py - Hidden Field Detection Tutorial

This script detects data stored in hidden fields on TN3270 screens without requiring GUI "Hack Fields" mode.

## Overview

Mainframe applications often use "hidden" fields to store sensitive data or internal state. These fields are invisible to users but the data is still transmitted. This script analyzes raw TN3270 data to find and extract hidden field contents.

## Prerequisites

- `hack3270` running and connected to DVCA
- Terminal at a screen you want to analyze
- No database file needed

## Key Concept: 3270 Field Attributes

Every field on a 3270 screen has attributes defined by a Start Field (SF) or Start Field Extended (SFE) order. The Basic Field Attribute byte contains protection and visibility flags:

```
Bit layout of Basic Field Attribute:
  Bit 5: Protected (1) / Unprotected (0)
  Bit 4: Numeric (1) / Alphanumeric (0)
  Bit 3-2: Display type
           00 = Normal display
           01 = Normal display
           10 = Intensified display
           11 = Hidden (non-display)
```

When bits 3-2 are both set (`11`), the field is **hidden**.

## How The Code Works

### Get Last Server Response

```python
result = api.analyze_hidden()
```

The `analyze_hidden()` API function:
1. Gets the last server response (raw bytes)
2. Parses the TN3270 data stream
3. Finds all field definitions (SF, SFE, MF orders)
4. Checks the "hidden" bit in each field's attribute
5. Extracts data following hidden fields
6. Returns structured results

### Parse The Results

```python
if result.get('hidden_count', 0) > 0:
    print(f"Hidden fields: {result['hidden_count']}")
    print(f"Fields with data: {result['data_in_hidden_count']}")
    
    for field in result.get('hidden_fields', []):
        if field.get('data'):
            print(f"  - {field['data']}")
```

The result contains:
- `hidden_count`: Total hidden fields found
- `data_in_hidden_count`: Hidden fields containing actual data
- `hidden_fields`: List of field details with positions and data

## TN3270 Order Parsing

The API parses these orders to find fields:

| Order | Hex | Description |
|-------|-----|-------------|
| SF | 0x1D | Start Field (1-byte attribute) |
| SFE | 0x29 | Start Field Extended (multiple attributes) |
| MF | 0x2C | Modify Field (change existing field) |

### SF (Start Field) Example

```
1D 60
^  ^
|  Basic Field Attribute (0x60 = hidden)
Start Field order
```

### SFE (Start Field Extended) Example

```
29 03 C0 60 42 F2
^  ^  ^  ^  ^  ^
|  |  |  |  |  Color attribute (Blue)
|  |  |  |  Attribute type (0x42 = Color)
|  |  |  Basic Field Attribute (0x60 = hidden)
|  |  Attribute type (0xC0 = Basic)
|  Number of attributes (3)
Start Field Extended order
```

## Checking The Hidden Bit

```python
def is_hidden(attribute_byte):
    # Bits 3-2 both set = hidden
    return (attribute_byte & 0x0C) == 0x0C
```

The mask `0x0C` isolates bits 3-2. If both are set, the field is hidden.

## What DVCA Reveals

Running `check_hidden.py` on DVCA's Options menu reveals:

```
Hidden Field Analysis
==================================================
Screen size: 1920 bytes
Hidden fields: 3
Fields with data: 1

Hidden field data found:
  - "Delete Order History"
```

This shows a hidden menu option that isn't visible on screen!

## Security Implications

Hidden fields often contain:
- **Sensitive menu options** (like "Delete Order History")
- **User privileges or roles**
- **Internal IDs or keys**
- **Transaction state**

Attackers can:
1. Discover hidden functionality
2. Modify hidden field values
3. Bypass client-side restrictions

## No GUI Required

Unlike the GUI's "Hack Fields" mode which requires clicking a button, this script:
- Works programmatically
- Can be part of automated scanning
- Doesn't change the terminal display

## Code Structure

```
check_hidden.py
├── Configuration
│   └── API connection settings
├── main()
│   ├── Connect to API
│   ├── Call analyze_hidden()
│   ├── Display results
│   │   ├── Screen size
│   │   ├── Hidden field count
│   │   ├── Data count
│   │   └── List each hidden field with data
│   └── Disconnect
└── Error handling
```

## Integrating Into Larger Scripts

```python
# Check for hidden data after each screen
api.send_aid('PF1')
time.sleep(0.5)

result = api.analyze_hidden()
if result.get('data_in_hidden_count', 0) > 0:
    print("WARNING: Hidden data found!")
    for field in result['hidden_fields']:
        log_finding(field)
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "hidden_count: 0" | Screen may not have hidden fields |
| Empty data | Field is hidden but contains spaces/nulls |
| Connection error | Ensure hack3270 is running |

## Advanced: Manual Parsing

If you need to parse manually:

```python
raw = api.get_last_server_raw()

i = 0
while i < len(raw):
    if raw[i] == 0x1D:  # SF
        attr = raw[i+1]
        if (attr & 0x0C) == 0x0C:
            print(f"Hidden field at position {i}")
        i += 2
    elif raw[i] == 0x29:  # SFE
        count = raw[i+1]
        # Parse extended attributes...
        i += 2 + (count * 2)
    else:
        i += 1
```

## See Also

- `aid_scan.py` - Find hidden screens via AID keys
- API Documentation - `analyze_hidden()` function details
