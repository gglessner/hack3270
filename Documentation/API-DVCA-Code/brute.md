# brute.py - Database Template Brute Force Tutorial

This script performs brute force attacks on input fields using a captured packet as a template.

## Overview

`brute.py` uses the "template" approach: capture a packet containing a mask (like `****`), then replace the mask with each value from a wordlist. This preserves all the complex packet structure while only changing the target field.

## Prerequisites

- `hack3270` running and connected to DVCA
- `dvca-brute.db` containing a captured packet with mask
- Terminal at the screen matching your template
- Wordlist file in `../injections/`

## Key Concept: Template Injection

A TN3270 packet can be complex, containing multiple fields and orders. Instead of rebuilding it from scratch, we:

1. **Capture** a packet with a placeholder (mask)
2. **Extract** the parts before and after the mask
3. **Inject** new values in place of the mask

```
Original:  [preamble][****][postamble]
Injected:  [preamble][1337][postamble]
```

## How The Code Works

### Load Database

```python
api.load_db('dvca-brute.db')
```

The database contains your captured packets. You need the ID of a client packet where you typed `****` in the target field.

### Get Template

```python
template = api.get_inject_template(TEMPLATE_ID, MASK)
```

The `get_inject_template()` function:
1. Reads the raw packet from the database
2. Converts the mask character to EBCDIC (`*` = 0x5C)
3. Finds where the mask starts (preamble)
4. Counts how many mask characters (length)
5. Finds what comes after (postamble)

Returns:
```python
{
    'status': 'ok',
    'preamble': bytes,    # Everything before mask
    'postamble': bytes,   # Everything after mask
    'mask_length': int    # Number of mask characters
}
```

### Load Wordlist

```python
codes = api.load_injection_file(INJECTION_FILE)
```

Reads values from a text file, one per line:
```
0000
0001
0002
...
1337
...
9999
```

### Injection Loop

```python
for code in codes:
    api.inject(template, code)
    time.sleep(DELAY)
    
    response = api.get_last_server()
    if ERROR_MSG not in response:
        print(f"*** FOUND: {code} ***")
        break
```

The `inject()` function:
1. Converts the value to EBCDIC
2. Pads/truncates to mask length
3. Assembles: preamble + value + postamble
4. Sends via `send_raw()`

## Creating Your Template

### Step 1: Navigate to Target Screen

Get to the screen with the input field you want to brute force.

### Step 2: Enter Mask Characters

Type `****` (or however many characters the field accepts) in the target field.

### Step 3: Submit

Press ENTER to send the packet.

### Step 4: Find the Packet ID

Check hack3270's Logs tab. Find the client packet containing your mask. Note the ID.

### Step 5: Export Database

Copy `pentest.db` to `dvca-brute.db` (or your preferred name).

### Step 6: Update Script

```python
TEMPLATE_ID = 41  # Your captured packet ID
MASK = '*'        # Mask character used
```

## Mask Modes

The `inject()` function supports modes (via internal logic):

| Mode | Behavior |
|------|----------|
| TRUNC | Truncate value if too long |
| SKIP | Skip values that are too long |
| OVERFLOW | Send value even if longer than mask |

## Response Analysis

```python
ERROR_MSG = 'INVALID SUPERVISOR CODE'

if ERROR_MSG not in response:
    # Success! Value was accepted
```

When the error message is absent, we've likely found a valid value.

## DVCA Example

For the supervisor code field:
- **Template ID**: 41 (packet with `****`)
- **Mask**: `*` (4 characters)
- **Wordlist**: `dvca-demo-numeric-4.txt` (4-digit codes)
- **Error**: "INVALID SUPERVISOR CODE"
- **Success**: Code 1337 - no error message

## Code Structure

```
brute.py
├── Configuration
│   ├── TEMPLATE_ID
│   ├── MASK character
│   ├── INJECTION_FILE
│   ├── ERROR_MSG
│   └── DELAY
├── main()
│   ├── Load database
│   ├── Connect to API
│   ├── Get template
│   ├── Load wordlist
│   ├── For each code:
│   │   ├── Inject value
│   │   ├── Check response
│   │   └── Report if found
│   └── Disconnect
└── Error handling
```

## Advantages

| Aspect | Benefit |
|--------|---------|
| Preserves packet structure | Works with complex forms |
| Simple value substitution | Easy to understand |
| Any field size | Mask determines length |
| Reusable template | Capture once, use many times |

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "Mask not found" | Packet doesn't contain mask character |
| Wrong template ID | Verify ID in Logs tab |
| Values not working | Ensure you're on matching screen |
| All values rejected | Check ERROR_MSG is correct |

## Optimizing Speed

```python
DELAY = 0.3  # Seconds between attempts

# Faster (may miss responses):
DELAY = 0.1

# Safer (guaranteed stable):
DELAY = 0.5
```

Lower delay = faster but less reliable. Adjust based on your mainframe's response time.

## See Also

- `brute2.py` - Same goal, no database required (raw packets)
- GUI "Inject Fields" tab - Manual field injection
- `../injections/` - Available wordlists
