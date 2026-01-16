# aid_scan.py - AID Key Scanning Tutorial

This script scans all AID (Attention Identifier) keys to discover hidden screens and functionality.

## Overview

3270 terminals have special keys (PF1-24, PA1-3, CLEAR, etc.) that send "AID" bytes to the mainframe. Different AIDs may trigger different application behavior. This script systematically tests each AID to find screens or functions not accessible through normal navigation.

## Prerequisites

- `hack3270` running and connected to DVCA
- Terminal at the screen you want to scan FROM
- No database file needed

## Key Concept: AID (Attention Identifier)

When you press a key on a 3270 terminal, it sends an AID byte identifying which key was pressed:

| Key | AID Hex | Description |
|-----|---------|-------------|
| ENTER | 0x7D | Submit/confirm |
| CLEAR | 0x6D | Clear screen |
| PF1 | 0xF1 | Program Function 1 |
| PF2 | 0xF2 | Program Function 2 |
| ... | ... | ... |
| PF24 | 0x7B | Program Function 24 |
| PA1 | 0x6C | Program Attention 1 |
| PA2 | 0x6E | Program Attention 2 |
| PA3 | 0x6B | Program Attention 3 |

## How The Code Works

### Define AIDs to Test

```python
AIDS_TO_TEST = [
    'PF1', 'PF2', 'PF3', 'PF4', 'PF6', 'PF7', 'PF8', 'PF9',
    'PF10', 'PF11', 'PF12', 'PF13', 'PF14', 'PF15', 'PF16',
    'PF17', 'PF18', 'PF19', 'PF20', 'PF21', 'PF22', 'PF23', 'PF24',
    'PA1', 'PA2', 'PA3'
]
```

Note: PF5, CLEAR, and ENTER are excluded:
- **PF5**: May be used for refresh (causes false positives)
- **CLEAR**: Clears the screen (disrupts testing)
- **ENTER**: Submit action (may have side effects)

### Get Baseline

```python
baseline = api.get_last_server_raw()
baseline_len = len(baseline)
```

Capture the current screen's raw bytes as a reference point.

### Scan Each AID

```python
for aid in AIDS_TO_TEST:
    api.send_aid(aid)
    time.sleep(DELAY)
    
    response = api.get_last_server_raw()
    response_len = len(response)
```

For each AID:
1. Send the AID key
2. Wait for response
3. Get the new screen data

### Detect Changes

```python
if response_len != baseline_len:
    print(f"*** NEW SCREEN: {aid} ({response_len} bytes, was {baseline_len}) ***")
```

A different response length indicates a different screen. This could be:
- A hidden menu
- An error message
- A completely different application area

### Filter False Positives

```python
response_text = api.get_last_server()
if "Invalid attention" in response_text:
    continue  # Skip - AID not recognized
```

Some AIDs generate error messages rather than new screens.

## What DVCA Reveals

Running on DVCA's Options menu:

```
AID Scanner
==================================================
Scanning AIDs for hidden screens...

*** NEW SCREEN: PA1 (1889 bytes, was 1567) ***
*** NEW SCREEN: PF3 (245 bytes, was 1567) ***

Scan complete. Found 2 screen changes.
```

- **PA1**: Triggers a hidden admin screen!
- **PF3**: Exit function (smaller screen)

Running again FROM the PA1 screen reveals more easter eggs.

## Detection Methods

### Length-Based Detection

```python
if response_len != baseline_len:
    # Different screen
```

Simple but effective. Catches most screen changes.

### Content-Based Detection

```python
if response != baseline:
    # Content changed (even if same length)
```

More thorough but may catch minor updates.

### Pattern-Based Detection

```python
if "ADMIN" in response_text or "DEBUG" in response_text:
    # Interesting keywords found
```

Look for specific indicators of hidden functionality.

## Security Implications

Hidden AID functionality may reveal:
- **Admin panels** (PA1 in DVCA)
- **Debug modes**
- **Developer tools**
- **Undocumented features**

These often bypass normal security controls because developers assumed users wouldn't find them.

## Code Structure

```
aid_scan.py
├── Configuration
│   ├── AIDS_TO_TEST list
│   └── DELAY between tests
├── main()
│   ├── Connect to API
│   ├── Get baseline screen
│   ├── For each AID:
│   │   ├── Send AID
│   │   ├── Get response
│   │   ├── Compare to baseline
│   │   └── Report changes
│   ├── Summary
│   └── Disconnect
└── Error handling
```

## Advanced: Recursive Scanning

```python
def scan_recursive(api, depth=0, max_depth=3, visited=set()):
    if depth > max_depth:
        return
    
    screen_hash = hash(api.get_last_server_raw())
    if screen_hash in visited:
        return
    visited.add(screen_hash)
    
    for aid in AIDS_TO_TEST:
        api.send_aid(aid)
        new_hash = hash(api.get_last_server_raw())
        
        if new_hash not in visited:
            print(f"{'  ' * depth}New screen via {aid}")
            scan_recursive(api, depth+1, max_depth, visited)
        
        # Return to original screen
        api.send_aid('PF3')  # or appropriate back key
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| No changes detected | Try from different starting screen |
| Too many false positives | Add content filtering |
| Script gets stuck | Add timeout handling |
| Screen changes unexpectedly | Some AIDs have side effects |

## Best Practices

1. **Save your position**: Know how to return to starting screen
2. **Start from interesting screens**: Options menus, admin areas
3. **Run multiple times**: From different starting points
4. **Document findings**: Map out the AID behavior
5. **Be careful with PA keys**: Often have unexpected effects

## See Also

- `check_hidden.py` - Find hidden fields on current screen
- GUI "Inject Keys" tab - Manual AID testing
- GUI "AID Fuzzer" - Automated AID testing with capture
