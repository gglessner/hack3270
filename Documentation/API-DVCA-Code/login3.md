# login3.py - Reconnect Handling Tutorial

This script extends `login2.py` with automatic handling of "USERID ALREADY LOGGED ON" scenarios.

## Overview

When a user is already logged in on a mainframe, attempting to log in again fails with a message like "USERID DVCA ALREADY LOGGED ON". This script detects that condition and sends a reconnect command to take over the existing session.

## Prerequisites

- `hack3270` running and connected to DVCA
- No database file needed
- Terminal connected through hack3270 proxy

## The Problem: Session Already Active

Mainframe sessions persist even after disconnection. If you:
1. Log in as DVCA
2. Disconnect without logging off
3. Try to log in again

You get: `USERID DVCA ALREADY LOGGED ON TO SYSTEM`

## The Solution: LOGON RECONNECT

TSO supports reconnecting to existing sessions:

```
LOGON DVCA RECONNECT
```

This command:
1. Takes over the existing session
2. Prompts for password verification
3. Resumes where you left off

## How The Code Works

### Detection

After sending the username, check the server response:

```python
screen = api.get_last_server()

if "LOGGED ON" in screen or "IN USE" in screen:
    print("User already logged on - attempting reconnect...")
    reconnected = True
```

The response contains phrases like:
- "USERID DVCA ALREADY LOGGED ON"
- "USERID DVCA IN USE"

### Send Reconnect Command

```python
api.send_command(f'LOGON {USERNAME} RECONNECT')
```

This sends: `LOGON DVCA RECONNECT` with ENTER AID.

### Verify Password Prompt

```python
screen = api.get_last_server()
if "PASSWORD" not in screen.upper():
    print("ERROR: Expected password prompt after reconnect")
    return
```

After reconnect command, the system prompts for password verification.

### Different Post-Login Flow

Normal login and reconnect have different post-login behavior:

```python
if reconnected:
    # Reconnect: ENTER → *** → CLEAR
    api.send_aid('ENTER')
    time.sleep(DELAY)
    screen = api.get_last_server()
    if "***" in screen:
        api.send_aid('CLEAR')
        time.sleep(DELAY)
else:
    # Normal: Handle two *** prompts, then CLEAR
    if "***" in screen:
        api.send_aid('ENTER')
    # ...etc
```

## Flow Comparison

### Normal Login Flow

```
Username → Password → *** → ENTER → *** → CLEAR → CLEAR → MCGM → PF5
```

### Reconnect Flow

```
Username → "LOGGED ON" detected
         ↓
         LOGON DVCA RECONNECT
         ↓
         Password → ENTER → *** → CLEAR → MCGM → PF5
```

## Key Code Sections

### The reconnected Flag

```python
reconnected = False

if "LOGGED ON" in screen or "IN USE" in screen:
    reconnected = True
    # ... handle reconnect ...
```

This flag tracks which path we took, so post-login handling can differ.

### Case-Insensitive Matching

```python
if "PASSWORD" not in screen.upper():
```

Mainframe messages may be uppercase, lowercase, or mixed. Using `.upper()` handles all cases.

### The Reconnect Command

```python
api.send_command(f'LOGON {USERNAME} RECONNECT')
```

Uses an f-string to include the username variable. The `send_command()` function:
1. Converts the string to EBCDIC
2. Builds a packet with ENTER AID
3. Sends to the mainframe

## Testing Reconnect

To force a reconnect scenario:

1. Run `login3.py` successfully (normal login)
2. Don't log off
3. Run `login3.py` again
4. It should detect "LOGGED ON" and reconnect

## Error Handling

The script checks for:
- Password prompt after reconnect command
- *** prompts after password
- "Option" in final screen

If any check fails, it reports the issue.

## Advantages

| Scenario | login2.py | login3.py |
|----------|-----------|-----------|
| Fresh login | ✓ Works | ✓ Works |
| Session in use | ✗ Fails | ✓ Reconnects |
| No database needed | ✓ | ✓ |

## Code Structure

```
login3.py
├── Configuration
│   ├── Credentials (ASCII)
│   └── Field addresses
├── main()
│   ├── Connect to API
│   ├── Handle splash screen
│   ├── send_field(USERNAME)
│   ├── Check for "LOGGED ON"
│   │   └── If yes: send_command(LOGON RECONNECT)
│   ├── send_field(PASSWORD)
│   ├── Branch on reconnected flag
│   │   ├── Reconnect: ENTER → CLEAR
│   │   └── Normal: Handle *** prompts
│   ├── send_command(MCGM)
│   ├── send_aid(PF5)
│   └── Verify success
└── Cleanup
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "Expected password prompt" | Reconnect command failed, check spelling |
| Doesn't detect LOGGED ON | Check for exact phrase in response |
| Gets stuck after password | Post-login flow needs adjustment |

## See Also

- `login2.py` - Same approach without reconnect handling
- `login.py` - Simpler database replay approach
