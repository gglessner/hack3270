# login.py - Database Replay Login Tutorial

This script automates DVCA login by replaying pre-captured packets from a SQLite database.

## Overview

`login.py` demonstrates the simplest approach to automation: capture a working session once, then replay those exact packets to reproduce the login sequence.

## Prerequisites

- `hack3270` running and connected to DVCA
- `dvca-login.db` containing captured login packets
- Terminal connected through hack3270 proxy

## How It Works

### Step 1: Load the Database

```python
api.load_db('dvca-login.db')
```

The script loads a SQLite database containing previously captured TN3270 packets. Each packet is stored with:
- **ID**: Sequential identifier
- **RAW_DATA**: The actual bytes sent/received
- **C_S**: Direction ('C' for client, 'S' for server)
- **Timestamp**: When it was captured

### Step 2: Connect to the API

```python
api.connect()
```

Establishes a connection to hack3270's Web API on port 31337. This allows the script to send commands and receive responses.

### Step 3: Replay Login Packets

```python
for log_id in LOGIN_IDS:
    api.send_client_data(log_id)
    time.sleep(DELAY)
```

The script sends each captured client packet in sequence:
- **ID 7**: Username entry (DVCA + ENTER)
- **ID 9**: TN3270E negotiation response
- **ID 11**: Password entry (DVCA + ENTER)

The `send_client_data()` function:
1. Reads the raw bytes from the database
2. Sends them through the API to hack3270
3. hack3270 forwards them to the mainframe

### Step 4: Post-Login Navigation

After login, the script handles the TSO welcome screens:

```python
api.send_aid('ENTER')  # Dismiss first prompt
api.send_aid('CLEAR')  # Clear second prompt
api.send_aid('CLEAR')  # Get to command mode
```

### Step 5: Launch MCGM Transaction

```python
api.send_client_data(MCGM_ID)  # Send "MCGM" transaction
api.send_aid('PF5')            # Navigate to Options menu
```

## Key Concepts

### Database Replay

The database contains exact copies of packets from a working session. This approach:
- **Pros**: Simple, reliable, captures complex protocol details
- **Cons**: Requires initial capture, not flexible for different data

### Packet IDs

Each packet has a unique ID. You find these by:
1. Performing the action manually in the terminal
2. Checking the Logs tab in hack3270
3. Noting the ID of each client ('C') packet

### Timing

```python
DELAY = 3.0  # seconds between packets
```

Mainframes process sequentially. Too fast = packets get lost or rejected.

## Creating Your Own Database

1. Start hack3270 with a fresh project
2. Manually perform the login sequence
3. Note the packet IDs from the Logs tab
4. Copy `pentest.db` to `dvca-login.db`
5. Update the script with your IDs

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "Log ID not found" | Wrong database or ID doesn't exist |
| "Connection refused" | hack3270 not running |
| Login fails | Packets may be session-specific, recapture |

## Code Structure

```
login.py
├── Configuration (IDs, delays)
├── main()
│   ├── Load database
│   ├── Connect to API
│   ├── Send login packets
│   ├── Handle post-login screens
│   ├── Send MCGM transaction
│   └── Verify success
└── Cleanup
```

## See Also

- `login2.py` - Same result without database (raw packets)
- `login3.py` - Adds reconnect handling
