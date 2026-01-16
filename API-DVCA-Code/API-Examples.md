# DVCA API Examples

This directory contains example scripts demonstrating the hack3270 Web API against the DVCA (Damn Vulnerable CICS Application) mainframe.

## Prerequisites

1. **Docker** - DVCA runs in a Docker container
2. **hack3270** - Must be running and connected to DVCA
3. **x3270 or similar TN3270 terminal** - Connected through hack3270 proxy

## Setup

### 1. Start Fresh DVCA Container

```bash
# Stop and remove existing container (if any)
docker stop dvca
docker rm dvca

# Start fresh DVCA container
docker run -d --name dvca -p 3270:3270 mainframed767/dvca
```

Wait about 30 seconds for the mainframe to fully boot.

### 2. Start hack3270

From the hack3270 directory:

```bash
python hack3270.py 127.0.0.1 3270
```

### 3. Connect TN3270 Terminal

Connect your x3270 terminal to hack3270's proxy port (default: 3271).

You should see the DVCA splash screen.

---

## Demo Scripts

Run all scripts from the `API-DVCA-Code` directory.

### Step 1: Login

Three login scripts are provided, each demonstrating different approaches:

#### `login.py` - Database Replay

Replays pre-captured packets from `dvca-login.db`. Simple but requires the database file.

```bash
cd API-DVCA-Code
python login.py
```

#### `login2.py` - Raw Packet Construction (No Database)

Builds TN3270 packets programmatically using `send_field()` and `send_command()`. No database required - credentials are defined as ASCII strings converted to EBCDIC at runtime.

```python
USERNAME = 'DVCA'
PASSWORD = 'DVCA'
TRANSACTION = 'MCGM'
```

```bash
python login2.py
```

**Key difference:** Uses `api.send_field()` and `api.send_command()` instead of `api.send_client_data()`.

#### `login3.py` - Raw Packets + Reconnect Handling

Same as `login2.py` but handles the "USERID ALREADY LOGGED ON" scenario by sending:

```
LOGON DVCA RECONNECT
```

Then continues with password entry and normal flow.

```bash
python login3.py
```

**Expected output (reconnect case):**
```
Sending username: DVCA
User already logged on - attempting reconnect...
Reconnect accepted, at password prompt
Sending password: DVCA
  Sending ENTER...
  Found *** prompt, sending CLEAR...
Sending transaction: MCGM
Sending PF5...

==================================================
SUCCESS: At MCGM Options menu!
==================================================
```

| Script | Database Required | Reconnect Handling |
|--------|-------------------|-------------------|
| `login.py` | Yes (`dvca-login.db`) | No |
| `login2.py` | No | No |
| `login3.py` | No | Yes |

---

### Step 2: Check Hidden Fields (`check_hidden.py`)

Detects data in hidden fields on the current screen - **without** enabling "Hack Fields" mode in the GUI.

```bash
python check_hidden.py
```

**Expected output:**
```
Hidden Field Analysis
==================================================
Screen size: 1920 bytes
Hidden fields: 3
Fields with data: 1

Hidden field data found:
  - "Delete Order History"
```

This reveals a hidden "Delete Order History" option that isn't visible on the normal screen!

---

### Step 3: AID Scan (`aid_scan.py`)

Scans all AID keys to find hidden screens.

```bash
python aid_scan.py
```

**Expected output:**
```
AID Scanner
==================================================
Scanning AIDs for hidden screens...

*** NEW SCREEN: PA1 (1889 bytes, was 1567) ***
*** NEW SCREEN: PF3 (245 bytes, was 1567) ***

Scan complete. Found 2 screen changes.
```

- **PA1** triggers a hidden admin screen
- **PF3** is the exit function

**Run it again** from the hidden screen to find an easter egg:

```bash
python aid_scan.py
```

You'll discover additional hidden functionality!

---

### Step 4: Brute Force Supervisor Code

Two brute force scripts are provided:

#### `brute.py` - Database Template

Uses a captured packet from `dvca-brute.db` as a template. Requires capturing a screen with `****` mask.

```bash
python brute.py
```

#### `brute2.py` - Raw Packets (No Database)

Builds TN3270 packets programmatically with all form data defined in ASCII:

```python
FORM_FIELDS = [
    (bytes([0xC6, 0xE7]), 'Phillip Young', 44),
    (bytes([0xC9, 0xC7]), '101 Adelaide St W', 44),
    (bytes([0x4B, 0xE7]), 'Toronto', 44),
    (bytes([0x4E, 0xC7]), 'Ontario', 44),
    (bytes([0x50, 0xE7]), 'M5H 0B3', 44),
    (bytes([0xD3, 0xC7]), 'Canada', 44),
]
```

No database required - all data converted from ASCII to EBCDIC at runtime.

```bash
python brute2.py
```

**Expected output:**
```
Supervisor Code Brute Force (Raw Packets)
==================================================
Connected!

Loaded 50 codes to try

[10/50]
[20/50]
[30/50]
[40/50]

*** FOUND: 1337 ***
```

| Script | Database Required | Form Data |
|--------|-------------------|-----------|
| `brute.py` | Yes (`dvca-brute.db`) | From captured packet |
| `brute2.py` | No | Hardcoded in ASCII |

The supervisor code is **1337**.

---

## Database Files

Each script may use its own `.db` file to store captured traffic:

| Script | Database |
|--------|----------|
| `login.py` | `dvca-login.db` |
| `brute.py` | `dvca-brute.db` |

These contain pre-captured packets for replaying login sequences and injection templates.

---

## Summary

| Script | Purpose |
|--------|---------|
| `login.py` | Automated login (database replay) |
| `login2.py` | Automated login (raw packets, no database) |
| `login3.py` | Automated login with reconnect handling |
| `check_hidden.py` | Detect hidden field data |
| `aid_scan.py` | Find hidden screens via AID scanning |
| `brute.py` | Brute force supervisor code (database template) |
| `brute2.py` | Brute force supervisor code (raw packets) |

---

## Troubleshooting

**"Connection refused"** - Make sure hack3270 is running

**"Mask not found"** - The template log ID doesn't contain the mask character. Recapture while on the correct screen.

**"USERID DVCA IN USE"** - Use `login3.py` which handles reconnection, or restart the DVCA container for a fresh session.

**Scripts not finding library** - Run from the `API-DVCA-Code` directory, not the parent.
