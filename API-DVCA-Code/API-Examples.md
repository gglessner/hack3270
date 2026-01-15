# DVCA API Examples

This directory contains example scripts demonstrating the hack3270 Web API against the DVCA (Damn Vulnerable COBOL Application) mainframe.

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

### Step 1: Login (`login.py`)

Automates the login sequence and navigates to the MCGM main menu.

```bash
cd API-DVCA-Code
python login.py
```

**Expected output:**
```
DVCA Login Script
==================================================
Connecting...
Handling initial screen...
Logging in...
Navigating to MCGM menu...
Login complete! At Options menu.
```

Your terminal should now display the MCGM Options menu.

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

### Step 4: Brute Force Supervisor Code (`brute.py`)

First, set up the correct application state:

1. Exit the hidden screen (press PF3 or navigate back to Options menu)
2. Select **Option 2** - "Update Shipping Address"
3. Enter any invalid supervisor code (e.g., `0000`) to get to the code entry screen
4. **Capture the screen** in hack3270 - note the log ID with `****` mask

Then update `brute.py` if needed:
- Set `DB_FILE` to your database file
- Set `TEMPLATE_ID` to the log ID containing the `****` mask

Run the brute force:

```bash
python brute.py
```

**Expected output:**
```
Supervisor Code Brute Force
==================================================
Mask: 4 chars
Trying 50 codes...

[10/50]
[20/50]
[30/50]
[40/50]

*** FOUND: 1337 ***
```

The supervisor code is **1337**.

---

## Database Files

Each script may use its own `.db` file to store captured traffic:

| Script | Database |
|--------|----------|
| `login.py` | `dvca-login.db` |
| `login-reconnect.py` | `dvca-reconnect.db` |
| `brute.py` | `dvca-brute.db` |

These contain pre-captured packets for replaying login sequences and injection templates.

---

## Summary

| Script | Purpose |
|--------|---------|
| `login.py` | Automated login to MCGM menu |
| `login-reconnect.py` | Login with session reconnect handling |
| `check_hidden.py` | Detect hidden field data |
| `aid_scan.py` | Find hidden screens via AID scanning |
| `brute.py` | Brute force supervisor code |

---

## Troubleshooting

**"Connection refused"** - Make sure hack3270 is running

**"Mask not found"** - The template log ID doesn't contain the mask character. Recapture while on the correct screen.

**"USERID DVCA IN USE"** - Use `login-reconnect.py` instead, or restart the DVCA container.

**Scripts not finding library** - Run from the `API-DVCA-Code` directory, not the parent.
