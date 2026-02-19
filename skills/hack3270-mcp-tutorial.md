# hack3270 MCP Tutorial: A Complete Guide for AI Assistants

This document teaches you everything you need to know to operate the hack3270 MCP tools. Read this **before** reading any skill file. It assumes you know nothing about mainframes, TN3270, or hack3270.

---

## Table of Contents

1. [What is hack3270?](#1-what-is-hack3270)
2. [Your First Session](#2-your-first-session)
3. [Understanding Screens](#3-understanding-screens)
4. [Core Concepts](#4-core-concepts)
5. [Tool Reference](#5-tool-reference)
6. [Recipes & Common Patterns](#6-recipes--common-patterns)
7. [Gotchas & Troubleshooting](#7-gotchas--troubleshooting)
8. [TN3270 Protocol Cheat Sheet](#8-tn3270-protocol-cheat-sheet)

---

## 1. What is hack3270?

### Architecture

There are four components in the chain. You (the AI) are at one end, the mainframe is at the other:

```
You (AI)  <-->  MCP Server  <-->  hack3270 Proxy  <-->  Mainframe
              (Python)         (Python GUI app)       (IBM z/OS, MVS, etc.)
```

- **You** call MCP tools like `get_screen()` or `send_field_data()`.
- **The MCP server** (`hack3270_mcp.py`) translates your tool calls into hack3270 API calls over a local TCP socket.
- **The hack3270 proxy** is a GUI application that sits between a TN3270 terminal emulator and the mainframe. It intercepts, logs, and manipulates the TN3270 data stream. It also exposes a local API on port 31337 for the MCP server.
- **The mainframe** is the target system running CICS, TSO, VTAM, etc.

**Key point:** You never talk to the mainframe directly. You talk to the MCP server, which talks to the proxy, which talks to the mainframe. The proxy must be running and connected to a mainframe before you can do anything.

### What Gets Logged

The hack3270 proxy automatically logs every packet (both client-to-server and server-to-client) into a SQLite database file (`.db`). This is what your human means when they say "read the logs" or "check the session database." These are `.db` files in the project directory. If there are multiple `.db` files, the newest one is the current session unless the human says otherwise.

### The Human's View vs Your View

The human sees a graphical terminal emulator window showing the mainframe screen. You see the same screen data, but as text output from `get_screen()`. You both see the same content, but in different formats. The human can also toggle features like "Hack fields" in the GUI which changes what they see but does NOT affect what you receive -- you always get the raw data.

---

## 2. Your First Session

Here is exactly what a first session looks like, step by step.

### Step 1: Check connectivity

```
Tool: ping()
Expected output: "pong - API is responsive"
```

If you get an error like "Connection refused" or "No connection", the hack3270 proxy is not running. Tell the human: "The hack3270 proxy doesn't appear to be running. Please start it and connect to the mainframe first."

If you get a "broken pipe" or "connection reset" error, try:

```
Tool: reconnect_api()
```

### Step 2: Read the screen

```
Tool: get_screen()
```

This returns 24 lines of text, each 80 characters wide. This is exactly what the human sees on their terminal. Example output:

```
 1| MCGM     Mel's Cargo - Global Menu                         
 2|                                                              
 3|  Welcome to Mel's Cargo Management System                    
 4|                                                              
 5|  Select an option:                                           
 6|                                                              
 7|    1. Shipping Address Management                            
 8|    2. Order Management                                       
 9|    3. Account Settings                                       
10|    4. Reports                                                
11|                                                              
12|  Selection: _                                                
...
24| PF3=Exit                                                     
```

The line numbers on the left (` 1|`, ` 2|`, etc.) are added by the tool for your reference. They are NOT part of the screen.

### Step 3: Understand what you see

From this screen you can learn:
- **Transaction code**: `MCGM` (top-left, line 1) -- this is the CICS transaction that produced this screen
- **Application name**: "Mel's Cargo - Global Menu"
- **Menu options**: 1-4
- **Input field**: Somewhere around line 12, there's a field for typing a selection
- **PF key hints**: PF3 exits (line 24)

### Step 4: Discover the fields

```
Tool: analyze_screen_fields()
```

This tells you exactly where every field is, what type it is (input, protected, hidden), and what value it contains. Example output:

```
Field  0: Protected  addr=   1  len=4   value="MCGM"
Field  1: Protected  addr=  10  len=35  value="Mel's Cargo - Global Menu"
Field  2: Input      addr= 892  len=1   value=" "
```

**This is how you know where to type.** Field 2 is the input field at address 892. To select menu option 1, you would type "1" into address 892.

### Step 5: Send data to a field

```
Tool: send_field_data(text="1", field_address=892)
```

This types "1" into the field at address 892 AND presses ENTER. The mainframe processes this and sends back a new screen. The tool returns the new screen automatically.

### Step 6: Read the new screen

The `send_field_data` tool already returned the new screen, but if you need to re-read it:

```
Tool: get_screen()
```

### That's it. That's the basic loop.

Everything you do on a mainframe follows this pattern:
1. Read the screen (`get_screen`)
2. Find the fields (`analyze_screen_fields`)
3. Send data or press a key (`send_field_data`, `send_enter`, `send_aid_key`, etc.)
4. Read the new screen
5. Repeat

---

## 3. Understanding Screens

### Screen Geometry

A 3270 screen is always **24 rows x 80 columns = 1,920 positions**. Positions are numbered 0 to 1919, left-to-right, top-to-bottom:

```
Position 0 = row 0, col 0  (top-left)
Position 79 = row 0, col 79 (top-right)
Position 80 = row 1, col 0  (second row, leftmost)
Position 1919 = row 23, col 79 (bottom-right)
```

**Formula:** `position = (row * 80) + col` (0-indexed)

The tools `get_screen()` and `get_text_at()` use 1-indexed rows and columns (row 1 = top row). But field addresses from `analyze_screen_fields()` use 0-indexed buffer positions.

### What the Screen Rows Mean

Typical 3270 screen layout:

```
Row 1:  Transaction code + title (e.g., "MCGM  Mel's Cargo")
Row 2:  Blank or subtitle
Row 3-20: Application content (menus, forms, data)
Row 21-23: Messages, errors, status
Row 24: PF key hints (e.g., "PF3=Exit PF7=Back PF8=Forward")
```

This is a convention, not a rule. Every application is different.

### Types of Fields

There are three types of fields on a 3270 screen:

**1. Input fields** (unprotected) -- Where the user types. `analyze_screen_fields()` labels these as "Input". You send data to these with `send_field_data()`.

**2. Protected fields** -- Display-only fields like labels, titles, and data values. The terminal prevents the user from typing in them. BUT: `send_field_data()` and `send_raw_hex()` can write to them anyway because they bypass the terminal. This is the basis of protected field tampering attacks.

**3. Hidden fields** -- Fields with a non-display attribute. They contain data that is sent to/from the mainframe but is invisible on the terminal screen. Use `get_hidden_fields()` or `analyze_hidden()` to find them. Hidden fields often contain secret menu options, status flags, debug data, or internal IDs.

### How to Tell If a Screen Is Formatted or Unformatted

This is **critical**. Using the wrong send function causes APCT abend errors.

**Formatted screen:** Has fields (input boxes, labels, protected areas). Most application screens are formatted. `analyze_screen_fields()` returns one or more fields.

**Unformatted screen:** No fields at all. Just a blank screen, maybe with a cursor. You see this after pressing CLEAR, or at some command-line prompts (like TSO's `READY` prompt). `analyze_screen_fields()` returns zero fields or an error.

**Rules:**
- Formatted screen → use `send_field_data()` to type into fields
- Unformatted screen → use `send_command()` to type text at the cursor position
- If you use `send_command()` on a formatted screen, it may work but is unreliable
- If you use `send_field_data()` on an unformatted screen, it will fail or cause APCT abends

**How to check:** Call `analyze_screen_fields()`. If it returns fields, the screen is formatted. If it returns nothing or an error, the screen is unformatted.

---

## 4. Core Concepts

### EBCDIC

Mainframes use EBCDIC character encoding, not ASCII. The MCP tools handle conversion automatically for you:
- `send_field_data(text="HELLO")` converts "HELLO" to EBCDIC internally
- `get_screen()` converts the screen from EBCDIC to ASCII for you
- You only need manual conversion (`convert_ascii_to_ebcdic`, `convert_ebcdic_to_ascii`) when building raw packets with `send_raw_hex()`

### AID Keys (Attention Identifier Keys)

An AID key is a special key that tells the mainframe "the user pressed something." Every interaction with the mainframe starts with an AID key. The most common ones:

- **ENTER** (`0x7D`) -- Submit. Used 90% of the time. `send_enter()` or `send_field_data()` sends this automatically.
- **PF1-PF24** -- Program Function keys. Used for navigation (PF3 = Exit, PF7/PF8 = scroll, etc.). Use `send_pf_key(3)` or `send_aid_key("PF3")`.
- **PA1-PA3** (`0x6C`, `0x6E`, `0x6B`) -- Program Attention keys. These are special: they send ONLY the key press, NO field data. Developers sometimes hide secret functions behind PA keys because normal users never press them. Always test PA1, PA2, PA3 on every screen.
- **CLEAR** (`0x6D`) -- Clears the screen and resets to an unformatted state. Use `send_clear()`. After CLEAR, the screen is unformatted, so use `send_command()` to type.
- **SYSREQ** (`0xF0`) -- System Request key. Rarely used but can access system functions.

### Transaction Codes

A CICS transaction code is a 1-4 character identifier that launches a program. Examples: `MCGM`, `CESN`, `CEMT`. To invoke a transaction:

1. Press CLEAR (screen becomes unformatted)
2. Type the transaction code using `send_command("MCGM")`
3. The mainframe launches the program and sends back a formatted screen

You can also type a transaction code into an input field on some screens -- this depends on the application.

### Abend Codes

An "abend" (abnormal end) is a mainframe crash. If you cause one, the screen shows an error message with a code. Common codes:

- **APCT** -- "Program not found." You tried to run a transaction that doesn't exist. Low severity. Usually means you typed a wrong name, or you used `send_command` with SBA on an unformatted screen (corrupting the transaction name).
- **ASRA** -- Program crash (data exception, memory fault, etc.). **Critical finding.** The program doesn't validate input properly. **Stop testing that payload immediately.**
- **SOC7/S0C7** -- Bad decimal data. The program expected a number and got something else. **Critical finding.** Stop and document.
- **SOC4/S0C4** -- Memory protection exception. Possible buffer overflow. **Critical finding.** Stop and document.
- **AICA** -- Runaway task (infinite loop). **Critical.** Stop immediately.

Use `check_abend()` after any send operation to detect abends.

---

## 5. Tool Reference

This section documents every MCP tool. For each tool: what it does, when to use it, example call, and common mistakes.

### 5.1 Connection Tools

#### `connect_api(host="127.0.0.1", port=31337)`

**What:** Establishes a connection from the MCP server to the hack3270 proxy. You usually don't need to call this -- the other tools auto-connect.

**When to use:** Only if you need to connect to a non-default host/port.

**Example:**
```
connect_api()                          # Default: localhost:31337
connect_api(host="192.168.1.5", port=31337)  # Remote proxy
```

**Note:** This connects to the hack3270 PROXY, not to the mainframe. The proxy must already be connected to the mainframe.

#### `disconnect_api()`

**What:** Disconnects the MCP server from the hack3270 proxy.

**When to use:** When you're completely done and want to clean up. Rarely needed.

#### `ping()`

**What:** Tests if the hack3270 proxy is reachable. Returns "pong" if connected.

**When to use:** First thing in any session. Also use to check if the connection is still alive after a period of inactivity.

**Example:**
```
ping()
# Success: "pong - API is responsive"
# Failure: error about connection refused or broken pipe
```

#### `reconnect_api()`

**What:** Drops the existing connection and establishes a new one.

**When to use:** After the hack3270 proxy has been restarted, or if you get "broken pipe" errors. The MCP server tries to auto-reconnect, but if that fails, call this explicitly.

#### `check_connection()`

**What:** Returns detailed connection status including protocol mode (TN3270 vs TN3270E).

**When to use:** Debugging connection issues. Shows whether you're connected, what protocol mode is active, and if the mainframe is responsive.

#### `test_mainframe_connection()`

**What:** Sends ENTER to the mainframe and checks for a response. **This actually sends a keystroke!**

**When to use:** To verify the mainframe is responsive (not just the proxy). Be aware this presses ENTER on whatever screen is currently displayed, which may have side effects (submitting a form, advancing past a screen, etc.).

**Common mistake:** Calling this when you're on a form with data filled in -- it will submit the form.

---

### 5.2 Screen Reading Tools

#### `get_screen()`

**What:** Returns the current mainframe screen as 24 lines of ASCII text, each 80 characters wide. Lines are numbered for your reference.

**When to use:** After every send operation. This is your eyes. Call it frequently.

**Example output:**
```
 1| MCGM     Mel's Cargo - Global Menu                          
 2|                                                              
 3|  Select an option:                                           
...
24| PF3=Exit                                                     
```

**The line numbers (` 1|`, ` 2|`) are NOT part of the screen.** They are added by the tool for reference.

**Common mistake:** Not calling this after sending data. You sent something but don't know what happened because you didn't read the result.

#### `get_screen_raw()`

**What:** Returns the raw server response with control code markers like `[0x11]`, `[0x1D]` visible as text.

**When to use:** When you need to see the raw 3270 data stream but still want it somewhat readable. Useful for understanding field boundaries and control codes.

**You probably don't need this.** Use `get_screen()` for normal reading and `analyze_screen_fields()` for field analysis. Only use `get_screen_raw()` if you need to debug protocol issues.

#### `get_screen_raw_hex()`

**What:** Returns the raw TN3270 data stream as hex bytes.

**When to use:** Building raw packets, debugging protocol issues, or comparing packet structures. Advanced use only.

**Common mistake:** Trying to read this as text. It's hex bytes like `f5c3114040...`. Use `get_screen()` instead if you want readable text.

#### `find_text(pattern)`

**What:** Searches the current screen for text using exact match or regex. Returns the row, column, and matched text.

**When to use:** Checking if specific text is on the screen (error messages, menu items, labels).

**Example:**
```
find_text("INVALID")           # Exact match
find_text("PF[0-9]+=")         # Regex: find PF key hints
find_text("Error.*")           # Regex: find error messages
```

**Tip:** Use this to check for abend messages, error text, or to verify navigation worked.

#### `find_field_value(label)`

**What:** Finds a field's value by searching for its label on screen. Looks for patterns like "Label: value" or "Label . . . value".

**When to use:** Quick way to read a specific labeled value without analyzing all fields.

**Example:**
```
find_field_value("Account")    # Finds "Account: 12345" and returns "12345"
find_field_value("Balance")    # Finds "Balance . . . $1,234.56"
```

#### `get_text_at(row, col, length=0)`

**What:** Gets text at a specific screen position. Row and column are 1-indexed.

**When to use:** Reading a specific part of the screen when you know exactly where it is.

**Example:**
```
get_text_at(1, 1, 4)    # Get first 4 characters of row 1 (transaction code)
get_text_at(24, 1, 80)  # Get entire bottom row (PF key hints)
```

**If `length` is 0**, it returns text from that position to the end of the line.

---

### 5.3 Field Analysis Tools

#### `analyze_screen_fields()`

**What:** The most important analysis tool. Parses the current screen and returns every field with its buffer address, type (Input/Protected/Hidden), length, and current value.

**When to use:** On EVERY new screen. This is how you discover where to type, what data is displayed, and what might be hidden.

**Example output:**
```
=== Screen Field Analysis ===
Total fields: 8

Field  0: Protected  addr=   1  len=4   value="MCGM"
Field  1: Protected  addr=  10  len=35  value="Mel's Cargo - Global Menu"
Field  2: Protected  addr= 161  len=20  value="Select an option:"
Field  3: Input      addr= 892  len=1   value=" "
Field  4: Hidden     addr= 900  len=3   value="ADM"
...
```

**Key information in the output:**
- `addr` = buffer address. This is what you pass to `send_field_data(field_address=...)`.
- `Input` = you can type here
- `Protected` = display-only (but you CAN write to it with `send_field_data` for tampering)
- `Hidden` = invisible on screen but contains data

**Common mistake:** Not calling this on every new screen. You cannot send field data if you don't know the field addresses.

#### `get_input_fields()`

**What:** Returns only the editable (unprotected) input fields. A filtered view of `analyze_screen_fields()`.

**When to use:** When you only care about where you can type. Faster than parsing the full field analysis.

#### `get_hidden_fields()`

**What:** Returns hidden (non-display) fields. These are fields the user cannot see on the terminal.

**When to use:** On every screen during pen testing. Hidden fields often contain:
- Secret menu options (e.g., a hidden "5" option for admin access)
- Status flags (e.g., "Purchaseable: Y")
- Internal IDs, debug data, authorization tokens
- The current transaction routing code

#### `analyze_hidden()`

**What:** Server-side deep analysis of hidden fields, performed by the hack3270 proxy itself. May detect fields that client-side parsing misses.

**When to use:** After `get_hidden_fields()` if you want a second opinion, or if you suspect there are hidden fields that the client-side parser missed.

#### `check_abend()`

**What:** Checks the current screen for abend (crash) indicators. Looks for codes like DFHAC2, ASRA, AICA, SOC7, APCT, etc.

**When to use:** After EVERY send operation that might cause a crash (fuzzing, sending unusual data, testing new transactions). Returns the abend code if found, or empty/null if no abend.

**Example:**
```
check_abend()
# Abend: "ASRA" -- stop testing immediately
# No abend: "" or "No abend detected"
```

---

### 5.4 Sending Data Tools

This is the most important section. Getting this wrong causes errors and abends.

#### Decision Tree: Which Send Tool Do I Use?

Ask yourself these questions in order:

**Q1: Is the screen formatted (has fields) or unformatted (blank/after CLEAR)?**
- Unformatted → use `send_command()`
- Formatted → continue to Q2

**Q2: Do I want to type into one field?**
- Yes → use `send_field_data()`

**Q3: Do I want to type into multiple fields at once?**
- Yes → use `send_fields_data()`

**Q4: Do I just want to press a key without typing anything?**
- ENTER → `send_enter()`
- PF key → `send_pf_key(number)` or `send_aid_key("PF3")`
- CLEAR → `send_clear()`
- PA key → `send_aid_key("PA1")` (etc.)
- Any AID → `send_aid_key("key_name")`

**Q5: Do I need full control over the raw packet?**
- I have ASCII text → `build_and_send_packet()`
- I have raw hex bytes → `send_raw_hex()`

#### `send_enter()`

**What:** Presses ENTER on the current screen. Does not send any field data -- just the keystroke.

**When to use:** When the screen has data already filled in (by a previous operation or by the mainframe) and you just want to submit it.

**Example:** After navigating to a screen that says "Press ENTER to continue":
```
send_enter()
```

**Returns:** The new screen content.

#### `send_aid_key(key)`

**What:** Sends any AID key. The `key` parameter is a string like "ENTER", "PF3", "PA1", "CLEAR", etc. Or a hex value like "0x7D".

**When to use:** When you want to press any special key.

**Example:**
```
send_aid_key("PF3")    # Exit / go back
send_aid_key("PA1")    # Program Attention 1 (test for hidden function)
send_aid_key("PA3")    # Program Attention 3 (test for hidden function)
send_aid_key("CLEAR")  # Clear screen
send_aid_key("PF7")    # Scroll up / page back
send_aid_key("PF8")    # Scroll down / page forward
```

**Returns:** The new screen content.

#### `send_pf_key(number)`

**What:** Shorthand for `send_aid_key("PFn")`. Takes an integer 1-24.

**Example:**
```
send_pf_key(3)     # Same as send_aid_key("PF3")
send_pf_key(12)    # Same as send_aid_key("PF12")
```

#### `send_clear()`

**What:** Sends the CLEAR key. This resets the screen to an unformatted state.

**When to use:** Before entering a transaction code. The standard way to invoke a CICS transaction is: CLEAR, then type the transaction code on the blank screen.

**IMPORTANT:** After CLEAR, the screen is **unformatted**. Use `send_command()` to type, NOT `send_field_data()`.

#### `send_command(text, cursor_row=0, cursor_col=0)`

**What:** Sends text on an **unformatted** screen. Converts the text to EBCDIC and sends it with ENTER.

**When to use:**
- After CLEAR, to enter a transaction code
- On command-line screens like TSO's `READY` prompt
- Any screen with no fields

**Example:**
```
send_command("MCGM")    # Enter the MCGM transaction
send_command("TIME")    # TSO command
send_command("LOGOFF")  # TSO logoff
```

**CRITICAL: Do NOT use this on formatted screens.** It sends the data WITHOUT an SBA (Set Buffer Address) order, which means the mainframe doesn't know which field to put the data in. On a formatted screen, this corrupts the data stream and causes APCT abends.

**Common mistake:** Using `send_command` to type into a form field. Use `send_field_data` instead.

#### `send_field_data(text, field_address, cursor_address=-1, add_space=False, aid="ENTER")`

**What:** Types text into a specific field on a formatted screen and submits it.

**When to use:** Whenever you want to type into a field on a formatted screen. This is the tool you'll use most often.

**Parameters:**
- `text` -- The ASCII text to type (automatically converted to EBCDIC)
- `field_address` -- The buffer address of the field (get this from `analyze_screen_fields()`)
- `cursor_address` -- Where to place the cursor (-1 = same as field_address, which is usually what you want)
- `add_space` -- Add a trailing space after the text (helps clear leftover characters from a previous value)
- `aid` -- Which key to "press" after typing. Default is "ENTER". Can be any AID key name: "PF1"-"PF24", "PA1"-"PA3", "CLEAR", etc.

**Examples:**
```
# Type "1" into the menu selection field and press ENTER
send_field_data(text="1", field_address=892)

# Type a password and press ENTER
send_field_data(text="secret123", field_address=200, add_space=True)

# Type a value and press PF5 instead of ENTER
send_field_data(text="SEARCH", field_address=160, aid="PF5")

# Tamper with a protected field (price)
send_field_data(text="0.01", field_address=340)
```

**The `aid` parameter is important.** Some screens process data differently depending on which key you press. For example, a search screen might require PF5 to search, not ENTER.

**Returns:** The new screen content after the mainframe processes the input.

**Common mistakes:**
- Using a wrong `field_address`. Always call `analyze_screen_fields()` first.
- Using this on an unformatted screen. Use `send_command()` instead.
- Forgetting `add_space=True` when the field previously had a longer value (leftover characters remain).

#### `send_fields_data(fields_json, aid="ENTER")`

**What:** Types into multiple fields at once and submits with a single keystroke. Instead of calling `send_field_data` three times (which presses ENTER three times), this fills all fields and presses ENTER once.

**When to use:** Forms with multiple fields (login screens with username + password, search forms with multiple criteria, etc.)

**Parameters:**
- `fields_json` -- A JSON string containing an array of objects. Each object has `address` (int) and `text` (str).
- `aid` -- Which key to press after filling all fields. Default: "ENTER".

**Examples:**
```
# Login form: username at address 200, password at address 280
send_fields_data(
  fields_json='[{"address": 200, "text": "admin"}, {"address": 280, "text": "password123"}]'
)

# Fill a search form and press PF5 to search
send_fields_data(
  fields_json='[{"address": 100, "text": "SMITH"}, {"address": 200, "text": "NEW YORK"}]',
  aid="PF5"
)
```

**Why use this instead of multiple `send_field_data` calls?** Because `send_field_data` presses ENTER (or the specified AID) after every call. If you call it twice, you press ENTER twice. For a login form, the first ENTER would submit with only the username filled in, which fails. `send_fields_data` fills everything first, then presses ENTER once.

#### `send_raw_hex(hex_data, description="MCP: Send raw hex")`

**What:** Sends raw bytes directly to the mainframe. No conversion, no formatting. You provide the complete packet as a hex string.

**When to use:** Advanced protocol manipulation. Building custom packets for specific attacks. You must construct the entire TN3270 packet yourself, including TN3270E headers (if applicable), AID byte, cursor address, SBA orders, EBCDIC data, and IAC+EOR terminator.

**Example:**
```
# Send a raw ENTER keystroke (TN3270 mode)
send_raw_hex("7D4040FFEF", description="Raw ENTER key")
```

**You probably don't need this.** Use `send_field_data`, `send_fields_data`, or `build_and_send_packet` instead. Only use `send_raw_hex` when you need exact byte-level control.

#### `build_and_send_packet(text, field_position=-1, cursor_position=0, aid="ENTER")`

**What:** Builds a proper TN3270 packet from components and sends it. Handles TN3270E headers and EBCDIC conversion automatically.

**When to use:** When you need more control than `send_field_data` but don't want to construct raw hex. For example, sending data with SBA to an arbitrary position with a specific AID key.

**Parameters:**
- `text` -- ASCII text (will be converted to EBCDIC)
- `field_position` -- Buffer position for the SBA order (-1 = no SBA, meaning unformatted mode)
- `cursor_position` -- Buffer position for the cursor
- `aid` -- AID key name or hex value

**Examples:**
```
# Send "MCGM" on an unformatted screen (no SBA)
build_and_send_packet(text="MCGM", field_position=-1, cursor_position=0, aid="ENTER")

# Send "ADMIN" to field at position 200
build_and_send_packet(text="ADMIN", field_position=200, cursor_position=200, aid="ENTER")
```

---

### 5.5 Waiting Tools

#### `wait_for_text(pattern, timeout=10.0)`

**What:** Polls the screen repeatedly until the specified text appears or the timeout expires.

**When to use:** When you expect the mainframe to take time to process something. For example, after submitting a long-running query, waiting for "READY" to appear.

**Example:**
```
wait_for_text("READY", timeout=15.0)
wait_for_text("Complete", timeout=30.0)
```

#### `wait_for_screen_change(timeout=10.0)`

**What:** Waits until the screen changes from its current state.

**When to use:** After sending a command when you're not sure what text to look for. It waits for ANY change.

---

### 5.6 Session Database Tools

The hack3270 proxy logs every packet to a SQLite `.db` file. These tools let you analyze captured session data.

**When your human says "read the logs" or "check the session database," this is what they mean.** Follow these steps:

1. Use `list_databases()` to find available `.db` files
2. Pick the newest one (or the one the human specifies)
3. Use `load_database(filename)` to open it
4. Use `get_logs()` to browse entries

#### `list_databases()`

**What:** Lists all `.db` files in the hack3270 directory.

**Example output:**
```
Available databases:
  session_20260213_141523.db  (2.1 MB, modified 2026-02-13 14:23:00)
  session_20260212_091000.db  (1.4 MB, modified 2026-02-12 11:45:00)
```

**If there are multiple files**, the newest one is the current session unless the human tells you otherwise.

#### `load_database(filename)`

**What:** Opens a session database file for analysis.

**Example:**
```
load_database("session_20260213_141523.db")
```

#### `close_database()`

**What:** Closes the currently loaded database. Call before loading a different one.

#### `get_logs(direction="", limit=50)`

**What:** Returns log entries from the loaded database. Each entry has an ID, timestamp, direction, notes, and data length.

**Parameters:**
- `direction` -- Filter by direction: `"C"` for client-to-server (what was sent), `"S"` for server-to-client (what was received), or `""` for both
- `limit` -- Maximum entries to return

**Example:**
```
get_logs(direction="C", limit=20)    # Show last 20 client packets
get_logs()                           # Show last 50 entries (both directions)
```

#### `get_log_entry(log_id)`

**What:** Gets full details of a specific log entry, including raw hex data and ASCII interpretation.

**When to use:** To examine a specific packet in detail. Use the ID from `get_logs()`.

#### `replay_client_data(log_id)`

**What:** Resends a previously captured client packet to the mainframe. Sends the exact same bytes.

**When to use:** Replaying a specific action (e.g., re-sending a login packet, replaying a transaction).

#### `replay_sequence(log_ids, delay=0.5)`

**What:** Replays multiple packets in sequence with a delay between each.

**Parameters:**
- `log_ids` -- Comma-separated string of log IDs: `"5,6,7,8"`
- `delay` -- Seconds between each replay

**Example:**
```
replay_sequence("10,12,14,16", delay=1.0)   # Replay a login sequence
```

---

### 5.7 Attack & Fuzzing Tools

#### `list_wordlists()`

**What:** Lists wordlist files available in the `injections/` directory. These contain values for brute forcing and fuzzing.

**Common wordlists:**
- `numeric-4.txt` -- All 4-digit PINs (0000-9999)
- `pin-common.txt` -- Most common PINs
- `default-passwords.txt` -- Common default passwords
- `common-userids.txt` -- Common usernames
- `cics-default-transactions.txt` -- Known CICS transaction codes
- `sql-injection.txt` -- SQL injection payloads

#### `load_wordlist(filename)`

**What:** Loads and previews a wordlist. Shows the first and last entries plus total count.

#### `get_wordlist_contents(filename, start=1, count=50)`

**What:** Reads entries from a wordlist with pagination. `start` is 1-indexed.

**Example:**
```
get_wordlist_contents("numeric-4.txt", start=1, count=20)   # First 20 PINs
```

#### `setup_injection(log_id, mask="*")`

**What:** Creates an injection template from a captured packet. It finds the mask character in the packet and splits it into a preamble (before the mask) and postamble (after the mask), allowing you to inject arbitrary values at that position.

**How it works:**
1. First, send a packet with a marker value (e.g., type `*` into a field)
2. That packet gets logged to the database with a log ID
3. Call `setup_injection(log_id=that_id, mask="*")` to create a template
4. Now you can inject values at that position using `inject_value()` or `brute_force_field()`

**Example workflow:**
```
# Step 1: Type "*" into the PIN field
send_field_data(text="*", field_address=200)

# Step 2: Find the log entry ID for that packet
get_logs(direction="C", limit=5)
# Let's say the log ID is 42

# Step 3: Set up injection at the "*" position
setup_injection(log_id=42, mask="*")

# Step 4: Now brute force
brute_force_field(wordlist="numeric-4.txt", log_id=42, mask="*", fail_pattern="INVALID")
```

#### `inject_value(value, log_id=-1, mask="*", mode="TRUNC")`

**What:** Injects a single value into the injection template and sends the packet.

**Parameters:**
- `value` -- The value to inject
- `log_id` -- The captured packet to use as template (-1 = use the last setup)
- `mask` -- The character to replace
- `mode` -- `"TRUNC"` truncates to field length, `"PAD"` pads with spaces

#### `brute_force_field(wordlist, log_id=-1, mask="*", mode="TRUNC", fail_pattern="", success_pattern="", max_attempts=0, delay=0.2)`

**What:** Iterates through a wordlist, injecting each value and checking the response.

**Parameters:**
- `wordlist` -- Wordlist filename (from `injections/` directory)
- `fail_pattern` -- Text that indicates failure (e.g., "INVALID", "INCORRECT"). The tool skips these responses.
- `success_pattern` -- Text that indicates success (e.g., "WELCOME", "AUTHORIZED"). The tool stops when found.
- `max_attempts` -- Stop after this many attempts (0 = try all)
- `delay` -- Seconds between attempts

**Example:**
```
brute_force_field(
    wordlist="numeric-4.txt",
    log_id=42,
    mask="*",
    fail_pattern="INVALID PIN",
    delay=1.0
)
```

#### `scan_aid_keys(keys="PF1,...,PA3,CLEAR", delay=0.5)`

**What:** Tests each AID key on the current screen and compares responses to a baseline. Identifies keys that produce unique/different responses.

**When to use:** Discovering hidden functions on a screen.

**Limitation:** If a key (like PF3) exits the application, all subsequent keys are tested on the wrong screen. For this reason, consider testing PA keys and CLEAR separately/manually.

**Example:**
```
scan_aid_keys()                                  # Test all default keys
scan_aid_keys(keys="PA1,PA2,PA3", delay=1.0)     # Test only PA keys
scan_aid_keys(keys="PF13,PF14,PF15,PF16,PF17,PF18,PF19,PF20,PF21,PF22,PF23,PF24")  # High PF keys
```

#### `fuzz_field(field_address, payloads="overflow,decimal,control,sql,cics", cursor_address=-1, delay=0.3)`

**What:** Sends various malicious/edge-case payloads to a specific input field.

**Parameters:**
- `field_address` -- The field to fuzz (from `analyze_screen_fields()`)
- `payloads` -- Comma-separated categories to test:
  - `overflow` -- Long strings that exceed field length (CAUTION: may crash the region)
  - `decimal` -- Numeric edge cases (negative, zero, max values)
  - `control` -- Control characters and special bytes
  - `sql` -- SQL injection payloads
  - `cics` -- CICS-specific attack strings

**Example:**
```
fuzz_field(field_address=892, payloads="decimal,sql")    # Safe fuzzing
fuzz_field(field_address=892, payloads="overflow")       # Dangerous - may crash
```

#### `fuzz_all_input_fields(payloads="overflow,decimal,control,sql", delay=0.3)`

**What:** Discovers all input fields on the current screen and fuzzes each one.

**When to use:** Quick broad fuzzing of all inputs.

#### `fuzz_transaction_codes(wordlist="cics-default-transactions.txt", delay=0.3, max_codes=0, clear_between=True)`

**What:** Tries transaction codes from a wordlist, looking for ones that produce unique (non-error) responses.

**When to use:** Discovering which CICS transactions are available.

---

### 5.8 Utility Tools

#### `convert_ascii_to_ebcdic(text)`

**What:** Converts ASCII text to EBCDIC hex bytes. Shows you what the text looks like on the wire.

**When to use:** Building raw packets, understanding protocol encoding.

**Example:**
```
convert_ascii_to_ebcdic("HELLO")   # Returns "C8C5D3D3D6"
```

#### `convert_ebcdic_to_ascii(hex_data)`

**What:** Converts EBCDIC hex bytes back to ASCII text.

**Example:**
```
convert_ebcdic_to_ascii("C8C5D3D3D6")   # Returns "HELLO"
```

#### `encode_buffer_address(position)`

**What:** Converts a screen position (0-1919) to the 2-byte 12-bit buffer address used in 3270 packets.

**Example:**
```
encode_buffer_address(0)     # Returns "40 40" (position 0)
encode_buffer_address(80)    # Returns "C1 50" (row 1, col 0)
```

#### `decode_buffer_address(byte1, byte2)`

**What:** Converts a 2-byte buffer address back to a screen position.

**Example:**
```
decode_buffer_address(0xC1, 0x50)   # Returns position 80 (row 1, col 0)
```

---

### 5.9 Recording & Playback Tools

#### `start_recording()`

**What:** Starts recording all send operations for later playback. Every `send_aid`, `send_raw`, and replay operation is captured.

**When to use:** When you want to build a replayable sequence (e.g., record a login flow to replay later).

#### `stop_recording()`

**What:** Stops recording and returns the list of recorded actions.

#### `playback_recording(delay=0.5, repeat=1)`

**What:** Replays the last recorded sequence.

**Parameters:**
- `delay` -- Seconds between each action
- `repeat` -- Number of times to repeat the entire sequence

---

### 5.10 Protocol Info

#### `get_protocol_info()`

**What:** Returns protocol details about the current connection: TN3270 vs TN3270E mode, screen dimensions, AID keys seen on the current screen, and protocol constants.

**When to use:** When you need to know if you're in TN3270 or TN3270E mode (this affects packet headers). Also useful for seeing protocol constants and reference values.

---

## 6. Recipes & Common Patterns

### Recipe: Navigate to a Transaction

```
# Step 1: Clear the screen
send_clear()

# Step 2: Type the transaction code (screen is now unformatted)
send_command("MCGM")

# Step 3: Read the new screen
get_screen()
```

### Recipe: Fill Out a Single-Field Form

```
# Step 1: Read the screen to see what's there
get_screen()

# Step 2: Find the input field address
analyze_screen_fields()
# Output shows: Field 2: Input addr=892 len=1

# Step 3: Type the value and press ENTER
send_field_data(text="1", field_address=892)
```

### Recipe: Fill Out a Multi-Field Form (e.g., Login)

```
# Step 1: Read the screen
get_screen()

# Step 2: Find the field addresses
analyze_screen_fields()
# Output shows: 
#   Field 3: Input addr=200 len=8 (username)
#   Field 5: Input addr=280 len=8 (password)

# Step 3: Fill both fields and submit once
send_fields_data(
  fields_json='[{"address": 200, "text": "admin"}, {"address": 280, "text": "secret"}]'
)
```

### Recipe: Explore a Menu System

```
# Step 1: Map the main menu
get_screen()
analyze_screen_fields()
get_hidden_fields()

# Step 2: Try each visible menu option
send_field_data(text="1", field_address=892)
# Record what screen option 1 goes to
get_screen()
analyze_screen_fields()
# Go back
send_pf_key(3)    # PF3 usually goes back

# Repeat for option 2, 3, etc.
send_field_data(text="2", field_address=892)
# ...and so on
```

### Recipe: Check for Hidden Fields on Every Screen

```
# Always do these three together on each screen:
get_screen()
analyze_screen_fields()
get_hidden_fields()

# If hidden fields show interesting values (like "5" or "ADM"):
# Try entering them into the input field
send_field_data(text="5", field_address=892)
```

### Recipe: Test PA Keys (Hidden Functions)

```
# On each screen, manually test PA keys:
send_aid_key("PA1")
get_screen()    # Did the screen change? Document what you see.

# Go back if it changed
send_pf_key(3)

send_aid_key("PA2")
get_screen()

send_pf_key(3)

send_aid_key("PA3")
get_screen()
```

### Recipe: Read the Session Logs

This is what to do when the human says "read the logs" or "check the database":

```
# Step 1: Find the database files
list_databases()

# Step 2: Load the most recent one
load_database("session_20260213_141523.db")

# Step 3: Browse the log entries
get_logs(limit=50)

# Step 4: Look at specific entries for details
get_log_entry(42)

# Step 5: When done
close_database()
```

### Recipe: Send Data with a PF Key Instead of ENTER

```
# Some screens require a specific PF key to process input.
# For example, a search screen might need PF5:
send_field_data(text="SMITH", field_address=160, aid="PF5")

# Or a save screen might need PF2:
send_field_data(text="new value", field_address=200, aid="PF2")
```

### Recipe: Recover from an Abend

```
# Step 1: Read the abend screen
get_screen()
check_abend()
# Output: "ASRA"

# Step 2: Document what caused it (the last thing you sent)

# Step 3: Press CLEAR to dismiss the abend
send_clear()

# Step 4: Re-enter the application
send_command("MCGM")

# Step 5: Verify the application is working
get_screen()
```

### Recipe: Brute Force a PIN Field

```
# Step 1: Navigate to the screen with the PIN field
# Step 2: Find the PIN field address
analyze_screen_fields()
# Field 4: Input addr=350 len=4

# Step 3: Type a marker character
send_field_data(text="*", field_address=350)

# Step 4: Find the log entry for that packet
get_logs(direction="C", limit=5)
# Log ID 42 is the one with our "*"

# Step 5: Set up injection
setup_injection(log_id=42, mask="*")

# Step 6: Check available wordlists
list_wordlists()

# Step 7: Brute force
brute_force_field(
    wordlist="numeric-4.txt",
    log_id=42,
    mask="*",
    fail_pattern="INVALID",
    delay=1.0
)
```

### Recipe: Tamper with a Protected Field

```
# Step 1: Find protected fields with interesting data
analyze_screen_fields()
# Field 6: Protected addr=340 len=8 value="$100.00"

# Step 2: Send a new value to that protected field address
# The terminal normally prevents this, but send_field_data bypasses it
send_field_data(text="$0.01", field_address=340)

# Step 3: Check if the server accepted the tampered value
get_screen()
```

---

## 7. Gotchas & Troubleshooting

### "I got an APCT abend"

**Cause:** You used `send_command()` on a formatted screen, or the transaction code was wrong.

**Fix:** Use `send_field_data()` on formatted screens. Use `send_command()` only on unformatted screens (after CLEAR). Check that the transaction code is spelled correctly.

**How to recover:** Press CLEAR (`send_clear()`), then re-enter your transaction (`send_command("MCGM")`).

### "The screen didn't change after I sent something"

**Possible causes:**
1. The mainframe is slow. Try `wait_for_screen_change(timeout=10.0)`.
2. The input was rejected silently. Check the bottom of the screen for error messages: `find_text("Error")` or `find_text("Invalid")`.
3. The field data was ignored. Verify you sent to the correct field address.
4. The AID key was wrong. Some screens only respond to specific keys (e.g., PF5 for search, not ENTER).

### "I see garbage characters or hex"

**You're probably using the wrong screen reading tool.**
- `get_screen()` -- returns readable ASCII text (USE THIS)
- `get_screen_raw()` -- returns ASCII with control code markers (for debugging)
- `get_screen_raw_hex()` -- returns raw hex bytes (for protocol analysis)

If you want to read what's on the screen, use `get_screen()`.

### "I don't know which field to type into"

Call `analyze_screen_fields()`. Look for fields marked as "Input". The `addr` value is what you pass to `send_field_data(field_address=...)`.

If there are no Input fields, the screen might be:
- A display-only screen (just press ENTER or a PF key to continue)
- An unformatted screen (use `send_command()` instead)

### "My field data is being truncated or has leftover characters"

**Truncation:** The field has a maximum length. Your text is being cut to fit. This is normal.

**Leftover characters:** If you previously typed "HELLO" (5 chars) and now type "HI" (2 chars), the field shows "HIllo" because the old characters weren't cleared. Fix: use `add_space=True` to pad with spaces, or send the full field length of data.

### "The human said 'read the logs' but I don't see any log files"

The human means the hack3270 session database (`.db` files). Use `list_databases()` to find them. Then `load_database("filename.db")` and `get_logs()`. See the "Read the Session Logs" recipe above.

### "I got a broken pipe / connection reset error"

The hack3270 proxy was restarted or lost connection. Try:
```
reconnect_api()
```
If that fails, tell the human to restart the hack3270 proxy and reconnect to the mainframe.

### "Multiple .db files -- which one do I use?"

Use the newest one (most recent modification time). `list_databases()` shows timestamps. If the human wants a specific one, they'll tell you.

### "The hack3270 proxy is not running"

You cannot do anything without the proxy. Tell the human: "The hack3270 proxy doesn't appear to be running. Please start it and connect to the mainframe first, then I can interact with the terminal."

### "PF3 exited the application and now I'm on a blank screen"

PF3 commonly means "Exit." You left the application. Re-enter via:
```
send_clear()
send_command("MCGM")   # Replace with your entry-point transaction
```

### "I used send_command but got a weird error or wrong screen"

Most likely the screen was formatted (had fields) and you should have used `send_field_data()` instead. Check with `analyze_screen_fields()` -- if it returns fields, the screen is formatted.

### "The scan_aid_keys tool gave weird results"

`scan_aid_keys()` takes a baseline snapshot, then sends each key and compares. If one of the early keys (like PF3) exits the application, all subsequent keys are tested on the wrong screen. Test PA keys separately:
```
scan_aid_keys(keys="PA1,PA2,PA3")
```

Then test PF keys in small batches, avoiding PF3 until last.

---

## 8. TN3270 Protocol Cheat Sheet

### Screen Geometry

- 24 rows x 80 columns = 1,920 buffer positions
- Position = (row * 80) + col, 0-indexed
- Position 0 = top-left, position 1919 = bottom-right
- Buffer addresses are 12-bit encoded into 2 bytes

### Character Encoding (EBCDIC)

Mainframes use EBCDIC, not ASCII. The MCP tools convert automatically. Reference:

| ASCII | EBCDIC | ASCII | EBCDIC |
|-------|--------|-------|--------|
| A-I   | 0xC1-0xC9 | 0-9 | 0xF0-0xF9 |
| J-R   | 0xD1-0xD9 | Space | 0x40 |
| S-Z   | 0xE2-0xE9 | .     | 0x4B |

### AID Key Bytes

| Key   | Hex  | Key   | Hex  |
|-------|------|-------|------|
| ENTER | 0x7D | CLEAR | 0x6D |
| PF1   | 0xF1 | PF13  | 0xC1 |
| PF2   | 0xF2 | PF14  | 0xC2 |
| PF3   | 0xF3 | PF15  | 0xC3 |
| PF4   | 0xF4 | PF16  | 0xC4 |
| PF5   | 0xF5 | PF17  | 0xC5 |
| PF6   | 0xF6 | PF18  | 0xC6 |
| PF7   | 0xF7 | PF19  | 0xC7 |
| PF8   | 0xF8 | PF20  | 0xC8 |
| PF9   | 0xF9 | PF21  | 0xC9 |
| PF10  | 0x7A | PF22  | 0x4A |
| PF11  | 0x7B | PF23  | 0x4B |
| PF12  | 0x7C | PF24  | 0x4C |
| PA1   | 0x6C | PA2   | 0x6E |
| PA3   | 0x6B | SYSREQ| 0xF0 |

### 3270 Data Stream Orders

| Byte | Order | Purpose |
|------|-------|---------|
| 0x11 | SBA   | Set Buffer Address -- positions the cursor/data at a specific screen location |
| 0x1D | SF    | Start Field -- defines a field with basic attributes |
| 0x29 | SFE   | Start Field Extended -- defines a field with extended attributes (used for hidden fields) |
| 0x3C | RA    | Repeat to Address -- fills positions with a character up to a target address |
| 0x12 | EUA   | Erase Unprotected to Address -- clears unprotected fields |
| 0x13 | IC    | Insert Cursor -- positions the cursor |
| 0x05 | PT    | Program Tab -- advances to next unprotected field |
| 0x08 | GE    | Graphic Escape -- next byte is from an alternate character set |

### Packet Structure

**Client-to-server (unformatted screen):**
```
[TN3270E header if applicable] + AID + cursor_addr(2 bytes) + EBCDIC_data + IAC_EOR
```

**Client-to-server (formatted screen, one field):**
```
[TN3270E header if applicable] + AID + cursor_addr(2 bytes) + SBA + field_addr(2 bytes) + EBCDIC_data + IAC_EOR
```

**Client-to-server (formatted screen, multiple fields):**
```
[TN3270E header if applicable] + AID + cursor_addr(2 bytes) + SBA + field1_addr + data1 + SBA + field2_addr + data2 + ... + IAC_EOR
```

- **TN3270E header**: 5 bytes `00 00 00 00 01` (only present in TN3270E mode, not plain TN3270)
- **AID**: 1 byte identifying the key pressed (see AID Key Bytes table above)
- **cursor_addr**: 2 bytes, 12-bit encoded position of the cursor
- **SBA**: `0x11` followed by 2-byte field address
- **IAC_EOR**: `FF EF` -- packet terminator

### Field Attributes (SF/SFE)

| Bit Pattern | Meaning |
|------------|---------|
| Protected + Non-display | Hidden field -- data is there but invisible |
| Protected + Display | Normal label/display field |
| Unprotected + Display | Input field -- user can type here |
| Unprotected + Non-display | Hidden input field (rare) |

### TN3270 vs TN3270E

- **TN3270**: Basic protocol. Packets start directly with the AID byte.
- **TN3270E**: Extended protocol. Packets have a 5-byte header before the AID byte. Supports device names, logical units, and response handling.

The MCP tools handle this automatically. Use `check_connection()` or `get_protocol_info()` to see which mode is active.
