# hack3270 MCP Server Setup Guide

This guide covers how to install and configure the hack3270 MCP server for **Cursor** and **Microsoft Visual Studio Code**, enabling AI-assisted mainframe penetration testing through natural language.

## Overview

The MCP (Model Context Protocol) server exposes all 52 hack3270 tools to an AI coding assistant. The AI can then read mainframe screens, send commands, analyze hidden fields, brute force credentials, fuzz inputs, craft raw TN3270 packets, and more -- all through conversational instructions.

### Architecture

```
+------------------+       stdio        +----------------+     TCP:31337     +---------------+     TN3270      +------------+
|                  | <--- JSON-RPC ---> |                | <--- HTTP ----->  |               | <--- 3270 --->  |            |
|  AI Agent        |                    |  mcp_server.py |                   |  hack3270     |                 | Mainframe  |
|  (Cursor/Copilot)|                    |  (52 tools)    |                   |  Proxy + GUI  |                 | (CICS/TSO) |
|                  |                    |                |                   |  :3271 proxy  |                 |            |
+------------------+                    +----------------+                   +---------------+                 +------------+
                                                                                   ^
                                                                                   |  TN3270 (unencrypted)
                                                                            +---------------+
                                                                            |  Terminal     |
                                                                            |  Emulator     |
                                                                            |  (x3270)      |
                                                                            +---------------+
```

---

## Prerequisites

Before configuring the MCP server, ensure you have:

1. **Python 3.10+** installed and on your system PATH
2. **hack3270** cloned or downloaded to a local directory
3. **Required Python packages** installed:

```bash
cd /path/to/hack3270
pip install -r requirements.txt
```

This installs:
- `PySide6>=6.5.0` -- Qt6 GUI framework for hack3270
- `mcp>=1.26.0` -- Model Context Protocol SDK

4. **A TN3270 terminal emulator** (x3270, c3270, or wx3270)

### Verify Installation

```bash
python -c "from mcp.server.fastmcp import FastMCP; print('MCP SDK OK')"
python -c "from hack3270_api import Hack3270API; print('hack3270 API OK')"
```

Both commands should print "OK" with no errors.

---

## Step 1: Start hack3270

The MCP server connects to the hack3270 proxy's API on port 31337. hack3270 must be running first.

```bash
# Connect to your target mainframe
python hack3270.py <MAINFRAME_IP> <PORT> -n pentest

# Example: Connect to DVCA running in Docker
python hack3270.py 127.0.0.1 3270 -n dvca
```

Then connect your terminal emulator (x3270/wx3270) to the proxy:
- **Host:** `127.0.0.1`
- **Port:** `3271`

Click "Continue" in the hack3270 GUI when the connection is received.

---

## Step 2: Configure Your Editor

### Cursor IDE

Create the file `.cursor/mcp.json` in your **project root** (the hack3270 directory):

#### Windows

```json
{
  "mcpServers": {
    "hack3270": {
      "command": "python",
      "args": ["mcp_server.py"],
      "cwd": "C:\\path\\to\\hack3270"
    }
  }
}
```

#### macOS / Linux

```json
{
  "mcpServers": {
    "hack3270": {
      "command": "python3",
      "args": ["mcp_server.py"],
      "cwd": "/path/to/hack3270"
    }
  }
}
```

> **Important:** Replace the `cwd` path with the actual absolute path to your hack3270 directory. On Windows, use double backslashes (`\\`).

After saving, **restart Cursor** or reload the window (`Ctrl+Shift+P` > "Developer: Reload Window"). The hack3270 MCP tools should appear in your AI agent's tool list.

#### Verify in Cursor

1. Open the Cursor Settings (`Ctrl+Shift+J` or `Cmd+Shift+J`)
2. Navigate to **MCP** in the sidebar
3. You should see **hack3270** listed with a green status indicator
4. If it shows red, check the error message and verify your Python path and `cwd`

---

### Microsoft Visual Studio Code

VS Code supports MCP servers through GitHub Copilot's agent mode. Configuration goes in your **User Settings** or **Workspace Settings**.

#### Option A: Workspace Settings (Recommended)

Create or edit `.vscode/settings.json` in your project root:

```json
{
  "github.copilot.chat.mcpServers": {
    "hack3270": {
      "command": "python",
      "args": ["mcp_server.py"],
      "cwd": "C:\\path\\to\\hack3270"
    }
  }
}
```

#### Option B: User Settings (Global)

Open VS Code Settings JSON (`Ctrl+Shift+P` > "Preferences: Open User Settings (JSON)") and add:

```json
{
  "github.copilot.chat.mcpServers": {
    "hack3270": {
      "command": "python",
      "args": ["mcp_server.py"],
      "cwd": "C:\\path\\to\\hack3270"
    }
  }
}
```

#### macOS / Linux

Use `python3` instead of `python` and forward-slash paths:

```json
{
  "github.copilot.chat.mcpServers": {
    "hack3270": {
      "command": "python3",
      "args": ["mcp_server.py"],
      "cwd": "/path/to/hack3270"
    }
  }
}
```

#### Verify in VS Code

1. Open the Copilot Chat panel (`Ctrl+Shift+I` or `Cmd+Shift+I`)
2. Switch to **Agent** mode (click the mode selector at the top of the chat)
3. Click the **Tools** icon (wrench) to see available MCP tools
4. You should see hack3270 tools like `connect_api`, `get_screen`, `send_command`, etc.

> **Note:** VS Code MCP support requires **GitHub Copilot** and **GitHub Copilot Chat** extensions. The feature is available in VS Code 1.99+ with Copilot agent mode.

---

## Step 3: Connect and Test

Once your editor recognizes the MCP server, test the connection:

1. Open the AI chat in your editor
2. Ask: *"Connect to the hack3270 API and show me the current mainframe screen."*
3. The AI should call `connect_api` then `get_screen` and display the terminal contents

If connection fails:
- Verify hack3270 is running (check for the GUI window)
- Verify the terminal emulator is connected
- Verify the API is listening: open `http://127.0.0.1:31337/ping` in a browser (should return `pong`)

---

## Available Tools (52 total)

### Connection Management (6 tools)

| Tool | Description |
|------|-------------|
| `connect_api` | Connect to the hack3270 API server (default: 127.0.0.1:31337) |
| `disconnect_api` | Disconnect from the API |
| `reconnect_api` | Reconnect if the connection was lost |
| `ping` | Test API connectivity (returns "pong") |
| `check_connection` | Check connection status and protocol mode |
| `test_mainframe_connection` | Send ENTER to verify mainframe is responsive |

### Screen Reading (6 tools)

| Tool | Description |
|------|-------------|
| `get_screen` | Get the current screen as formatted text (24x80) |
| `get_screen_raw` | Get raw screen with control code markers |
| `get_screen_raw_hex` | Get raw TN3270 data stream as hex bytes |
| `find_text` | Search screen for text (supports regex) |
| `find_field_value` | Find a field value by its label (e.g., "Userid") |
| `get_text_at` | Get text at a specific row/column position |

### Field Analysis (5 tools)

| Tool | Description |
|------|-------------|
| `analyze_screen_fields` | Parse ALL fields: input, protected, hidden with addresses and values |
| `get_input_fields` | Get only editable (unprotected) input fields |
| `get_hidden_fields` | Get hidden/non-display fields |
| `analyze_hidden` | Deep hidden field analysis via server-side detection |
| `check_abend` | Detect mainframe abend/crash codes (ASRA, AICA, SOC7, etc.) |

### Input / AID Keys (4 tools)

| Tool | Description |
|------|-------------|
| `send_enter` | Press ENTER |
| `send_aid_key` | Send any AID key: ENTER, CLEAR, PF1-PF24, PA1-PA3, SYSREQ |
| `send_pf_key` | Send a PF key by number (1-24) |
| `send_clear` | Send the CLEAR key |

### Data Sending (4 tools)

| Tool | Description |
|------|-------------|
| `send_command` | Type a command on an unformatted screen (e.g., transaction codes) |
| `send_field_data` | Send text to a specific field by buffer address |
| `send_raw_hex` | Send raw bytes directly to the mainframe |
| `build_and_send_packet` | Build a TN3270 packet from components and send |

### Waiting (2 tools)

| Tool | Description |
|------|-------------|
| `wait_for_text` | Wait until specific text appears on screen |
| `wait_for_screen_change` | Wait for the screen to change from current state |

### Database / Replay (7 tools)

| Tool | Description |
|------|-------------|
| `load_database` | Load a session database (.db file) |
| `close_database` | Close the current database |
| `list_databases` | List available .db session files |
| `get_logs` | Get log entries (client/server/all) |
| `get_log_entry` | Get a specific log entry with full hex data |
| `replay_client_data` | Replay a captured client packet |
| `replay_sequence` | Replay multiple packets in sequence |

### Injection / Brute Force (6 tools)

| Tool | Description |
|------|-------------|
| `list_wordlists` | List available wordlist files |
| `load_wordlist` | Load and preview a wordlist |
| `get_wordlist_contents` | Read entries from a wordlist with pagination |
| `setup_injection` | Create an injection template from a captured packet |
| `inject_value` | Inject a single value into a field |
| `brute_force_field` | Brute force a field using a wordlist with success/fail detection |

### Fuzzing / Scanning (4 tools)

| Tool | Description |
|------|-------------|
| `scan_aid_keys` | Send all AID keys and compare responses to find hidden functions |
| `fuzz_field` | Fuzz a specific field with overflow, SQL, decimal, and control payloads |
| `fuzz_all_input_fields` | Auto-discover and fuzz all input fields on the current screen |
| `fuzz_transaction_codes` | Test transaction codes from a wordlist to find valid ones |

### Encoding / Utilities (5 tools)

| Tool | Description |
|------|-------------|
| `convert_ascii_to_ebcdic` | Convert ASCII text to EBCDIC hex |
| `convert_ebcdic_to_ascii` | Convert EBCDIC hex to ASCII text |
| `encode_buffer_address` | Encode a screen position to a 2-byte 12-bit address |
| `decode_buffer_address` | Decode a 2-byte address to a screen position |
| `get_protocol_info` | Get TN3270 protocol info, screen dimensions, and AID key reference |

### Recording / Playback (3 tools)

| Tool | Description |
|------|-------------|
| `start_recording` | Start recording actions |
| `stop_recording` | Stop recording and return action list |
| `playback_recording` | Replay the last recorded actions |

---

## Usage Examples

### Basic Reconnaissance

> "Connect to the hack3270 API, show me the screen, and analyze all fields including hidden ones."

### Transaction Enumeration

> "Fuzz all CICS transaction codes to find which ones are valid on this system."

### Protected Field Tampering

> "Analyze the screen fields, find the price field address, encode the buffer address, convert my new price to EBCDIC, and send a raw packet to change the protected price field."

### Brute Force Attack

> "Navigate to the shipping address screen, find the supervisor code field, type **** as a mask, set up injection from the log, and brute force using pin-common.txt. Stop when INVALID doesn't appear."

### Full Pen Test

> "Pen test this mainframe application. Check for hidden fields, test all AID keys, try to tamper with protected fields, brute force any PIN codes, enumerate transactions, and write a report."

---

## Troubleshooting

### MCP server not appearing in editor

| Issue | Solution |
|-------|----------|
| Server shows red/error in Cursor MCP settings | Check the error message -- usually a wrong path or missing dependency |
| `python` not found | Use the full path to Python (e.g., `C:\\Python310\\python.exe`) or ensure Python is on PATH |
| `ModuleNotFoundError: No module named 'mcp'` | Run `pip install mcp>=1.26.0` |
| `ModuleNotFoundError: No module named 'hack3270_api'` | Verify `cwd` points to the hack3270 directory containing `hack3270_api.py` |
| Tools don't appear in VS Code | Ensure you're in Agent mode (not Ask mode) in Copilot Chat |

### Connection to hack3270 fails

| Issue | Solution |
|-------|----------|
| `Connection refused` on port 31337 | Start hack3270 first: `python hack3270.py <IP> <PORT>` |
| `Connection refused` after restart | Reconnect using the `reconnect_api` tool |
| API connected but screen is blank | Connect your terminal emulator to port 3271 first |
| `USERID IN USE` on TSO logon | Type `LOGON <userid> RECONNECT` and enter the password |

### Common Gotchas

- **hack3270 must be running before the MCP server connects.** The MCP server is a client that connects to the hack3270 API on port 31337.
- **The terminal emulator must be connected.** hack3270 acts as a proxy between the terminal and mainframe. Without the terminal connected, there's no active session.
- **`send_command()` quirk on MVS3.8j/KICKS:** On unformatted screens (after CLEAR), `send_command` may include an SBA order that causes APCT abends. Use `send_raw_hex` to send transaction codes directly: `7d40c4` + EBCDIC text + `ffef`. Use `convert_ascii_to_ebcdic` to get the EBCDIC hex for your command.
- **CLEAR doesn't always blank the screen.** On formatted screens, CLEAR may reset field values but keep the screen format. Press PF3 (Quit) first to exit the current transaction, then CLEAR.

---

## Security Considerations

- The MCP server communicates with hack3270 over **unencrypted localhost TCP** (port 31337)
- The MCP server itself runs via **stdio** (no network exposure)
- All pen testing activity is logged in the hack3270 session database (`.db` file)
- Do not expose the hack3270 API port (31337) to untrusted networks
- Obtain proper authorization before pen testing any mainframe system

---

## AI Skill File (Pen Testing Knowledge Base)

hack3270 ships with a **TN3270 penetration testing skill file** that teaches the AI agent mainframe-specific attack techniques, protocol details, and a structured pen test methodology. This file dramatically improves the AI's effectiveness when pen testing mainframes.

The skill file is located at:

```
.cursor/skills/tn3270-pentest/SKILL.md
```

### Using the Skill in Cursor

Cursor loads skill files from `.cursor/skills/` automatically. No additional configuration is needed -- the AI agent will reference the skill whenever it detects a relevant task (mainframe interaction, TN3270 protocol, CICS pen testing, etc.).

### Using the Skill in Microsoft Visual Studio Code

VS Code with GitHub Copilot reads project-level instructions from `.github/copilot-instructions.md`. To use the hack3270 pen testing skill:

#### Option A: Copilot Instructions File (Recommended)

Create `.github/copilot-instructions.md` in your project root and reference the skill content:

1. Create the directory and file:

```bash
mkdir .github
```

2. Copy the skill file content into the Copilot instructions file:

**Windows (PowerShell):**
```powershell
Copy-Item ".cursor\skills\tn3270-pentest\SKILL.md" ".github\copilot-instructions.md"
```

**macOS / Linux:**
```bash
cp .cursor/skills/tn3270-pentest/SKILL.md .github/copilot-instructions.md
```

3. Remove the YAML front matter (the `---` delimited block at the top with `name:` and `description:`) since Copilot does not use that format. The file should start directly with the `# TN3270 Mainframe Penetration Testing` heading.

GitHub Copilot automatically reads `.github/copilot-instructions.md` and applies the instructions to all chat interactions in the project.

#### Option B: VS Code Settings Reference

Add a file-based instruction reference in `.vscode/settings.json`:

```json
{
  "github.copilot.chat.codeGeneration.instructions": [
    {
      "file": ".cursor/skills/tn3270-pentest/SKILL.md"
    }
  ]
}
```

This tells Copilot to include the skill file content as context during code generation tasks.

#### Option C: Manual Context

If you prefer not to configure automatic loading, you can manually attach the skill file to any Copilot Chat conversation by typing `#file:.cursor/skills/tn3270-pentest/SKILL.md` in the chat input. This is useful for one-off sessions.

### What the Skill Covers

The skill file teaches the AI agent:

- **TN3270 protocol** -- unformatted vs formatted screens, SBA/SF/SFE orders, AID keys, EBCDIC encoding
- **CICS system transactions** -- CESN, CEMT, CEDA, CECI, CEDF, CEBR exploitation techniques
- **Attack patterns** -- hidden field tampering, protected field manipulation, transaction enumeration, brute forcing, AID key scanning (including PA keys), RACF bypass via CEDA, JCL submission for RCE
- **Default credentials** -- common CICS/TSO default userids and passwords
- **Abend codes** -- what ASRA, SOC7, SOC4, AKCS mean during testing
- **16-step pen test methodology** -- a structured approach from VTAM enumeration through traffic analysis

---

## File Reference

| File | Purpose |
|------|---------|
| `mcp_server.py` | The MCP server (52 tools wrapping the hack3270 API) |
| `hack3270_api.py` | Python client library for the hack3270 Web API |
| `hack3270.py` | Main hack3270 application (proxy + GUI) |
| `.cursor/mcp.json` | Cursor IDE MCP configuration |
| `.cursor/skills/tn3270-pentest/SKILL.md` | AI pen testing skill file (Cursor auto-loads, VS Code needs setup) |
| `.vscode/settings.json` | VS Code MCP configuration -- not shipped, you create this (see Step 2) |
| `requirements.txt` | Python dependencies (`PySide6`, `mcp`) |
| `injections/` | Wordlist directory for brute forcing and fuzzing |

---

## License

GNU General Public License v3.0 -- see [LICENSE](LICENSE) for details.
