#!/usr/bin/env python3
"""
hack3270 MCP Server - Mainframe Penetration Testing Tools

Exposes the full hack3270 API as MCP tools, giving an AI agent
complete access to pen test mainframes via TN3270.

Architecture:
    [Cursor AI] <--stdio--> [This MCP Server] <--TCP:31337--> [hack3270 Proxy] <--TN3270--> [Mainframe]

Prerequisites:
    1. hack3270 running and connected to a mainframe
    2. Terminal emulator connected to the proxy (port 3271)
    3. API automatically available on port 31337
"""

import sys
import os
import json
import base64
import time
import asyncio
from pathlib import Path
from typing import Optional

from mcp.server.fastmcp import FastMCP

# Add hack3270_libs and the vendored hackterm-core to path
_REPO_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str((_REPO_ROOT / "hackterm-core").resolve()))
sys.path.insert(0, str((_REPO_ROOT / "hack3270_libs").resolve()))

from hack3270_api import Hack3270API, Hack3270APIError

# ---------------------------------------------------------------------------
# MCP Server
# ---------------------------------------------------------------------------

mcp = FastMCP(
    "hack3270",
    instructions="Mainframe penetration testing toolkit via TN3270. "
                 "Provides screen reading, AID key injection, field manipulation, "
                 "brute forcing, fuzzing, hidden field detection, and full protocol control.",
)

# ---------------------------------------------------------------------------
# Shared API instance (persistent connection across tool calls)
# ---------------------------------------------------------------------------

_api: Optional[Hack3270API] = None


def _get_api() -> Hack3270API:
    """Get or create the API connection."""
    global _api
    if _api is None:
        _api = Hack3270API()
    return _api


def _ensure_connected() -> Hack3270API:
    """Ensure API is connected, auto-reconnect on broken pipe / hack3270 restart."""
    api = _get_api()
    if api._sock is None:
        api.connect()
        return api
    # Ping health check -- detects broken pipes from hack3270 restarts.
    # Sub-millisecond on localhost so negligible overhead.
    try:
        api.ping()
    except Exception:
        api.reconnect()
    return api


def _parse_screen(api: Hack3270API) -> list:
    """
    Parse 3270 data stream into clean 24x80 ASCII screen lines.
    Properly handles SBA, SF, SFE, SA, MF, RA, EUA, IC, PT, GE orders.
    """
    raw = api.get_last_server_raw()
    if not raw:
        return [''] * 24

    SCREEN_SIZE = 24 * 80
    screen = [0x40] * SCREEN_SIZE  # EBCDIC spaces
    pos = 0
    i = 0

    ADDR_TABLE = [
        0x40,0xC1,0xC2,0xC3,0xC4,0xC5,0xC6,0xC7,0xC8,0xC9,0x4A,0x4B,0x4C,0x4D,0x4E,0x4F,
        0x50,0xD1,0xD2,0xD3,0xD4,0xD5,0xD6,0xD7,0xD8,0xD9,0x5A,0x5B,0x5C,0x5D,0x5E,0x5F,
        0x60,0x61,0xE2,0xE3,0xE4,0xE5,0xE6,0xE7,0xE8,0xE9,0x6A,0x6B,0x6C,0x6D,0x6E,0x6F,
        0xF0,0xF1,0xF2,0xF3,0xF4,0xF5,0xF6,0xF7,0xF8,0xF9,0x7A,0x7B,0x7C,0x7D,0x7E,0x7F,
    ]

    def decode_addr(b1, b2):
        if b1 & 0xC0 == 0x00:
            return ((b1 & 0x3F) << 8) | b2
        try:
            return (ADDR_TABLE.index(b1) << 6) | ADDR_TABLE.index(b2)
        except ValueError:
            return -1

    # Skip write command + WCC
    if raw[0] in (0xF1, 0xF5, 0x7E, 0xF3):
        i = 1
        if raw[0] in (0xF5, 0x7E):
            i = 2

    while i < len(raw):
        b = raw[i]
        if b == 0x11:  # SBA
            if i + 2 < len(raw):
                pos = decode_addr(raw[i+1], raw[i+2])
                if pos < 0:
                    pos = 0
                i += 3
            else:
                i += 1
        elif b == 0x1D:  # SF
            pos += 1
            i += 2
        elif b == 0x29:  # SFE
            if i + 1 < len(raw):
                count = raw[i+1]
                i += 2 + count * 2
                pos += 1
            else:
                i += 1
        elif b == 0x28:  # SA
            i += 3
        elif b == 0x2C:  # MF
            if i + 1 < len(raw):
                count = raw[i+1]
                i += 2 + count * 2
            else:
                i += 1
        elif b == 0x3C:  # RA
            if i + 3 < len(raw):
                target = decode_addr(raw[i+1], raw[i+2])
                char = raw[i+3]
                if target < 0:
                    target = pos
                while pos < target and pos < SCREEN_SIZE:
                    screen[pos] = char
                    pos += 1
                i += 4
            else:
                i += 1
        elif b == 0x13:  # IC
            i += 1
        elif b == 0x05:  # PT
            i += 1
        elif b == 0x08:  # GE
            i += 2
        elif b == 0x12:  # EUA
            if i + 2 < len(raw):
                target = decode_addr(raw[i+1], raw[i+2])
                if target < 0:
                    target = pos
                while pos < target and pos < SCREEN_SIZE:
                    screen[pos] = 0x40
                    pos += 1
                i += 3
            else:
                i += 1
        elif b == 0xFF:  # IAC
            break
        else:
            if 0 <= pos < SCREEN_SIZE:
                screen[pos] = b
                pos += 1
            i += 1

    E2A = api.E2A
    text = ''.join(E2A.get(b, ' ') for b in screen)
    return [text[r*80:(r+1)*80] for r in range(24)]


def _format_fields(fields: list, show_values: bool = True) -> str:
    """Format field list for display."""
    if not fields:
        return "No fields found."
    lines = []
    for i, f in enumerate(fields):
        flags = []
        if f.get('protected'):
            flags.append('PROTECTED')
        if f.get('numeric'):
            flags.append('NUMERIC')
        if f.get('hidden'):
            flags.append('HIDDEN')
        flag_str = ', '.join(flags) if flags else 'INPUT'
        
        addr = f.get('address', '?')
        length = f.get('length', '?')
        
        line = f"  [{i}] Address: {addr}, Length: {length}, Type: {flag_str}"
        if show_values and f.get('value'):
            try:
                api = _get_api()
                ascii_val = api.ebcdic_to_ascii(f['value']).strip()
                if ascii_val:
                    line += f', Value: "{ascii_val}"'
            except:
                pass
        lines.append(line)
    return '\n'.join(lines)


def _resolve_aid(aid: str) -> int:
    """Resolve an AID key name or hex string to its byte value."""
    AID_MAP = {
        'ENTER': 0x7D, 'CLEAR': 0x6D,
        'PA1': 0x6C, 'PA2': 0x6E, 'PA3': 0x6B,
        'SYSREQ': 0xF0,
    }
    pf_bytes = [
        0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0x7A,
        0x7B, 0x7C, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8,
        0xC9, 0x4A, 0x4B, 0x4C
    ]
    for i in range(1, 25):
        AID_MAP[f'PF{i}'] = pf_bytes[i - 1]

    aid_upper = aid.upper()
    if aid_upper.startswith('0X'):
        return int(aid_upper, 16)
    if aid_upper in AID_MAP:
        return AID_MAP[aid_upper]
    raise ValueError(f"Unknown AID: {aid}. Use ENTER, CLEAR, PF1-PF24, PA1-PA3, SYSREQ, or hex.")


# =========================================================================
# CONNECTION MANAGEMENT
# =========================================================================

@mcp.tool()
def connect_api(host: str = "127.0.0.1", port: int = 31337) -> str:
    """
    Connect to the hack3270 API server.
    
    This must be called first (or will be auto-called by other tools).
    hack3270 must already be running with a terminal emulator connected.
    
    Args:
        host: API server address (default: 127.0.0.1)
        port: API server port (default: 31337)
    """
    global _api
    try:
        if _api:
            _api.disconnect()
        _api = Hack3270API(host=host, port=port)
        _api.connect()
        
        # Test with ping
        resp = _api.ping()
        
        # Check TN3270E mode
        mode = "TN3270E" if _api.is_tn3270e() else "TN3270"
        
        return f"Connected to hack3270 API at {host}:{port}. Protocol: {mode}. Ping: {resp}"
    except Exception as e:
        return f"Connection failed: {e}"


@mcp.tool()
def disconnect_api() -> str:
    """Disconnect from the hack3270 API server."""
    global _api
    if _api:
        _api.disconnect()
        _api = None
        return "Disconnected from hack3270 API."
    return "Not connected."


@mcp.tool()
def ping() -> str:
    """Test API connectivity. Returns 'pong' if connected."""
    try:
        api = _ensure_connected()
        return api.ping()
    except Exception as e:
        return f"Ping failed: {e}"


@mcp.tool()
def reconnect_api() -> str:
    """Reconnect to the API if the connection was lost."""
    try:
        api = _get_api()
        api.reconnect()
        return "Reconnected successfully."
    except Exception as e:
        return f"Reconnect failed: {e}"


@mcp.tool()
def check_connection() -> str:
    """
    Check API connection status and protocol mode.
    Returns connection state, TN3270/TN3270E mode, and mainframe responsiveness.
    """
    try:
        api = _get_api()
        connected = api._sock is not None
        if not connected:
            return "Status: DISCONNECTED. Call connect_api() first."
        
        mode = "TN3270E (IBM mainframe)" if api.is_tn3270e() else "TN3270 (TK4/emulator)"
        return f"Status: CONNECTED. Protocol: {mode}."
    except Exception as e:
        return f"Error checking connection: {e}"


@mcp.tool()
def test_mainframe_connection() -> str:
    """
    Test if the mainframe is responsive by sending ENTER and checking for a response.
    This actually sends a keystroke - use with awareness of current screen state.
    """
    try:
        api = _ensure_connected()
        result = api.test_connection()
        if result:
            return "Mainframe is responsive."
        return "Mainframe did not respond. Check terminal emulator connection."
    except Exception as e:
        return f"Test failed: {e}"


# =========================================================================
# SCREEN READING
# =========================================================================

@mcp.tool()
def get_screen() -> str:
    """
    Get the current mainframe screen as formatted text (24 rows x 80 columns).
    
    This is the primary way to see what's on the terminal. Returns the full screen
    with row numbers for easy reference. Control codes are stripped for readability.
    """
    try:
        api = _ensure_connected()
        lines = _parse_screen(api)
        
        # Format with row numbers
        output = []
        for i, line in enumerate(lines):
            output.append(f"{i+1:2}| {line}")
        return '\n'.join(output)
    except Exception as e:
        return f"Error reading screen: {e}"


@mcp.tool()
def get_screen_raw() -> str:
    """
    Get the raw last server response as ASCII text (includes control code markers).
    
    This shows the unprocessed screen data with [0xNN] control code markers intact.
    Useful for understanding the exact 3270 data stream structure.
    """
    try:
        api = _ensure_connected()
        return api.get_last_server()
    except Exception as e:
        return f"Error reading raw screen: {e}"


@mcp.tool()
def get_screen_raw_hex() -> str:
    """
    Get the raw TN3270 data stream as hex bytes.
    
    Returns the actual binary data from the mainframe as a hex string.
    Useful for protocol-level analysis and crafting custom packets.
    """
    try:
        api = _ensure_connected()
        raw = api.get_last_server_raw()
        hex_str = raw.hex()
        # Format in groups of 2 with spaces, 32 bytes per line
        formatted = []
        for i in range(0, len(hex_str), 64):
            line = ' '.join(hex_str[j:j+2] for j in range(i, min(i+64, len(hex_str)), 2))
            formatted.append(f"{i//2:04x}: {line}")
        return f"Raw data ({len(raw)} bytes):\n" + '\n'.join(formatted)
    except Exception as e:
        return f"Error reading raw hex: {e}"


@mcp.tool()
def find_text(pattern: str) -> str:
    """
    Find text on the current screen using exact match or regex.
    
    Args:
        pattern: Text to search for (case-insensitive). Supports regex.
    
    Returns locations as (row, col) with the matched text.
    """
    try:
        api = _ensure_connected()
        import re
        lines = _parse_screen(api)
        
        try:
            regex = re.compile(pattern, re.IGNORECASE)
        except re.error:
            regex = re.compile(re.escape(pattern), re.IGNORECASE)
        
        results = []
        for row, line in enumerate(lines):
            for match in regex.finditer(line):
                results.append((row, match.start(), match.group()))
        
        if not results:
            return f"Pattern '{pattern}' not found on screen."
        
        output = [f"Found {len(results)} match(es) for '{pattern}':"]
        for row, col, match in results:
            output.append(f"  Row {row+1}, Col {col+1}: \"{match}\"")
        return '\n'.join(output)
    except Exception as e:
        return f"Error searching screen: {e}"


@mcp.tool()
def find_field_value(label: str) -> str:
    """
    Find a field's value by its label text on screen.
    
    Looks for patterns like 'Label: value' or 'Label . . . value' on the screen.
    
    Args:
        label: The field label to search for (e.g., 'Userid', 'Password', 'Balance')
    """
    try:
        api = _ensure_connected()
        value = api.find_field(label)
        if value:
            return f"Field '{label}' = \"{value}\""
        return f"Field '{label}' not found on screen."
    except Exception as e:
        return f"Error finding field: {e}"


@mcp.tool()
def get_text_at(row: int, col: int, length: int = 0) -> str:
    """
    Get text at a specific screen position.
    
    Args:
        row: Row number (1-24, 1-indexed for readability)
        col: Column number (1-80, 1-indexed for readability)
        length: Number of characters to read (0 = to end of line)
    """
    try:
        api = _ensure_connected()
        r = row - 1  # Convert to 0-indexed
        c = col - 1
        text = api.get_text_at(r, c, length if length > 0 else None)
        return f"Text at row {row}, col {col}: \"{text}\""
    except Exception as e:
        return f"Error reading text: {e}"


# =========================================================================
# SCREEN ANALYSIS
# =========================================================================

@mcp.tool()
def analyze_screen_fields() -> str:
    """
    Parse the current screen to discover ALL fields (input, protected, hidden).
    
    Returns a comprehensive list of every field on the screen with:
    - Buffer address (position)
    - Field type (INPUT, PROTECTED, NUMERIC, HIDDEN)
    - Field length
    - Current value (EBCDIC decoded to ASCII)
    
    This is essential for understanding the screen layout before sending data.
    """
    try:
        api = _ensure_connected()
        fields = api.parse_screen_fields()
        
        if not fields:
            return "No fields found. Screen may be unformatted (use send_command instead of send_field)."
        
        input_fields = [f for f in fields if not f['protected']]
        protected_fields = [f for f in fields if f['protected'] and not f['hidden']]
        hidden_fields = [f for f in fields if f['hidden']]
        
        output = [f"Screen Fields: {len(fields)} total ({len(input_fields)} input, {len(protected_fields)} protected, {len(hidden_fields)} hidden)\n"]
        
        if input_fields:
            output.append("INPUT FIELDS (editable):")
            output.append(_format_fields(input_fields))
            output.append("")
        
        if protected_fields:
            output.append("PROTECTED FIELDS (read-only):")
            output.append(_format_fields(protected_fields))
            output.append("")
        
        if hidden_fields:
            output.append("HIDDEN FIELDS (invisible to user):")
            output.append(_format_fields(hidden_fields))
        
        return '\n'.join(output)
    except Exception as e:
        return f"Error analyzing fields: {e}"


@mcp.tool()
def get_input_fields() -> str:
    """
    Get only the editable (unprotected) input fields on the current screen.
    
    These are the fields where a user can type. Each field shows its buffer address,
    length, and current value. Use the address for send_field operations.
    """
    try:
        api = _ensure_connected()
        fields = api.get_input_fields()
        if not fields:
            return "No input fields found. Screen may be unformatted."
        return f"Input Fields ({len(fields)}):\n{_format_fields(fields)}"
    except Exception as e:
        return f"Error getting input fields: {e}"


@mcp.tool()
def get_hidden_fields() -> str:
    """
    Get hidden fields on the current screen.
    
    Hidden fields are invisible to the terminal user but contain data in the 3270 stream.
    These often hold sensitive information like internal IDs, authorization tokens,
    debug data, or application state that the developer tried to hide.
    """
    try:
        api = _ensure_connected()
        fields = api.get_hidden_fields()
        if not fields:
            return "No hidden fields found on current screen."
        return f"Hidden Fields ({len(fields)}):\n{_format_fields(fields)}"
    except Exception as e:
        return f"Error getting hidden fields: {e}"


@mcp.tool()
def analyze_hidden() -> str:
    """
    Deep analysis of hidden fields via the hack3270 server-side analyzer.
    
    This uses the proxy's own hidden field detection, which may find fields
    that client-side parsing misses. Returns structured data about each hidden field.
    """
    try:
        api = _ensure_connected()
        result = api.analyze_hidden()
        
        if result.get('status') == 'error':
            return f"Error: {result.get('message', 'Unknown error')}"
        
        output = [f"Screen data: {result.get('total_bytes', '?')} bytes"]
        output.append(f"Hidden fields: {result.get('hidden_count', 0)}")
        
        for field in result.get('hidden_fields', []):
            data = field.get('data', '').strip()
            output.append(f"  Type: {field.get('type', '?')}, Position: {field.get('position', '?')}")
            if data:
                output.append(f"  Data: \"{data}\"")
        
        return '\n'.join(output)
    except Exception as e:
        return f"Error analyzing hidden fields: {e}"


@mcp.tool()
def check_abend() -> str:
    """
    Check if the current screen contains a mainframe abend (crash/error).
    
    Detects: DFHAC2, ABEND, ASRA, AICA, AEY7, APCT, SOC7, SOC4, S0C7, S0C4, ASRB, AEXL
    
    These indicate the application crashed - a critical finding during pen testing.
    """
    try:
        api = _ensure_connected()
        abend = api.check_abend()
        if abend:
            screen = api.get_last_server()
            return f"ABEND DETECTED: {abend}\n\nScreen content:\n{screen[:500]}"
        return "No abend detected on current screen."
    except Exception as e:
        return f"Error checking abend: {e}"


# =========================================================================
# SENDING DATA - AID KEYS
# =========================================================================

@mcp.tool()
def send_enter() -> str:
    """
    Press ENTER on the mainframe. The most common action.
    Returns the new screen content after the keypress.
    """
    try:
        api = _ensure_connected()
        api.send_aid('ENTER')
        time.sleep(0.3)
        lines = _parse_screen(api)
        output = []
        for i, line in enumerate(lines):
            output.append(f"{i+1:2}| {line}")
        return '\n'.join(output)
    except Exception as e:
        return f"Error sending ENTER: {e}"


@mcp.tool()
def send_aid_key(key: str) -> str:
    """
    Send an AID (Attention Identifier) key to the mainframe.
    
    Args:
        key: One of: ENTER, CLEAR, PF1-PF24, PA1-PA3, SYSREQ
             Or hex value like '0x7d' for ENTER.
    
    PF keys (Program Function) often navigate menus or trigger hidden functions.
    PA keys (Program Attention) are unusual and may trigger error handlers.
    CLEAR resets the screen.
    SYSREQ is the System Request key.
    """
    try:
        api = _ensure_connected()
        resp = api.send_aid(key)
        time.sleep(0.3)
        
        # Get updated screen
        lines = _parse_screen(api)
        output = [f"Sent AID: {key} (response: {resp.strip()})", ""]
        for i, line in enumerate(lines):
            output.append(f"{i+1:2}| {line}")
        
        # Check for abend
        abend = api.check_abend()
        if abend:
            output.append(f"\n*** ABEND DETECTED: {abend} ***")
        
        return '\n'.join(output)
    except Exception as e:
        return f"Error sending AID key '{key}': {e}"


@mcp.tool()
def send_pf_key(number: int) -> str:
    """
    Send a PF (Program Function) key. Shorthand for send_aid_key('PFn').
    
    Args:
        number: PF key number 1-24
    """
    if not 1 <= number <= 24:
        return "PF key must be between 1 and 24."
    return send_aid_key(f"PF{number}")


@mcp.tool()
def send_clear() -> str:
    """Send the CLEAR key. Resets the terminal screen."""
    return send_aid_key("CLEAR")


# =========================================================================
# SENDING DATA - TEXT & COMMANDS
# =========================================================================

@mcp.tool()
def send_command(text: str, cursor_row: int = 0, cursor_col: int = 0) -> str:
    """
    Send a command on an unformatted screen (e.g., CICS transaction codes like CESN, MCGM).
    
    Use this when the screen has no visible fields - just a blank or command-line area.
    The text is typed at the cursor position and ENTER is pressed.
    
    Args:
        text: Command text to send (e.g., 'CESN', 'MCGM', 'LOGON APPLID(CICS)')
        cursor_row: Optional cursor row (1-24, 0 = default position)
        cursor_col: Optional cursor col (1-80, 0 = default position)
    """
    try:
        api = _ensure_connected()
        
        cursor_addr = None
        if cursor_row > 0 and cursor_col > 0:
            pos = (cursor_row - 1) * 80 + (cursor_col - 1)
            cursor_addr = api.encode_buffer_address(pos)
        
        resp = api.send_command(text, cursor_addr=cursor_addr)
        time.sleep(0.3)
        
        lines = _parse_screen(api)
        output = [f"Sent command: \"{text}\" (response: {resp.strip()})", ""]
        for i, line in enumerate(lines):
            output.append(f"{i+1:2}| {line}")
        
        abend = api.check_abend()
        if abend:
            output.append(f"\n*** ABEND DETECTED: {abend} ***")
        
        return '\n'.join(output)
    except Exception as e:
        return f"Error sending command '{text}': {e}"


@mcp.tool()
def send_field_data(text: str, field_address: int, cursor_address: int = -1, add_space: bool = False, aid: str = "ENTER") -> str:
    """
    Send text to a specific field on a formatted screen.
    
    Use analyze_screen_fields() first to discover field addresses.
    The text is converted from ASCII to EBCDIC automatically.
    
    Args:
        text: ASCII text to send (e.g., 'ADMIN', 'password123')
        field_address: Buffer address of the target field (from analyze_screen_fields)
        cursor_address: Buffer address for cursor position (-1 = same as field)
        add_space: Add trailing space after text (helps clear leftover chars)
        aid: AID key to send with the data (default: 'ENTER'). Options: ENTER, CLEAR, PF1-PF24, PA1-PA3, SYSREQ, or hex like '0x7d'.
    """
    try:
        api = _ensure_connected()
        aid_byte = _resolve_aid(aid)
        
        field_addr = api.encode_buffer_address(field_address)
        if cursor_address < 0:
            cursor_addr = field_addr
        else:
            cursor_addr = api.encode_buffer_address(cursor_address)
        
        resp = api.send_field(text, cursor_addr, field_addr, add_space=add_space, aid_byte=aid_byte)
        time.sleep(0.3)
        
        lines = _parse_screen(api)
        output = [f"Sent field data: \"{text}\" to address {field_address} (AID={aid}, response: {resp.strip()})", ""]
        for i, line in enumerate(lines):
            output.append(f"{i+1:2}| {line}")
        
        abend = api.check_abend()
        if abend:
            output.append(f"\n*** ABEND DETECTED: {abend} ***")
        
        return '\n'.join(output)
    except Exception as e:
        return f"Error sending field data: {e}"


@mcp.tool()
def send_fields_data(fields_json: str, aid: str = "ENTER") -> str:
    """
    Send data to multiple fields in a single packet and submit.
    
    Useful for filling out forms with several fields (e.g., username + password)
    in one operation instead of separate send_field_data calls.
    
    Args:
        fields_json: JSON array of objects with 'address' (int) and 'text' (str).
                     Example: '[{"address": 10, "text": "admin"}, {"address": 50, "text": "secret"}]'
        aid: AID key to send (default: 'ENTER'). Options: ENTER, CLEAR, PF1-PF24, PA1-PA3, SYSREQ, or hex.
    """
    try:
        api = _ensure_connected()
        aid_byte = _resolve_aid(aid)
        
        fields = json.loads(fields_json)
        if not isinstance(fields, list) or not fields:
            return "Error: fields_json must be a non-empty JSON array of {\"address\": int, \"text\": str} objects"
        
        for f in fields:
            if 'address' not in f or 'text' not in f:
                return f"Error: each field must have 'address' and 'text' keys. Got: {f}"
        
        resp = api.send_fields(fields, aid_byte=aid_byte)
        time.sleep(0.3)
        
        lines = _parse_screen(api)
        field_desc = ", ".join(f'addr {f["address"]}="{f["text"]}"' for f in fields)
        output = [f"Sent {len(fields)} fields: {field_desc} (AID={aid}, response: {resp.strip()})", ""]
        for i, line in enumerate(lines):
            output.append(f"{i+1:2}| {line}")
        
        abend = api.check_abend()
        if abend:
            output.append(f"\n*** ABEND DETECTED: {abend} ***")
        
        return '\n'.join(output)
    except json.JSONDecodeError as e:
        return f"Error parsing fields_json: {e}"
    except Exception as e:
        return f"Error sending fields data: {e}"


@mcp.tool()
def send_raw_hex(hex_data: str, description: str = "MCP: Send raw hex") -> str:
    """
    Send raw bytes (as hex string) directly to the mainframe.
    
    This is the lowest-level send operation. You must construct the complete
    TN3270 packet including AID, cursor address, SBA orders, EBCDIC data, and IAC EOR.
    
    Args:
        hex_data: Hex string of bytes to send (e.g., '7d4040' for ENTER with cursor at 0,0)
        description: Log description for this packet
    """
    try:
        api = _ensure_connected()
        data = bytes.fromhex(hex_data.replace(' ', ''))
        resp = api.send_raw(data, description)
        time.sleep(0.3)
        
        lines = _parse_screen(api)
        output = [f"Sent {len(data)} raw bytes (response: {resp.strip()})", ""]
        for i, line in enumerate(lines):
            output.append(f"{i+1:2}| {line}")
        
        return '\n'.join(output)
    except Exception as e:
        return f"Error sending raw data: {e}"


@mcp.tool()
def build_and_send_packet(
    text: str,
    field_position: int = -1,
    cursor_position: int = 0,
    aid: str = "ENTER"
) -> str:
    """
    Build a proper TN3270 packet from components and send it.
    
    Higher-level than send_raw_hex but more flexible than send_field_data.
    Automatically handles TN3270E headers, EBCDIC conversion, and packet structure.
    
    Args:
        text: ASCII text payload (will be converted to EBCDIC)
        field_position: Buffer position for SBA order (-1 = no SBA/field addressing)
        cursor_position: Buffer position for cursor (0 = position 0)
        aid: AID key name ('ENTER', 'PF1', 'CLEAR', etc.) or hex like '0x7d'
    """
    try:
        api = _ensure_connected()
        aid_byte = _resolve_aid(aid)
        
        ebcdic_data = api.ascii_to_ebcdic(text)
        
        field_addr = field_position if field_position >= 0 else None
        
        packet = api.build_raw_packet(
            data=ebcdic_data,
            cursor_addr=cursor_position,
            field_addr=field_addr,
            aid=aid_byte
        )
        
        resp = api.send_raw(packet, f'MCP: Packet "{text[:30]}" AID={aid}')
        time.sleep(0.3)
        
        lines = _parse_screen(api)
        output = [f"Built & sent packet: \"{text}\" (AID={aid}, field_pos={field_position}, cursor_pos={cursor_position})", ""]
        for i, line in enumerate(lines):
            output.append(f"{i+1:2}| {line}")
        
        abend = api.check_abend()
        if abend:
            output.append(f"\n*** ABEND DETECTED: {abend} ***")
        
        return '\n'.join(output)
    except Exception as e:
        return f"Error building/sending packet: {e}"


# =========================================================================
# WAITING & POLLING
# =========================================================================

@mcp.tool()
def wait_for_text(pattern: str, timeout: float = 10.0) -> str:
    """
    Wait until specific text appears on the screen.
    
    Polls the screen repeatedly until the pattern is found or timeout occurs.
    Case-insensitive matching.
    
    Args:
        pattern: Text or regex pattern to wait for
        timeout: Maximum seconds to wait (default: 10)
    """
    try:
        api = _ensure_connected()
        found = api.wait_for(pattern, timeout=timeout)
        
        if found:
            lines = _parse_screen(api)
            output = [f"Pattern '{pattern}' FOUND on screen.", ""]
            for i, line in enumerate(lines):
                output.append(f"{i+1:2}| {line}")
            return '\n'.join(output)
        else:
            lines = _parse_screen(api)
            output = [f"TIMEOUT: Pattern '{pattern}' not found after {timeout}s.", "Current screen:", ""]
            for i, line in enumerate(lines):
                output.append(f"{i+1:2}| {line}")
            return '\n'.join(output)
    except Exception as e:
        return f"Error waiting for text: {e}"


@mcp.tool()
def wait_for_screen_change(timeout: float = 10.0) -> str:
    """
    Wait for the screen to change from its current state.
    
    Useful after sending a command - waits until the mainframe responds
    with new content.
    
    Args:
        timeout: Maximum seconds to wait (default: 10)
    """
    try:
        api = _ensure_connected()
        new_screen = api.wait_for_change(timeout=timeout)
        
        if new_screen:
            lines = _parse_screen(api)
            output = ["Screen changed!", ""]
            for i, line in enumerate(lines):
                output.append(f"{i+1:2}| {line}")
            return '\n'.join(output)
        else:
            return f"No screen change detected after {timeout}s."
    except Exception as e:
        return f"Error waiting for change: {e}"


# =========================================================================
# DATABASE OPERATIONS
# =========================================================================

@mcp.tool()
def load_database(filename: str) -> str:
    """
    Load a hack3270 session database (.db file).
    
    Session databases contain all captured TN3270 traffic. Required for:
    - Replaying captured packets (send_client_data)
    - Injection templates (get_inject_template)
    - Analyzing past sessions
    
    Args:
        filename: Path to .db file (e.g., 'pentest.db', 'dvca.db')
    """
    try:
        api = _ensure_connected()
        
        # Try relative to hack3270 dir first
        db_path = HACK3270_DIR / filename
        if not db_path.exists():
            db_path = Path(filename)
        
        if not db_path.exists():
            # List available .db files
            dbs = list(HACK3270_DIR.glob('*.db'))
            available = '\n'.join(f"  - {db.name}" for db in dbs) if dbs else "  (none found)"
            return f"Database file not found: {filename}\n\nAvailable databases:\n{available}"
        
        api.load_db(str(db_path))
        return f"Loaded database: {db_path.name}"
    except Exception as e:
        return f"Error loading database: {e}"


@mcp.tool()
def close_database() -> str:
    """Close the currently loaded session database."""
    try:
        api = _get_api()
        api.close_db()
        return "Database closed."
    except Exception as e:
        return f"Error closing database: {e}"


@mcp.tool()
def list_databases() -> str:
    """List available .db session database files in the hack3270 directory."""
    try:
        dbs = list(HACK3270_DIR.glob('*.db'))
        if not dbs:
            return "No .db files found in hack3270 directory."
        
        output = ["Available session databases:"]
        for db in sorted(dbs):
            size = db.stat().st_size
            output.append(f"  {db.name} ({size:,} bytes)")
        return '\n'.join(output)
    except Exception as e:
        return f"Error listing databases: {e}"


@mcp.tool()
def get_logs(direction: str = "", limit: int = 50) -> str:
    """
    Get log entries from the loaded database.
    
    Args:
        direction: 'C' for client (sent to mainframe), 'S' for server (from mainframe), 
                   '' for all
        limit: Maximum number of entries to return (default: 50)
    
    Each entry shows: ID, timestamp, direction (C/S), notes, and data length.
    """
    try:
        api = _ensure_connected()
        dir_filter = direction.upper() if direction else None
        logs = api.db_get_logs(direction=dir_filter, limit=limit)
        
        if not logs:
            return "No log entries found. Is a database loaded?"
        
        output = [f"Log entries ({len(logs)} shown):"]
        output.append(f"{'ID':>6}  {'Time':<20}  {'Dir':<3}  {'Len':>6}  Notes")
        output.append("-" * 80)
        
        for log in logs:
            log_id, timestamp, cs, notes, data_len = log
            notes_str = (notes or '')[:40]
            output.append(f"{log_id:>6}  {str(timestamp):<20}  {cs:<3}  {data_len:>6}  {notes_str}")
        
        return '\n'.join(output)
    except Exception as e:
        return f"Error getting logs: {e}"


@mcp.tool()
def get_log_entry(log_id: int) -> str:
    """
    Get a specific log entry with full details.
    
    Args:
        log_id: The log entry ID number.
    
    Shows the complete entry including raw data as hex and ASCII interpretation.
    """
    try:
        api = _ensure_connected()
        log = api.db_get_log(log_id)
        
        if not log:
            return f"Log entry {log_id} not found."
        
        entry_id, timestamp, cs, notes, data_len, raw_data = log
        direction = 'Client -> Server' if cs == 'C' else 'Server -> Client'
        
        output = [
            f"Log Entry #{entry_id}",
            f"  Timestamp: {timestamp}",
            f"  Direction: {direction} ({cs})",
            f"  Notes: {notes or '(none)'}",
            f"  Data length: {data_len} bytes",
        ]
        
        if raw_data:
            hex_str = raw_data.hex()
            output.append(f"\n  Hex ({len(raw_data)} bytes):")
            for i in range(0, len(hex_str), 64):
                line = ' '.join(hex_str[j:j+2] for j in range(i, min(i+64, len(hex_str)), 2))
                output.append(f"    {i//2:04x}: {line}")
            
            # EBCDIC decode attempt
            try:
                ascii_text = api.ebcdic_to_ascii(raw_data)
                output.append(f"\n  EBCDIC -> ASCII: \"{ascii_text[:200]}\"")
            except:
                pass
        
        return '\n'.join(output)
    except Exception as e:
        return f"Error getting log entry: {e}"


@mcp.tool()
def replay_client_data(log_id: int) -> str:
    """
    Replay a captured client packet to the mainframe.
    
    Sends the exact bytes that were captured in the log entry, as if the
    terminal user typed them again. Great for repeating login sequences
    or re-sending specific requests.
    
    Args:
        log_id: Log entry ID to replay (must be a client 'C' entry)
    """
    try:
        api = _ensure_connected()
        resp = api.send_client_data(log_id)
        time.sleep(0.3)
        
        lines = _parse_screen(api)
        output = [f"Replayed log #{log_id} (response: {resp.strip()})", ""]
        for i, line in enumerate(lines):
            output.append(f"{i+1:2}| {line}")
        
        abend = api.check_abend()
        if abend:
            output.append(f"\n*** ABEND DETECTED: {abend} ***")
        
        return '\n'.join(output)
    except Exception as e:
        return f"Error replaying data: {e}"


@mcp.tool()
def replay_sequence(log_ids: str, delay: float = 0.5) -> str:
    """
    Replay multiple captured packets in sequence (e.g., a login flow).
    
    Args:
        log_ids: Comma-separated log entry IDs (e.g., '7,9,11')
        delay: Seconds between each replay (default: 0.5)
    """
    try:
        api = _ensure_connected()
        ids = [int(x.strip()) for x in log_ids.split(',')]
        
        responses = api.replay_sequence(ids, delay=delay)
        
        output = [f"Replayed {len(ids)} packets:"]
        for r in responses:
            output.append(f"  Log #{r['id']}: {r['response'][:80].strip()}")
        
        # Show final screen
        output.append("\nFinal screen:")
        lines = _parse_screen(api)
        for i, line in enumerate(lines):
            output.append(f"{i+1:2}| {line}")
        
        return '\n'.join(output)
    except Exception as e:
        return f"Error replaying sequence: {e}"


# =========================================================================
# FIELD INJECTION / BRUTE FORCE
# =========================================================================

@mcp.tool()
def list_wordlists() -> str:
    """
    List available injection wordlist files in the injections/ directory.
    
    These contain values for brute forcing fields: PINs, passwords, transaction codes,
    user IDs, SQL injection payloads, buffer overflow strings, and more.
    """
    try:
        inject_dir = HACK3270_DIR / 'injections'
        if not inject_dir.exists():
            return "injections/ directory not found."
        
        files = sorted(inject_dir.glob('*.txt'))
        if not files:
            return "No wordlist files found."
        
        output = ["Available wordlists (injections/ directory):"]
        for f in files:
            try:
                with open(f, 'r') as fh:
                    count = sum(1 for line in fh if line.strip())
                output.append(f"  {f.name} ({count:,} entries)")
            except:
                output.append(f"  {f.name}")
        
        return '\n'.join(output)
    except Exception as e:
        return f"Error listing wordlists: {e}"


@mcp.tool()
def load_wordlist(filename: str) -> str:
    """
    Load and preview a wordlist file. Shows first/last entries and total count.
    
    Args:
        filename: Wordlist filename (e.g., 'pin-common.txt', 'cics-default-transactions.txt')
                  Can be just the filename or full path.
    """
    try:
        api = _ensure_connected()
        
        # Try in injections dir first
        filepath = HACK3270_DIR / 'injections' / filename
        if not filepath.exists():
            filepath = HACK3270_DIR / filename
        if not filepath.exists():
            filepath = Path(filename)
        
        if not filepath.exists():
            return f"Wordlist not found: {filename}. Use list_wordlists() to see available files."
        
        values = api.load_injection_file(str(filepath))
        
        output = [f"Loaded {len(values):,} entries from {filepath.name}"]
        
        # Preview
        preview_count = min(10, len(values))
        output.append(f"\nFirst {preview_count} entries:")
        for v in values[:preview_count]:
            output.append(f"  \"{v}\"")
        
        if len(values) > 20:
            output.append("  ...")
            output.append(f"\nLast 5 entries:")
            for v in values[-5:]:
                output.append(f"  \"{v}\"")
        
        return '\n'.join(output)
    except Exception as e:
        return f"Error loading wordlist: {e}"


@mcp.tool()
def setup_injection(log_id: int, mask: str = "*") -> str:
    """
    Create an injection template from a captured packet.
    
    Before calling this:
    1. Load a database with load_database()
    2. In the terminal, type the mask character (e.g., '****') in the target field
    3. Press Enter to capture the packet
    4. Find the log ID of that packet in get_logs(direction='C')
    
    The template splits the packet into preamble (before mask) and postamble (after mask),
    allowing injection of arbitrary values into that exact field position.
    
    Args:
        log_id: Log entry ID containing the mask characters
        mask: The mask character used (default: '*')
    """
    try:
        api = _ensure_connected()
        template = api.get_inject_template(log_id, mask)
        
        if template.get('status') != 'ok':
            return f"Error: {template.get('message', 'Unknown error')}"
        
        output = [
            f"Injection template created from log #{log_id}:",
            f"  Mask character: '{mask}'",
            f"  Field length: {template['mask_length']} characters",
            f"  Preamble: {len(template['preamble'])} bytes",
            f"  Postamble: {len(template['postamble'])} bytes",
            "",
            "Ready for injection. Use inject_value() or brute_force_field()."
        ]
        
        # Store template for later use
        _get_api()._last_template = template
        
        return '\n'.join(output)
    except Exception as e:
        return f"Error setting up injection: {e}"


@mcp.tool()
def inject_value(value: str, log_id: int = -1, mask: str = "*", mode: str = "TRUNC") -> str:
    """
    Inject a single value into the target field.
    
    Args:
        value: ASCII text to inject (e.g., '1234', 'ADMIN')
        log_id: Log entry ID for template (-1 = use last setup_injection template)
        mask: Mask character (default: '*')
        mode: TRUNC (pad/truncate to field length), SKIP (skip if too long), OVERFLOW (send full value)
    """
    try:
        api = _ensure_connected()
        
        # Get or create template
        if log_id >= 0:
            template = api.get_inject_template(log_id, mask)
        elif hasattr(api, '_last_template') and api._last_template:
            template = api._last_template
        else:
            return "No injection template. Call setup_injection() first, or provide log_id."
        
        if template.get('status') != 'ok':
            return f"Template error: {template.get('message')}"
        
        resp = api.inject(template, value, mode=mode)
        
        if resp is None:
            return f"Value '{value}' skipped (too long for field in SKIP mode)."
        
        time.sleep(0.3)
        lines = _parse_screen(api)
        output = [f"Injected: \"{value}\" (mode={mode})", ""]
        for i, line in enumerate(lines):
            output.append(f"{i+1:2}| {line}")
        
        abend = api.check_abend()
        if abend:
            output.append(f"\n*** ABEND DETECTED: {abend} ***")
        
        return '\n'.join(output)
    except Exception as e:
        return f"Error injecting value: {e}"


@mcp.tool()
def brute_force_field(
    wordlist: str,
    log_id: int = -1,
    mask: str = "*",
    mode: str = "TRUNC",
    fail_pattern: str = "",
    success_pattern: str = "",
    max_attempts: int = 0,
    delay: float = 0.2
) -> str:
    """
    Brute force a field using a wordlist. Stops on success or anomaly detection.
    
    Args:
        wordlist: Wordlist filename (from injections/ dir) or full path
        log_id: Log entry ID for injection template (-1 = use last setup_injection)
        mask: Mask character (default: '*')
        mode: TRUNC, SKIP, or OVERFLOW
        fail_pattern: Text that indicates failure (e.g., 'INVALID', 'INCORRECT'). 
                      If set, any response WITHOUT this text is flagged as success.
        success_pattern: Text that indicates success (e.g., 'WELCOME', 'AUTHORIZED').
                         If set, stops when this appears.
        max_attempts: Maximum attempts (0 = try all)
        delay: Seconds between attempts (default: 0.2)
    """
    try:
        api = _ensure_connected()
        
        # Load wordlist
        filepath = HACK3270_DIR / 'injections' / wordlist
        if not filepath.exists():
            filepath = HACK3270_DIR / wordlist
        if not filepath.exists():
            filepath = Path(wordlist)
        if not filepath.exists():
            return f"Wordlist not found: {wordlist}"
        
        values = api.load_injection_file(str(filepath))
        
        # Get template
        if log_id >= 0:
            template = api.get_inject_template(log_id, mask)
        elif hasattr(api, '_last_template') and api._last_template:
            template = api._last_template
        else:
            return "No injection template. Call setup_injection() first, or provide log_id."
        
        if template.get('status') != 'ok':
            return f"Template error: {template.get('message')}"
        
        total = len(values)
        if max_attempts > 0:
            values = values[:max_attempts]
        
        output = [f"Brute forcing with {len(values)} values from {filepath.name}..."]
        hits = []
        abends = []
        
        for i, value in enumerate(values):
            resp = api.inject(template, value, mode=mode)
            if resp is None:
                continue
            
            time.sleep(delay)
            response = api.get_last_server()
            
            # Check for abend
            abend = api.check_abend(response)
            if abend:
                abends.append((value, abend))
                output.append(f"  [{i+1}/{len(values)}] \"{value}\" -> ABEND: {abend}")
                continue
            
            # Check patterns
            if success_pattern and success_pattern.upper() in response.upper():
                hits.append(value)
                output.append(f"\n*** SUCCESS at [{i+1}/{len(values)}]: \"{value}\" ***")
                output.append(f"Pattern '{success_pattern}' found in response!")
                break
            elif fail_pattern and fail_pattern.upper() not in response.upper():
                hits.append(value)
                output.append(f"\n*** HIT at [{i+1}/{len(values)}]: \"{value}\" ***")
                output.append(f"Response does NOT contain '{fail_pattern}'!")
                break
            
            # Progress update
            if (i + 1) % 50 == 0:
                output.append(f"  Progress: {i+1}/{len(values)}")
        
        # Summary
        output.append(f"\nCompleted: {len(values)} attempts")
        if hits:
            output.append(f"HITS: {', '.join(hits)}")
        if abends:
            output.append(f"ABENDs: {len(abends)} triggered")
            for val, code in abends[:5]:
                output.append(f"  \"{val}\" -> {code}")
        if not hits and not abends:
            output.append("No hits found.")
        
        # Show final screen
        output.append("\nFinal screen:")
        lines = _parse_screen(api)
        for i, line in enumerate(lines):
            output.append(f"{i+1:2}| {line}")
        
        return '\n'.join(output)
    except Exception as e:
        return f"Error during brute force: {e}"


# =========================================================================
# AID KEY SCANNING
# =========================================================================

@mcp.tool()
def scan_aid_keys(
    keys: str = "PF1,PF2,PF3,PF4,PF5,PF6,PF7,PF8,PF9,PF10,PF11,PF12,PF13,PF14,PF15,PF16,PF17,PF18,PF19,PF20,PF21,PF22,PF23,PF24,PA1,PA2,PA3,CLEAR",
    delay: float = 0.5
) -> str:
    """
    Scan AID keys to discover hidden functions and different screen responses.
    
    Sends each AID key and compares the response to a baseline. Any key that
    produces a different screen is flagged - it may lead to hidden menus,
    admin functions, debug screens, or undocumented features.
    
    Args:
        keys: Comma-separated list of AID keys to test (default: PF1-24, PA1-3, CLEAR)
        delay: Seconds between each key press (default: 0.5)
    """
    try:
        api = _ensure_connected()
        key_list = [k.strip() for k in keys.split(',')]
        
        # Get baseline
        baseline = api.get_last_server()
        baseline_len = len(baseline)
        
        output = [f"AID Key Scan - Testing {len(key_list)} keys", f"Baseline screen length: {baseline_len}", ""]
        
        findings = []
        
        for key in key_list:
            try:
                api.send_aid(key)
                time.sleep(delay)
                
                response = api.get_last_server()
                resp_len = len(response)
                
                abend = api.check_abend(response)
                
                if abend:
                    status = f"*** ABEND: {abend} ***"
                    findings.append((key, status, resp_len))
                elif resp_len != baseline_len:
                    diff = resp_len - baseline_len
                    status = f"DIFFERENT SCREEN ({resp_len} chars, {'+' if diff > 0 else ''}{diff})"
                    findings.append((key, status, resp_len))
                else:
                    status = "same"
                
                output.append(f"  {key:>6}: {status}")
            except Exception as e:
                output.append(f"  {key:>6}: ERROR - {e}")
        
        if findings:
            output.append(f"\n{'='*60}")
            output.append(f"FINDINGS: {len(findings)} keys produced different responses:")
            for key, status, resp_len in findings:
                output.append(f"  {key}: {status}")
        else:
            output.append("\nNo different responses detected.")
        
        return '\n'.join(output)
    except Exception as e:
        return f"Error scanning AID keys: {e}"


# =========================================================================
# DATA CONVERSION UTILITIES
# =========================================================================

@mcp.tool()
def convert_ascii_to_ebcdic(text: str) -> str:
    """
    Convert ASCII text to EBCDIC hex bytes.
    
    Useful for understanding how text is encoded on the mainframe wire.
    
    Args:
        text: ASCII text to convert
    """
    try:
        api = _get_api()
        ebcdic = api.ascii_to_ebcdic(text)
        return f"ASCII: \"{text}\"\nEBCDIC hex: {ebcdic.hex()}\nEBCDIC bytes: {list(ebcdic)}"
    except Exception as e:
        return f"Error converting: {e}"


@mcp.tool()
def convert_ebcdic_to_ascii(hex_data: str) -> str:
    """
    Convert EBCDIC hex bytes to ASCII text.
    
    Args:
        hex_data: Hex string of EBCDIC bytes (e.g., 'c8c5d3d3d6' = 'HELLO')
    """
    try:
        api = _get_api()
        data = bytes.fromhex(hex_data.replace(' ', ''))
        text = api.ebcdic_to_ascii(data)
        return f"EBCDIC hex: {hex_data}\nASCII: \"{text}\""
    except Exception as e:
        return f"Error converting: {e}"


@mcp.tool()
def encode_buffer_address(position: int) -> str:
    """
    Encode a screen position (0-1919) to a 2-byte 12-bit buffer address.
    
    Screen positions: row * 80 + col (0-indexed).
    Row 0, Col 0 = position 0. Row 23, Col 79 = position 1919.
    
    Args:
        position: Buffer position (0-1919 for 24x80 screen)
    """
    try:
        api = _get_api()
        addr = api.encode_buffer_address(position)
        row = position // 80
        col = position % 80
        return f"Position {position} (row {row+1}, col {col+1}) = address bytes: 0x{addr[0]:02x} 0x{addr[1]:02x} ({addr.hex()})"
    except Exception as e:
        return f"Error encoding address: {e}"


@mcp.tool()
def decode_buffer_address(byte1: int, byte2: int) -> str:
    """
    Decode a 2-byte buffer address to a screen position.
    
    Args:
        byte1: First address byte (0-255)
        byte2: Second address byte (0-255)
    """
    try:
        api = _get_api()
        pos = api.decode_buffer_address(byte1, byte2)
        row = pos // 80
        col = pos % 80
        return f"Address 0x{byte1:02x} 0x{byte2:02x} = position {pos} (row {row+1}, col {col+1})"
    except Exception as e:
        return f"Error decoding address: {e}"


# =========================================================================
# RECORDING & PLAYBACK
# =========================================================================

@mcp.tool()
def start_recording() -> str:
    """
    Start recording actions for later playback.
    
    All subsequent send_aid, send_raw, and replay operations will be recorded.
    Use stop_recording() to get the recorded actions.
    """
    try:
        api = _ensure_connected()
        api.record_start()
        return "Recording started. All send operations will be recorded."
    except Exception as e:
        return f"Error starting recording: {e}"


@mcp.tool()
def stop_recording() -> str:
    """
    Stop recording and return the list of recorded actions.
    These can be replayed with playback_recording().
    """
    try:
        api = _ensure_connected()
        actions = api.record_stop()
        
        if not actions:
            return "Recording stopped. No actions were recorded."
        
        # Store for playback
        api._last_recording = actions
        
        output = [f"Recording stopped. {len(actions)} actions recorded:"]
        for i, (action_type, data) in enumerate(actions):
            if action_type == 'AID':
                output.append(f"  {i+1}. AID: {data}")
            elif action_type == 'RAW':
                output.append(f"  {i+1}. RAW: {len(data)} bytes")
            elif action_type == 'LOG':
                output.append(f"  {i+1}. REPLAY: log #{data}")
        
        return '\n'.join(output)
    except Exception as e:
        return f"Error stopping recording: {e}"


@mcp.tool()
def playback_recording(delay: float = 0.5, repeat: int = 1) -> str:
    """
    Playback the last recorded actions.
    
    Args:
        delay: Seconds between each action (default: 0.5)
        repeat: Number of times to replay the full sequence (default: 1)
    """
    try:
        api = _ensure_connected()
        
        if not hasattr(api, '_last_recording') or not api._last_recording:
            return "No recording to playback. Use start_recording() and stop_recording() first."
        
        actions = api._last_recording
        
        output = [f"Playing back {len(actions)} actions x{repeat}..."]
        
        for rep in range(repeat):
            if repeat > 1:
                output.append(f"\nIteration {rep+1}/{repeat}:")
            api.playback(actions, delay=delay)
        
        output.append("\nPlayback complete.")
        
        lines = _parse_screen(api)
        output.append("\nFinal screen:")
        for i, line in enumerate(lines):
            output.append(f"{i+1:2}| {line}")
        
        return '\n'.join(output)
    except Exception as e:
        return f"Error during playback: {e}"


# =========================================================================
# FUZZING
# =========================================================================

@mcp.tool()
def fuzz_field(
    field_address: int,
    payloads: str = "overflow,decimal,control,sql,cics",
    cursor_address: int = -1,
    delay: float = 0.3
) -> str:
    """
    Fuzz a specific input field with various attack payloads.
    
    Sends a variety of malicious/edge-case payloads to test field validation:
    - overflow: Long strings to test buffer handling
    - decimal: Invalid packed decimal / zoned decimal values
    - control: EBCDIC control characters
    - sql: DB2 SQL injection attempts
    - cics: CICS transaction injection attempts
    
    Args:
        field_address: Buffer address of the target field
        payloads: Comma-separated payload categories to use
        cursor_address: Cursor position (-1 = same as field)
        delay: Seconds between each payload (default: 0.3)
    """
    try:
        api = _ensure_connected()
        categories = [p.strip().lower() for p in payloads.split(',')]
        
        fuzz_payloads = []
        
        if 'overflow' in categories:
            fuzz_payloads.extend([
                ('overflow', 'A' * 80),
                ('overflow', 'A' * 256),
                ('overflow', '9' * 80),
                ('overflow', '9' * 256),
                ('overflow', ' ' * 80),
            ])
        
        if 'decimal' in categories:
            fuzz_payloads.extend([
                ('decimal', '-1'),
                ('decimal', '-99999'),
                ('decimal', '99999999999'),
                ('decimal', '0.0001'),
                ('decimal', '1E10'),
                ('decimal', '.'),
                ('decimal', ',,,'),
                ('decimal', '000000'),
            ])
        
        if 'control' in categories:
            fuzz_payloads.extend([
                ('control', '\x00' * 10),
                ('control', '\xff' * 10),
                ('control', '\x01\x02\x03\x04\x05'),
            ])
        
        if 'sql' in categories:
            fuzz_payloads.extend([
                ('sql', "' OR 1=1 --"),
                ('sql', "'; DROP TABLE--"),
                ('sql', "1 UNION SELECT"),
                ('sql', "' OR ''='"),
                ('sql', "-1 OR 1=1"),
            ])
        
        if 'cics' in categories:
            fuzz_payloads.extend([
                ('cics', 'CEMT I TASK'),
                ('cics', 'CEDA VIEW'),
                ('cics', 'CEDF'),
                ('cics', 'CEBR'),
                ('cics', 'CESF LOGOFF'),
            ])
        
        field_addr = api.encode_buffer_address(field_address)
        if cursor_address < 0:
            cursor_addr = field_addr
        else:
            cursor_addr = api.encode_buffer_address(cursor_address)
        
        output = [f"Fuzzing field at address {field_address} with {len(fuzz_payloads)} payloads...", ""]
        findings = []
        
        for i, (category, payload) in enumerate(fuzz_payloads):
            try:
                display_payload = repr(payload)[:50]
                api.send_field(payload, cursor_addr, field_addr, add_space=True)
                time.sleep(delay)
                
                response = api.get_last_server()
                abend = api.check_abend(response)
                
                if abend:
                    findings.append((category, display_payload, f"ABEND: {abend}"))
                    output.append(f"  [{i+1}] {category}: {display_payload} -> *** ABEND: {abend} ***")
                else:
                    output.append(f"  [{i+1}] {category}: {display_payload} -> OK ({len(response)} chars)")
            except Exception as e:
                output.append(f"  [{i+1}] {category}: {display_payload} -> ERROR: {e}")
        
        if findings:
            output.append(f"\n{'='*60}")
            output.append(f"FINDINGS: {len(findings)} payloads triggered errors:")
            for cat, payload, result in findings:
                output.append(f"  [{cat}] {payload} -> {result}")
        else:
            output.append("\nNo crashes or abends detected.")
        
        return '\n'.join(output)
    except Exception as e:
        return f"Error fuzzing field: {e}"


@mcp.tool()
def fuzz_all_input_fields(
    payloads: str = "overflow,decimal,control,sql",
    delay: float = 0.3
) -> str:
    """
    Automatically discover all input fields on the current screen and fuzz each one.
    
    This combines field discovery with fuzzing - no manual field address needed.
    
    Args:
        payloads: Comma-separated payload categories (overflow, decimal, control, sql, cics)
        delay: Seconds between each payload (default: 0.3)
    """
    try:
        api = _ensure_connected()
        fields = api.get_input_fields()
        
        if not fields:
            return "No input fields found on current screen."
        
        output = [f"Found {len(fields)} input fields. Fuzzing each one...", ""]
        
        total_findings = []
        
        for fi, field in enumerate(fields):
            addr = field['address']
            length = field['length']
            output.append(f"\n--- Field [{fi}] Address: {addr}, Length: {length} ---")
            
            result = fuzz_field(
                field_address=addr,
                payloads=payloads,
                delay=delay
            )
            output.append(result)
        
        return '\n'.join(output)
    except Exception as e:
        return f"Error fuzzing all fields: {e}"


@mcp.tool()
def fuzz_transaction_codes(
    wordlist: str = "cics-default-transactions.txt",
    delay: float = 0.3,
    max_codes: int = 0,
    clear_between: bool = True
) -> str:
    """
    Discover valid CICS transaction codes by sending each one and analyzing responses.
    
    Sends transaction codes from a wordlist and flags any that produce unique responses
    (different from the typical "INVALID TRANSACTION" error).
    
    Args:
        wordlist: Transaction code wordlist file (default: cics-default-transactions.txt)
        delay: Seconds between each attempt (default: 0.3)
        max_codes: Maximum codes to test (0 = all)
        clear_between: Send CLEAR between each attempt (default: True)
    """
    try:
        api = _ensure_connected()
        
        # Load wordlist
        filepath = HACK3270_DIR / 'injections' / wordlist
        if not filepath.exists():
            filepath = Path(wordlist)
        if not filepath.exists():
            return f"Wordlist not found: {wordlist}"
        
        values = api.load_injection_file(str(filepath))
        if max_codes > 0:
            values = values[:max_codes]
        
        output = [f"Testing {len(values)} transaction codes from {filepath.name}...", ""]
        
        # Get baseline error response
        baseline_responses = {}
        findings = []
        abends = []
        
        for i, code in enumerate(values):
            try:
                if clear_between:
                    api.send_aid('CLEAR')
                    time.sleep(0.2)
                
                api.send_command(code)
                time.sleep(delay)
                
                response = api.get_last_server()
                resp_len = len(response)
                
                abend = api.check_abend(response)
                
                if abend:
                    abends.append((code, abend))
                    output.append(f"  {code:>8}: *** ABEND: {abend} ***")
                else:
                    baseline_responses[resp_len] = baseline_responses.get(resp_len, 0) + 1
                    
                    # We'll flag unique responses at the end
                    findings.append((code, resp_len, response[:100]))
                
                if (i + 1) % 25 == 0:
                    output.append(f"  Progress: {i+1}/{len(values)}")
            except Exception as e:
                output.append(f"  {code:>8}: ERROR - {e}")
        
        # Find the most common response length (baseline)
        if baseline_responses:
            common_len = max(baseline_responses, key=baseline_responses.get)
            
            output.append(f"\nBaseline response length: {common_len} (seen {baseline_responses[common_len]} times)")
            
            unique = [(code, rlen, preview) for code, rlen, preview in findings if rlen != common_len]
            
            if unique:
                output.append(f"\nUNIQUE RESPONSES ({len(unique)} found):")
                for code, rlen, preview in unique:
                    output.append(f"  {code}: {rlen} chars - \"{preview.strip()[:60]}\"")
        
        if abends:
            output.append(f"\nABENDS ({len(abends)}):")
            for code, abend in abends:
                output.append(f"  {code}: {abend}")
        
        output.append(f"\nScan complete: {len(values)} codes tested.")
        
        return '\n'.join(output)
    except Exception as e:
        return f"Error scanning transaction codes: {e}"


# =========================================================================
# PROTOCOL-LEVEL TOOLS
# =========================================================================

@mcp.tool()
def get_protocol_info() -> str:
    """
    Get TN3270 protocol information about the current connection.
    
    Returns:
    - Protocol mode (TN3270 vs TN3270E)
    - Screen dimensions
    - Available AID keys seen on current screen
    - Protocol constants for reference
    """
    try:
        api = _ensure_connected()
        
        mode = "TN3270E" if api.is_tn3270e() else "TN3270"
        
        output = [
            "TN3270 Protocol Information:",
            f"  Mode: {mode}",
            f"  Screen: {api.SCREEN_ROWS} rows x {api.SCREEN_COLS} cols ({api.SCREEN_ROWS * api.SCREEN_COLS} positions)",
            "",
            "AID Key Reference:",
            "  ENTER=0x7D  CLEAR=0x6D  SYSREQ=0xF0",
            "  PF1=0xF1  PF2=0xF2  PF3=0xF3  PF4=0xF4  PF5=0xF5  PF6=0xF6",
            "  PF7=0xF7  PF8=0xF8  PF9=0xF9  PF10=0x7A PF11=0x7B PF12=0x7C",
            "  PF13=0xC1 PF14=0xC2 PF15=0xC3 PF16=0xC4 PF17=0xC5 PF18=0xC6",
            "  PF19=0xC7 PF20=0xC8 PF21=0xC9 PF22=0x4A PF23=0x4B PF24=0x4C",
            "  PA1=0x6C  PA2=0x6E  PA3=0x6B",
            "",
            "TN3270 Orders:",
            "  SBA (0x11) - Set Buffer Address",
            "  SF  (0x1D) - Start Field",
            "  SFE (0x29) - Start Field Extended",
            "  SA  (0x28) - Set Attribute",
            "  MF  (0x2C) - Modify Field",
            "  RA  (0x3C) - Repeat to Address",
            "  EUA (0x12) - Erase Unprotected to Address",
            "  IC  (0x13) - Insert Cursor",
            "  PT  (0x05) - Program Tab",
            "  GE  (0x08) - Graphic Escape",
        ]
        
        if mode == "TN3270E":
            output.extend([
                "",
                "TN3270E Header: 5 bytes (00 00 00 00 01) prepended to all client data.",
            ])
        
        return '\n'.join(output)
    except Exception as e:
        return f"Error getting protocol info: {e}"


# =========================================================================
# INJECTION FILE OPERATIONS
# =========================================================================

@mcp.tool()
def get_wordlist_contents(filename: str, start: int = 1, count: int = 50) -> str:
    """
    Read entries from a wordlist file with pagination.
    
    Args:
        filename: Wordlist filename in injections/ directory
        start: Starting entry number (1-indexed)
        count: Number of entries to show
    """
    try:
        filepath = HACK3270_DIR / 'injections' / filename
        if not filepath.exists():
            filepath = Path(filename)
        if not filepath.exists():
            return f"File not found: {filename}"
        
        with open(filepath, 'r') as f:
            all_lines = [line.rstrip('\n\r') for line in f if line.strip()]
        
        total = len(all_lines)
        start_idx = max(0, start - 1)
        end_idx = min(total, start_idx + count)
        
        output = [f"Wordlist: {filepath.name} ({total:,} total entries)"]
        output.append(f"Showing entries {start_idx+1}-{end_idx}:")
        
        for i in range(start_idx, end_idx):
            output.append(f"  {i+1:>6}: {all_lines[i]}")
        
        if end_idx < total:
            output.append(f"\n  ... {total - end_idx} more entries")
        
        return '\n'.join(output)
    except Exception as e:
        return f"Error reading wordlist: {e}"


# =========================================================================
# MAIN
# =========================================================================

if __name__ == "__main__":
    mcp.run(transport="stdio")
