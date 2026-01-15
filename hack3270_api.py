#!/usr/bin/env python3
"""
hack3270_api.py - Python client library for hack3270 Web API

Connect to hack3270 proxy on port 31337 to automate TN3270 testing.

Example:
    from hack3270_api import Hack3270API
    
    with Hack3270API() as api:
        api.load_db('pentest.db')
        api.send_client_data(42)  # Replay log ID 42
        
        # Wait for specific response
        if api.wait_for('READY', timeout=5):
            print("System ready!")
"""

import socket
import json
import sqlite3
import base64
import time
import re


class Hack3270APIError(Exception):
    """Base exception for hack3270 API errors"""
    pass


class Hack3270API:
    """Client library for hack3270 Web API."""
    
    HOST = '127.0.0.1'
    PORT = 31337
    TIMEOUT = 10.0
    BUFFER = 65536
    SCREEN_COLS = 80
    SCREEN_ROWS = 24
    
    # EBCDIC <-> ASCII conversion tables
    A2E = {
        ' ': 0x40, 'a': 0x81, 'b': 0x82, 'c': 0x83, 'd': 0x84, 'e': 0x85, 'f': 0x86, 'g': 0x87,
        'h': 0x88, 'i': 0x89, 'j': 0x91, 'k': 0x92, 'l': 0x93, 'm': 0x94, 'n': 0x95, 'o': 0x96,
        'p': 0x97, 'q': 0x98, 'r': 0x99, 's': 0xa2, 't': 0xa3, 'u': 0xa4, 'v': 0xa5, 'w': 0xa6,
        'x': 0xa7, 'y': 0xa8, 'z': 0xa9, 'A': 0xc1, 'B': 0xc2, 'C': 0xc3, 'D': 0xc4, 'E': 0xc5,
        'F': 0xc6, 'G': 0xc7, 'H': 0xc8, 'I': 0xc9, 'J': 0xd1, 'K': 0xd2, 'L': 0xd3, 'M': 0xd4,
        'N': 0xd5, 'O': 0xd6, 'P': 0xd7, 'Q': 0xd8, 'R': 0xd9, 'S': 0xe2, 'T': 0xe3, 'U': 0xe4,
        'V': 0xe5, 'W': 0xe6, 'X': 0xe7, 'Y': 0xe8, 'Z': 0xe9, '0': 0xf0, '1': 0xf1, '2': 0xf2,
        '3': 0xf3, '4': 0xf4, '5': 0xf5, '6': 0xf6, '7': 0xf7, '8': 0xf8, '9': 0xf9,
        '.': 0x4b, '<': 0x4c, '(': 0x4d, '+': 0x4e, '|': 0x4f, '&': 0x50, '!': 0x5a, '$': 0x5b,
        '*': 0x5c, ')': 0x5d, ';': 0x5e, '-': 0x60, '/': 0x61, ',': 0x6b, '%': 0x6c, '_': 0x6d,
        '>': 0x6e, '?': 0x6f, ':': 0x7a, '#': 0x7b, '@': 0x7c, "'": 0x7d, '=': 0x7e, '"': 0x7f,
    }
    E2A = {v: k for k, v in A2E.items()}  # Reverse mapping
    
    def __init__(self, host=None, port=None, timeout=None):
        self.host = host or self.HOST
        self.port = port or self.PORT
        self.timeout = timeout or self.TIMEOUT
        self._sock = None
        self._db = None
        self._cur = None
        self._recording = False
        self._recorded = []
    
    def __enter__(self):
        self.connect()
        return self
    
    def __exit__(self, *args):
        self.close_db()
        self.disconnect()
    
    # =========================================================================
    # Connection
    # =========================================================================
    
    def connect(self):
        """Connect to hack3270 API."""
        if self._sock:
            return
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.settimeout(self.timeout)
            self._sock.connect((self.host, self.port))
        except socket.error as e:
            self._sock = None
            raise Hack3270APIError(f"Connection failed: {e}")
    
    def disconnect(self):
        """Disconnect from API."""
        if self._sock:
            try:
                self._sock.close()
            except:
                pass
            self._sock = None
    
    def is_connected(self):
        """Check if connected to API."""
        if not self._sock:
            return False
        try:
            # Try a ping to verify connection is alive
            self._sock.setblocking(False)
            try:
                self._sock.send(b'ping\n')
                self._sock.setblocking(True)
                self._sock.settimeout(1.0)
                data = self._sock.recv(self.BUFFER)
                self._sock.settimeout(self.timeout)
                return bool(data)
            except:
                self._sock.setblocking(True)
                self._sock.settimeout(self.timeout)
                return False
        except:
            return False
    
    def reconnect(self):
        """Reconnect to API if disconnected."""
        self.disconnect()
        self.connect()
    
    def _send(self, data):
        """Send data to API."""
        if not self._sock:
            raise Hack3270APIError("Not connected")
        if isinstance(data, str):
            data = data.encode('utf-8')
        self._sock.sendall(data)
    
    def _recv(self):
        """Receive data from API."""
        if not self._sock:
            raise Hack3270APIError("Not connected")
        data = self._sock.recv(self.BUFFER)
        if not data:
            raise Hack3270APIError("Connection closed")
        return data.decode('utf-8')
    
    def _recv_raw(self):
        """Receive raw bytes from API."""
        if not self._sock:
            raise Hack3270APIError("Not connected")
        data = self._sock.recv(self.BUFFER)
        if not data:
            raise Hack3270APIError("Connection closed")
        return data
    
    # =========================================================================
    # Database (direct SQLite3 access)
    # =========================================================================
    
    def load_db(self, filename):
        """Load a pentest.db session file."""
        self.close_db()
        try:
            self._db = sqlite3.connect(filename)
            self._cur = self._db.cursor()
        except sqlite3.Error as e:
            raise Hack3270APIError(f"Database error: {e}")
    
    def close_db(self):
        """Close the database."""
        if self._db:
            self._db.close()
        self._db = None
        self._cur = None
    
    def db_get_raw(self, log_id):
        """Get raw bytes from a log entry."""
        if not self._cur:
            raise Hack3270APIError("No database loaded")
        self._cur.execute("SELECT RAW_DATA FROM Logs WHERE ID = ?", (log_id,))
        row = self._cur.fetchone()
        return row[0] if row else None
    
    def db_get_log(self, log_id):
        """Get a log entry: (ID, TIMESTAMP, C_S, NOTES, DATA_LEN, RAW_DATA)"""
        if not self._cur:
            raise Hack3270APIError("No database loaded")
        self._cur.execute(
            "SELECT ID, TIMESTAMP, C_S, NOTES, DATA_LEN, RAW_DATA FROM Logs WHERE ID = ?",
            (log_id,)
        )
        return self._cur.fetchone()
    
    def db_get_logs(self, direction=None, limit=None):
        """Get log entries. direction='C' or 'S' to filter."""
        if not self._cur:
            raise Hack3270APIError("No database loaded")
        sql = "SELECT ID, TIMESTAMP, C_S, NOTES, DATA_LEN FROM Logs"
        params = []
        if direction:
            sql += " WHERE C_S = ?"
            params.append(direction)
        sql += " ORDER BY ID ASC"
        if limit:
            sql += " LIMIT ?"
            params.append(limit)
        self._cur.execute(sql, params)
        return self._cur.fetchall()
    
    # =========================================================================
    # API Commands
    # =========================================================================
    
    def ping(self):
        """Ping the API."""
        self._send('ping\n')
        return self._recv().strip()
    
    def get_last_server(self):
        """Get last server response as ASCII text."""
        self._send('GET_LAST_SERVER\n')
        resp = self._recv()
        if resp.startswith('OK:'):
            parts = resp[3:].split(':', 1)
            return parts[1].rstrip('\n') if len(parts) >= 2 else ''
        return resp
    
    def get_last_server_raw(self):
        """Get last server response as raw bytes (base64 decoded)."""
        self._send('GET_LAST_SERVER_RAW\n')
        resp = self._recv()
        try:
            result = json.loads(resp)
            if result.get('status') == 'ok':
                return base64.b64decode(result['data_b64'])
            raise Hack3270APIError(result.get('message', 'Unknown error'))
        except json.JSONDecodeError:
            raise Hack3270APIError(f"Invalid response: {resp}")
    
    def send_aid(self, aid):
        """Send an AID key (ENTER, CLEAR, PF1-24, PA1-3, etc.)"""
        self._send(f'SEND_AID:{aid}\n')
        resp = self._recv().strip()
        if resp.startswith('ERROR:'):
            raise Hack3270APIError(resp[6:])
        if self._recording:
            self._recorded.append(('AID', aid))
        return resp
    
    def send_raw(self, data):
        """Send raw bytes to the server."""
        header = f"SEND_RAW:{len(data)}\n"
        self._sock.sendall(header.encode('utf-8') + data)
        resp = self._recv()
        if self._recording:
            self._recorded.append(('RAW', data))
        return resp
    
    def send_client_data(self, log_id):
        """Replay client data from a log entry."""
        raw = self.db_get_raw(log_id)
        if raw is None:
            raise Hack3270APIError(f"Log {log_id} not found")
        if self._recording:
            self._recorded.append(('LOG', log_id))
        return self.send_raw(raw)
    
    def analyze_hidden(self):
        """Analyze last server response for hidden fields."""
        self._send('ANALYZE_HIDDEN\n')
        try:
            return json.loads(self._recv())
        except json.JSONDecodeError as e:
            raise Hack3270APIError(f"Invalid response: {e}")
    
    # =========================================================================
    # Response Handling
    # =========================================================================
    
    def wait_for(self, pattern, timeout=None, poll_interval=0.2):
        """
        Wait until pattern appears in server response.
        
        Args:
            pattern: String or regex pattern to match
            timeout: Max seconds to wait (default: self.timeout)
            poll_interval: Seconds between checks
            
        Returns:
            True if pattern found, False if timeout
        """
        timeout = timeout or self.timeout
        start = time.time()
        
        # Compile regex if needed
        if isinstance(pattern, str):
            regex = re.compile(re.escape(pattern), re.IGNORECASE)
        else:
            regex = pattern
        
        while time.time() - start < timeout:
            response = self.get_last_server()
            if regex.search(response):
                return True
            time.sleep(poll_interval)
        
        return False
    
    def wait_for_change(self, timeout=None, poll_interval=0.2):
        """
        Wait for screen to change from current state.
        
        Returns:
            New response text if changed, None if timeout
        """
        timeout = timeout or self.timeout
        start = time.time()
        original = self.get_last_server()
        
        while time.time() - start < timeout:
            current = self.get_last_server()
            if current != original:
                return current
            time.sleep(poll_interval)
        
        return None
    
    # =========================================================================
    # Screen Analysis
    # =========================================================================
    
    def get_screen_text(self):
        """
        Get screen as plain text (control codes stripped).
        Returns list of 24 lines, 80 chars each.
        """
        response = self.get_last_server()
        
        # Remove common control code patterns [0xNN], [Name], etc.
        text = re.sub(r'\[0x[0-9a-fA-F]+\]', '', response)
        text = re.sub(r'\[[^\]]+\]', '', text)
        
        # Pad/split into screen lines
        text = text.ljust(self.SCREEN_COLS * self.SCREEN_ROWS)
        lines = []
        for i in range(self.SCREEN_ROWS):
            start = i * self.SCREEN_COLS
            lines.append(text[start:start + self.SCREEN_COLS])
        
        return lines
    
    def find_text(self, pattern):
        """
        Find text pattern on screen.
        
        Args:
            pattern: String or regex to find
            
        Returns:
            List of (row, col, match) tuples (0-indexed)
        """
        lines = self.get_screen_text()
        
        if isinstance(pattern, str):
            regex = re.compile(re.escape(pattern), re.IGNORECASE)
        else:
            regex = pattern
        
        results = []
        for row, line in enumerate(lines):
            for match in regex.finditer(line):
                results.append((row, match.start(), match.group()))
        
        return results
    
    def find_field(self, label):
        """
        Find field value by its label.
        Looks for 'label:' or 'label .' pattern and returns text after it.
        
        Args:
            label: Field label text
            
        Returns:
            Field value (stripped) or None if not found
        """
        lines = self.get_screen_text()
        full_text = ''.join(lines)
        
        # Look for common patterns: "Label:" or "Label . . ."
        patterns = [
            rf'{re.escape(label)}\s*:\s*(\S+)',
            rf'{re.escape(label)}\s*\.+\s*(\S+)',
            rf'{re.escape(label)}\s+(\S+)',
        ]
        
        for pat in patterns:
            match = re.search(pat, full_text, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        
        return None
    
    def get_text_at(self, row, col, length=None):
        """
        Get text at specific screen position.
        
        Args:
            row: Row number (0-23)
            col: Column number (0-79)
            length: Characters to read (default: to end of line)
            
        Returns:
            Text at position
        """
        lines = self.get_screen_text()
        if 0 <= row < len(lines):
            line = lines[row]
            if length:
                return line[col:col + length]
            return line[col:]
        return ''
    
    # =========================================================================
    # Data Conversion
    # =========================================================================
    
    def ascii_to_ebcdic(self, s):
        """Convert ASCII string to EBCDIC bytes."""
        return bytes(self.A2E.get(c, 0x40) for c in s)
    
    def ebcdic_to_ascii(self, data):
        """Convert EBCDIC bytes to ASCII string."""
        if isinstance(data, str):
            data = data.encode('latin-1')
        return ''.join(self.E2A.get(b, ' ') for b in data)
    
    # =========================================================================
    # Field Injection
    # =========================================================================
    
    def get_inject_template(self, log_id, mask='*'):
        """
        Get preamble/postamble from a captured packet for injection.
        Uses LOCAL database (not server's database).
        Returns dict with 'preamble' and 'postamble' as bytes, plus 'mask_length'.
        """
        # Get raw data from local database
        raw_data = self.db_get_raw(log_id)
        if raw_data is None:
            return {'status': 'error', 'message': f'Log ID {log_id} not found'}
        
        # Convert ASCII mask to EBCDIC
        ebcdic_mask = self.A2E.get(mask)
        if ebcdic_mask is None:
            return {'status': 'error', 'message': f'Cannot convert mask char to EBCDIC'}
        
        # Find preamble (before mask)
        preamble_count = 0
        for x in range(len(raw_data)):
            if raw_data[x] != ebcdic_mask:
                preamble_count += 1
            else:
                break
        
        # Count mask length
        mask_count = 0
        for x in range(preamble_count, len(raw_data)):
            if raw_data[x] == ebcdic_mask:
                mask_count += 1
            else:
                break
        
        if mask_count == 0:
            return {'status': 'error', 'message': 'Mask not found in data'}
        
        # Split into preamble and postamble
        preamble = raw_data[:preamble_count]
        postamble = raw_data[preamble_count + mask_count:]
        
        return {
            'status': 'ok',
            'log_id': log_id,
            'mask_length': mask_count,
            'preamble': preamble,
            'postamble': postamble
        }
    
    def load_injection_file(self, filename):
        """Load injection values from file (one per line)."""
        with open(filename, 'r') as f:
            return [line.rstrip('\n\r') for line in f if line.strip()]
    
    def inject(self, template, value, mode='TRUNC'):
        """
        Build and send an injection packet.
        
        Args:
            template: Result from get_inject_template()
            value: ASCII string to inject
            mode: 'TRUNC' (truncate/pad), 'SKIP' (skip if too long), 'OVERFLOW'
            
        Returns:
            Response from server, or None if skipped
        """
        preamble = template['preamble']
        postamble = template['postamble']
        mask_len = template['mask_length']
        
        # Convert to EBCDIC
        ebcdic = self.ascii_to_ebcdic(value)
        
        # Handle modes
        if mode == 'SKIP' and len(ebcdic) > mask_len:
            return None
        
        if mode == 'TRUNC' or (mode == 'OVERFLOW' and len(ebcdic) < mask_len):
            ebcdic = ebcdic[:mask_len]
            if len(ebcdic) < mask_len:
                ebcdic += bytes([0x40] * (mask_len - len(ebcdic)))
        
        packet = preamble + ebcdic + postamble
        return self.send_raw(packet)
    
    # =========================================================================
    # Automation
    # =========================================================================
    
    def replay_sequence(self, log_ids, delay=0.5):
        """
        Replay multiple log entries with delay between each.
        
        Args:
            log_ids: List of log entry IDs to replay
            delay: Seconds between each replay
            
        Returns:
            List of responses
        """
        responses = []
        for log_id in log_ids:
            resp = self.send_client_data(log_id)
            responses.append({'id': log_id, 'response': resp})
            if delay > 0:
                time.sleep(delay)
        return responses
    
    def record_start(self):
        """Start recording actions for later playback."""
        self._recording = True
        self._recorded = []
    
    def record_stop(self):
        """
        Stop recording and return recorded actions.
        
        Returns:
            List of (action_type, data) tuples
        """
        self._recording = False
        return self._recorded.copy()
    
    def playback(self, actions, delay=0.5):
        """
        Playback recorded actions.
        
        Args:
            actions: List from record_stop()
            delay: Seconds between actions
        """
        for action_type, data in actions:
            if action_type == 'AID':
                self.send_aid(data)
            elif action_type == 'RAW':
                self.send_raw(data)
            elif action_type == 'LOG':
                self.send_client_data(data)
            if delay > 0:
                time.sleep(delay)


# Convenience function
def connect(host=None, port=None):
    """Create and connect an API client."""
    api = Hack3270API(host, port)
    api.connect()
    return api
