#!/usr/bin/env python3
"""
order_fuzz.py - TN3270 Order Injection Attack Surface Mapper

Targeted fuzzing of TN3270 data stream orders to map vulnerabilities
in mainframe terminal handling. Tests various order byte sequences
that could cause parsing errors, buffer manipulation, or session drops.

Uses the hack3270_api library for packet building and connection management.
"""

import sys
sys.path.insert(0, '..')

import time
from hack3270_api import Hack3270API

# Configuration
API_HOST = '127.0.0.1'
API_PORT = 31337
DELAY = 0.5  # Slightly longer delay for stability

# Default field addresses (can be overridden)
CURSOR_ADDR = 423   # Default cursor position
FIELD_ADDR = 583    # Default field to inject into

# Additional order bytes not in the API
EXTENDED_ORDERS = {
    0x05: 'PT',    # Program Tab
    0x08: 'GE',    # Graphic Escape
    0x11: 'SBA',   # Set Buffer Address
    0x12: 'EUA',   # Erase Unprotected to Address
    0x13: 'IC',    # Insert Cursor
    0x1D: 'SF',    # Start Field
    0x28: 'SA',    # Set Attribute
    0x29: 'SFE',   # Start Field Extended
    0x2C: 'MF',    # Modify Field
    0x3C: 'RA',    # Repeat to Address
}


def build_injection_packet(api, injection_bytes, use_field=True):
    """Build a packet with injected bytes in the data portion."""
    SBA = 0x11
    AID_ENTER = 0x7D
    IAC_EOR = bytes([0xFF, 0xEF])
    
    cursor = api.encode_buffer_address(CURSOR_ADDR)
    field = api.encode_buffer_address(FIELD_ADDR)
    
    # Build packet with TN3270E header if needed
    if api.is_tn3270e():
        packet = bytes([0x00, 0x00, 0x00, 0x00, 0x01, AID_ENTER]) + cursor
    else:
        packet = bytes([AID_ENTER]) + cursor
    
    if use_field:
        # Normal field structure with injection in data
        packet += bytes([SBA]) + field + injection_bytes
    else:
        # Raw injection after AID + cursor
        packet += injection_bytes
    
    packet += IAC_EOR
    return packet


def reconnect(api):
    """Attempt to reconnect to the API."""
    try:
        api.disconnect()
    except:
        pass
    
    time.sleep(1)
    
    try:
        api.connect()
        return True
    except:
        return False


def run_test(api, name, injection_bytes, use_field=True):
    """Run a single injection test."""
    hex_display = injection_bytes.hex()
    print(f"  [{name}] {hex_display[:40]}{'...' if len(hex_display) > 40 else ''}", end=" ", flush=True)
    
    try:
        packet = build_injection_packet(api, injection_bytes, use_field)
        desc = f'Fuzz: Order/{name}'
        api.send_raw(packet, desc)
        time.sleep(DELAY)
        
        response = api.get_last_server()
        
        if not response or len(response) == 0:
            print("*** NO RESPONSE ***")
            return 'no_response', injection_bytes
        
        # Check for abend using API
        abend = api.check_abend(response)
        if abend:
            print(f"*** ABEND: {abend} ***")
            return 'abend', injection_bytes
        
        print("OK")
        return 'ok', None
        
    except (ConnectionError, ConnectionResetError, ConnectionAbortedError, 
            BrokenPipeError, OSError) as e:
        print(f"*** CRASH: {e} ***")
        return 'crash', injection_bytes
    except Exception as e:
        if "10053" in str(e) or "10054" in str(e):
            print(f"*** CRASH: {e} ***")
            return 'crash', injection_bytes
        print(f"ERROR: {e}")
        return 'error', injection_bytes


def main():
    api = Hack3270API(host=API_HOST, port=API_PORT)
    
    print("=" * 75)
    print("TN3270 ORDER INJECTION ATTACK SURFACE MAPPER")
    print("=" * 75)
    print()
    print("Testing order byte sequences that may cause:")
    print("  - Connection termination (DoS)")
    print("  - Buffer address manipulation")
    print("  - Field attribute corruption")
    print("  - Screen position hijacking")
    print()
    print(f"Using API orders: {list(api.ORDERS.values())}")
    print()
    
    api.connect()
    print("Connected!\n")
    
    findings = {
        'crash': [],
        'abend': [],
        'no_response': [],
    }
    
    total_tests = 0
    
    # Use orders from API
    orders_to_test = api.ORDERS.copy()
    
    # ==========================================================================
    # TEST 1: Single Order Bytes
    # ==========================================================================
    print("=" * 75)
    print("TEST 1: Single Order Bytes (repeated)")
    print("=" * 75)
    
    for order_byte, order_name in orders_to_test.items():
        for repeat in [1, 2, 4, 8, 16]:
            total_tests += 1
            injection = bytes([order_byte] * repeat)
            result, data = run_test(api, f"{order_name}x{repeat}", injection)
            
            if result == 'crash':
                findings['crash'].append((f"{order_name}x{repeat}", injection))
                print("\n  !!! Reconnecting...")
                if not reconnect(api):
                    print("  Failed to reconnect. Exiting.")
                    break
                print("  Reconnected.\n")
            elif result in findings:
                findings[result].append((f"{order_name}x{repeat}", injection))
    
    if not api.test_connection():
        if not reconnect(api):
            print("Connection lost. Exiting.")
            return
    
    # ==========================================================================
    # TEST 2: SBA with Various Address Bytes
    # ==========================================================================
    print()
    print("=" * 75)
    print("TEST 2: SBA (0x11) with Various Address Encodings")
    print("=" * 75)
    
    sba_tests = [
        ("SBA-NULL", bytes([0x11, 0x00, 0x00])),
        ("SBA-MIN", bytes([0x11, 0x40, 0x40])),
        ("SBA-MAX", bytes([0x11, 0x7F, 0x7F])),
        ("SBA-FF", bytes([0x11, 0xFF, 0xFF])),
        ("SBA-HALF", bytes([0x11, 0x40])),
        ("SBA-ONLY", bytes([0x11])),
        ("SBA-TRIPLE", bytes([0x11, 0x11, 0x11])),
        ("SBA-ROW0", bytes([0x11, 0x40, 0x40])),
        ("SBA-ROW24", bytes([0x11, 0x5D, 0x7F])),
        ("SBA-OVERFLOW", bytes([0x11, 0x7F, 0x7F, 0x7F, 0x7F])),
        ("SBA-CHAIN", bytes([0x11, 0x40, 0x40, 0x11, 0x40, 0x50])),
    ]
    
    for name, injection in sba_tests:
        total_tests += 1
        result, data = run_test(api, name, injection)
        
        if result == 'crash':
            findings['crash'].append((name, injection))
            print("\n  !!! Reconnecting...")
            if not reconnect(api):
                break
            print("  Reconnected.\n")
        elif result in findings:
            findings[result].append((name, injection))
    
    if not api.test_connection():
        if not reconnect(api):
            print("Connection lost. Exiting.")
            return
    
    # ==========================================================================
    # TEST 3: Start Field (SF) Variations
    # ==========================================================================
    print()
    print("=" * 75)
    print("TEST 3: Start Field (0x1D) Attribute Variations")
    print("=" * 75)
    
    sf_tests = [
        ("SF-ONLY", bytes([0x1D])),
        ("SF-NULL", bytes([0x1D, 0x00])),
        ("SF-PROTECTED", bytes([0x1D, 0x20])),
        ("SF-NUMERIC", bytes([0x1D, 0x10])),
        ("SF-HIDDEN", bytes([0x1D, 0x0C])),
        ("SF-INTENSE", bytes([0x1D, 0x08])),
        ("SF-MDT", bytes([0x1D, 0x01])),
        ("SF-ALLBITS", bytes([0x1D, 0xFF])),
        ("SF-CHAIN", bytes([0x1D, 0x00, 0x1D, 0x20, 0x1D, 0x0C])),
        ("SF-MANY", bytes([0x1D, 0x00] * 20)),
    ]
    
    for name, injection in sf_tests:
        total_tests += 1
        result, data = run_test(api, name, injection)
        
        if result == 'crash':
            findings['crash'].append((name, injection))
            print("\n  !!! Reconnecting...")
            if not reconnect(api):
                break
            print("  Reconnected.\n")
        elif result in findings:
            findings[result].append((name, injection))
    
    if not api.test_connection():
        if not reconnect(api):
            print("Connection lost. Exiting.")
            return
    
    # ==========================================================================
    # TEST 4: Start Field Extended (SFE) Variations
    # ==========================================================================
    print()
    print("=" * 75)
    print("TEST 4: Start Field Extended (0x29) Variations")
    print("=" * 75)
    
    sfe_tests = [
        ("SFE-ONLY", bytes([0x29])),
        ("SFE-COUNT0", bytes([0x29, 0x00])),
        ("SFE-COUNT1", bytes([0x29, 0x01, 0xC0, 0x00])),
        ("SFE-COUNT2", bytes([0x29, 0x02, 0xC0, 0x00, 0x41, 0xF1])),
        ("SFE-COUNTFF", bytes([0x29, 0xFF])),
        ("SFE-PARTIAL", bytes([0x29, 0x02, 0xC0])),
        ("SFE-HIGHLIGHT", bytes([0x29, 0x01, 0x41, 0xF1])),
        ("SFE-COLOR", bytes([0x29, 0x01, 0x42, 0xF4])),
        ("SFE-BADTYPE", bytes([0x29, 0x01, 0xFF, 0xFF])),
        ("SFE-MANY", bytes([0x29, 0x05, 0xC0, 0x00, 0x41, 0xF1, 0x42, 0xF4, 0x43, 0x00, 0x45, 0x00])),
    ]
    
    for name, injection in sfe_tests:
        total_tests += 1
        result, data = run_test(api, name, injection)
        
        if result == 'crash':
            findings['crash'].append((name, injection))
            print("\n  !!! Reconnecting...")
            if not reconnect(api):
                break
            print("  Reconnected.\n")
        elif result in findings:
            findings[result].append((name, injection))
    
    if not api.test_connection():
        if not reconnect(api):
            print("Connection lost. Exiting.")
            return
    
    # ==========================================================================
    # TEST 5: Repeat to Address (RA) Variations
    # ==========================================================================
    print()
    print("=" * 75)
    print("TEST 5: Repeat to Address (0x3C) Variations")
    print("=" * 75)
    
    ra_tests = [
        ("RA-ONLY", bytes([0x3C])),
        ("RA-PARTIAL", bytes([0x3C, 0x40])),
        ("RA-NOCHAR", bytes([0x3C, 0x40, 0x40])),
        ("RA-SPACE", bytes([0x3C, 0x40, 0x40, 0x40])),
        ("RA-NULL", bytes([0x3C, 0x40, 0x40, 0x00])),
        ("RA-STAR", bytes([0x3C, 0x5D, 0x7F, 0x5C])),
        ("RA-MAXADDR", bytes([0x3C, 0x7F, 0x7F, 0xC1])),
        ("RA-CHAIN", bytes([0x3C, 0x40, 0x50, 0x40, 0x3C, 0x40, 0x60, 0x40])),
    ]
    
    for name, injection in ra_tests:
        total_tests += 1
        result, data = run_test(api, name, injection)
        
        if result == 'crash':
            findings['crash'].append((name, injection))
            print("\n  !!! Reconnecting...")
            if not reconnect(api):
                break
            print("  Reconnected.\n")
        elif result in findings:
            findings[result].append((name, injection))
    
    if not api.test_connection():
        if not reconnect(api):
            print("Connection lost. Exiting.")
            return
    
    # ==========================================================================
    # TEST 6: Erase Unprotected to Address (EUA) Variations
    # ==========================================================================
    print()
    print("=" * 75)
    print("TEST 6: Erase Unprotected to Address (0x12) Variations")
    print("=" * 75)
    
    eua_tests = [
        ("EUA-ONLY", bytes([0x12])),
        ("EUA-PARTIAL", bytes([0x12, 0x40])),
        ("EUA-START", bytes([0x12, 0x40, 0x40])),
        ("EUA-END", bytes([0x12, 0x5D, 0x7F])),
        ("EUA-MAX", bytes([0x12, 0x7F, 0x7F])),
        ("EUA-CHAIN", bytes([0x12, 0x40, 0x50, 0x12, 0x40, 0x60])),
    ]
    
    for name, injection in eua_tests:
        total_tests += 1
        result, data = run_test(api, name, injection)
        
        if result == 'crash':
            findings['crash'].append((name, injection))
            print("\n  !!! Reconnecting...")
            if not reconnect(api):
                break
            print("  Reconnected.\n")
        elif result in findings:
            findings[result].append((name, injection))
    
    if not api.test_connection():
        if not reconnect(api):
            print("Connection lost. Exiting.")
            return
    
    # ==========================================================================
    # TEST 7: Mixed Order Sequences
    # ==========================================================================
    print()
    print("=" * 75)
    print("TEST 7: Mixed Order Sequences")
    print("=" * 75)
    
    mixed_tests = [
        ("MIX-SBA-SF", bytes([0x11, 0x40, 0x40, 0x1D, 0x00])),
        ("MIX-SF-SBA", bytes([0x1D, 0x00, 0x11, 0x40, 0x40])),
        ("MIX-SBA-SFE", bytes([0x11, 0x40, 0x40, 0x29, 0x01, 0xC0, 0x00])),
        ("MIX-ALL", bytes([0x11, 0x40, 0x40, 0x1D, 0x00, 0x29, 0x01, 0xC0, 0x00, 0x13])),
        ("MIX-NESTED-SBA", bytes([0x11, 0x11, 0x40, 0x40])),
        ("MIX-PT-IC", bytes([0x05, 0x13, 0x05, 0x13])),
        ("MIX-GE-DATA", bytes([0x08, 0xC1, 0x08, 0xC2])),
        ("MIX-CHAOS", bytes([0x11, 0x1D, 0x29, 0x3C, 0x12, 0x13, 0x05, 0x08])),
    ]
    
    for name, injection in mixed_tests:
        total_tests += 1
        result, data = run_test(api, name, injection)
        
        if result == 'crash':
            findings['crash'].append((name, injection))
            print("\n  !!! Reconnecting...")
            if not reconnect(api):
                break
            print("  Reconnected.\n")
        elif result in findings:
            findings[result].append((name, injection))
    
    if not api.test_connection():
        if not reconnect(api):
            print("Connection lost. Exiting.")
            return
    
    # ==========================================================================
    # TEST 8: Telnet/TN3270E Control Sequences
    # ==========================================================================
    print()
    print("=" * 75)
    print("TEST 8: Telnet/TN3270E Control Injection")
    print("=" * 75)
    
    telnet_tests = [
        ("TEL-IAC", bytes([0xFF])),
        ("TEL-IAC-IAC", bytes([0xFF, 0xFF])),
        ("TEL-EOR", bytes([0xFF, 0xEF])),
        ("TEL-SE", bytes([0xFF, 0xF0])),
        ("TEL-NOP", bytes([0xFF, 0xF1])),
        ("TEL-DM", bytes([0xFF, 0xF2])),
        ("TEL-BRK", bytes([0xFF, 0xF3])),
        ("TEL-IP", bytes([0xFF, 0xF4])),
        ("TEL-AO", bytes([0xFF, 0xF5])),
        ("TEL-AYT", bytes([0xFF, 0xF6])),
        ("TEL-EC", bytes([0xFF, 0xF7])),
        ("TEL-EL", bytes([0xFF, 0xF8])),
        ("TEL-GA", bytes([0xFF, 0xF9])),
        ("TEL-SB", bytes([0xFF, 0xFA, 0x28, 0x00, 0xFF, 0xF0])),
        ("TEL-WILL", bytes([0xFF, 0xFB, 0x28])),
        ("TEL-WONT", bytes([0xFF, 0xFC, 0x28])),
        ("TEL-DO", bytes([0xFF, 0xFD, 0x28])),
        ("TEL-DONT", bytes([0xFF, 0xFE, 0x28])),
        ("TEL-FLOOD", bytes([0xFF] * 20)),
        ("TEL-MIX", bytes([0xFF, 0xEF, 0xFF, 0xF0, 0xFF, 0xFB, 0x00])),
    ]
    
    for name, injection in telnet_tests:
        total_tests += 1
        result, data = run_test(api, name, injection)
        
        if result == 'crash':
            findings['crash'].append((name, injection))
            print("\n  !!! Reconnecting...")
            if not reconnect(api):
                break
            print("  Reconnected.\n")
        elif result in findings:
            findings[result].append((name, injection))
    
    if not api.test_connection():
        if not reconnect(api):
            print("Connection lost. Exiting.")
            return
    
    # ==========================================================================
    # TEST 9: Raw Order Injection (no field wrapper)
    # ==========================================================================
    print()
    print("=" * 75)
    print("TEST 9: Raw Order Injection (no SBA field wrapper)")
    print("=" * 75)
    
    raw_tests = [
        ("RAW-SBA", bytes([0x11, 0x40, 0x40])),
        ("RAW-SF", bytes([0x1D, 0x00])),
        ("RAW-SFE", bytes([0x29, 0x01, 0xC0, 0x00])),
        ("RAW-RA-FILL", bytes([0x3C, 0x5D, 0x7F, 0x40])),
        ("RAW-EUA-ALL", bytes([0x12, 0x5D, 0x7F])),
        ("RAW-IC", bytes([0x13])),
        ("RAW-PT", bytes([0x05])),
    ]
    
    for name, injection in raw_tests:
        total_tests += 1
        result, data = run_test(api, name, injection, use_field=False)
        
        if result == 'crash':
            findings['crash'].append((name, injection))
            print("\n  !!! Reconnecting...")
            if not reconnect(api):
                break
            print("  Reconnected.\n")
        elif result in findings:
            findings[result].append((name, injection))
    
    # ==========================================================================
    # SUMMARY
    # ==========================================================================
    print()
    print("=" * 75)
    print("ATTACK SURFACE MAPPING COMPLETE")
    print("=" * 75)
    print(f"Total tests: {total_tests}")
    print()
    
    if findings['crash']:
        print(f"!!! CRASHES FOUND: {len(findings['crash'])} !!!")
        print("-" * 40)
        for name, data in findings['crash']:
            print(f"  {name}: {data.hex()}")
        print()
    
    if findings['abend']:
        print(f"!!! ABENDS FOUND: {len(findings['abend'])} !!!")
        print("-" * 40)
        for name, data in findings['abend']:
            print(f"  {name}: {data.hex()}")
        print()
    
    if findings['no_response']:
        print(f"NO RESPONSE: {len(findings['no_response'])}")
        print("-" * 40)
        for name, data in findings['no_response']:
            print(f"  {name}: {data.hex()}")
        print()
    
    if not any(findings.values()):
        print("No vulnerabilities found - all orders handled gracefully.")
    
    try:
        api.disconnect()
    except:
        pass
    print("\nDisconnected.")


if __name__ == '__main__':
    main()
