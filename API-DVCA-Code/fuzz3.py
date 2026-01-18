#!/usr/bin/env python3
"""
fuzz3.py - Protected & Hidden Field Fuzzer

Extends fuzz2.py to also fuzz protected and hidden fields.
This tests whether the server properly validates that "read-only"
data wasn't tampered with - a common security vulnerability.

Protected fields: Terminal prevents editing, but raw packets can modify
Hidden fields: Contains data not shown to user, often sensitive

Uses the hack3270_api library for screen parsing and packet building.
"""

import sys
import time
import random
import socket

sys.path.insert(0, '..')
from hack3270_api import Hack3270API

# Configuration
API_HOST = '127.0.0.1'
API_PORT = 31337
DELAY = 0.3
DEBUG = False

# What to fuzz
FUZZ_UNPROTECTED = True   # Normal input fields
FUZZ_PROTECTED = True     # Read-only fields (server may not expect changes)
FUZZ_HIDDEN = True        # Hidden fields (may contain sensitive data)

# TN3270 constants
AID_ENTER = 0x7D
SBA = 0x11
IAC_EOR = bytes([0xFF, 0xEF])

# Extended corruption patterns
CORRUPTION_PATTERNS = [
    'NOT FOUND', 'UNDEFINED', 'UNKNOWN TRANSACTION',
    'PROGRAM NOT', 'INVALID TRANSACTION'
]


def get_fuzzable_fields(api, raw_data=None):
    """Get fields to fuzz based on configuration."""
    all_fields = api.parse_screen_fields(raw_data)
    fuzzable = []
    
    for f in all_fields:
        if f['protected'] and f['hidden']:
            if FUZZ_HIDDEN:
                fuzzable.append(f)
        elif f['protected']:
            if FUZZ_PROTECTED:
                fuzzable.append(f)
        elif f['hidden']:
            if FUZZ_HIDDEN:
                fuzzable.append(f)
        else:
            if FUZZ_UNPROTECTED:
                fuzzable.append(f)
    
    return fuzzable, all_fields


def generate_payloads(field, is_protected, is_hidden):
    """Generate fuzzing payloads based on field type."""
    payloads = []
    field_length = field['length']
    
    # All fields get basic overflow tests
    payloads.append(('overflow_2x', 'A' * (field_length * 2), False))
    payloads.append(('overflow_10x', 'X' * min(field_length * 10, 500), False))
    
    # Binary injection
    payloads.append(('nulls', '\x00' * 10, True))
    payloads.append(('high_values', b'\xFF' * 10, True))
    
    # TN3270 order injection
    payloads.append(('sba_inject', b'\x11\x11\x11\x11', True))
    payloads.append(('sf_inject', b'\x1D\x00\x1D\x00', True))
    
    if is_protected:
        # Protected field specific - try to change read-only data
        payloads.append(('clear_protected', ' ' * field_length, False))
        payloads.append(('modify_protected', 'HACKED' * (field_length // 6 + 1), False))
        payloads.append(('numeric_inject', '99999999', False))
        
        # Try to inject commands/data that might be trusted
        payloads.append(('admin_inject', 'ADMIN', False))
        payloads.append(('root_inject', 'ROOT', False))
        payloads.append(('system_inject', 'SYSTEM', False))
    
    if is_hidden:
        # Hidden field specific - may contain session/auth data
        payloads.append(('session_clear', '\x00' * field_length, True))
        payloads.append(('session_modify', b'\xFF' * min(field_length, 32), True))
        payloads.append(('auth_bypass', 'Y' * field_length, False))
        payloads.append(('privilege_inject', 'ADMIN   ', False))
        
        # Try common auth values
        payloads.append(('true_inject', 'TRUE', False))
        payloads.append(('one_inject', '1', False))
        payloads.append(('yes_inject', 'YES', False))
    
    # Random binary for all
    payloads.append(('random_32', bytes([random.randint(0, 255) for _ in range(32)]), True))
    
    return payloads


def build_fuzz_packet(api, fuzz_field, fuzz_data, is_binary):
    """Build a packet modifying one specific field."""
    # Build packet with TN3270E header if needed
    if api.is_tn3270e():
        packet = bytes([0x00, 0x00, 0x00, 0x00, 0x01, AID_ENTER])
    else:
        packet = bytes([AID_ENTER])
    
    # Cursor at the fuzzed field
    cursor_addr = api.encode_buffer_address(fuzz_field['address'])
    packet += cursor_addr
    
    # Add ONLY the fuzzed field (to isolate the test)
    field_addr = api.encode_buffer_address(fuzz_field['address'])
    
    if is_binary:
        field_data = fuzz_data if isinstance(fuzz_data, bytes) else fuzz_data.encode('latin-1')
    else:
        field_data = api.ascii_to_ebcdic(fuzz_data)
    
    packet += bytes([SBA]) + field_addr + field_data
    packet += IAC_EOR
    
    return packet


def check_for_interesting(api, response, original_response=None):
    """Check for interesting responses."""
    results = []
    response_upper = response.upper()
    
    # Check for abend using API
    abend = api.check_abend(response)
    if abend:
        results.append(('ABEND', abend))
    
    # Corruption indicators
    for pattern in CORRUPTION_PATTERNS:
        if pattern in response_upper:
            results.append(('CORRUPTION', pattern))
    
    # Error messages that might indicate validation
    error_patterns = ['INVALID', 'ERROR', 'NOT AUTHORIZED', 'ACCESS DENIED',
                      'SECURITY', 'VIOLATION', 'PROTECTED']
    for pattern in error_patterns:
        if pattern in response_upper:
            results.append(('ERROR', pattern))
    
    # Success indicators (when modifying protected fields)
    success_patterns = ['UPDATED', 'SAVED', 'SUCCESS', 'COMPLETE', 'ACCEPTED']
    for pattern in success_patterns:
        if pattern in response_upper:
            results.append(('SUCCESS', pattern))
    
    # Check if response changed significantly (possible bypass)
    if original_response and len(response) != len(original_response):
        results.append(('LENGTH_CHANGE', f'{len(original_response)} -> {len(response)}'))
    
    return results


def main():
    api = Hack3270API(host=API_HOST, port=API_PORT)
    
    print("=" * 70)
    print("Protected & Hidden Field Fuzzer")
    print("=" * 70)
    print(f"\nFuzzing: Unprotected={FUZZ_UNPROTECTED}, Protected={FUZZ_PROTECTED}, Hidden={FUZZ_HIDDEN}")
    
    try:
        api.connect()
        print("[+] Connected to API\n")
        
        print("[*] Analyzing current screen...")
        raw_data = api.get_last_server_raw()
        
        if not raw_data:
            print("[!] No screen data available.")
            return
        
        # Get baseline response
        original_response = api.get_last_server()
        
        # Parse all fields using API
        fuzzable, all_fields = get_fuzzable_fields(api, raw_data)
        
        # Categorize fields
        unprotected = [f for f in all_fields if not f['protected'] and not f['hidden']]
        protected = [f for f in all_fields if f['protected'] and not f['hidden']]
        hidden = [f for f in all_fields if f['hidden']]
        
        print(f"\n[+] Field Analysis:")
        print(f"    Total fields:     {len(all_fields)}")
        print(f"    Unprotected:      {len(unprotected)}")
        print(f"    Protected:        {len(protected)}")
        print(f"    Hidden:           {len(hidden)}")
        print(f"    Will fuzz:        {len(fuzzable)}")
        
        if not fuzzable:
            print("\n[!] No fields to fuzz with current settings.")
            return
        
        # Display fields to fuzz
        print("\n[*] Fields to fuzz:")
        for idx, field in enumerate(fuzzable):
            attrs = []
            if field['protected']:
                attrs.append('PROTECTED')
            if field['hidden']:
                attrs.append('HIDDEN')
            if field['numeric']:
                attrs.append('numeric')
            attr_str = f" [{', '.join(attrs)}]" if attrs else ""
            
            val_preview = ''
            if field['value']:
                try:
                    val_preview = api.ebcdic_to_ascii(field['value'])[:30]
                    val_preview = f" = '{val_preview}'"
                except:
                    val_preview = f" = <{len(field['value'])} bytes>"
            
            encoded = api.encode_buffer_address(field['address'])
            print(f"  [{idx}] Addr: {field['address']:04d} ({encoded.hex()})  Len: {field['length']:3d}{attr_str}{val_preview}")
        
        print()
        
        # Confirm
        if '--yes' not in sys.argv:
            print("[!] WARNING: This fuzzer modifies protected/hidden fields.")
            print("    This may cause unexpected application behavior.")
            try:
                confirm = input("    Continue? (y/N): ").strip().lower()
                if confirm != 'y':
                    print("[*] Aborted.")
                    return
            except EOFError:
                print("[*] Non-interactive mode. Use --yes to proceed.")
                return
        
        print("\n" + "=" * 70)
        print("Starting Fuzzing")
        print("=" * 70)
        
        findings = []
        total_tests = 0
        last_successful_payload = None
        corruption_detected = False
        
        for field_idx, field in enumerate(fuzzable):
            if corruption_detected:
                print("\n[!!!] Stopping due to detected corruption.")
                break
            
            field_type = []
            if field['protected']:
                field_type.append('PROTECTED')
            if field['hidden']:
                field_type.append('HIDDEN')
            type_str = f" [{'/'.join(field_type)}]" if field_type else ""
            
            print(f"\n[*] Fuzzing field {field_idx} (addr {field['address']}, len {field['length']}){type_str}")
            
            payloads = generate_payloads(field, field['protected'], field['hidden'])
            
            for payload_name, payload_data, is_binary in payloads:
                total_tests += 1
                
                try:
                    packet = build_fuzz_packet(api, field, payload_data, is_binary)
                    api.send_raw(packet)
                    time.sleep(DELAY)
                    
                    response = api.get_last_server()
                    interesting = check_for_interesting(api, response, original_response)
                    
                    if interesting:
                        for finding_type, detail in interesting:
                            print(f"  [!] {finding_type}: {payload_name} -> {detail}")
                            findings.append({
                                'field': field_idx,
                                'address': field['address'],
                                'protected': field['protected'],
                                'hidden': field['hidden'],
                                'payload': payload_name,
                                'payload_data': repr(payload_data)[:100],
                                'type': finding_type,
                                'detail': detail
                            })
                            
                            # Check for corruption
                            if finding_type == 'CORRUPTION':
                                print(f"\n  [!!!] CORRUPTION DETECTED!")
                                print(f"        Field: {field_idx} (addr {field['address']})")
                                print(f"        Payload: {payload_name}")
                                print(f"        Data: {repr(payload_data)[:100]}")
                                print(f"        Previous: {last_successful_payload}")
                                corruption_detected = True
                                break
                    else:
                        print(f"  [.] {payload_name}: OK")
                        last_successful_payload = f"Field {field_idx}, {payload_name}"
                    
                    if corruption_detected:
                        break
                        
                except socket.error as e:
                    print(f"\n[!!!] CONNECTION LOST: {payload_name}")
                    findings.append({
                        'field': field_idx,
                        'address': field['address'],
                        'payload': payload_name,
                        'type': 'CRASH',
                        'detail': str(e)
                    })
                    
                    print("[*] Attempting reconnect...")
                    try:
                        api.disconnect()
                        time.sleep(2)
                        api.connect()
                        print("[+] Reconnected!")
                        raw_data = api.get_last_server_raw()
                        if raw_data:
                            fuzzable, all_fields = get_fuzzable_fields(api, raw_data)
                    except:
                        print("[!] Reconnect failed. Stopping.")
                        break
        
        # Summary
        print("\n" + "=" * 70)
        print("Fuzzing Complete")
        print("=" * 70)
        print(f"\nTotal tests: {total_tests}")
        print(f"Findings: {len(findings)}")
        
        if findings:
            # Group by type
            by_type = {}
            for f in findings:
                t = f['type']
                if t not in by_type:
                    by_type[t] = []
                by_type[t].append(f)
            
            print("\nFindings by type:")
            for ftype, items in by_type.items():
                print(f"\n  {ftype} ({len(items)}):")
                for item in items:
                    prot = "[PROT]" if item.get('protected') else ""
                    hid = "[HID]" if item.get('hidden') else ""
                    print(f"    - Field {item['field']} {prot}{hid}: {item['payload']} -> {item['detail']}")
        
    except Exception as e:
        print(f"[!] Error: {e}")
        raise
    finally:
        api.disconnect()
        print("\n[*] Disconnected")


if __name__ == '__main__':
    main()
