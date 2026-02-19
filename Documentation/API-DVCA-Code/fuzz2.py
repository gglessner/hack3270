#!/usr/bin/env python3
"""
fuzz2.py - Dynamic Field Discovery Fuzzer

Analyzes the current screen to discover input fields,
then fuzzes each field with various payloads.

Uses the hack3270_api library for screen parsing and packet building.
"""

import sys
import os
import time
import random
import socket

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'hack3270_libs'))
from hack3270_api import Hack3270API

# Configuration
API_HOST = '127.0.0.1'
API_PORT = 31337
DELAY = 0.3
DEBUG = False  # Set to True to see packet details


def generate_payloads(field_length, is_numeric):
    """Generate fuzzing payloads for a field."""
    payloads = []
    
    # Overflow payloads
    payloads.append(('overflow_2x', 'A' * (field_length * 2), False))
    payloads.append(('overflow_10x', 'X' * (field_length * 10), False))
    
    # Numeric field specific
    if is_numeric:
        payloads.append(('negative', '-' * field_length, False))
        payloads.append(('alpha_in_num', 'ABCD', False))
        payloads.append(('max_int', '9' * 18, False))
        payloads.append(('min_int', '-' + '9' * 17, False))
    
    # Special strings
    payloads.append(('nulls', '\x00' * 10, True))
    payloads.append(('high_values', b'\xFF' * 10, True))
    payloads.append(('binary_mix', bytes(range(256)), True))
    
    # TN3270 order injection
    payloads.append(('sba_inject', b'\x11\x11\x11\x11', True))
    payloads.append(('sf_inject', b'\x1D\x00\x1D\x00', True))
    payloads.append(('sfe_inject', b'\x29\x01\xC0\x00', True))
    
    # CICS/COBOL specific
    payloads.append(('packed_invalid', b'\xFF\xFF\xFF\xFF', True))
    payloads.append(('low_values', b'\x00\x00\x00\x00', True))
    
    # SQL injection attempts
    payloads.append(('sql_quote', "' OR '1'='1", False))
    payloads.append(('sql_comment', "'; --", False))
    
    # Random binary
    payloads.append(('random_16', bytes([random.randint(0, 255) for _ in range(16)]), True))
    payloads.append(('random_64', bytes([random.randint(0, 255) for _ in range(64)]), True))
    
    return payloads


def build_fuzz_packet(api, fields, fuzz_idx, fuzz_data, is_binary, debug=False):
    """Build a packet with all input fields, one fuzzed."""
    SBA = 0x11
    AID_ENTER = 0x7D
    IAC_EOR = bytes([0xFF, 0xEF])
    
    input_fields = [f for f in fields if not f['protected']]
    
    # Build packet with TN3270E header if needed
    if api.is_tn3270e():
        packet = bytes([0x00, 0x00, 0x00, 0x00, 0x01, AID_ENTER])
    else:
        packet = bytes([AID_ENTER])
    
    # Cursor at first input field
    if input_fields:
        cursor_addr = api.encode_buffer_address(input_fields[0]['address'])
    else:
        cursor_addr = bytes([0x40, 0x40])
    packet += cursor_addr
    
    if debug:
        print(f"    [DEBUG] Cursor addr bytes: {cursor_addr.hex()}")
    
    # Add each input field
    for idx, field in enumerate(input_fields):
        field_addr = api.encode_buffer_address(field['address'])
        
        if idx == fuzz_idx:
            if is_binary:
                field_data = fuzz_data if isinstance(fuzz_data, bytes) else fuzz_data.encode('latin-1')
            else:
                field_data = api.ascii_to_ebcdic(fuzz_data)
        else:
            if field['value']:
                field_data = field['value']
            else:
                field_data = api.ascii_to_ebcdic(' ')
        
        packet += bytes([SBA]) + field_addr + field_data
        
        if debug:
            print(f"    [DEBUG] Field {idx}: addr={field['address']} -> bytes={field_addr.hex()}, data_len={len(field_data)}")
    
    packet += IAC_EOR
    
    if debug:
        print(f"    [DEBUG] Total packet: {len(packet)} bytes")
        print(f"    [DEBUG] First 50 bytes: {packet[:50].hex()}")
    
    return packet


def main():
    api = Hack3270API(host=API_HOST, port=API_PORT)
    
    print("=" * 60)
    print("Dynamic Field Discovery Fuzzer")
    print("=" * 60)
    
    try:
        api.connect()
        print("[+] Connected to API\n")
        
        # Get current screen
        print("[*] Analyzing current screen...")
        raw_data = api.get_last_server_raw()
        
        if not raw_data:
            print("[!] No screen data available. Make sure a screen is displayed.")
            return
        
        if DEBUG:
            print(f"[DEBUG] Raw data length: {len(raw_data)} bytes")
            print(f"[DEBUG] First 100 bytes: {raw_data[:100].hex()}")
        
        # Parse fields using API
        all_fields = api.parse_screen_fields(raw_data)
        input_fields = api.get_input_fields(raw_data)
        
        print(f"[+] Found {len(all_fields)} total fields")
        print(f"[+] Found {len(input_fields)} input fields:\n")
        
        if not input_fields:
            print("[!] No input fields found on this screen.")
            return
        
        # Display discovered fields
        for idx, field in enumerate(input_fields):
            attrs = []
            if field['numeric']:
                attrs.append('numeric')
            if field['hidden']:
                attrs.append('hidden')
            attr_str = f" ({', '.join(attrs)})" if attrs else ""
            
            val_preview = ''
            if field['value']:
                try:
                    val_preview = api.ebcdic_to_ascii(field['value'])[:20]
                    val_preview = f" = '{val_preview}'"
                except:
                    val_preview = f" = <{len(field['value'])} bytes>"
            
            encoded = api.encode_buffer_address(field['address'])
            print(f"  [{idx}] Addr: {field['address']:04d} ({encoded.hex()})  Len: {field['length']:3d}{attr_str}{val_preview}")
        
        print()
        
        # Confirm
        if '--yes' not in sys.argv:
            print("[!] WARNING: Fuzzing may cause application crashes or abends.")
            print("    Use --yes flag to skip this prompt.")
            try:
                confirm = input("    Continue? (y/N): ").strip().lower()
                if confirm != 'y':
                    print("[*] Aborted.")
                    return
            except EOFError:
                print("[*] Non-interactive mode detected. Use --yes to proceed.")
                return
        
        print("\n" + "=" * 60)
        print("Starting Fuzzing")
        print("=" * 60 + "\n")
        
        abends_found = []
        crashes_found = []
        total_tests = 0
        
        # Fuzz each input field
        for field_idx, field in enumerate(input_fields):
            print(f"\n[*] Fuzzing field {field_idx} (addr {field['address']}, len {field['length']})")
            
            payloads = generate_payloads(field['length'], field['numeric'])
            
            for payload_name, payload_data, is_binary in payloads:
                total_tests += 1
                
                try:
                    show_debug = DEBUG and (total_tests == 1)
                    packet = build_fuzz_packet(api, all_fields, field_idx, payload_data, is_binary, debug=show_debug)
                    
                    if show_debug:
                        print(f"    [DEBUG] Sending packet...")
                    
                    desc = f'Fuzz: Field_{field_idx}/{payload_name}'
                    api.send_raw(packet, desc)
                    time.sleep(DELAY)
                    
                    response = api.get_last_server()
                    
                    # Check for abend using API
                    abend = api.check_abend(response)
                    if abend:
                        print(f"  [!] ABEND {abend} with payload: {payload_name}")
                        abends_found.append({
                            'field': field_idx,
                            'payload': payload_name,
                            'abend': abend
                        })
                    else:
                        print(f"  [.] {payload_name}: OK")
                        
                except socket.error as e:
                    print(f"\n[!!!] CONNECTION LOST during {payload_name}")
                    print(f"      Field: {field_idx}, Payload: {payload_name}")
                    crashes_found.append({
                        'field': field_idx,
                        'payload': payload_name,
                        'error': str(e)
                    })
                    
                    print("[*] Attempting to reconnect...")
                    try:
                        api.disconnect()
                        time.sleep(2)
                        api.connect()
                        print("[+] Reconnected!")
                        
                        raw_data = api.get_last_server_raw()
                        if raw_data:
                            all_fields = api.parse_screen_fields(raw_data)
                    except:
                        print("[!] Reconnect failed. Stopping.")
                        break
        
        # Summary
        print("\n" + "=" * 60)
        print("Fuzzing Complete")
        print("=" * 60)
        print(f"\nTotal tests: {total_tests}")
        print(f"Abends found: {len(abends_found)}")
        print(f"Crashes found: {len(crashes_found)}")
        
        if abends_found:
            print("\nAbend Details:")
            for a in abends_found:
                print(f"  - Field {a['field']}, Payload: {a['payload']}, Abend: {a['abend']}")
        
        if crashes_found:
            print("\nCrash Details:")
            for c in crashes_found:
                print(f"  - Field {c['field']}, Payload: {c['payload']}, Error: {c['error']}")
        
    except Exception as e:
        print(f"[!] Error: {e}")
        raise
    finally:
        api.disconnect()
        print("\n[*] Disconnected")


if __name__ == '__main__':
    main()
