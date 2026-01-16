#!/usr/bin/env python3
"""
login2.py - DVCA login using raw packet construction (no .db file)

Demonstrates building TN3270 packets programmatically with:
- Username: DVCA
- Password: DVCA  
- Transaction: MCGM
"""

import sys
sys.path.insert(0, '..')

import time
from hack3270_api import Hack3270API

# Configuration
API_HOST = '127.0.0.1'
API_PORT = 31337
DELAY = 3.0

# Login credentials (ASCII - will be converted to EBCDIC)
USERNAME = 'DVCA'
PASSWORD = 'DVCA'
TRANSACTION = 'MCGM'

# Screen positions (from captured packets)
# These are buffer addresses in 12-bit encoding
USERNAME_CURSOR = bytes([0x5B, 0xF4])
USERNAME_FIELD = bytes([0x5B, 0xF0])
PASSWORD_CURSOR = bytes([0xC1, 0xD5])
PASSWORD_FIELD = bytes([0xC1, 0xD1])


def main():
    api = Hack3270API(host=API_HOST, port=API_PORT)
    
    print("DVCA Login Script (Raw Packets)")
    print("=" * 50)
    print(f"Username: {USERNAME}")
    print(f"Password: {PASSWORD}")
    print(f"Transaction: {TRANSACTION}")
    print()
    
    # Connect to API
    print("Connecting to API...")
    api.connect()
    print("Connected!\n")
    
    try:
        # Check initial screen
        time.sleep(1)
        screen = api.get_last_server()
        
        if "CLEAR the screen" in screen:
            print("Splash screen detected, sending CLEAR...")
            api.send_aid('CLEAR')
            time.sleep(DELAY)
        
        # Verify at TSO logon
        screen = api.get_last_server()
        if "TSO" not in screen and "Logon" not in screen:
            print(f"Warning: May not be at login screen")
        
        # Step 1: Send username
        print(f"Sending username: {USERNAME}")
        api.send_field(USERNAME, USERNAME_CURSOR, USERNAME_FIELD, add_space=True)
        time.sleep(DELAY)
        
        # Step 2: Send password
        print(f"Sending password: {PASSWORD}")
        api.send_field(PASSWORD, PASSWORD_CURSOR, PASSWORD_FIELD)
        time.sleep(DELAY)
        
        # Check for login success or "IN USE"
        screen = api.get_last_server()
        if "IN USE" in screen:
            print("ERROR: USERID DVCA IN USE - restart DVCA container")
            return
        
        # Step 3: Handle post-login screens
        print("Handling post-login screens...")
        
        # Look for *** prompt
        if "***" in screen:
            print("  Found *** prompt, sending ENTER...")
            api.send_aid('ENTER')
            time.sleep(DELAY)
        
        screen = api.get_last_server()
        if "***" in screen:
            print("  Found another *** prompt, sending CLEAR...")
            api.send_aid('CLEAR')
            time.sleep(DELAY)
        
        # Send extra CLEAR to get to command mode
        print("Sending CLEAR...")
        api.send_aid('CLEAR')
        time.sleep(DELAY)
        
        # Step 4: Send MCGM transaction
        print(f"Sending transaction: {TRANSACTION}")
        api.send_command(TRANSACTION)
        time.sleep(DELAY)
        
        # Step 5: Send PF5 to get to options menu
        print("Sending PF5...")
        api.send_aid('PF5')
        time.sleep(DELAY)
        
        # Verify at options menu
        screen = api.get_last_server()
        if "Option" in screen:
            print("\n" + "=" * 50)
            print("SUCCESS: At MCGM Options menu!")
            print("=" * 50)
        else:
            print("\nMay not be at Options menu. Check terminal.")
        
    finally:
        api.disconnect()
        print("\nDisconnected.")


if __name__ == '__main__':
    main()
