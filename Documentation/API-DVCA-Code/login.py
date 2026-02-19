#!/usr/bin/env python3
"""
login.py - Connect and login to DVCA
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'hack3270_libs'))

import time
from hack3270_api import Hack3270API

# Login sequence IDs from dvca-login.db
LOGIN = [7, 11]
MCGM_ID = 32
DELAY = 3.0


def main():
    api = Hack3270API()
    api.load_db('dvca-login.db')
    api.connect()
    
    print("DVCA Login")
    print("=" * 60)
    
    # Get initial screen
    screen = api.get_last_server()
    print("Initial screen received")
    
    # Check what screen we're on
    if 'CLEAR the screen or hit ENTER' in screen:
        # Splash screen - need to send CLEAR
        print("Splash screen detected, sending CLEAR...")
        api.send_aid('CLEAR')
        time.sleep(DELAY)
        screen = api.get_last_server()
        
        if 'TSO Logon' in screen:
            print("SUCCESS: At TSO Logon prompt\n")
        else:
            print("WARNING: TSO Logon prompt not detected")
            api.disconnect()
            return
            
    elif 'TSO Logon' in screen:
        # Already at logon prompt
        print("Already at TSO Logon prompt\n")
        
    else:
        print("Unknown screen state")
        print(f"Screen contains: {screen[:200]}...")
        api.disconnect()
        return
    
    # Send login sequence
    print("Sending login sequence...")
    for log_id in LOGIN:
        print(f"  Sending ID {log_id}...")
        api.send_client_data(log_id)
        time.sleep(DELAY)
    
    # Pause and check for ***
    time.sleep(DELAY)
    screen = api.get_last_server()
    if '***' in screen:
        print("Found *** after login")
    else:
        print("WARNING: *** not found after login")
    
    # Send ENTER
    print("Sending ENTER...")
    api.send_aid('ENTER')
    time.sleep(DELAY)
    
    # Check for ***
    screen = api.get_last_server()
    if '***' in screen:
        print("Found *** after ENTER")
    else:
        print("WARNING: *** not found after ENTER")
    
    # Send CLEAR twice
    print("Sending CLEAR...")
    api.send_aid('CLEAR')
    time.sleep(DELAY)
    
    print("Sending CLEAR...")
    api.send_aid('CLEAR')
    time.sleep(DELAY)
    
    # Send MCGM
    print(f"Sending MCGM (ID {MCGM_ID})...")
    api.send_client_data(MCGM_ID)
    time.sleep(DELAY)
    
    # Send PF5
    print("Sending PF5...")
    api.send_aid('PF5')
    time.sleep(DELAY)
    
    # Check for Options
    screen = api.get_last_server()
    print("=" * 60)
    if 'Option' in screen:
        print("SUCCESS: At DVCA Options menu!")
    else:
        print(f"Result: {screen[:200]}...")
    
    api.disconnect()


if __name__ == '__main__':
    main()
