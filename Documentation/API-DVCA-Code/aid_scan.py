#!/usr/bin/env python3
"""
aid_scan.py - Scan AIDs to find hidden screens
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'hack3270_libs'))

import time
from hack3270_api import Hack3270API

# AIDs to scan (excluding ENTER, CLEAR, PF5)
AIDS = [
    'PA1', 'PA2', 'PA3',
    'PF1', 'PF2', 'PF3', 'PF4', 'PF6', 'PF7', 'PF8', 'PF9',
    'PF10', 'PF11', 'PF12', 'PF13', 'PF14', 'PF15', 'PF16', 'PF17',
    'PF18', 'PF19', 'PF20', 'PF21', 'PF22', 'PF23', 'PF24',
]

DELAY = 0.5


def main():
    api = Hack3270API()
    api.connect()
    
    print("AID Scanner")
    print("=" * 40)
    
    # Get baseline
    baseline = api.get_last_server()
    baseline_len = len(baseline)
    print(f"Baseline: {baseline_len} chars\n")
    
    found = []
    
    for aid in AIDS:
        api.send_aid(aid)
        time.sleep(DELAY)
        
        response = api.get_last_server()
        
        # Skip "invalid attention" messages
        if 'Invalid attention' in response:
            print(f"{aid}: ignored")
            continue
        
        if len(response) != baseline_len:
            print(f"{aid}: *** NEW SCREEN ({len(response)} chars) ***")
            found.append(aid)
        else:
            print(f"{aid}: same")
    
    if found:
        print(f"\n*** Found {len(found)} new screen(s): {', '.join(found)} ***")
    
    api.disconnect()


if __name__ == '__main__':
    main()
