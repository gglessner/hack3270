#!/usr/bin/env python3
"""
check_hidden.py - Detect hidden fields on current screen
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'hack3270_libs'))

from hack3270_api import Hack3270API


def main():
    api = Hack3270API()
    api.connect()
    
    print("Analyzing screen for hidden fields...\n")
    
    result = api.analyze_hidden()
    
    if result.get('status') != 'ok':
        print(f"Error: {result.get('message')}")
        api.disconnect()
        return
    
    print(f"Screen: {result['total_bytes']} bytes")
    print(f"Hidden fields: {result['hidden_count']}")
    
    if result['hidden_count'] > 0:
        print("\n" + "-" * 40)
        for i, field in enumerate(result['hidden_fields'], 1):
            data = field.get('data', '').strip()
            marker = "***" if data else ""
            print(f"[{i}] {field['type']} @ {field['position']}: {data or '(empty)'} {marker}")
        
        # Alert on non-empty fields
        with_data = [f for f in result['hidden_fields'] if f.get('data', '').strip()]
        if with_data:
            print(f"\n*** ALERT: {len(with_data)} hidden field(s) contain data! ***")
    
    api.disconnect()


if __name__ == '__main__':
    main()
