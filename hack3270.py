#!/usr/bin/env python3
"""
Hack3270 - The TN3270 Penetration Testing Toolkit

Main entry point for the hack3270 application.
"""
__author__ = 'Garland Glessner'
__license__ = "GPL-3.0"

import sys
import os
_here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_here, 'hackterm-core'))
sys.path.insert(0, os.path.join(_here, 'hack3270_libs'))
import gui
import libhack3270
import argparse
import logging

def main():

    desc = 'Hack3270 - The TN3270 Penetration Testing Toolkit'
    epilog = '''Example:
    %(prog)s -n prod_lpar3 10.10.10.10 992 -l 31337 --proxy_ip 0.0.0.0 --debug
    %(prog)s -o'''
    arg_parser = argparse.ArgumentParser(description=desc,
                        usage='%(prog)s [options] IP PORT',
                        formatter_class=argparse.RawTextHelpFormatter,
                        epilog=epilog)
    arg_parser.add_argument('-n', '--name', help='Project name (default: %(default)s)', default="pentest")
    arg_parser.add_argument('-p', '--proxy_port', help='Local TN3270 proxy port (default: %(default)s)', default=3271)
    arg_parser.add_argument('--proxy_ip', help="Local TN3270 proxy IP (default: %(default)s)", default="127.0.0.1")
    arg_parser.add_argument('-t', '--tls', help="Enable TLS encryption for server connection (default: %(default)s)", action="store_true", default=False)
    arg_parser.add_argument('-o', '--offline', help="Offline log analysis mode (default: %(default)s)", action="store_true", default=False)
    arg_parser.add_argument('-d', '--debug', help="Print debugging statements (default: %(default)s)", action="store_const", dest="loglevel", const=logging.DEBUG, default=logging.WARNING)
    arg_parser.add_argument("IP", nargs='?', help="TN3270 server IP address")
    arg_parser.add_argument("PORT", nargs='?', help="TN3270 server port")

    args = arg_parser.parse_args()

    # Validate: IP and PORT are required unless in offline mode
    if not args.offline and (args.IP is None or args.PORT is None):
        arg_parser.error("IP and PORT are required unless using -o/--offline mode")

    hack3270 = libhack3270.hack3270(
                 server_ip = args.IP,
                 server_port = args.PORT, 
                 proxy_port=args.proxy_port, 
                 proxy_ip=args.proxy_ip, 
                 offline_mode = args.offline,
                 project_name = args.name, 
                 loglevel=args.loglevel,
                 tls_enabled = args.tls,
                 logfile=None
    )

    # Launch PySide6 GUI
    # The root and style parameters are kept for compatibility but not used
    my_gui = gui.tkhack3270(None, None, hack3270, logfile=None, loglevel=args.loglevel)


if __name__ == '__main__':
    try:
        main()
    except libhack3270.Hack3270Error as e:
        print(f"\nError: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\nUnexpected error: {e}", file=sys.stderr)
        sys.exit(1)
