#!/usr/bin/env python3

import tk
from tkinter import Tk
import libhack3270
from tkinter import ttk
import argparse
import logging

def main():

    desc = 'Hack3270 - The TN3270 Penetration Testting Toolkit'
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
    arg_parser.add_argument("IP", help="TN3270 server IP address")
    arg_parser.add_argument("PORT", help="TN3270 server port")



    args = arg_parser.parse_args()

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

    root = Tk()
    style = ttk.Style()
    style.theme_create( "hackallthethings", parent="alt", settings={
            "TButton": {"configure": {"background": "light grey" , "anchor": "center", "relief": "solid"} },
            "Treeview": {"configure": {"background": "white" } },
            "TNotebook": {"configure": {"tabmargins": [2, 5, 2, 0] } },
            "TNotebook.Tab": {
                "configure": {"padding": [5, 1], "background": "dark grey" },
                "map":       {"background": [("selected", "light grey"), ('disabled','grey')], 
                            "expand": [("selected", [1, 1, 1, 0])] } } } )
    style.theme_use("hackallthethings")
    my_gui = tk.tkhack3270(root, style, hack3270, logfile=None,loglevel=args.loglevel)
    

main()

