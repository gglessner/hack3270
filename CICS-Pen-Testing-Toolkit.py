#!/usr/bin/env python3

# CICS-Pen-Testing-Toolkit
# Copyright Garland Glessner (2022-2023)
# Contact email: gglessner@gmail.com
#
# This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
# of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# Project Contributors:
# ---------------------
#  Jan Nunez - email: theprobingteep@protonmail.com
#  Claire Ould
#  Jay Smith - email: CadmusOfThebes@protonmail.com
#  Chance Warren
#  Phil Young - email: mainframed767@gmail.com
# ---------------------

import sys
import getopt
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
import tkinter.scrolledtext as tkk
from re import search
import select
import lib3270
import sqlite3
import time
import datetime
import signal
import platform
from pathlib import Path
from tkinter import font

NAME = "CICS-Pen-Testing-Toolkit"
VERSION = "1.1.1"
PROJECT_NAME = "pentest"
SERVER_IP = ''
SERVER_PORT = 3270
PROXY_IP = "127.0.0.1"
PROXY_PORT = 3271
TLS_ENABLED = 0
BUFFER_MAX = 10000
root_height = 100
client_data = []
server_data = []
hack_on = 0
silence = 0
offline_mode = 0
inject_setup_capture = 0
inject_file_set = 0
inject_config_set = 0
inject_filename = ''
inject_mask_len = 0
inject_preamble = b''
inject_postample = b''
root = tk.Tk()
style = ttk.Style()
style.theme_create( "hackallthethings", parent="alt", settings={
        "TButton": {"configure": {"background": "light grey" , "anchor": "center", "relief": "solid"} },
        "Treeview": {"configure": {"background": "white" } },
        "TNotebook": {"configure": {"tabmargins": [2, 5, 2, 0] } },
        "TNotebook.Tab": {
            "configure": {"padding": [5, 1], "background": "grey" },
            "map":       {"background": [("selected", "light grey"), ('disabled','dark grey')], 
                          "expand": [("selected", [1, 1, 1, 0])] } } } )
style.theme_use("hackallthethings")
tabControl = ttk.Notebook(root)
tab1 = tk.Frame(tabControl, background="light grey")
tab2 = tk.Frame(tabControl, background="light grey")
tab3 = tk.Frame(tabControl, background="light grey")
tab4 = tk.Frame(tabControl, background="light grey")
tab5 = tk.Frame(tabControl, background="light grey")
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()
hack_prot = tk.IntVar(value = 1)
hack_sf = tk.IntVar(value = 1)
hack_sfe = tk.IntVar(value = 1)
hack_sa = tk.IntVar(value = 1)
hack_mf = tk.IntVar(value = 1)
hack_hf = tk.IntVar(value = 1)
hack_rnr = tk.IntVar(value = 1)
hack_ei = tk.IntVar(value = 1)
hack_hv = tk.IntVar(value = 1)
aid_no = tk.IntVar(value = 1)
aid_qreply = tk.IntVar(value = 1)
aid_enter = tk.IntVar(value = 0)
aid_pf1 = tk.IntVar(value = 1)
aid_pf2 = tk.IntVar(value = 1)
aid_pf3 = tk.IntVar(value = 1)
aid_pf4 = tk.IntVar(value = 1)
aid_pf5 = tk.IntVar(value = 1)
aid_pf6 = tk.IntVar(value = 1)
aid_pf7 = tk.IntVar(value = 1)
aid_pf8 = tk.IntVar(value = 1)
aid_pf9 = tk.IntVar(value = 1)
aid_pf10 = tk.IntVar(value = 1)
aid_pf11 = tk.IntVar(value = 1)
aid_pf12 = tk.IntVar(value = 1)
aid_pf13 = tk.IntVar(value = 1)
aid_pf14 = tk.IntVar(value = 1)
aid_pf15 = tk.IntVar(value = 1)
aid_pf16 = tk.IntVar(value = 1)
aid_pf17 = tk.IntVar(value = 1)
aid_pf18 = tk.IntVar(value = 1)
aid_pf19 = tk.IntVar(value = 1)
aid_pf20 = tk.IntVar(value = 1)
aid_pf21 = tk.IntVar(value = 1)
aid_pf22 = tk.IntVar(value = 1)
aid_pf23 = tk.IntVar(value = 1)
aid_pf24 = tk.IntVar(value = 1)
aid_oicr = tk.IntVar(value = 1)
aid_msr_mhs = tk.IntVar(value = 1)
aid_select = tk.IntVar(value = 1)
aid_pa1 = tk.IntVar(value = 1)
aid_pa2 = tk.IntVar(value = 1)
aid_pa3 = tk.IntVar(value = 1)
aid_clear = tk.IntVar(value = 0)
aid_sysreq = tk.IntVar(value = 1)
inject_enter = tk.IntVar(value = 1)
inject_clear = tk.IntVar(value = 0)
inject_mask = tk.StringVar(value = '*')
inject_key = tk.StringVar(value = 'ENTER')
inject_trunc = tk.StringVar(value = 'SKIP')
EXIT_LOOP = 0
hack_toggled = 0
last_db_id = 0
db_filename = ''
message_count = 0

def usage():
    print("\nUsage: " + sys.argv[0] + " [OPTIONS]\n")
    print("\t-n, --name\t\tProject name [Default: pentest]")
    print("\t-i, --ip\t\tServer IP address")
    print("\t-p, --port\t\tServer TCP port [Default: 3270]")
    print("\t-t, --tls\t\tEnable TLS encryption for server connection")
    print("\t-l, --local\t\tLocal tn3270 proxy port [Default: 3271]")
    print("\t-o, --offline\t\tOffline log analysis mode")
    print("\t-h, --help\t\tThis help message")
    return

def on_closing():
    global tabControl, root, sql_con, client, server

    tabControl.tab(0, state="disabled")
    tabControl.tab(1, state="disabled")
    tabControl.tab(3, state="disabled")
    tabControl.tab(4, state="disabled")
    tabControl.tab(4, state="disabled")
    root.destroy()
    sql_con.commit()
    sql_con.close()
    client.close()
    server.close()
    print("\nClosing log database.\nExited.")
    sys.exit(0)

def sigint_handler(signum, frame):
    on_closing()

def hack_button_pressed():
    global hack_on, hack_toggled

    if hack_on:
        hack_on = 0
        hack_button["text"] = 'OFF'
        root.update()
        hack_toggled = 1
    else:
        hack_on = 1
        hack_button["text"] = 'ON'
        root.update()
        hack_toggled = 1
    return

def hack_toggle():
    global hack_toggled

    hack_toggled = 1
    return

def continue_func():
    global EXIT_LOOP

    frame.destroy()
    root.update()
    root.geometry(str(int(screen_width * 0.99))+'x'+str(root_height)+'+0+0')
    EXIT_LOOP = 1
    return

def browse_files():
    global inject_status, inject_file_set, inject_filename

    inject_filename = filedialog.askopenfilename(initialdir = "injections", title = "Select file for injections", filetypes = (("Text Files", "*.txt"), ("All Files", "*")))
    if inject_filename:
        inject_status["text"] = "Filename set to: " + inject_filename
        inject_file_set = 1
    else:
        inject_status["text"] = "Error: file not set."
        inject_file_set = 0
    root.update()
    return

def inject_setup():
    global inject_status, inject_setup_capture

    inject_status["text"] = "Submit data using mask character of '" + inject_mask.get() + "' to setup injection."
    root.update()
    inject_setup_capture = 1
    return

def inject_go():
    global inject_file_set, inject_config_set, inject_status, inject_filename, inject_mask_len
    global inject_preamble, inject_postamble, inject_trunc, inject_key, tabControl

    if inject_file_set == 0 and inject_config_set == 0:
        inject_status["text"] = "First select a file for injection, then click SETUP."
        root.update()
        return
    if inject_file_set == 0:
        inject_status["text"] = "Injection file not set.  Click FILE."
        root.update()
        return
    if inject_config_set == 0:
        inject_status["text"] = "Field for injection hasn't been setup.  Click SETUP."
        root.update()
        return

    # All setup conditions met...
    tabControl.tab(0, state="disabled")
    tabControl.tab(2, state="disabled")
    tabControl.tab(3, state="disabled")
    tabControl.tab(4, state="disabled")
    injections = open(inject_filename, 'r')
    while True:
        injection_line = injections.readline()
        if not injection_line:
            break
        injection_line = injection_line.rstrip()
        if inject_trunc.get() == 'TRUNC':
            injection_line = injection_line[:inject_mask_len]
        if len(injection_line) <= inject_mask_len:
            injection_ebcdic = lib3270.get_ebcdic(injection_line)
            bytes_ebcdic = inject_preamble + injection_ebcdic + inject_postamble
            write_log('C', 'Sending: ' + injection_line, bytes_ebcdic)
            server.send(bytes_ebcdic)
            inject_status["text"] = "Sending: " + injection_line
            root.update()
            tend_server()
        if inject_key.get() == 'ENTER+CLEAR':
            send_key('CLEAR', b'\x6d')
        elif inject_key.get() == 'ENTER+PF3+CLEAR':
            send_key('PF3', b'\xf3')
            send_key('CLEAR', b'\x6d')
    injections.close()
    tabControl.tab(0, state="normal")
    tabControl.tab(2, state="normal")
    tabControl.tab(3, state="normal")
    tabControl.tab(4, state="normal")
    return

def inject_reset():
    global inject_config_set, inject_status

    inject_config_set = 0
    inject_status["text"] = "Configuration cleared."
    root.update()
    return

def aid_setdef():
    aid_no.set(1)
    aid_qreply.set(1)
    aid_enter.set(0)
    aid_pf1.set(1)
    aid_pf2.set(1)
    aid_pf3.set(1)
    aid_pf4.set(1)
    aid_pf5.set(1)
    aid_pf6.set(1)
    aid_pf7.set(1)
    aid_pf8.set(1)
    aid_pf9.set(1)
    aid_pf10.set(1)
    aid_pf11.set(1)
    aid_pf12.set(1)
    aid_pf13.set(1)
    aid_pf14.set(1)
    aid_pf15.set(1)
    aid_pf16.set(1)
    aid_pf17.set(1)
    aid_pf18.set(1)
    aid_pf19.set(1)
    aid_pf20.set(1)
    aid_pf21.set(1)
    aid_pf22.set(1)
    aid_pf23.set(1)
    aid_pf24.set(1)
    aid_oicr.set(1)
    aid_msr_mhs.set(1)
    aid_select.set(1)
    aid_pa1.set(1)
    aid_pa2.set(1)
    aid_pa3.set(1)
    aid_clear.set(0)
    aid_sysreq.set(1)
    return

def tend_server():
    global server, hack_on, hack_prot, hack_hf, hack_rnr, hack_sf, hack_sfe, hack_sa, hack_mf

    while True:
        my_rlist, w, e = select.select([server], [], [], 1)
        if server in my_rlist:
            server_data = server.recv(BUFFER_MAX)
            if len(server_data) > 0:
                if hack_on:
                    hacked_server = lib3270.manipulate(server_data, hack_sf.get(), hack_sfe.get(), hack_sa.get(), hack_mf.get(), hack_prot.get(), hack_hf.get(), hack_rnr.get(), hack_ei.get(), hack_hv.get())
                    client.send(hacked_server)
                    write_log('S', 'Hack Field Attributes: ENABLED (' +
                            'Remove Field Prot: ' + str(hack_prot.get()) + " - " +
                           'Show Hidden: ' + str(hack_hf.get()) + " - " +
                          'Remove NUM Prot: ' + str(hack_rnr.get()) + ") (" +
                          'SF: ' + str(hack_sf.get()) + " - " +
                          'SFE: ' + str(hack_sfe.get()) + " - " +
                          'SA: ' + str(hack_sa.get()) + " - " +
                          'MF: ' + str(hack_mf.get()) + " - " +
                          'EI: ' + str(hack_ei.get()) + " - " +
                          'HV: ' + str(hack_hv.get()) +
                          ')', hacked_server)
                else:
                    client.send(server_data)
                    write_log('S', '', server_data)
        else:
            break
    return

def send_key(send_text, byte_code):
    global server, send_label

    send_label["text"] = 'Send: ' + send_text
    root.update()
    write_log('C', 'Sending: ' + send_text, byte_code + b'\xff\xef')
    # MVS Version
    server.send(byte_code + b'\xff\xef')
    # zOS Version 
    # server.send(byte_code + b'\x00\x00\x00\x00' + byte_code + b'\xff\xef')
    tend_server()
    return

def send_keys():
    global send_label

    tabControl.tab(0, state="disabled")
    tabControl.tab(1, state="disabled")
    tabControl.tab(3, state="disabled")
    tabControl.tab(4, state="disabled")
    if aid_no.get(): send_key('NO', b'\x60')
    if aid_qreply.get(): send_key('QREPLY', b'\x61')
    if aid_enter.get(): send_key('ENTER', b'\x7d')
    if aid_pf1.get(): send_key('PF1', b'\xf1')
    if aid_pf2.get(): send_key('PF2', b'\xf2')
    if aid_pf3.get(): send_key('PF3', b'\xf3')
    if aid_pf4.get(): send_key('PF4', b'\xf4')
    if aid_pf5.get(): send_key('PF5', b'\xf5')
    if aid_pf6.get(): send_key('PF6', b'\xf6')
    if aid_pf7.get(): send_key('PF7', b'\xf7')
    if aid_pf8.get(): send_key('PF8', b'\xf8')
    if aid_pf9.get(): send_key('PF9', b'\xf9')
    if aid_pf10.get(): send_key('PF10', b'\x7a')
    if aid_pf11.get(): send_key('PF11', b'\x7b')
    if aid_pf12.get(): send_key('PF12', b'\x7c')
    if aid_pf13.get(): send_key('PF13', b'\xc1')
    if aid_pf14.get(): send_key('PF14', b'\xc2')
    if aid_pf15.get(): send_key('PF15', b'\xc3')
    if aid_pf16.get(): send_key('PF16', b'\xc4')
    if aid_pf17.get(): send_key('PF17', b'\xc5')
    if aid_pf18.get(): send_key('PF18', b'\xc6')
    if aid_pf19.get(): send_key('PF19', b'\xc7')
    if aid_pf20.get(): send_key('PF20', b'\xc8')
    if aid_pf21.get(): send_key('PF21', b'\xc9')
    if aid_pf22.get(): send_key('PF22', b'\x4a')
    if aid_pf23.get(): send_key('PF23', b'\x4b')
    if aid_pf24.get(): send_key('PF24', b'\x4c')
    if aid_oicr.get(): send_key('OICR', b'\xe6')
    if aid_msr_mhs.get(): send_key('MSR_MHS', b'\xe7')
    if aid_select.get(): send_key('SELECT', b'\x7e')
    if aid_pa1.get(): send_key('PA1', b'\x6c')
    if aid_pa2.get(): send_key('PA2', b'\x6e')
    if aid_pa3.get(): send_key('PA3', b'\x6b')
    if aid_clear.get(): send_key('CLEAR', b'\x6d')
    if aid_sysreq.get(): send_key('SYSREQ', b'\xf0')
    send_label["text"] = 'Ready.'
    tabControl.tab(0, state="normal")
    tabControl.tab(1, state="normal")
    tabControl.tab(3, state="normal")
    tabControl.tab(4, state="normal")
    return

def aid_refresh(server_data):
    global aid_pf1, aid_pf2, aid_pf3, aid_pf4, aid_pf5, aid_pf6, aid_pf7, aid_pf8, aid_pf9, aid_pf10
    global aid_pf11, aid_pf12, aid_pf13, aid_pf14, aid_pf15, aid_pf16, aid_pf17, aid_pf18, aid_pf19, aid_pf20
    global aid_pf21, aid_pf22, aid_pf23, aid_pf24

    aid_setdef()
    server_ascii = lib3270.get_ascii(server_data)
    if search("PF1[^0-9]", server_ascii): aid_pf1.set(0)
    if search("PF2[^0-9]", server_ascii): aid_pf2.set(0)
    if search("PF3[^0-9]", server_ascii): aid_pf3.set(0)
    if search("PF4[^0-9]", server_ascii): aid_pf4.set(0)
    if search("PF5[^0-9]", server_ascii): aid_pf5.set(0)
    if search("PF6[^0-9]", server_ascii): aid_pf6.set(0)
    if search("PF7[^0-9]", server_ascii): aid_pf7.set(0)
    if search("PF8[^0-9]", server_ascii): aid_pf8.set(0)
    if search("PF9[^0-9]", server_ascii): aid_pf9.set(0)
    if search("PF10[^0-9]", server_ascii): aid_pf10.set(0)
    if search("PF11[^0-9]", server_ascii): aid_pf11.set(0)
    if search("PF12[^0-9]", server_ascii): aid_pf12.set(0)
    if search("PF13[^0-9]", server_ascii): aid_pf13.set(0)
    if search("PF14[^0-9]", server_ascii): aid_pf14.set(0)
    if search("PF15[^0-9]", server_ascii): aid_pf15.set(0)
    if search("PF16[^0-9]", server_ascii): aid_pf16.set(0)
    if search("PF17[^0-9]", server_ascii): aid_pf17.set(0)
    if search("PF18[^0-9]", server_ascii): aid_pf18.set(0)
    if search("PF19[^0-9]", server_ascii): aid_pf19.set(0)
    if search("PF20[^0-9]", server_ascii): aid_pf20.set(0)
    if search("PF21[^0-9]", server_ascii): aid_pf21.set(0)
    if search("PF22[^0-9]", server_ascii): aid_pf22.set(0)
    if search("PF23[^0-9]", server_ascii): aid_pf23.set(0)
    if search("PF24[^0-9]", server_ascii): aid_pf24.set(0)
    return

def write_log(direction, notes, data):
    global sql_con, sql_cur, treev, last_db_id, message_count

    message_count = message_count + 1
    if message_count == 1:
        notes = notes + "tn3270 handshake - Initial connection"
    elif message_count == 2:
        notes = notes + "tn3270 handshake - Initial connection - client response"
    elif message_count == 3:
        notes = notes + "tn3270 handshake - Settings negotiation"
    elif message_count == 4:
        if data[13] == 0x35:
            notes = notes + "tn3270 handshake - Settings negotiation - Screen Size: Model 5 (132x27)"
        elif data[13] == 0x34:
            notes = notes + "tn3270 handshake - Settings negotiation - Screen Size: Model 4 (80x43)"
        elif data[13] == 0x33:
            notes = notes + "tn3270 handshake - Settings negotiation - Screen Size: Model 3 (80x32)"
        elif data[13] == 0x32:
            notes = notes + "tn3270 handshake - Settings negotiation - Screen Size: Model 2 (80x24)"
        else:
            # Byte count will probably also be 17 instead of 18
            notes = notes + "tn3270 handshake - Settings negotiation - Screen Size: Oversized"
    elif message_count == 5:
        notes = notes + "tn3270 handshake"
    elif message_count == 6:
        notes = notes + "tn3270 handshake"

    log_time = time.time()
    sql_cur.execute("INSERT INTO Logs ('TIMESTAMP', 'C_S', 'NOTES', 'DATA_LEN', 'RAW_DATA') VALUES (?, ?, ?, ?, ?)", (str(log_time), direction, notes, str(len(data)), sqlite3.Binary(data)))
    sql_con.commit()
    last_db_id += 1
    treev.insert('', 'end',text="",values=(str(last_db_id), datetime.datetime.fromtimestamp(log_time), expand_CS(direction), str(len(data)), notes))
    root.update()
    return

def expand_CS(text):
    if text == "C":
        return("Client")
    elif text == "S":
        return("Server")

def fetch_item(a):
    global sql_cur, treev, d1, client

    current_item = treev.focus()
    dict_item = treev.item(current_item)
    record_id = dict_item['values'][0]
    record_cs = dict_item['values'][2]

    sql_text = "SELECT * FROM Logs WHERE ID=" + str(record_id)
    sql_cur.execute(sql_text)
    records = sql_cur.fetchall()
    for row in records:
        ebcdic_data = lib3270.get_ascii(row[5])
        d1.config(state='normal')
        d1.delete('1.0', tk.END)
        d1.insert(tk.INSERT, ebcdic_data)
        d1.config(state='disabled')
        root.update()
        if record_cs == "Server":
            client.send(row[5])

    return

# Main start---
try:
    opts, args = getopt.getopt(sys.argv[1:], 'n:i:p:tl:oh', ['name=', 'ip=', 'port=', 'tls', 'local=', 'offline', 'help'])
except getopt.GetoptError:
    usage()
    sys.exit(2)

for opt, arg in opts:
    if opt in ('-h', '--help'):
        usage()
        sys.exit(2)
    if opt in ('-n', '--name'):
        PROJECT_NAME = arg
    if opt in ('-i', '--ip'):
        SERVER_IP = arg
    if opt in ('-p', '--port'):
        SERVER_PORT = int(arg)
    if opt in ('-t', '--tls'):
        TLS_ENABLED = 1
    if opt in ('-l', '--local'):
        PROXY_PORT = int(arg)
    if opt in ('-o', '--offline'):
        offline_mode = 1

# SQLite3---

db_filename = PROJECT_NAME + ".db"
# If DB file doesn't exist and Server IP address isn't set, exit---
if not Path(db_filename).is_file():
    if not SERVER_IP:
        usage()
        sys.exit(2)
sql_con = sqlite3.connect(db_filename)
sql_cur = sql_con.cursor()

sql_cur.execute("SELECT count(name) FROM sqlite_master WHERE TYPE='table' AND NAME='Config'")

# If table exits, load previous settings---
if sql_cur.fetchone()[0] == 1:
    sql_cur.execute("SELECT * FROM Config")
    record = sql_cur.fetchall()
    for row in record:
        if SERVER_IP != '' and SERVER_IP != row[1]:
            print("\nError! -i setting doesn't match server IP address in existig project file!")
            sys.exit(2)
        SERVER_IP = row[1];
        if SERVER_PORT != 0 and SERVER_PORT != int(row[2]):
            print("\nError! -p setting doesn't match server TCP port in existig project file!")
            sys.exit(2)
        SERVER_PORT = int(row[2])
        PROXY_PORT = int(row[3])
        TLS_ENABLED = int(row[4])
# else create table with current configuration---
else:
    sql_cur.execute('CREATE TABLE Config (CREATION_TS TEXT NOT NULL, SERVER_IP TEXT NOT NULL, SERVER_PORT INT NOT NULL, PROXY_PORT INT NOT NULL, TLS_ENABLED INT NOT NULL)')
    sql_cur.execute("INSERT INTO Config ('CREATION_TS', 'SERVER_IP', 'SERVER_PORT', 'PROXY_PORT', 'TLS_ENABLED') VALUES ('" + str(time.time()) + "', '" + SERVER_IP + "', '" + str(SERVER_PORT) + "', '" + str(PROXY_PORT) + "', '" + str(TLS_ENABLED) + "')")

sql_cur.execute("SELECT count(name) FROM sqlite_master WHERE TYPE='table' AND NAME='Logs'")
if sql_cur.fetchone()[0] != 1:
    # Create table for logging---
    sql_cur.execute('CREATE TABLE Logs (ID INTEGER PRIMARY KEY AUTOINCREMENT, TIMESTAMP TEXT, C_S CHAR(1), NOTES TEXT, DATA_LEN INT, RAW_DATA BLOB(4000))') # 3,564
    
if not SERVER_IP:
    usage()
    sys.exit(2)

signal.signal(signal.SIGINT, sigint_handler)
root.protocol("WM_DELETE_WINDOW", on_closing)
frame = tk.Frame(root)
frame.pack(side="top", expand=True, fill="both")

readme_file = open("README", "r")
readme_text = readme_file.read(10000)

root.title(NAME + " v"+VERSION)

# Adjust root_height based on platform...
if platform.system()=="Darwin":
    root.geometry(str(int(screen_width / 2))+'x120+'+str(int((screen_width / 4)))+'+0')
else:
    root.geometry(str(int(screen_width / 2))+'x100+'+str(int((screen_width / 4)))+'+0')

client = lib3270.client_connect(frame, PROXY_IP, PROXY_PORT)
if not offline_mode:
    server = lib3270.server_connect(frame, SERVER_IP, SERVER_PORT, TLS_ENABLED)
else:
    status = tk.Label(frame, text="Offline log analysis mode!", bg='light grey').pack()

B = tk.Button(frame, text ="Click to Continue", command = continue_func)
B.pack()

# Wait for button press upon inital connection...
while True:
    root.update()
    if EXIT_LOOP:
        break

def play_record(record_id):
    global sql_cur, client

    sql_text = "SELECT * FROM Logs WHERE ID=" + str(record_id)
    sql_cur.execute(sql_text)
    records = sql_cur.fetchall()
    for row in records:
        client.send(row[5])
        client.recv(BUFFER_MAX)

if offline_mode:
    play_record(1)
    play_record(3)
    play_record(5)

# Tabs---
tabControl.add(tab1, text ='Hack Field Attributes')
tabControl.add(tab2, text ='Inject Into Fields')
tabControl.add(tab3, text ='Inject Key Presses')
tabControl.add(tab4, text ='Logs')
tabControl.add(tab5, text ='Help')
tabControl.pack(expand = 1, fill ="both")
# Tab : Hack Field Attributes---
a1 = tk.Label(tab1, text='Hack Fields:', font="TkDefaultFont 12 underline", bg='light grey').place(x=22, y=10)
hack_button = ttk.Button(tab1, text='OFF', width=8, command=hack_button_pressed)
hack_button.place(x=20,y=33)
a2 = tk.Checkbutton(tab1, text='Disable Field Protection', bg='light grey', variable=hack_prot, onvalue=1, offvalue=0, command=hack_toggle).place(x=150, y=0)
a3 = tk.Checkbutton(tab1, text='Enable Hidden Fields', bg='light grey', variable=hack_hf, onvalue=1, offvalue=0, command=hack_toggle).place(x=150, y=25)
a4 = tk.Checkbutton(tab1, text='Remove Numeric Only Restrictions', bg='light grey', variable=hack_rnr, onvalue=1, offvalue=0, command=hack_toggle).place(x=150, y=50)
a5 = tk.Label(tab1, text='Fields Types:', font="TkDefaultFont 12 underline", bg='light grey').place(x=610, y=2)
a6 = tk.Checkbutton(tab1, text='Start Field', bg='light grey', variable=hack_sf, onvalue=1, offvalue=0, command=hack_toggle).place(x=500, y=25)
a7 = tk.Checkbutton(tab1, text='Start Field Extended', bg='light grey', variable=hack_sfe, onvalue=1, offvalue=0, command=hack_toggle).place(x=500, y=50)
a8 = tk.Checkbutton(tab1, text='Set Attribute', bg='light grey', variable=hack_sa, onvalue=1, offvalue=0, command=hack_toggle).place(x=700, y=25)
a9 = tk.Checkbutton(tab1, text='Modify Field', bg='light grey', variable=hack_mf, onvalue=1, offvalue=0, command=hack_toggle).place(x=700, y=50)
a10 = tk.Label(tab1, text='Hidden Field Highlighting:', font="TkDefaultFont 12 underline", bg='light grey').place(x=900, y=2)
a11 = tk.Checkbutton(tab1, text='Enable Intensity', bg='light grey', variable=hack_ei, onvalue=1, offvalue=0, command=hack_toggle).place(x=900, y=25)
a12 = tk.Checkbutton(tab1, text='High Visibility', bg='light grey', variable=hack_hv, onvalue=1, offvalue=0, command=hack_toggle).place(x=900, y=50)
# Tab : Inject Into Fields---
b0 = tk.Label(tab2, text='Status:', font="TkDefaultFont 12 underline", bg='light grey').place(x=22, y=12)
inject_status = tk.Label(tab2, text = 'Not Ready.', bg='light grey')
inject_status.place(x=23, y=40)
inject_file_button = ttk.Button(tab2, text='FILE', width=8, command=browse_files).place(x=125, y=2)
inject_setup_button = ttk.Button(tab2, text='SETUP', width=8, command=inject_setup).place(x=200, y=2)
inject_button = ttk.Button(tab2, text='INJECT', width=8, command=inject_go).place(x=275, y=2)
inject_reset_button = ttk.Button(tab2, text='RESET', width=8, command=inject_reset).place(x=350, y=2)
b1 = tk.Label(tab2, text='Mask:', font="TkDefaultFont 12 underline", bg='light grey').place(x=475, y=9)
b2options = ["@", "#", "$", "%", "^", "&", "*"]
b2 =ttk.OptionMenu(tab2, inject_mask, b2options[6], *b2options).place(x=525, y=8)
b3 = tk.Label(tab2, text='Mode:', font="TkDefaultFont 12 underline", bg='light grey').place(x=600, y=9)
b4options = ["SKIP", "TRUNC"]
b4 =ttk.OptionMenu(tab2, inject_trunc, b4options[0], *b4options).place(x=650, y=8)
b5 = tk.Label(tab2, text='Keys:', font="TkDefaultFont 12 underline", bg='light grey').place(x=750, y=9)
b6options = ["ENTER", "ENTER+CLEAR", "ENTER+PF3+CLEAR"]
b6 =ttk.OptionMenu(tab2, inject_key, b6options[0], *b6options).place(x=800, y=8)
# Tab : Inject Key Presses---
send_button = ttk.Button(tab3, text = 'Send Keys', command=send_keys, width=10).place(x=25, y=12)
send_label = tk.Label(tab3, text = 'Ready.', bg='light grey')
send_label.place(x=25, y=50)
c1 = tk.Checkbutton(tab3, text='NO',variable=aid_no, onvalue=1, offvalue=0, bg='light grey').place(x=150, y=0)
c2 = tk.Checkbutton(tab3, text='QREPLY',variable=aid_qreply, onvalue=1, offvalue=0, bg='light grey').place(x=250, y=0)
c3 = tk.Checkbutton(tab3, text='ENTER',variable=aid_enter, onvalue=1, offvalue=0, bg='light grey').place(x=350, y=0)
c4 = tk.Checkbutton(tab3, text='PF1',variable=aid_pf1, onvalue=1, offvalue=0, bg='light grey').place(x=450, y=0)
c5 = tk.Checkbutton(tab3, text='PF2',variable=aid_pf2, onvalue=1, offvalue=0, bg='light grey').place(x=550, y=0)
c6 = tk.Checkbutton(tab3, text='PF3',variable=aid_pf3, onvalue=1, offvalue=0, bg='light grey').place(x=650, y=0)
c7 = tk.Checkbutton(tab3, text='PF4',variable=aid_pf4, onvalue=1, offvalue=0, bg='light grey').place(x=750, y=0)
c8 = tk.Checkbutton(tab3, text='PF5',variable=aid_pf5, onvalue=1, offvalue=0, bg='light grey').place(x=850, y=0)
c9 = tk.Checkbutton(tab3, text='PF6',variable=aid_pf6, onvalue=1, offvalue=0, bg='light grey').place(x=950, y=0)
c10 = tk.Checkbutton(tab3, text='PF7',variable=aid_pf7, onvalue=1, offvalue=0, bg='light grey').place(x=1050, y=0)
c11 = tk.Checkbutton(tab3, text='PF8',variable=aid_pf8, onvalue=1, offvalue=0, bg='light grey').place(x=1150, y=0)
c12 = tk.Checkbutton(tab3, text='PF9',variable=aid_pf9, onvalue=1, offvalue=0, bg='light grey').place(x=1250, y=0)
c13 = tk.Checkbutton(tab3, text='PF10',variable=aid_pf10, onvalue=1, offvalue=0, bg='light grey').place(x=150, y=25)
c14 = tk.Checkbutton(tab3, text='PF11',variable=aid_pf11, onvalue=1, offvalue=0, bg='light grey').place(x=250, y=25)
c15 = tk.Checkbutton(tab3, text='PF12',variable=aid_pf12, onvalue=1, offvalue=0, bg='light grey').place(x=350, y=25)
c16 = tk.Checkbutton(tab3, text='PF13',variable=aid_pf13, onvalue=1, offvalue=0, bg='light grey').place(x=450, y=25)
c17 = tk.Checkbutton(tab3, text='PF14',variable=aid_pf14, onvalue=1, offvalue=0, bg='light grey').place(x=550, y=25)
c18 = tk.Checkbutton(tab3, text='PF15',variable=aid_pf15, onvalue=1, offvalue=0, bg='light grey').place(x=650, y=25)
c19 = tk.Checkbutton(tab3, text='PF16',variable=aid_pf16, onvalue=1, offvalue=0, bg='light grey').place(x=750, y=25)
c20 = tk.Checkbutton(tab3, text='PF17',variable=aid_pf17, onvalue=1, offvalue=0, bg='light grey').place(x=850, y=25)
c21 = tk.Checkbutton(tab3, text='PF18',variable=aid_pf18, onvalue=1, offvalue=0, bg='light grey').place(x=950, y=25)
c22 = tk.Checkbutton(tab3, text='PF19',variable=aid_pf19, onvalue=1, offvalue=0, bg='light grey').place(x=1050, y=25)
c23 = tk.Checkbutton(tab3, text='PF20',variable=aid_pf20, onvalue=1, offvalue=0, bg='light grey').place(x=1150, y=25)
c24 = tk.Checkbutton(tab3, text='PF21',variable=aid_pf21, onvalue=1, offvalue=0, bg='light grey').place(x=1250, y=25)
c25 = tk.Checkbutton(tab3, text='PF22',variable=aid_pf22, onvalue=1, offvalue=0, bg='light grey').place(x=150, y=50)
c26 = tk.Checkbutton(tab3, text='PF23',variable=aid_pf23, onvalue=1, offvalue=0, bg='light grey').place(x=250, y=50)
c27 = tk.Checkbutton(tab3, text='PF24',variable=aid_pf24, onvalue=1, offvalue=0, bg='light grey').place(x=350, y=50)
c28 = tk.Checkbutton(tab3, text='OICR',variable=aid_oicr, onvalue=1, offvalue=0, bg='light grey').place(x=450, y=50)
c29 = tk.Checkbutton(tab3, text='MSR_MHS',variable=aid_msr_mhs, onvalue=1, offvalue=0, bg='light grey').place(x=550, y=50)
c30 = tk.Checkbutton(tab3, text='SELECT',variable=aid_select, onvalue=1, offvalue=0, bg='light grey').place(x=650, y=50)
c31 = tk.Checkbutton(tab3, text='PA1',variable=aid_pa1, onvalue=1, offvalue=0, bg='light grey').place(x=750, y=50)
c32 = tk.Checkbutton(tab3, text='PA2',variable=aid_pa2, onvalue=1, offvalue=0, bg='light grey').place(x=850, y=50)
c33 = tk.Checkbutton(tab3, text='PA3',variable=aid_pa3, onvalue=1, offvalue=0, bg='light grey').place(x=950, y=50)
c34 = tk.Checkbutton(tab3, text='CLEAR',variable=aid_clear, onvalue=1, offvalue=0, bg='light grey').place(x=1050, y=50)
c35 = tk.Checkbutton(tab3, text='SYSREQ',variable=aid_sysreq, onvalue=1, offvalue=0, bg='light grey').place(x=1150, y=50)
# Tab : Logs---
treev = ttk.Treeview(tab4, selectmode="browse")
treev.place(x=25, y=10, height=220)
verscrlbar = ttk.Scrollbar(tab4, orient ="vertical", command = treev.yview)
treev.configure(xscrollcommand = verscrlbar.set)
verscrlbar.place(x=5, y=10, height=220)
treev["columns"] = ("1", "2", "3", "4", "5")
treev['show'] = 'headings'
treev.column("1", width = int(screen_width * 0.05), anchor ='center')
treev.column("2", width = int(screen_width * 0.15), anchor ='center')
treev.column("3", width = int(screen_width * 0.05), anchor ='center')
treev.column("4", width = int(screen_width * 0.05), anchor ='se')
treev.column("5", width = int(screen_width * 0.66), anchor ='sw')
treev.heading("1", text ="ID")
treev.heading("2", text ="Timestamp")
treev.heading("3", text ="Sender")
treev.heading("4", text ="Length")
treev.heading("5", text ="Notes")
sql_cur.execute("SELECT * FROM Logs")
records = sql_cur.fetchall()
for row in records:
    treev.insert('', 'end',text="",values=(row[0], datetime.datetime.fromtimestamp(float(row[1])), expand_CS(row[2]), row[4], row[3]))
    last_db_id = int(row[0])
treev.bind('<<TreeviewSelect>>', fetch_item)
d1 = tkk.ScrolledText(master = tab4, wrap = tk.CHAR, height=12)
if platform.system()=="Darwin":
    d1.place(x=25, y=235, width=screen_width - 105, height=220)
else:
    d1.place(x=25, y=235, width=screen_width - 60, height=220)
d1.config(state = "disabled")
# Tab : Help---
e1 = tkk.ScrolledText(master = tab5, wrap = tk.WORD, width = 20, height = 20)
e1.insert(tk.INSERT, readme_text)
e1.pack(padx = 10, pady = 10, fill=tk.BOTH, expand=True)
e1.config(state = "disabled")

if offline_mode:
    tabControl.tab(0, state="disabled")
    tabControl.tab(1, state="disabled")
    tabControl.tab(2, state="disabled")

lastTab = 0
while True:
    # Tend to tab selection
    tabNum = tabControl.index(tabControl.select())
    if tabNum != lastTab:
        if tabNum == 2: # Inject Key Presses
            aid_refresh(server_data)
            root.geometry(str(int(screen_width * 0.99))+'x'+str(root_height)+'+0+0')
        elif tabNum == 3: # Logs
            root.geometry(str(int(screen_width * 0.99))+'x485+0+0')
        elif tabNum == 4: # Help
            root.geometry(str(int(screen_width * 0.99))+'x485+0+0')
        else:
            root.geometry(str(int(screen_width * 0.99))+'x'+str(root_height)+'+0+0')

    if offline_mode:
        lastTab = tabNum
        root.update()
        continue

    # Tend to client sending data
    rlist, w, e = select.select([client, server], [], [], 0)
    if client in rlist:
        client_data = client.recv(BUFFER_MAX)
        if len(client_data) > 0:
            if not silence:
                print("Client:")
                print(bytes(client_data))
                print(lib3270.get_ascii(client_data))
            if inject_setup_capture:
                preamble_count = 0
                postamble_count = 0
                mask_count = 0
                mask_character = inject_mask.get()
                for x in range(0, len(client_data) - 1):
                    character = lib3270.get_ascii(client_data[x].to_bytes(1, 'little'))
                    if character != mask_character:
                        preamble_count += 1
                    else:
                        break
                for x in range(preamble_count, len(client_data)):
                    character = lib3270.get_ascii(client_data[x].to_bytes(1, 'little'))
                    if character == mask_character:
                        mask_count += 1
                    else:
                        break
                postamble_count = len(client_data) - preamble_count - mask_count
                if mask_count > 0:
                    inject_status["text"] = "Mask found (length: " + str(mask_count) + ") - Input field identified - Ready for injection."
                    inject_mask_len = mask_count
                    inject_preamble = client_data[:preamble_count]
                    inject_postamble = client_data[preamble_count + mask_count:]
                    inject_config_set = 1
                    write_log('C', 'Inject setup - Mask:' + inject_mask.get() + " - Length: " + str(mask_count), client_data)
                else:
                    inject_status["text"] = "Error: Mask not found."
                    inject_mask_len = 0
                    inject_config_set = 0
                    write_log('C', 'Inject setup - Mask:' + inject_mask.get() + " - Mask not found!", client_data)
                inject_setup_capture = 0
                root.update()
            else:
                write_log('C', '', client_data)
            server.send(client_data)

    # Tend to server sending data
    if server in rlist:
        server_data = server.recv(BUFFER_MAX)
        if len(server_data) > 0:
            if not silence:
                print("Server:")
                print(bytes(server_data))
                print(lib3270.get_ascii(server_data))
            if hack_on:
                hacked_server = lib3270.manipulate(server_data, hack_sf.get(), hack_sfe.get(), hack_sa.get(), hack_mf.get(), hack_prot.get(), hack_hf.get(), hack_rnr.get(), hack_ei.get(), hack_hv.get())
                write_log('S', 'Hack Field Attributes: ENABLED (' +
                        'Remove Field Prot: ' + str(hack_prot.get()) + " - " +
                        'Show Hidden: ' + str(hack_hf.get()) + " - " +
                        'Remove NUM Prot: ' + str(hack_rnr.get()) + ") (" +
                        'SF: ' + str(hack_sf.get()) + " - " +
                        'SFE: ' + str(hack_sfe.get()) + " - " +
                        'SA: ' + str(hack_sa.get()) + " - " +
                        'MF: ' + str(hack_mf.get()) + " - " +
                        'EI: ' + str(hack_ei.get()) + " - " +
                        'HV: ' + str(hack_hv.get()) +
                        ')', hacked_server)
                client.send(hacked_server)
            else:
                write_log('S', '', server_data)
                client.send(server_data)
        if tabNum == 2: # Inject Keys
            aid_refresh(server_data)
    if hack_toggled:
        if len(server_data) > 0:
            if hack_on:
                hacked_server = lib3270.manipulate(server_data, hack_sf.get(), hack_sfe.get(), hack_sa.get(), hack_mf.get(), hack_prot.get(), hack_hf.get(), hack_rnr.get(), hack_ei.get(), hack_hv.get())
                write_log('S', 'Hack Field Attributes: TOGGLED ON (' +
                        'Remove Field Prot: ' + str(hack_prot.get()) + " - " +
                        'Show Hidden: ' + str(hack_hf.get()) + " - " +
                        'Remove NUM Prot: ' + str(hack_rnr.get()) + ") (" +
                        'SF: ' + str(hack_sf.get()) + " - " +
                        'SFE: ' + str(hack_sfe.get()) + " - " +
                        'SA: ' + str(hack_sa.get()) + " - " +
                        'MF: ' + str(hack_mf.get()) + " - " +
                        'EI: ' + str(hack_ei.get()) + " - " +
                        'HV: ' + str(hack_hv.get()) +
                        ')', hacked_server)
                client.send(hacked_server)
            else:
                write_log('S', 'Hack Fields Attributes: TOGGLED OFF', server_data)
                client.send(server_data)
        hack_toggled = 0

    # Set lastTab to be able to tend to tab selection on next pass
    lastTab = tabNum
    root.update()

# Main end---
