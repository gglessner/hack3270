# lib3270.py - A Tiny Python 3270 Library
#
# Copyright Garland Glessner (2022-2023)
# Contact email: gglessner@gmail.com
#
# This file is part of CICS-Pen-Testing-Toolkit.
#
# CICS-Pen-Testing-Toolkit is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
#
# CICS-Pen-Testing-Toolkit is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with CICS-Pen-Testing-Toolkit.
# If not, see <https://www.gnu.org/licenses/>.

import tkinter as tk
import socket
import ssl
import select

# EBCDIC to ASCII conversion table
table = [
  '[NUL]', '[SOH]', '[STX]', '[ETX]', '[PF]', '[HT]', '[LC]', '[DEL]', '[GE]', '[RLF]', '[SMM]', '[VT]', '[FF]', '[CR]', '[SO]', '[SI]',
  '[DLE]', '[DC1]', '[DC2]', '[TM]', '[RES]', '[NL]', '[BS]', '[IL]', '[CAN]', '[EM]', '[CC]', '[CU1]', '[IFS]', '[IGS]', '[IRS]', '[IUS]',
  '[DS]', '[SOS]', '[FS]', '[0x23]', '[BYP]', '[LF]', '[ETB]', '[ESC]', '[0x28]', '[0x29]', '[SM]', '[CU2]', '[0x2C]', '[ENQ]', '[ACK]', '[BEL]',
  '[0x30]', '[0x31]', '[SYN]', '[0x33]', '[PN]', '[RS]', '[UC]', '[EOT]', '[0x38]', '[0x39]', '[0x3A]', '[CUB]', '[DC4]', '[NAK]', '[0x3E]', '[SUB]',
  ' ', '[0x41]', '[0x42]', '[0x43]', '[0x44]', '[0x45]', '[0x46]', '[0x47]', '[0x48]', '[0x49]', '[cent]', '.', '<', '(', '+', '[vert line]',
  '&', '[0x51]', '[0x52]', '[0x53]', '[0x54]', '[0x55]', '[0x56]', '[0x57]', '[0x58]', '[0x59]', '!', '$', '*', ')', ';', '[not equal]',
  '-', '/', '[0x62]', '[0x63]', '[0x64]', '[0x65]', '[0x66]', '[0x67]', '[0x68]', '[0x69]', '|', ',', '%', '_', '>',
  '?', '[0x70]', '[0x71]', '[0x72]', '[0x73]', '[074]', '[0x75]', '[0x76]', '[0x77]', '[0x78]', '`', ':', '#', '@', '\'', '=',
  '"', '[0x80]', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', '[0x8A]', '[0x8B]', '[0x8C]', '[0x8D]', '[0x8E]',
  '[0x8F]', '[0x90]', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', '[0x9A]', '[0x9B]', '[0x9C]', '[0x9D]', '[0x9E]',
  '[0x9F]', '[0xA0]', '~', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '[0xAA]', '[0xAB]', '[0xAC]', '[0xAD]', '[0xAE]',
  '[0xAF]', '[0xB0]', '[0xB1]', '[0xB2]', '[0xB3]', '[0xB4]', '[0xB5]', '[0xB6]', '[0xB7]', '[0xB8]', '[0xB9]', '[0xBA]', '[0xBB]', '[0xBC]', '[0xBD]', '[0xBE]',
  '[0xBF]', '{', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', '[0xCA]', '[0xCB]', '[0xCC]', '[0xCD]', '[0xCE]',
  '[0xCF]', '}', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', '[0xDA]', '[0xDB]', '[0xDC]', '[0xDD]', '[0xDE]',
  '[0xDF]', '\\', '[0xE1]', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '[0xEA]', '[0xEB]', '[0xEC]', '[0xED]', '[0xEE]',
  '[0xEF]', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '[0xEF]', '[0xFA]', '[0xFB]', '[0xFC]', '[0xFD]', '[0xFE]', '[EO]' ]

def get_ascii(ebcdic_string):
    my_string = ""
    for x in range(0, len(ebcdic_string)):
        my_string += table[ebcdic_string[x]]
    return my_string

def get_ebcdic(string):
    my_string = b''
    for x in range(0, len(string)):
        for y in range(0, len(table)):
            if string[x] == table[y]:
                my_string += y.to_bytes(1, 'little')
    return(my_string)

def client_connect(window, lport, port):
    status = tk.Label(window, text = "Waiting for TN3270 connection on port " + str(port))
    status.pack()
    window.update()
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    client_sock.bind((lport, port))
    client_sock.listen(4)
    (conn, (ip,port)) = client_sock.accept()
    client = conn
    status = tk.Label(window, text = "Connection received.")
    status.pack()
    window.update()
    return(client)

def server_connect(window, ip, port, tls_enabled):
    status = tk.Label(window, text = "Creating TCP connection to: " + ip + ":" + str(port))
    status.pack()
    window.update()
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if tls_enabled:
        server = ssl.wrap_socket(server_sock, ssl_version=ssl.PROTOCOL_SSLv23)
    else:
        server = server_sock
    server.connect((ip, port))
    status = tk.Label(window, text = "Connected to Server: " + ip + ":" + str(port))
    status.pack()
    window.update()
    return(server)

def flip_bits(passed_value, hack_prot, hack_hf, hack_rnr):
    value = passed_value
    # Turn of 'Protected' Flag (Bit 6) if Set
    if hack_prot:
        if value & 0b00100000 == 0b00100000:
            value ^= 0b00100000
    # Turn off 'Non-display' Flag (Bit 4) if Set (i.e. Bits 3 and 4 are on)
    if hack_hf:
        if value & 0b00001100 == 0b00001100:
            value ^= 0b00001000
    # Turn off 'Numeric Only' Flag (Bit 5) if Set
    if hack_rnr:
        if value & 0b00010000 == 0b00010000:
            value ^= 0b00010000
    return(value)

def manipulate(passed_data, hack_sf, hack_sfe, hack_sa, hack_mf, hack_prot, hack_hf, hack_rnr):
    if len(passed_data) < 90:
        return(passed_data)
    data = bytearray(len(passed_data))
    data[:] = passed_data
    for x in range(len(data)):
        if hack_sf and data[x] == 0x1d: # Start Field
                value = data[x + 1]
                data[x + 1] = flip_bits(data[x + 1], hack_prot, hack_hf, hack_rnr)
        elif hack_sfe and data[x] == 0x29: # Start Field Extended
            for y in range(data[x + 1]):
                if(len(data) < ((x + 3) + (y * 2))):
                    continue
                if data[((x + 3) + (y * 2)) - 1] == 0xc0:
                    data[((x + 3) + (y * 2))] = flip_bits(data[((x + 3) + (y * 2))], hack_prot, hack_hf, hack_rnr)
            continue
        elif hack_sa and data[x] == 0x28: # Set Attribute
            if(len(data) < x + 3):
                continue
            if data[x + 2] == 0xc0: # Basic 3270 field attributes
                data[x + 3] = flip_bits(data[x + 3], hack_prot, hack_hf, hack_rnr)
            continue
        elif hack_mf and data[x] == 0x2c: # Modify Field
            for y in range(data[x + 1]):
                if(len(data) < ((x + 3) + (y * 2))):
                    continue
                if data[((x + 3) + (y * 2)) - 1] == 0xc0: # Basic 3270 field attributes
                    data[((x + 3) + (y * 2))] = flip_bits(data[((x + 3) + (y * 2))], hack_prot, hack_hf, hack_rnr)
            continue
    return(data)
