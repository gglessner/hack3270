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
import re

# EBCDIC to ASCII conversion table
table = [
  '[0x00]', '[0x01]', '[0x02]', '[0x03]', '[0x04]', '[0x05]', '[0x06]', '[0x07]', '[0x08]', '[0x09]', '[0x0A]', '[0x0B]', '[0x0C]', '[0x0D]', '[0x0E]', '[0x0F]',
  '[0x10]', '[0x11]', '[0x12]', '[0x13]', '[0x14]', '[0x15]', '[0x16]', '[0x17]', '[0x18]', '[0x19]', '[0x1A]', '[0x1B]', '[0x1C]', '[0x1D]', '[0x1E]', '[0x1F]',
  '[0x20]', '[0x21]', '[0x22]', '[0x23]', '[0x24]', '[0x25]', '[0x26]', '[0x27]', '[0x28]', '[0x29]', '[0x2A]', '[0x2B]', '[0x2C]', '[0x2D]', '[0x2E]', '[0x2F]',
  '[0x30]', '[0x31]', '[0x32]', '[0x33]', '[0x34]', '[0x35]', '[0x36]', '[0x37]', '[0x38]', '[0x39]', '[0x3A]', '[0x3B]', '[0x3C]', '[0x3D]', '[0x3E]', '[0x3F]',
  ' ', '[0x41]', '[0x42]', '[0x43]', '[0x44]', '[0x45]', '[0x46]', '[0x47]', '[0x48]', '[0x49]', '¢', '.', '<', '(', '+', '|',
  '&', '[0x51]', '[0x52]', '[0x53]', '[0x54]', '[0x55]', '[0x56]', '[0x57]', '[0x58]', '[0x59]', '!', '$', '*', ')', ';', '≠',
  '-', '/', '[0x62]', '[0x63]', '[0x64]', '[0x65]', '[0x66]', '[0x67]', '[0x68]', '[0x69]', '|', ',', '%', '_', '>', '?',
  '[0x70]', '[0x71]', '[0x72]', '[0x73]', '[074]', '[0x75]', '[0x76]', '[0x77]', '[0x78]', '`', ':', '#', '@', '\'', '=', '"',
  '[0x80]', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', '[0x8A]', '[0x8B]', '[0x8C]', '[0x8D]', '[0x8E]', '[0x8F]',
  '[0x90]', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', '[0x9A]', '[0x9B]', '[0x9C]', '[0x9D]', '[0x9E]', '[0x9F]',
  '[0xA0]', '~', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '[0xAA]', '[0xAB]', '[0xAC]', '[0xAD]', '[0xAE]', '[0xAF]',
  '[0xB0]', '[0xB1]', '[0xB2]', '[0xB3]', '[0xB4]', '[0xB5]', '[0xB6]', '[0xB7]', '[0xB8]', '[0xB9]', '[0xBA]', '[0xBB]', '[0xBC]', '[0xBD]', '[0xBE]', '[0xBF]',
  '{', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', '[0xCA]', '[0xCB]', '[0xCC]', '[0xCD]', '[0xCE]', '[0xCF]',
  '}', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', '[0xDA]', '[0xDB]', '[0xDC]', '[0xDD]', '[0xDE]', '[0xDF]',
  '\\', '[0xE1]', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '[0xEA]', '[0xEB]', '[0xEC]', '[0xED]', '[0xEE]', '[0xEF]',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '[0xFA]', '[0xFB]', '[0xFC]', '[0xFD]', '[0xFE]', '[0xFF]' ]

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

def flip_bits(passed_value, hack_prot, hack_hf, hack_rnr, hack_ei):
    value = passed_value
    # Turn of 'Protected' Flag (Bit 6) if Set
    if hack_prot:
        if value & 0b00100000 == 0b00100000:
            value ^= 0b00100000
    # Turn off 'Non-display' Flag (Bit 4) if Set (i.e. Bits 3 and 4 are on)
    if hack_hf:
        if value & 0b00001100 == 0b00001100:
	# Flip bit 3 instead of 4 if enable intentisty is selected
            if hack_ei:
                value ^= 0b00000100
            else:
                value ^= 0b00001000
    # Turn off 'Numeric Only' Flag (Bit 5) if Set
    if hack_rnr:
        if value & 0b00010000 == 0b00010000:
            value ^= 0b00010000
    return(value)

def check_hidden(passed_value):
    #if passed_value & 0b00001100 == 0b00001100:
    if passed_value & 12 == 12:
        return True
    else:
        return False

def manipulate(passed_data, hack_sf, hack_sfe, hack_mf, hack_prot, hack_hf, hack_rnr, hack_ei, hack_hv, hack_color_sfe, hack_color_mf, hack_color_sa, hack_color_hv):
    found_hidden_data = 0

    # Don't manipulate data if telnet
    if passed_data[0] == 255:
        return(passed_data)

    data = bytearray(len(passed_data))
    data[:] = passed_data

    # Process hacking of Basic Field Attributes
    for x in range(len(data)):
        if hack_sf and data[x] == 0x1d: # Start Field
            my_position = x
            found_hidden_data = check_hidden(data[x + 1])
            data[x + 1] = flip_bits(data[x + 1], hack_prot, hack_hf, hack_rnr, hack_ei)
            if hack_hf and found_hidden_data:
                bfa_byte = data[x + 1].to_bytes(1, byteorder='little')
                if hack_hv:
                    data2 = bytearray(len(data) + 6)
                    data2 = data[:x] + b'\x29\x03\xc0' + bfa_byte + b'\x41\xf2\x42\xf6' + data[x + 2:]
                    data = data2
                    x = x + 6
                else:
                    data2 = bytearray(len(data) + 4)
                    data2 = data[:x + 2] + b'\x28\x42\xf6' + data[x + 2:]
                    data2 = data[:x] + b'\x29\x02\xc0' + bfa_byte + b'\x42\xf6' + data[x + 2:]
                    x = x + 4
                found_hidden_data = 0
        elif data[x] == 0x29: # Start Field Extended
            for y in range(data[x + 1]):
                if(len(data) < ((x + 3) + (y * 2))):
                    continue
                if hack_sfe and data[((x + 3) + (y * 2)) - 1] == 0xc0: # Basic 3270 field attributes
                    if check_hidden(data[((x + 3) + (y * 2))]) and hack_hv:
                        found_hidden_data = 1
                    data[((x + 3) + (y * 2))] = flip_bits(data[((x + 3) + (y * 2))], hack_prot, hack_hf, hack_rnr, hack_ei)
            if hack_sfe and found_hidden_data:
                data[x + 1] = data[x + 1] + 2
                data2 = bytearray(len(data) + 4)
                data2 = data[:x + (data[x + 1] * 2) - 2] + b'\x41\xf2\x42\xf6' + data[x + (data[x + 1] * 2) - 2:]
                data = data2
                x = x + 4
                found_hidden_data = 0
            continue
        elif data[x] == 0x2c: # Modify Field
            for y in range(data[x + 1]):
                if(len(data) < ((x + 3) + (y * 2))):
                    continue
                if hack_mf and data[((x + 3) + (y * 2)) - 1] == 0xc0: # Basic 3270 field attributes
                    if check_hidden(data[((x + 3) + (y * 2))]) and hack_hv:
                        found_hidden_data = 1
                    data[((x + 3) + (y * 2))] = flip_bits(data[((x + 3) + (y * 2))], hack_prot, hack_hf, hack_rnr, hack_ei)
            if hack_mf and found_hidden_data:
                data[x + 1] = data[x + 1] + 2
                data2 = bytearray(len(data) + 4)
                data2 = data[:x + (data[x + 1] * 2) - 2] + b'\x41\xf2\x42\xf6' + data[x + (data[x + 1] * 2) - 2:]
                data = data2
                x = x + 4
                found_hidden_data = 0
            continue

    # Process hacking of Colors
    for x in range(len(data)):
        if data[x] == 0x29: # Start Field Extended
            for y in range(data[x + 1]):
                if(len(data) < ((x + 3) + (y * 2))):
                    continue
                if hack_color_sfe and data[((x + 3) + (y * 2)) - 1] == 0x42: # Color
                    if data[((x + 3) + (y * 2))] == 0xf8: # Black
                        if hack_color_hv:
                            data[x + 1] = data[x + 1] + 2
                            data2 = bytearray(len(data) + 4)
                            data2 = data[:((x + 3) + (y * 2)) + 1] + b'\x41\xf2\x42\xf6' + data[((x + 3) + (y * 2)) + 1:]
                            x = x + 4
                        else:
                            data[x + 1] = data[x + 1] + 1
                            data2 = bytearray(len(data) + 2)
                            data2 = data[:((x + 3) + (y * 2)) + 1] + b'\x42\xf6' + data[((x + 3) + (y * 2)) + 1:]
                            x = x + 2
                        data = data2
        elif data[x] == 0x28: # Set Attribute
            if hack_color_sa and data[x + 1] == 0x42: # Color
                if data[x + 2] == 0xf8: # Black
                    if hack_color_hv:
                        data2 = bytearray(len(data) + 6)
                        data2 = data[:x + 3] + b'\x28\x41\xf2\x28\x42\xf6' + data[x + 3:]
                        x = x + 6
                    else:
                        data2 = bytearray(len(data) + 3)
                        data2 = data[:x + 3] + b'\x28\x42\xf6' + data[x + 3:]
                        x = x + 3
                    data = data2
            continue
        elif data[x] == 0x2c: # Modify Field
            for y in range(data[x + 1]):
                if(len(data) < ((x + 3) + (y * 2))):
                    continue
                if hack_color_mf and data[((x + 3) + (y * 2)) - 1] == 0x42: # Color
                    if data[((x + 3) + (y * 2))] == 0xf8: # Black
                        if hack_color_hv:
                            data[x + 1] = data[x + 1] + 2
                            data2 = bytearray(len(data) + 4)
                            data2 = data[:((x + 3) + (y * 2)) + 1] + b'\x41\xf2\x42\xf6' + data[((x + 3) + (y * 2)) + 1:]
                            x = x + 4
                        else:
                            data[x + 1] = data[x + 1] + 1
                            data2 = bytearray(len(data) + 2)
                            data2 = data[:((x + 3) + (y * 2)) + 1] + b'\x42\xf6' + data[((x + 3) + (y * 2)) + 1:]
                            x = x + 2
                        data = data2
            continue

    return(data)

def parse_telnet(ebcdic_string):
    return_string = re.sub('\\[0xFF\\]', '[IAC]', ebcdic_string)
    return_string = re.sub('\\[0xFE\\]', '[DON\'T]', return_string)
    return_string = re.sub('\\[0xFD\\]', '[DO]', return_string)
    return_string = re.sub('\\[0xFC\\]', '[WON\'T]', return_string)
    return_string = re.sub('\\[0xFB\\]', '[WILL]', return_string)
    return_string = re.sub('\\[0xFA\\]', '[SB]', return_string)
    return_string = re.sub('\\[0x29\\]', '[3270-REGIME]', return_string)
    return_string = re.sub('\\[0x18\\]', '[TERMINAL-TYPE]', return_string)
    return_string = re.sub('\\[0x19\\]', '[END-OF-RECORD]', return_string)
    return_string = re.sub('\\[0x28\\]', '[TN3270E]', return_string)
    return_string = re.sub('\\[0x01\\]', '[SEND]', return_string)
    return_string = re.sub('\\[DO\\]\\[0x00\\]', '[DO][TRANSMIT-BINARY]', return_string)
    return_string = re.sub('\\[DON\'T\\]\\[0x00\\]', '[DON\'T][TRANSMIT-BINARY]', return_string)
    return_string = re.sub('\\[WILL\\]\\[0x00\\]', '[WILL][TRANSMIT-BINARY]', return_string)
    return_string = re.sub('\\[WON\'T\\]\\[0x00\\]', '[WON\'T][TRANSMIT-BINARY]', return_string)
    return_string = re.sub('\\[0x00\\]', '[IS]', return_string)
    return_string = re.sub('\\[0x49\\]\\[0x42\\]\(\\[0x2D\\]\\[0x33\\]\\[0x32\\]\\[0x37\\]\\[0x39\\]\\[0x2D\\]\\[0x32\\]\\[0x2D\\]\\[0x45\\]', '[IBM-3270-2-E]', return_string)
    return_string = re.sub('\\[0x49\\]\\[0x42\\]\(\\[0x2D\\]\\[0x33\\]\\[0x32\\]\\[0x37\\]\\[0x39\\]\\[0x2D\\]\\[0x33\\]\\[0x2D\\]\\[0x45\\]', '[IBM-3270-3-E]', return_string)
    return_string = re.sub('\\[0x49\\]\\[0x42\\]\(\\[0x2D\\]\\[0x33\\]\\[0x32\\]\\[0x37\\]\\[0x39\\]\\[0x2D\\]\\[0x34\\]\\[0x2D\\]\\[0x45\\]', '[IBM-3270-4-E]', return_string)
    return_string = re.sub('\\[0x49\\]\\[0x42\\]\(\\[0x2D\\]\\[0x33\\]\\[0x32\\]\\[0x37\\]\\[0x39\\]\\[0x2D\\]\\[0x35\\]\\[0x2D\\]\\[0x45\\]', '[IBM-3270-5-E]', return_string)
    return_string = re.sub('\\[0x49\\]\\[0x42\\]\(\\[0x2D\\]\\[0x33\\]\\[0x32\\]\\[0x37\\]\\[0x39\\]\\[0x2D\\]\\[0x44\\]\\[0x59\\]\\[0x4E\\]\\[0x41\\]\\[0x4D\\]\\[0x49\\]\\[0x43\\]', '[IBM-3270-DYNAMIC]', return_string)
    return_string = re.sub('\\[TN3270E\\]\\[0x08\\]\\[0x02\\]', '[TN3270E][SEND][DEVICE-TYPE]', return_string)
    return_string = re.sub('\\[TN3270E\\]\\[0x02\\]\\[0x07\\]', '[TN3270E][DEVICE-TYPE][REQUEST]', return_string)
    return_string = re.sub('\\[TN3270E\\]\\[0x02\\]\\[0x04\\]', '[TN3270E][DEVICE-TYPE][IS]', return_string)
    return_string = re.sub('\\]0$', '][SE]', return_string)
    return(return_string)

def parse_3270(ebcdic_string, raw_data):
    return_string = re.sub('\\[0x29\\]', '\n[Start Field Extended]', ebcdic_string)
    return_string = re.sub('\\[0x1D\\]', '\n[Start Field]', return_string)
    return_string = re.sub('\\[Start Field\\]0', '[Start Field][11110000]', return_string)
    return_string = re.sub('\\[Start Field\\]1', '[Start Field][11110001]', return_string)
    return_string = re.sub('\\[Start Field\\]2', '[Start Field][11110010]', return_string)
    return_string = re.sub('\\[Start Field\\]3', '[Start Field][11110011]', return_string)
    return_string = re.sub('\\[Start Field\\]4', '[Start Field][11110100]', return_string)
    return_string = re.sub('\\[Start Field\\]5', '[Start Field][11110101]', return_string)
    return_string = re.sub('\\[Start Field\\]6', '[Start Field][11110110]', return_string)
    return_string = re.sub('\\[Start Field\\]7', '[Start Field][11110111]', return_string)
    return_string = re.sub('\\[Start Field\\]8', '[Start Field][11111000]', return_string)
    return_string = re.sub('\\[Start Field\\]9', '[Start Field][11111001]', return_string)
    return_string = re.sub('\\[Start Field\\]A', '[Start Field][11000001]', return_string)
    return_string = re.sub('\\[Start Field\\]B', '[Start Field][11000010]', return_string)
    return_string = re.sub('\\[Start Field\\]C', '[Start Field][11000011]', return_string)
    return_string = re.sub('\\[0x28\\]', '[Set Attribute]', return_string)
    return_string = re.sub('{', '[Basic Field Attribute]', return_string)
    return_string = re.sub('\\[0x41\\]\\[0x00\\]', '[Highlighting - Default]', return_string)
    return_string = re.sub('\\[0x41\\]0', '[Highlighting - Normal]', return_string)
    return_string = re.sub('\\[0x41\\]1', '[Highlighting - Blink]', return_string)
    return_string = re.sub('\\[0x41\\]2', '[Highlighting - Reverse]', return_string)
    return_string = re.sub('\\[0x41\\]4', '[Highlighting - Underscore]', return_string)
    return_string = re.sub('\\[0x41\\]8', '[Highlighting - Intensity]', return_string)
    return_string = re.sub('\\[0x42\\]\\[0x00\\]', '[Color - Default]', return_string)
    return_string = re.sub('\\[0x42\\]0', '[Color - Neutral/Black]', return_string)
    return_string = re.sub('\\[0x42\\]1', '[Color - Blue]', return_string)
    return_string = re.sub('\\[0x42\\]2', '[Color - Red]', return_string)
    return_string = re.sub('\\[0x42\\]3', '[Color - Pink]', return_string)
    return_string = re.sub('\\[0x42\\]4', '[Color - Green]', return_string)
    return_string = re.sub('\\[0x42\\]5', '[Color - Yellow]', return_string)
    return_string = re.sub('\\[0x42\\]6', '[Color - Yellow]', return_string)
    return_string = re.sub('\\[0x42\\]7', '[Color - Neutral/White]', return_string)
    return_string = re.sub('\\[0x11\\]', '\n[Move Cursor Position]', return_string)
    return_string = re.sub('\\[Basic Field Attribute\\] \\[ ', '[Basic Field Attribute][0x40][', return_string)
    return(return_string)
