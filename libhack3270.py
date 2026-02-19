"""
Hack3270 Python Library
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This python library was developed to create an interoperable object
used to test 3270 based applications. This object manages the logging
database, connectivity and tracking state of the connections. There is no user
interface provided by this class, the example UI is included in tk.py
"""
__version__ = '2.6.2'
__author__ = 'Garland Glessner'
__license__ = "GPL-3.0"
__name__ = "hack3270"

import logging
import sqlite3
import socket
import time
import ssl
import re
import select
import csv
import datetime

from pathlib import Path


class Hack3270Error(Exception):
    """Base exception for hack3270 errors."""
    pass


class ConnectionError(Hack3270Error):
    """Raised when connection to the TN3270 server fails."""
    pass


class ProjectConfigError(Hack3270Error):
    """Raised when project configuration doesn't match existing database."""
    pass


# EBCDIC to ASCII table
e2a = [
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

# Reverse lookup: ASCII to EBCDIC (for O(1) lookup instead of O(256))
a2e = {char: idx for idx, char in enumerate(e2a)}

# Pre-compiled regex patterns for parse_telnet
TELNET_PATTERNS = [
    (re.compile(r'\[0xFF\]'), '[IAC]'),
    (re.compile(r'\[0xFE\]'), "[DON'T]"),
    (re.compile(r'\[0xFD\]'), '[DO]'),
    (re.compile(r'\[0xFC\]'), "[WON'T]"),
    (re.compile(r'\[0xFB\]'), '[WILL]'),
    (re.compile(r'\[0xFA\]'), '[SB]'),
    (re.compile(r'\[0x29\]'), '[3270-REGIME]'),
    (re.compile(r'\[0x18\]'), '[TERMINAL-TYPE]'),
    (re.compile(r'\[0x19\]'), '[END-OF-RECORD]'),
    (re.compile(r'\[0x28\]'), '[TN3270E]'),
    (re.compile(r'\[0x01\]'), '[SEND]'),
    (re.compile(r'\[DO\]\[0x00\]'), '[DO][TRANSMIT-BINARY]'),
    (re.compile(r"\[DON'T\]\[0x00\]"), "[DON'T][TRANSMIT-BINARY]"),
    (re.compile(r'\[WILL\]\[0x00\]'), '[WILL][TRANSMIT-BINARY]'),
    (re.compile(r"\[WON'T\]\[0x00\]"), "[WON'T][TRANSMIT-BINARY]"),
    (re.compile(r'\[0x00\]'), '[IS]'),
    (re.compile(r'\[0x49\]\[0x42\]\(\[0x2D\]\[0x33\]\[0x32\]\[0x37\]\[0x39\]\[0x2D\]\[0x32\]\[0x2D\]\[0x45\]'), '[IBM-3270-2-E]'),
    (re.compile(r'\[0x49\]\[0x42\]\(\[0x2D\]\[0x33\]\[0x32\]\[0x37\]\[0x39\]\[0x2D\]\[0x33\]\[0x2D\]\[0x45\]'), '[IBM-3270-3-E]'),
    (re.compile(r'\[0x49\]\[0x42\]\(\[0x2D\]\[0x33\]\[0x32\]\[0x37\]\[0x39\]\[0x2D\]\[0x34\]\[0x2D\]\[0x45\]'), '[IBM-3270-4-E]'),
    (re.compile(r'\[0x49\]\[0x42\]\(\[0x2D\]\[0x33\]\[0x32\]\[0x37\]\[0x39\]\[0x2D\]\[0x35\]\[0x2D\]\[0x45\]'), '[IBM-3270-5-E]'),
    (re.compile(r'\[0x49\]\[0x42\]\(\[0x2D\]\[0x33\]\[0x32\]\[0x37\]\[0x39\]\[0x2D\]\[0x44\]\[0x59\]\[0x4E\]\[0x41\]\[0x4D\]\[0x49\]\[0x43\]'), '[IBM-3270-DYNAMIC]'),
    (re.compile(r'\[TN3270E\]\[0x08\]\[0x02\]'), '[TN3270E][SEND][DEVICE-TYPE]'),
    (re.compile(r'\[TN3270E\]\[0x02\]\[0x07\]'), '[TN3270E][DEVICE-TYPE][REQUEST]'),
    (re.compile(r'\[TN3270E\]\[0x02\]\[0x04\]'), '[TN3270E][DEVICE-TYPE][IS]'),
    (re.compile(r'\]0$'), '][SE]'),
]

# Pre-compiled regex patterns for parse_3270
TN3270_PATTERNS = [
    (re.compile(r'\[0x29\]'), '\n[Start Field Extended]'),
    (re.compile(r'\[0x1D\]'), '\n[Start Field]'),
    (re.compile(r'\[Start Field\]0'), '[Start Field][11110000]'),
    (re.compile(r'\[Start Field\]1'), '[Start Field][11110001]'),
    (re.compile(r'\[Start Field\]2'), '[Start Field][11110010]'),
    (re.compile(r'\[Start Field\]3'), '[Start Field][11110011]'),
    (re.compile(r'\[Start Field\]4'), '[Start Field][11110100]'),
    (re.compile(r'\[Start Field\]5'), '[Start Field][11110101]'),
    (re.compile(r'\[Start Field\]6'), '[Start Field][11110110]'),
    (re.compile(r'\[Start Field\]7'), '[Start Field][11110111]'),
    (re.compile(r'\[Start Field\]8'), '[Start Field][11111000]'),
    (re.compile(r'\[Start Field\]9'), '[Start Field][11111001]'),
    (re.compile(r'\[Start Field\]A'), '[Start Field][11000001]'),
    (re.compile(r'\[Start Field\]B'), '[Start Field][11000010]'),
    (re.compile(r'\[Start Field\]C'), '[Start Field][11000011]'),
    (re.compile(r'\[0x28\]'), '[Set Attribute]'),
    (re.compile(r'\{'), '[Basic Field Attribute]'),
    (re.compile(r'\[0x41\]\[0x00\]'), '[Highlighting - Default]'),
    (re.compile(r'\[0x41\]0'), '[Highlighting - Normal]'),
    (re.compile(r'\[0x41\]1'), '[Highlighting - Blink]'),
    (re.compile(r'\[0x41\]2'), '[Highlighting - Reverse]'),
    (re.compile(r'\[0x41\]4'), '[Highlighting - Underscore]'),
    (re.compile(r'\[0x41\]8'), '[Highlighting - Intensity]'),
    (re.compile(r'\[0x42\]\[0x00\]'), '[Color - Default]'),
    (re.compile(r'\[0x42\]0'), '[Color - Neutral/Black]'),
    (re.compile(r'\[0x42\]1'), '[Color - Blue]'),
    (re.compile(r'\[0x42\]2'), '[Color - Red]'),
    (re.compile(r'\[0x42\]3'), '[Color - Pink]'),
    (re.compile(r'\[0x42\]4'), '[Color - Green]'),
    (re.compile(r'\[0x42\]5'), '[Color - Yellow]'),
    (re.compile(r'\[0x42\]6'), '[Color - Yellow]'),
    (re.compile(r'\[0x42\]7'), '[Color - Neutral/White]'),
    (re.compile(r'\[0x11\]'), '\n[Move Cursor Position]'),
    (re.compile(r'\[Basic Field Attribute\] \[ '), '[Basic Field Attribute][0x40]['),
]



BUFFER_MAX = 10000

class hack3270:

    AIDS = {
        'NO': b'\x60',
        'QREPLY': b'\x61',
        'ENTER': b'\x7d',
        'PF1': b'\xf1',
        'PF2': b'\xf2',
        'PF3': b'\xf3',
        'PF4': b'\xf4',
        'PF5': b'\xf5',
        'PF6': b'\xf6',
        'PF7': b'\xf7',
        'PF8': b'\xf8',
        'PF9': b'\xf9',
        'PF10': b'\x7a',
        'PF11': b'\x7b',
        'PF12': b'\x7c',
        'PF13': b'\xc1',
        'PF14': b'\xc2',
        'PF15': b'\xc3',
        'PF16': b'\xc4',
        'PF17': b'\xc5',
        'PF18': b'\xc6',
        'PF19': b'\xc7',
        'PF20': b'\xc8',
        'PF21': b'\xc9',
        'PF22': b'\x4a',
        'PF23': b'\x4b',
        'PF24': b'\x4c',
        'OICR': b'\xe6',
        'MSR_MHS': b'\xe7',
        'SELECT': b'\x7e',
        'PA1': b'\x6c',
        'PA2': b'\x6e',
        'PA3': b'\x6b',
        'CLEAR': b'\x6d',
        'SYSREQ': b'\xf0'
    }

    def __init__(self,
                 server_ip, 
                 server_port, 
                 proxy_port, 
                 proxy_ip="127.0.0.1", 
                 offline_mode = False,
                 project_name = "pentest", 
                 loglevel=logging.WARNING,
                 tls_enabled = False,
                 logfile=None):
        

        # Passed Variable for Init
        self.project_name = project_name
        self.server_ip = server_ip
        self.server_port = int(server_port) if server_port is not None else None
        self.proxy_ip = proxy_ip
        self.proxy_port = proxy_port
        self.tls_enabled = tls_enabled
        self.offline_mode = offline_mode

        # Internal Vars
        self.connected = False
        self.client = None
        self.server = None
        self.inject_mask = None
        self.inject_setup_capture = False
        self.inject_config_set = False 
        self.inject_preamble = 0
        self.inject_postamble = 0
        self.inject_mask_len = 0

        self.db_filename = self.project_name + ".db"
        self.found_aids = [] # for keeping track of AIDs found on screen
        self.server_data = b''  # Last server data received (for toggle resend)

        # State Tracking Vars
        self.hack_toggled = False
        self.hack_color_toggled =False
        self.hack_on = False        # We in the butter zone now
        self.hack_color_on = False
        self.hack_prot = False      # 'Protected' Flag (Bit 6) 
        self.hack_hf = False        # 'Non-display' Flag (Bit 4)
        self.hack_rnr = False       # 'Numeric Only' Flag (Bit 5)
        self.hack_ei = False        # enable intentisty
        self.hack_sf = False        # Start Field
        self.hack_sfe = False       # Start Field Extended
        self.hack_mf = False        # Modified Field
        self.hack_hv = False        # High Visibility
        self.hack_color_sfe = False # 
        self.hack_color_mf = False  # 
        self.hack_color_sa = False  # 
        self.hack_color_hv = False  #

        # AID Spoofing State
        self.aid_spoof_enabled = False
        self.aid_spoof_mode = 'MANUAL'  # 'MANUAL' or 'FUZZER'
        self.aid_spoof_value = 'ENTER'  # Selected AID name for manual mode
        self.aid_fuzzer_armed = False
        self.aid_fuzzer_running = False
        self.aid_fuzzer_paused = False
        self.aid_fuzzer_stopped = False
        self.aid_fuzzer_captured_data = None
        self.aid_fuzzer_progress = 0
        self.aid_fuzzer_callback = None  # GUI callback for status updates

        # Web API State
        self.api_port = 31337
        self.api_listener = None
        self.api_clients = []  # List of connected API client sockets 

        # Create the Loggers (file and stderr)
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        if logfile is not None:
            logger_formatter = logging.Formatter(
                '%(levelname)s :: {} :: %(funcName)s'
                ' :: %(message)s'.format(logfile))
        else:
            logger_formatter = logging.Formatter(
                '%(module)s :: %(levelname)s :: %(funcName)s :: %(lineno)d :: %(message)s')
        # Log to stderr
        ch = logging.StreamHandler()
        ch.setFormatter(logger_formatter)
        ch.setLevel(loglevel)
        if not self.logger.hasHandlers():
            self.logger.addHandler(ch)
        
        self.logger.debug("Hack3270 Initializing")
        # Initialize the database 
        self.db_init()

        self.logger.debug("Project Name: {}".format(self.project_name))
        self.logger.debug("Server: {}:{}".format(
                                            self.server_ip, self.server_port))
        self.logger.debug("Proxy: {}:{}".format(self.proxy_ip,self.proxy_port))
        self.current_state_debug_msg()

    def on_closing(self):
        self.logger.debug("Shutting Down database")
        self.sql_con.commit()
        self.sql_con.close()
        self.logger.debug("Shutting Down client connection")
        if self.client:
            self.client.close()
        self.logger.debug("Shutting Down server connection")
        if self.server:
            self.server.close()
        self.logger.debug("Shutting Down API listener")
        self.api_stop()

    def db_init(self):
        '''
        Either creates, or loads, a SQLite 3 database file based on the project 
        name.
        
        Args: 
            None
        Returns: 
            None but sql_con and sql_cur get populated as SQL objects

        TODO:
            Add support for other database types
        '''
        # SQLite3---

        # If DB file doesn't exist and Server IP address isn't set, exit---
        if not Path(self.db_filename).is_file() and not self.server_ip:
            if self.offline_mode:
                print(f"Error: Project file '{self.db_filename}' not found.")
                print(f"Offline mode requires an existing project database.")
                print(f"Use -n to specify a project name: python hack3270.py -n <project> -o")
                raise SystemExit(1)
            else:
                raise Exception("Cannot initialize without a server IP and port")

        self.logger.debug("Opening database file: {}".format(self.db_filename))

        self.sql_con = sqlite3.connect(self.db_filename)
        self.sql_con.set_trace_callback(self.logger.debug) # Use log for SQL debugging
        self.sql_cur = self.sql_con.cursor()

        self.sql_cur.execute("""
                             SELECT count(name) 
                             FROM sqlite_master 
                             WHERE TYPE='table' 
                                AND NAME='Config'
                             """)

        # If table exists, load previous settings---
        if self.sql_cur.fetchone()[0] == 1:
            self.logger.debug("Found existing project config")
            self.sql_cur.execute("SELECT * FROM Config")
            record = self.sql_cur.fetchall()
            for row in record:
                self.logger.debug(row)

                if self.server_ip != row[1] and self.offline_mode == 0:
                    raise ProjectConfigError(
                        f"IP address mismatch with existing project '{self.project_name}.db'.\n"
                        f"  Command line: {self.server_ip}\n"
                        f"  Project file: {row[1]}\n"
                        f"Either use the correct IP or delete '{self.project_name}.db' to start fresh."
                    )
                self.server_ip = row[1]

                self.logger.debug('{} {}'.format(type(self.server_port),type(row[2])))
                if self.server_port != int(row[2])  and self.offline_mode == 0:
                    raise ProjectConfigError(
                        f"Server port mismatch with existing project '{self.project_name}.db'.\n"
                        f"  Command line: {self.server_port}\n"
                        f"  Project file: {row[2]}\n"
                        f"Either use the correct port or delete '{self.project_name}.db' to start fresh."
                    )
                if self.proxy_port != int(row[2]):
                    self.logger.warn("Proxy port from project ({}) "
                                  "overiding proxy port argument ({}) ".format(
                                            row[2], self.proxy_port
                                     ))
                    
                self.server_port = int(row[2])
                self.proxy_port = int(row[3])
                self.tls_enabled = int(row[4])
        # else create table with current configuration---
        else:
            self.logger.debug("Creating Config table...")
            self.sql_cur.execute("""
                    CREATE TABLE Config (
                                 CREATION_TS TEXT NOT NULL, 
                                 SERVER_IP TEXT NOT NULL, 
                                 SERVER_PORT INT NOT NULL, 
                                 PROXY_PORT INT NOT NULL, 
                                 TLS_ENABLED INT NOT NULL
                                 )
                    """)
            
            insert = """
                      INSERT INTO Config (
                      'CREATION_TS', 
                      'SERVER_IP', 
                      'SERVER_PORT', 
                      'PROXY_PORT', 
                      'TLS_ENABLED'
                      ) VALUES (
                      '{time}',
                      '{server_ip}',
                      '{server_port}',
                      '{proxy_port}',
                      '{tls}' 
                      )""".format(
                        time= str(time.time()),
                        server_ip = self.server_ip,
                        server_port = str(self.server_port),
                        proxy_port = str(self.proxy_port),
                        tls = self.tls_enabled * 1 # Why times one? To convert it to an int
                      )
            
            self.sql_cur.execute(insert)
            self.sql_con.commit()

        self.sql_cur.execute("""
                             SELECT count(name) 
                             FROM sqlite_master 
                             WHERE TYPE='table' AND NAME='Logs'
                             """)
        if self.sql_cur.fetchone()[0] != 1:
            self.logger.debug("Creating Logs table...")
            self.sql_cur.execute("""
                            CREATE TABLE Logs (
                            ID INTEGER PRIMARY KEY AUTOINCREMENT, 
                            TIMESTAMP TEXT, 
                            C_S CHAR(1), 
                            NOTES TEXT, 
                            DATA_LEN INT, 
                            RAW_DATA BLOB(4000))
                            """) # 3,564
            self.sql_con.commit()
        
    def write_database_log(self, direction, notes, data):

        if data[0] == 255:
            notes = notes + "tn3270 negotiation"

        self.sql_cur.execute("INSERT INTO Logs ('TIMESTAMP', 'C_S', 'NOTES', 'DATA_LEN', 'RAW_DATA') VALUES (?, ?, ?, ?, ?)", (str(time.time()), direction, notes, str(len(data)), sqlite3.Binary(data)))

#        self.sql_cur.execute("""
#                             INSERT INTO Logs (
#                                'TIMESTAMP', 
#                                'C_S', 
#                                'NOTES', 
#                                'DATA_LEN', 
#                                'RAW_DATA') 
#                             VALUES (
#                                '{ts}', '{dir}', '{note}', '{len}', {bytes})""".format(
#                                ts=str(time.time()), 
#                                dir=direction, 
#                                note=notes, 
#                                len=str(len(data)), 
#                                bytes=sqlite3.Binary(data)))
        self.sql_con.commit()
        
        return
    
    def all_logs(self,start=0):
        '''
        Gets all logs from the database

            Args:
                start (int): the start record, default 0
        '''
        self.logger.debug("Start: {}".format(start))
        if start > 0 :
            self.logger.debug("Getting all records starting at {}".format(start))
            self.sql_cur.execute("SELECT * FROM Logs WHERE ID > {} ORDER BY ID ASC".format(start))
        else:
            self.logger.debug("Getting all records from database")
            self.sql_cur.execute("SELECT * FROM Logs ORDER BY ID ASC")

        return self.sql_cur.fetchall()
    
    def get_log(self, record_id):
        self.logger.debug("Fetching record id: {}".format(record_id))
        sql_text = "SELECT * FROM Logs WHERE ID=" + str(record_id)
        self.sql_cur.execute(sql_text)
        return self.sql_cur.fetchall()

    def check_inject_3270e(self):
        '''
        Checks the first record from the logs database and inspects it to
        identify if this server is in tn3270 extended mode or not

            Returns:
                True if the connection is in TN3270E mode
                False if not in TN3270E mode
        '''

        sql_text = "SELECT * FROM Logs WHERE ID=1"
        self.sql_cur.execute(sql_text)
        records = self.sql_cur.fetchall()
        for row in records:
            # If the third character is 
            if row[5][2] == 40:
                self.logger.debug("TN3270E Detected.")
                return True 
            else:
                self.logger.debug("TN3270 Detected.")
                return False

    def check_server(self,record_id):

        sql_text = "SELECT * FROM Logs WHERE ID=" + str(record_id)
        self.sql_cur.execute(sql_text)
        records = self.sql_cur.fetchall()
        for row in records:
            if row[2] == "S":
                return True
            else:
                return False

    def check_record(self, record_id):

        sql_text = "SELECT * FROM Logs WHERE ID=" + str(record_id)
        self.sql_cur.execute(sql_text)
        records = self.sql_cur.fetchall()
        for row in records:
            # If the first character is 0xFF then this is a telnet handshake message
            if row[5][0] == 255:
                return True
            else:
                return False

    def play_record(self,record_id):
        
        sql_text = "SELECT * FROM Logs WHERE ID=" + str(record_id)
        self.sql_cur.execute(sql_text)
        records = self.sql_cur.fetchall()
        for row in records:
            self.client.send(row[5])

    def export_csv(self,csv_filename=False):
        '''
        Writes the SQL logs to a CSV file

            Args:
                csv_filename (string): the path/filename where to write the csv
                                       file (optional)
            Returns:
                The filename of the csv file
        '''
        if not csv_filename:
            csv_filename = self.project_name + ".csv"

        self.logger.debug("Exporting databse to: {}".format(csv_filename))
        with sqlite3.connect(self.db_filename) as db:
            cursor = db.cursor()
            rows = cursor.execute("SELECT * FROM Logs")
            with open(csv_filename, "w", newline="") as csvfile:
                writer = csv.writer(csvfile)
                for row in rows:
                    ebcdic_data = self.get_ascii(row[5])
                    if re.search("^tn3270 ", row[3]):
                        parsed_3270 = self.parse_telnet(ebcdic_data)
                    else:
                        parsed_3270 = self.parse_3270(ebcdic_data)
                    data = parsed_3270.replace('\n', '')
                    timestamp = float(row[1])
                    dt = datetime.datetime.fromtimestamp(timestamp)
                    if row[2] == "C":
                        direction = "Client"
                    else:
                        direction = "Server"
                    writer.writerow([dt, direction, row[3], row[4], data.encode('utf-8')])
            self.logger.debug('Export finished, filename is: {}'.format(csv_filename))
        return csv_filename

    def current_state_debug_msg(self):

        template = "Hack {} Flag ({}): {}"
        self.logger.debug("Current Flag Settings")
        self.logger.debug("Hack Fields Enabled (hack_on): {}".format(self.hack_on))
        self.logger.debug("Hack Fields Colors Enabled (hack_color_on): {}".format(self.hack_color_on))
        self.logger.debug(template.format("Protected","hack_prot", self.hack_prot))
        self.logger.debug(template.format("Hidden","hack_hf", self.hack_hf))
        self.logger.debug(template.format("Numeric","hack_rnr",self.hack_rnr))
        self.logger.debug(template.format("Intensity","hack_ei", self.hack_ei))
        self.logger.debug(template.format("Start Field","hack_sf", self.hack_sf))
        self.logger.debug(template.format("Start Field Extended","hack_sfe", self.hack_sfe))
        self.logger.debug(template.format("Modify","hack_mf", self.hack_mf))
        self.logger.debug(template.format("High Visibility","hack_hv", self.hack_hv))
        self.logger.debug(template.format("Color Start Field Extended","hack_color_sfe", self.hack_color_sfe))
        self.logger.debug(template.format("Color Modify","hack_color_mf", self.hack_color_mf))
        self.logger.debug(template.format("Color Set Address","hack_color_sa", self.hack_color_sa))
        self.logger.debug(template.format("Color High Visibility","hack_color_hv", self.hack_color_hv))

    def get_ip_port(self):
        '''
        returns a tuple of the server and port
        '''
        return (self.server_ip, self.server_port)
    
    def get_proxy_ip_port(self):
        '''
        returns a tuple of the server and port
        '''
        return (self.proxy_ip, self.proxy_port)
    
    def get_tls(self):
        '''
        Returns whether or not the connection is using TLS
        '''
        return self.tls_enabled

    def get_inject_postamble(self):
        '''
        Returns the inject postamble
        '''
        return self.inject_postamble

    def get_inject_preamble(self):
        '''
        Returns the inject preamble
        '''
        return self.inject_preamble

    def get_inject_mask_len(self):
        '''
        Returns the current inject mask length
        '''
        return self.inject_mask_len
    
    def get_inject_config_set(self):
        '''
        Returns the current inject config (true/false)
        '''
        return self.inject_config_set
    
    def get_hack_on(self):
        '''
        Returns if hack mode is on
        '''
        return self.hack_on
    
    def get_hack_color_on(self):
        '''
        Returns if hack color mode is on
        '''
        return self.hack_color_on

    def is_offline(self):
        ''' Returns True if offline, False if not'''
        return self.offline_mode

    def set_inject_setup_capture(self,value=1):
        '''
        Sets the inject_setup_capture state
        '''
        self.logger.debug("Changing inject_setup_capture from {} to {}".format(
            self.inject_setup_capture, value))
        self.inject_setup_capture = value

    def set_inject_config_set(self,value=1):
        '''
        Sets the inject_config_set state
        '''
        self.logger.debug("Changing inject_config_set from {} to {}".format(
            self.inject_config_set, value))
        self.inject_config_set = value

    def set_hack_color_toggled(self,value=1):
        '''
        Sets the hack_color_toggled state
        '''
        self.logger.debug("Changing hack_color_toggled from {} to {}".format(
            self.hack_color_toggled, value))
        self.hack_color_toggled = value

    def set_hack_toggled(self,value=1):
        '''
        Sets the hack_toggled state
        '''
        self.logger.debug("Changing hack_toggled from {} to {}".format(
            self.hack_toggled, value))
        self.hack_toggled = value

    def set_hack_on(self,value=1):
        '''
        Sets the hack_on state
        '''
        self.logger.debug("Changing hack_on from {} to {}".format(
            self.hack_on, value))
        self.hack_on = value

    def set_hack_color_on(self,value=1):
        '''
        Sets the hack_color_on state
        '''
        self.logger.debug("Changing hack_color_on from {} to {}".format(
            self.hack_color_on, value))
        self.hack_color_on = value

    def set_hack_prot(self,value=1):
        '''
        Sets the hack_prot state
        '''
        self.logger.debug("Changing hack_prot from {} to {}".format(
            self.hack_prot, value))
        self.hack_prot = value

    def set_hack_hf(self,value=1):
        '''
        Sets the hack_hf state
        '''
        self.logger.debug("Changing hack_hf from {} to {}".format(
            self.hack_hf, value))
        self.hack_hf = value

    def set_hack_rnr(self,value=1):
        '''
        Sets the hack_rnr state
        '''
        self.logger.debug("Changing hack_rnr from {} to {}".format(
            self.hack_rnr, value))
        self.hack_rnr = value

    def set_hack_ei(self,value=1):
        '''
        Sets the hack_ei state
        '''
        self.logger.debug("Changing hack_ei from {} to {}".format(
            self.hack_ei, value))
        self.hack_ei = value

    def set_hack_sf(self,value=1):
        '''
        Sets the hack_sf state
        '''
        self.logger.debug("Changing hack_sf from {} to {}".format(
            self.hack_sf, value))
        self.hack_sf = value

    def set_hack_sfe(self,value=1):
        '''
        Sets the hack_sfe state
        '''
        self.logger.debug("Changing from {} to {}".format(
            self.hack_sfe, value))
        self.hack_sfe = value

    def set_hack_mf(self,value=1):
        '''
        Sets the hack_mf state
        '''
        self.logger.debug("Changing hack_mf from {} to {}".format(
            self.hack_mf, value))
        self.hack_mf = value

    def set_hack_hv(self,value=1):
        '''
        Sets the hack_prot state
        '''
        self.logger.debug("Changing from {} to {}".format(
            self.hack_hv, value))
        self.hack_hv = value

    def set_hack_color_sfe(self,value=1):
        '''
        Sets the hack_color_sfe state
        '''
        self.logger.debug("Changing hack_color_sfe from {} to {}".format(
            self.hack_color_sfe, value))
        self.hack_color_sfe = value

    def set_hack_color_mf(self,value=1):
        '''
        Sets the hack_color_mf state
        '''
        self.logger.debug("Changing hack_color_mf from {} to {}".format(
            self.hack_color_mf, value))
        self.hack_color_mf = value

    def set_hack_color_sa(self,value=1):
        '''
        Sets the hack_color_sa state
        '''
        self.logger.debug("Changing hack_color_sa from {} to {}".format(
            self.hack_color_sa, value))
        self.hack_color_sa = value

    def set_hack_color_hv(self,value=1):
        '''
        Sets the hack_color_hv state
        '''
        self.logger.debug("Changing hack_color_hv from {} to {}".format(
            self.hack_color_hv, value))
        self.hack_color_hv = value

    def set_inject_mask(self,mask="*"):
        '''Sets the mask to be used for injection'''
        self.logger.debug("Setting mask to '{}'".format(mask))
        self.inject_mask = mask

    ## TCP/IP Functions

    def client_connect(self):
        '''
        Creates the proxy server on proxy_ip, proxy_port
        '''
        
        self.logger.debug("Setting up proxy listener on {}:{}".format(
            self.proxy_ip, self.proxy_port
        ))

        client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        client_sock.bind((self.proxy_ip, self.proxy_port))
        client_sock.listen(4)

        self.logger.debug("Waiting for connection on {}:{}".format(
            self.proxy_ip, self.proxy_port
        ))

        (conn, (ip,port)) = client_sock.accept()

        self.logger.debug("Proxy Connection from {}:{}".format(ip,port))

        self.client = conn

    def server_connect(self):
        '''
        Connects to a TN3270 server on server_ip, server_port
        '''
        if self.offline_mode:
            raise Hack3270Error("Cannot connect when in Offline Mode")
        
        self.logger.debug("Connecting to {}:{}".format(
            self.server_ip,self.server_port))
        
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        if self.tls_enabled:
            self.logger.debug(self.tls_enabled)
            self.logger.debug("Connecting with TLS")
            context = ssl._create_unverified_context()
            self.server = context.wrap_socket(server_sock, server_hostname=self.server_ip)
        else:
            self.server = server_sock

        try:
            self.server.connect((self.server_ip, self.server_port))
        except ConnectionRefusedError:
            raise ConnectionError(
                f"Connection refused by {self.server_ip}:{self.server_port}.\n"
                f"Make sure the TN3270 server is running and accessible."
            )
        except socket.timeout:
            raise ConnectionError(
                f"Connection timed out to {self.server_ip}:{self.server_port}.\n"
                f"Check network connectivity and firewall settings."
            )
        except socket.gaierror as e:
            raise ConnectionError(
                f"Cannot resolve hostname '{self.server_ip}': {e}"
            )
        except OSError as e:
            raise ConnectionError(
                f"Network error connecting to {self.server_ip}:{self.server_port}: {e}"
            )
        
        self.logger.debug("Connected to {}:{}".format(
            self.server_ip,self.server_port))

    def api_start(self):
        '''
        Creates the Web API TCP listener on port 31337.
        This is a non-blocking listener that will be handled in the daemon() select loop.
        '''
        self.logger.debug(f"Starting Web API listener on port {self.api_port}")
        
        self.api_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.api_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.api_listener.setblocking(False)
        
        try:
            self.api_listener.bind(('127.0.0.1', self.api_port))
            self.api_listener.listen(5)
            self.logger.info(f"Web API listening on port {self.api_port}")
        except OSError as e:
            self.logger.error(f"Failed to start Web API on port {self.api_port}: {e}")
            self.api_listener = None
            raise ConnectionError(f"Failed to start Web API on port {self.api_port}: {e}")

    def api_stop(self):
        '''
        Stops the Web API listener and closes all API client connections.
        '''
        self.logger.debug("Stopping Web API listener")
        
        # Close all API client connections
        for client in self.api_clients:
            try:
                client.close()
            except:
                pass
        self.api_clients = []
        
        # Close the listener
        if self.api_listener:
            try:
                self.api_listener.close()
            except:
                pass
            self.api_listener = None
        
        self.logger.debug("Web API stopped")

    def handle_api_request(self, client_socket, data):
        '''
        Handles incoming API requests from connected clients.
        
        Supported commands:
            - SEND_RAW:<length>\n<binary_data> - Send raw bytes to the server
            - ping - Test connectivity
            - Other commands return placeholder response
        '''
        self.logger.debug(f"API request received: {len(data)} bytes")
        
        try:
            # Check for SEND_RAW command first (binary-safe check)
            if data.startswith(b'SEND_RAW:'):
                self._handle_api_send_raw(client_socket, data)
                return
            
            # Try to decode as text command
            try:
                text_data = data.decode('utf-8')
            except UnicodeDecodeError:
                text_data = None
            
            if text_data:
                cmd = text_data.strip().lower()
                
                # Handle ping
                if cmd == 'ping':
                    client_socket.send(b"pong\n")
                    return
                
                # Handle GET_LAST_SERVER - returns last server response as ASCII
                if cmd == 'get_last_server':
                    self._handle_api_get_last_server(client_socket)
                    return
                
                # Handle GET_LAST_SERVER_RAW - returns last server response as base64
                if cmd == 'get_last_server_raw':
                    self._handle_api_get_last_server_raw(client_socket)
                    return
                
                # Handle IS_TN3270E - check if connection is TN3270E mode
                if cmd == 'is_tn3270e':
                    is_3270e = self.check_inject_3270e()
                    client_socket.send(f"{'TRUE' if is_3270e else 'FALSE'}\n".encode('utf-8'))
                    return
                
                # Handle SEND_AID:<aid_name_or_hex> - send an AID key
                if cmd.startswith('send_aid:'):
                    aid_value = text_data.strip()[9:]  # Get original case after "SEND_AID:"
                    self._handle_api_send_aid(client_socket, aid_value)
                    return
                
                # Handle ANALYZE_HIDDEN - analyze last server response for hidden fields
                if cmd == 'analyze_hidden':
                    self._handle_api_analyze_hidden(client_socket)
                    return
                
                # Handle GET_INJECT_TEMPLATE:<id>:<mask_char> - get preamble/postamble for injection
                if cmd.startswith('get_inject_template:'):
                    parts = text_data.strip()[20:].split(':')
                    if len(parts) >= 2:
                        log_id = parts[0]
                        mask_char = parts[1]
                        self._handle_api_get_inject_template(client_socket, log_id, mask_char)
                    else:
                        client_socket.send(b'{"status": "error", "message": "Usage: GET_INJECT_TEMPLATE:<id>:<mask_char>"}\n')
                    return
            
            # Default response
            response = f"hack3270 API - Received {len(data)} bytes\n"
            client_socket.send(response.encode('utf-8'))
            
        except Exception as e:
            self.logger.error(f"Error handling API request: {e}")
            try:
                client_socket.send(f"ERROR: {e}\n".encode('utf-8'))
            except:
                pass
    
    def _handle_api_send_raw(self, client_socket, data):
        '''
        Handle SEND_RAW command - send raw bytes to the mainframe server.
        Format: SEND_RAW:<length>[:<description>]\n<binary_data>
        The description is optional and used for logging.
        '''
        try:
            # Find the header end (first newline)
            header_end = data.find(b'\n')
            if header_end == -1:
                client_socket.send(b"ERROR: Invalid SEND_RAW format\n")
                return
            
            header = data[:header_end].decode('utf-8')
            raw_data = data[header_end + 1:]
            
            # Parse header parts: SEND_RAW:<length>[:<description>]
            header_parts = header.split(':', 2)  # Split into at most 3 parts
            try:
                expected_len = int(header_parts[1])
            except (IndexError, ValueError):
                client_socket.send(b"ERROR: Invalid SEND_RAW header\n")
                return
            
            # Get optional description, default to generic message
            log_description = header_parts[2] if len(header_parts) > 2 else 'API: Send raw data'
            
            # Verify we have all the data
            if len(raw_data) != expected_len:
                client_socket.send(f"ERROR: Expected {expected_len} bytes, got {len(raw_data)}\n".encode('utf-8'))
                return
            
            # Send to the mainframe server
            if self.server:
                self.write_database_log('C', log_description, raw_data)
                self.server.send(raw_data)
                client_socket.send(f"OK: Sent {len(raw_data)} bytes to server\n".encode('utf-8'))
                self.logger.debug(f"API: Sent {len(raw_data)} bytes to server")
            else:
                client_socket.send(b"ERROR: No server connection\n")
                
        except Exception as e:
            self.logger.error(f"Error in SEND_RAW: {e}")
            client_socket.send(f"ERROR: {e}\n".encode('utf-8'))
    
    def _handle_api_send_aid(self, client_socket, aid_value):
        '''
        Handle SEND_AID command - send an AID key to the server.
        
        Args:
            aid_value: AID name (e.g., "ENTER", "PF1") or hex value (e.g., "0x7d", "7d")
        '''
        try:
            aid_value = aid_value.strip()
            
            # Try to look up by name first
            aid_upper = aid_value.upper()
            if aid_upper in self.AIDS:
                aid_byte = self.AIDS[aid_upper]
                aid_name = aid_upper
            else:
                # Try to parse as hex
                try:
                    hex_str = aid_value.lower().replace('0x', '')
                    aid_byte = bytes([int(hex_str, 16)])
                    aid_name = f"0x{hex_str.upper()}"
                except ValueError:
                    client_socket.send(f"ERROR: Unknown AID '{aid_value}'\n".encode('utf-8'))
                    return
            
            if self.server:
                # Check if TN3270E mode - add 5-byte header if so
                if self.check_inject_3270e():
                    # TN3270E: header (00 00 00 00 01) + AID + IAC EOR
                    aid_packet = b'\x00\x00\x00\x00\x01' + aid_byte + b'\xff\xef'
                    self.logger.debug(f"API: Sending AID as TN3270E: {aid_name}")
                else:
                    # Plain TN3270: AID + IAC EOR
                    aid_packet = aid_byte + b'\xff\xef'
                    self.logger.debug(f"API: Sending AID as TN3270: {aid_name}")
                
                self.write_database_log('C', f'API: Send AID {aid_name}', aid_packet)
                self.server.send(aid_packet)
                client_socket.send(f"OK: Sent AID {aid_name}\n".encode('utf-8'))
            else:
                client_socket.send(b"ERROR: No server connection\n")
                
        except Exception as e:
            self.logger.error(f"Error in SEND_AID: {e}")
            client_socket.send(f"ERROR: {e}\n".encode('utf-8'))
    
    def _handle_api_get_inject_template(self, client_socket, log_id, mask_char):
        '''
        Handle GET_INJECT_TEMPLATE command - get preamble and postamble for injection.
        This matches how the GUI Inject Fields feature works.
        
        Returns base64-encoded preamble and postamble that can be used for injection.
        '''
        import json
        import base64
        
        try:
            log_id = int(log_id)
            
            # Get the log entry
            self.sql_cur.execute(f"SELECT RAW_DATA, C_S FROM Logs WHERE ID = {log_id}")
            result = self.sql_cur.fetchone()
            
            if not result:
                client_socket.send(f'{{"status": "error", "message": "Log ID {log_id} not found"}}\n'.encode('utf-8'))
                return
            
            raw_data = result[0]
            direction = result[1]
            
            if direction != 'C':
                client_socket.send(f'{{"status": "error", "message": "Log ID {log_id} is not client data"}}\n'.encode('utf-8'))
                return
            
            # Convert ASCII mask char to EBCDIC
            if mask_char in a2e:
                ebcdic_mask = a2e[mask_char]
            else:
                client_socket.send(f'{{"status": "error", "message": "Cannot convert mask char to EBCDIC"}}\n'.encode('utf-8'))
                return
            
            # Find the mask - same logic as capture_mask()
            preamble_count = 0
            mask_count = 0
            
            # Find where mask starts (preamble)
            for x in range(len(raw_data)):
                if raw_data[x] != ebcdic_mask:
                    preamble_count += 1
                else:
                    break
            
            # Count mask length
            for x in range(preamble_count, len(raw_data)):
                if raw_data[x] == ebcdic_mask:
                    mask_count += 1
                else:
                    break
            
            if mask_count == 0:
                client_socket.send(f'{{"status": "error", "message": "Mask not found in data"}}\n'.encode('utf-8'))
                return
            
            # Split into preamble and postamble
            preamble = raw_data[:preamble_count]
            postamble = raw_data[preamble_count + mask_count:]
            
            response = {
                'status': 'ok',
                'log_id': log_id,
                'mask_char': mask_char,
                'mask_length': mask_count,
                'preamble_b64': base64.b64encode(preamble).decode('ascii'),
                'postamble_b64': base64.b64encode(postamble).decode('ascii'),
                'preamble_len': len(preamble),
                'postamble_len': len(postamble)
            }
            
            client_socket.send((json.dumps(response) + '\n').encode('utf-8'))
            
        except ValueError as e:
            client_socket.send(f'{{"status": "error", "message": "Invalid log ID: {e}"}}\n'.encode('utf-8'))
        except Exception as e:
            self.logger.error(f"Error in GET_INJECT_TEMPLATE: {e}")
            client_socket.send(f'{{"status": "error", "message": "{e}"}}\n'.encode('utf-8'))
    
    def _handle_api_analyze_hidden(self, client_socket):
        '''
        Handle ANALYZE_HIDDEN command - analyze last server response for hidden fields.
        Returns JSON with found hidden fields and their values.
        '''
        import json
        
        try:
            if not self.server_data or len(self.server_data) == 0:
                client_socket.send(b'{"status": "ok", "hidden_fields": [], "message": "No server data"}\n')
                return
            
            data = self.server_data
            hidden_fields = []
            x = 0
            
            while x < len(data) - 1:
                # Start Field (SF) - 0x1D
                if data[x] == 0x1d:
                    if x + 1 < len(data):
                        field_attr = data[x + 1]
                        if self.check_hidden(field_attr):
                            # Extract data after this field until next field marker
                            field_data = self._extract_field_data(data, x + 2)
                            hidden_fields.append({
                                'type': 'SF',
                                'position': x,
                                'attribute': hex(field_attr),
                                'data': field_data
                            })
                    x += 2
                    continue
                
                # Start Field Extended (SFE) - 0x29
                elif data[x] == 0x29:
                    if x + 1 < len(data):
                        pair_count = data[x + 1]
                        # Check each attribute pair for hidden bit
                        for y in range(pair_count):
                            pair_offset = x + 2 + (y * 2)
                            if pair_offset + 1 < len(data):
                                attr_type = data[pair_offset]
                                attr_value = data[pair_offset + 1]
                                # 0xC0 is Basic Field Attribute
                                if attr_type == 0xc0 and self.check_hidden(attr_value):
                                    # Extract data after this SFE
                                    data_start = x + 2 + (pair_count * 2)
                                    field_data = self._extract_field_data(data, data_start)
                                    hidden_fields.append({
                                        'type': 'SFE',
                                        'position': x,
                                        'attribute': hex(attr_value),
                                        'data': field_data
                                    })
                                    break
                        x += 2 + (pair_count * 2)
                    else:
                        x += 1
                    continue
                
                # Modify Field (MF) - 0x2C
                elif data[x] == 0x2c:
                    if x + 1 < len(data):
                        pair_count = data[x + 1]
                        for y in range(pair_count):
                            pair_offset = x + 2 + (y * 2)
                            if pair_offset + 1 < len(data):
                                attr_type = data[pair_offset]
                                attr_value = data[pair_offset + 1]
                                if attr_type == 0xc0 and self.check_hidden(attr_value):
                                    data_start = x + 2 + (pair_count * 2)
                                    field_data = self._extract_field_data(data, data_start)
                                    hidden_fields.append({
                                        'type': 'MF',
                                        'position': x,
                                        'attribute': hex(attr_value),
                                        'data': field_data
                                    })
                                    break
                        x += 2 + (pair_count * 2)
                    else:
                        x += 1
                    continue
                
                x += 1
            
            response = {
                'status': 'ok',
                'total_bytes': len(data),
                'hidden_count': len(hidden_fields),
                'hidden_fields': hidden_fields
            }
            client_socket.send((json.dumps(response) + '\n').encode('utf-8'))
            
        except Exception as e:
            self.logger.error(f"Error in ANALYZE_HIDDEN: {e}")
            client_socket.send(f'{{"status": "error", "message": "{e}"}}\n'.encode('utf-8'))
    
    def _extract_field_data(self, data, start_pos):
        '''
        Extract field data from start_pos until next field marker or end.
        Returns ASCII-converted string.
        '''
        field_bytes = []
        x = start_pos
        
        # Field markers that end a field
        field_markers = [0x1d, 0x29, 0x2c, 0x11, 0x13, 0xff]
        
        while x < len(data):
            if data[x] in field_markers:
                break
            field_bytes.append(data[x])
            x += 1
        
        if field_bytes:
            # Convert EBCDIC to ASCII
            return self.get_ascii(bytes(field_bytes))
        return ''
    
    def _handle_api_get_last_server(self, client_socket):
        '''
        Handle GET_LAST_SERVER command - returns last server response converted to ASCII.
        '''
        try:
            if self.server_data and len(self.server_data) > 0:
                # Convert EBCDIC to ASCII
                ascii_text = self.get_ascii(self.server_data)
                response = f"OK:{len(self.server_data)}:{ascii_text}\n"
            else:
                response = "OK:0:\n"
            client_socket.send(response.encode('utf-8', errors='replace'))
        except Exception as e:
            self.logger.error(f"Error in GET_LAST_SERVER: {e}")
            client_socket.send(f"ERROR: {e}\n".encode('utf-8'))
    
    def _handle_api_get_last_server_raw(self, client_socket):
        '''
        Handle GET_LAST_SERVER_RAW command - returns last server response as base64.
        '''
        import json
        import base64
        try:
            if self.server_data and len(self.server_data) > 0:
                data_b64 = base64.b64encode(self.server_data).decode('ascii')
                response = {
                    'status': 'ok',
                    'length': len(self.server_data),
                    'data_b64': data_b64
                }
            else:
                response = {'status': 'ok', 'length': 0, 'data_b64': ''}
            client_socket.send((json.dumps(response) + '\n').encode('utf-8'))
        except Exception as e:
            self.logger.error(f"Error in GET_LAST_SERVER_RAW: {e}")
            client_socket.send(f'{{"status": "error", "message": "{e}"}}\n'.encode('utf-8'))
    
    def handle_server(self,server_data):
        log_line = ''
        if len(server_data) > 0:
            if self.hack_on:
                log_line = self.hack_on_logline()
            
            if self.hack_color_on:
                log_line = log_line + self.hack_color_on_logline()
            
            # Manipulate if either hack mode is on, otherwise send raw
            if self.hack_on or self.hack_color_on:
                hacked_server = self.manipulate(server_data)
                self.client.send(hacked_server)
            else:
                self.client.send(server_data)
            
            self.write_database_log('S', log_line, server_data)

    def tend_server(self):
        select_timeout = 1
        while True:
            my_rlist, w, e = select.select([self.server],[],[],select_timeout)
            if self.server in my_rlist:
                select_timeout = 0.2
                server_data = self.server.recv(BUFFER_MAX)
                self.handle_server(server_data)
            else:
                break
        return

    def daemon(self):

        # Build the list of sockets to monitor
        read_sockets = [self.client, self.server]
        
        # Add API listener if active
        if self.api_listener:
            read_sockets.append(self.api_listener)
        
        # Add all connected API clients
        read_sockets.extend(self.api_clients)

        # Tend to client sending data
        rlist, w, e = select.select(read_sockets, [], [], 0)
        
        # Handle new API connections
        if self.api_listener and self.api_listener in rlist:
            try:
                api_client, addr = self.api_listener.accept()
                api_client.setblocking(False)
                self.api_clients.append(api_client)
                self.logger.debug(f"API client connected from {addr}")
            except Exception as e:
                self.logger.error(f"Error accepting API connection: {e}")
        
        # Handle API client data
        for api_client in self.api_clients[:]:  # Use slice copy to allow removal during iteration
            if api_client in rlist:
                try:
                    data = api_client.recv(BUFFER_MAX)
                    if len(data) > 0:
                        self.handle_api_request(api_client, data)
                    else:
                        # Client disconnected
                        self.logger.debug("API client disconnected")
                        self.api_clients.remove(api_client)
                        api_client.close()
                except Exception as e:
                    self.logger.error(f"Error handling API client: {e}")
                    self.api_clients.remove(api_client)
                    try:
                        api_client.close()
                    except:
                        pass

        if self.client in rlist:

            self.logger.debug("Client Data Detected")
            client_data = self.client.recv(BUFFER_MAX)
            if len(client_data) > 0:
                self.logger.debug("Client: {}".format(bytes(client_data)))
                self.logger.debug("Client: {}".format(self.get_ascii(client_data)))
                if self.inject_setup_capture:
                    self.capture_mask(client_data)
                # AID Fuzzer capture mode
                elif self.aid_spoof_enabled and self.aid_spoof_mode == 'FUZZER' and self.aid_fuzzer_armed and not self.aid_fuzzer_running:
                    # Capture this transmission for fuzzing
                    self.aid_fuzzer_captured_data = client_data
                    self.aid_fuzzer_armed = False
                    self.aid_fuzzer_running = True
                    self.aid_fuzzer_progress = 0
                    self.logger.debug("AID Fuzzer: Captured transmission, starting fuzz")
                    if self.aid_fuzzer_callback:
                        self.aid_fuzzer_callback('captured', 0, 256, None)
                    # Don't send yet - fuzzer loop will handle it
                # AID Manual spoof mode
                elif self.aid_spoof_enabled and self.aid_spoof_mode == 'MANUAL' and len(client_data) >= 1:
                    modified_data, orig_aid, spoof_aid = self.spoof_aid(client_data)
                    log_msg = f"AID Spoofed: {orig_aid} -> {spoof_aid}"
                    self.write_database_log('C', log_msg, modified_data)
                    self.server.send(modified_data)
                else:
                    self.write_database_log('C', '', client_data)
                    self.server.send(client_data)

        # Tend to server sending data
        if self.server in rlist:
            self.logger.debug("Server Data Detected")
            self.server_data = self.server.recv(BUFFER_MAX)
            if len(self.server_data) > 0:
                self.logger.debug("Server: {}".format(bytes(self.server_data)))
                self.logger.debug("Server: {}".format(self.get_ascii(self.server_data)))
                self.handle_server(self.server_data)
                self.refresh_aids(self.server_data)

        if self.hack_toggled or self.hack_color_toggled: # Resend data to client if either of these options are toggled.

            if self.hack_toggled:
                self.logger.debug("Hack Toggled, resending data to client")
            if self.hack_color_toggled:
                self.logger.debug("Hack Color Toggled, resending data to client")
            
            if len(self.server_data) > 0:
                log_line = ''

                if self.hack_toggled:
                    if self.hack_on:
                        log_line = ('Hack Field Attributes: TOGGLED ON (' 
                                    'Remove Field Prot: {pt}  - '
                                    'Show Hidden: {hf} - ' 
                                    'Remove NUM Prot: {rnr}) (' 
                                    'SF: {sf} - ' 
                                    'SFE: {sfe} - '
                                    'MF: {mf}  - ' 
                                    'EI: {ei} - ' 
                                    'HV: {hv})').format(
                                        pt=self.hack_prot,
                                        hf=self.hack_hf,
                                        rnr=self.hack_rnr,
                                        sf=self.hack_sf,
                                        sfe=self.hack_sfe,
                                        mf=self.hack_mf,
                                        ei=self.hack_ei,
                                        hv=self.hack_hv
                                        )
                    else:
                        log_line = 'Hack Fields Attributes: TOGGLED OFF '

                    self.hack_toggled = 0

                if self.hack_color_toggled:

                    if self.hack_color_on:
                        log_line = log_line + (
                            'Hack Text Color: TOGGLED ON (' 
                            'SFE: {sfe} - '
                            'MF: {mf} - '
                            'SF: {sf} - '
                            'HV: {hv})'
                            ).format(
                                sfe=self.hack_color_sfe,
                                mf=self.hack_color_mf,
                                sf=self.hack_color_sa,
                                hv=self.hack_color_hv
                                )
                    else:
                        log_line = 'Hack Text Color: TOGGLED OFF '

                    self.hack_color_toggled = 0

                hacked_server = self.manipulate(self.server_data)
                self.client.send(hacked_server)
                self.write_database_log('S', log_line, hacked_server)

    def recv(self):
        self.client.recv(BUFFER_MAX)

    def send_server(self, data):
        self.logger.debug("Sending Data to server: {}".format(data.hex()))
        self.server.send(data)

    def send_client(self, data):
        self.logger.debug("Sending Data to client: {}".format(data.hex()))
        self.client.send(data)
    
    def api_send_raw(self, data, description=None):
        '''
        Send raw bytes to the mainframe server (for GUI/internal use).
        Logs the transmission with optional description.
        
        Args:
            data: Raw bytes to send (should include IAC EOR if needed)
            description: Optional description for the log entry
        '''
        if self.server is None:
            raise Exception("No server connection")
        
        # Append IAC EOR if not present
        if not data.endswith(b'\xff\xef'):
            data = data + b'\xff\xef'
        
        # Log the transmission
        note = description if description else 'GUI: Fuzz packet'
        self.write_database_log('C', note, data)
        
        # Send to server
        self.server.send(data)
        self.logger.debug(f"GUI API: Sent {len(data)} bytes to server")
    
    def get_last_server_raw(self):
        '''Get the last server response as raw bytes (for GUI/internal use).'''
        return self.server_data if self.server_data else b''
    
    def get_last_server(self):
        '''Get the last server response converted to ASCII (for GUI/internal use).'''
        if self.server_data and len(self.server_data) > 0:
            return self.get_ascii(self.server_data)
        return ''
    ####

    def expand_CS(self, text):
        '''
        The datase stores client and server communication as one byt
        this function converts it to a string

            Returns: Either Client or Server
        '''
        if text == "C":
            return("Client")
        elif text == "S":
            return("Server")
        
    def send_key(self, send_text, byte_code):
        self.write_database_log('C', 'Sending key: ' + send_text, byte_code + b'\xff\xef')
        if self.check_inject_3270e():
            print("Sending as 3270E: " + send_text)
            self.server.send(b'\x00\x00\x00\x00\x01' + byte_code + b'\xff\xef')
        else:
            print("Sending as 3270: " + send_text)
            self.server.send(byte_code + b'\xff\xef')
        self.tend_server()
        return
    
    def write_log(self, direction, notes, data):
        self.write_database_log(direction, notes, data)

    # AID Spoofing Methods
    def set_aid_spoof_enabled(self, enabled):
        """Enable or disable AID spoofing."""
        self.aid_spoof_enabled = enabled
        self.logger.debug(f"AID Spoofing: {'enabled' if enabled else 'disabled'}")

    def set_aid_spoof_mode(self, mode):
        """Set AID spoof mode: 'MANUAL' or 'FUZZER'."""
        self.aid_spoof_mode = mode
        self.logger.debug(f"AID Spoof Mode: {mode}")

    def set_aid_spoof_value(self, aid_name):
        """Set the AID value to spoof to (for MANUAL mode)."""
        self.aid_spoof_value = aid_name
        self.logger.debug(f"AID Spoof Value: {aid_name}")

    def arm_aid_fuzzer(self):
        """Arm the AID fuzzer to capture the next transmission."""
        self.aid_fuzzer_armed = True
        self.aid_fuzzer_captured_data = None
        self.aid_fuzzer_progress = 0
        self.logger.debug("AID Fuzzer armed")

    def disarm_aid_fuzzer(self):
        """Disarm the AID fuzzer."""
        self.aid_fuzzer_armed = False
        self.aid_fuzzer_running = False
        self.aid_fuzzer_paused = False
        self.aid_fuzzer_stopped = False
        self.aid_fuzzer_captured_data = None
        self.aid_fuzzer_progress = 0
        self.logger.debug("AID Fuzzer disarmed")

    def stop_aid_fuzzer(self):
        """Stop the AID fuzzer."""
        self.aid_fuzzer_stopped = True
        self.aid_fuzzer_paused = False
        self.aid_fuzzer_running = False
        self.logger.debug("AID Fuzzer stopped")
        if self.aid_fuzzer_callback:
            self.aid_fuzzer_callback('stopped', self.aid_fuzzer_progress, 256, None)

    def resume_aid_fuzzer(self):
        """Resume the AID fuzzer after pause."""
        if self.aid_fuzzer_paused and not self.aid_fuzzer_stopped:
            self.aid_fuzzer_paused = False
            self.aid_fuzzer_running = True
            self.logger.debug("AID Fuzzer resumed")
            if self.aid_fuzzer_callback:
                self.aid_fuzzer_callback('resumed', self.aid_fuzzer_progress, 256, None)

    def pause_aid_fuzzer(self):
        """Pause the AID fuzzer."""
        self.aid_fuzzer_paused = True
        self.aid_fuzzer_running = False
        self.logger.debug("AID Fuzzer paused")
        if self.aid_fuzzer_callback:
            self.aid_fuzzer_callback('paused', self.aid_fuzzer_progress, 256, None)

    def set_aid_fuzzer_callback(self, callback):
        """Set callback function for fuzzer status updates."""
        self.aid_fuzzer_callback = callback

    def get_aid_name(self, aid_byte):
        """Get the AID name from a byte value."""
        for name, value in self.AIDS.items():
            if value == aid_byte:
                return name
        return f"0x{aid_byte.hex().upper()}"

    def spoof_aid(self, client_data):
        """
        Replace the AID byte in client data with the spoofed value.
        Returns the modified data.
        
        In TN3270E mode, AID is at byte 5 (after 5-byte header).
        In plain TN3270 mode, AID is at byte 0.
        """
        if len(client_data) < 1:
            return client_data
        
        # Get the spoofed AID byte
        spoofed_aid = self.AIDS.get(self.aid_spoof_value, None)
        spoofed_aid_name = self.aid_spoof_value
        
        # Determine AID position based on TN3270E mode
        if self.check_inject_3270e():
            # TN3270E: AID is at byte 5
            if len(client_data) < 6:
                return client_data, "?", spoofed_aid_name
            original_aid = client_data[5:6]
            original_aid_name = self.get_aid_name(original_aid)
            if spoofed_aid is None:
                spoofed_aid = original_aid
            modified_data = client_data[:5] + spoofed_aid + client_data[6:]
        else:
            # Plain TN3270: AID is at byte 0
            original_aid = client_data[0:1]
            original_aid_name = self.get_aid_name(original_aid)
            if spoofed_aid is None:
                spoofed_aid = original_aid
            modified_data = spoofed_aid + client_data[1:]
        
        self.logger.debug(f"AID Spoofed: {original_aid_name} -> {spoofed_aid_name}")
        return modified_data, original_aid_name, spoofed_aid_name

    def run_aid_fuzzer(self, client_data):
        """
        Run the AID fuzzer - replay captured data with all 256 AID values.
        This is called from the GUI's timer loop.
        Returns True if fuzzing is complete, False if still running.
        """
        # Check if stopped or paused
        if self.aid_fuzzer_stopped:
            return True
        
        if self.aid_fuzzer_paused:
            return False  # Still "running" but paused
        
        if not self.aid_fuzzer_running:
            return True
        
        if self.aid_fuzzer_progress >= 256:
            # Fuzzing complete
            self.aid_fuzzer_running = False
            self.aid_fuzzer_armed = False
            if self.aid_fuzzer_callback:
                self.aid_fuzzer_callback('complete', 256, 256, None)
            return True
        
        # Get current AID byte to test
        aid_byte = bytes([self.aid_fuzzer_progress])
        aid_name = self.get_aid_name(aid_byte)
        
        # Replace AID in captured data
        # In TN3270E mode, AID is at byte 5 (after 5-byte header)
        # In plain TN3270 mode, AID is at byte 0
        if self.check_inject_3270e():
            # TN3270E: header (5 bytes) + AID + data
            # Replace byte at position 5
            fuzzed_data = self.aid_fuzzer_captured_data[:5] + aid_byte + self.aid_fuzzer_captured_data[6:]
        else:
            # Plain TN3270: AID + data
            # Replace byte at position 0
            fuzzed_data = aid_byte + self.aid_fuzzer_captured_data[1:]
        
        # Log and send
        log_msg = f"AID Fuzz: {self.aid_fuzzer_progress}/255 (0x{self.aid_fuzzer_progress:02X} - {aid_name})"
        self.write_database_log('C', log_msg, fuzzed_data)
        self.server.send(fuzzed_data)
        
        # Wait for and log response
        self.tend_server()
        
        # Update progress
        self.aid_fuzzer_progress += 1
        
        # Callback to update GUI
        if self.aid_fuzzer_callback:
            self.aid_fuzzer_callback('progress', self.aid_fuzzer_progress, 256, aid_name)
        
        return False

    def capture_mask(self, client_data):

        preamble_count = 0
        mask_count = 0
        
        self.logger.debug("Capturing Mask location with mask {}".format(
                        self.inject_mask))
        
        for x in range(0, len(client_data) - 1):
            character = self.get_ascii(client_data[x].to_bytes(1, 'little'))
            if character != self.inject_mask:
                preamble_count += 1
            else:
                break

        for x in range(preamble_count, len(client_data)):
            character = self.get_ascii(client_data[x].to_bytes(1, 'little'))
            if character == self.inject_mask:
                mask_count += 1
            else:
                break

        if mask_count > 0:
            self.logger.debug(("Mask found (length: {})"
            " - Input field identified - Ready for injection.").format(
                                                                mask_count))
            self.inject_mask_len = mask_count
            self.inject_preamble = client_data[:preamble_count]
            self.inject_postamble = client_data[preamble_count + mask_count:]
            self.inject_config_set = 1
            log = 'Inject setup - Mask: {} - Length: {}'.format(self.inject_mask,mask_count)
            self.logger.debug(log)
            self.write_database_log('C', log, client_data)
        else:
            self.inject_mask_len = 0
            self.inject_config_set = 0
            log = 'Inject setup - Mask: {} - Mask not found!'.format(self.inject_mask)
            self.logger.debug(log)
            self.write_database_log('C', log, client_data)
        self.inject_setup_capture = False

    def hack_on_logline(self):
        return ("Hack Field Attributes: ENABLED ("
                                    "Remove Field Prot: {rfp} - "
                                    "Show Hidden: {sh} - "
                                    "Remove NUM Prot: {rnr}) ("
                                    "SF: {sf} - "
                                    "SFE: {sfe} - "
                                    "MF: {mf} - " 
                                    "EI: {ei} - "
                                    "HV: {hv} )"
                                    ).format(
                                        rfp=self.hack_prot,
                                        sh=self.hack_hf,
                                        rnr=self.hack_rnr,
                                        sf=self.hack_sf,
                                        sfe=self.hack_sfe,
                                        mf=self.hack_mf,
                                        ei=self.hack_ei,
                                        hv=self.hack_color_hv)

    def hack_color_on_logline(self):
        return ("Hack Text Color: ENABLED ("
                    "SFE: {sfe} - "
                    "MF: {mf} - "
                    "SF: {sf} - " 
                    "HV: {hv})"
                    ).format(
                        sfe=self.hack_color_sfe,
                        mf=self.hack_color_mf,
                        sf=self.hack_color_sa,
                        hv=self.hack_color_hv
                        )

    def get_ascii(self, ebcdic_string):
        ''' Converts EBCDIC to ASCII, returns ASCII string'''
        return ''.join(e2a[byte] for byte in ebcdic_string)

    def get_ebcdic(self, string):
        ''' Converts ASCII to EBCDIC, returns EBCDIC bytes'''
        result = bytearray()
        for char in string:
            if char in a2e:
                result.append(a2e[char])
        return bytes(result)
        
    def refresh_aids(self, server_data):
        '''
        Repopulates found_aids, poplates the array with any found aids
        '''
        search_string = "PF{}[^0-9]"
        self.found_aids = []
        server_ascii = self.get_ascii(server_data)
        for i in range(1,25):
            search_string.format(i)
            self.logger.debug("Searching for PF{}".format(i))
            if re.search(search_string.format(i), server_ascii):
                self.logger.debug("Found PF{}".format(i))
                self.found_aids.append("PF{}".format(i))
        self.logger.debug("Done")
    
    def current_aids(self):
        'Returns an array of PF keys found on the screen'
        #self.logger.debug("Found the Following Action Identifiers: {}".format(
        #    self.found_aids
        #))
        return self.found_aids

    def flip_bits(self, tn3270_data):
        '''
        Flips the Protected, Non-display, and numeric bits in the TN3270
        based on the values in hack_prot, hack_hf, hack_rnr.

        Args:
            tn3270_data (byte): tn3270 byte

        Returns: byte with bit changes
        '''
        value = tn3270_data
        self.logger.debug("Flipping bits in {:02X}".format(tn3270_data))
        # Turn of 'Protected' Flag (Bit 6) if Set
        if self.hack_prot:
            self.logger.debug("Flipping Protected bit")
            if value & 0b00100000 == 0b00100000:
                value ^= 0b00100000
        # Turn off 'Non-display' Flag (Bit 4) if Set (i.e. Bits 3 and 4 are on)
        if self.hack_hf:
            self.logger.debug("Flipping Non-display bit")
            if value & 0b00001100 == 0b00001100:
        # Flip bit 3 instead of 4 if enable intentisty is selected
                if self.hack_ei:
                    self.logger.debug("Flipping intensity bit")
                    value ^= 0b00000100
                else:
                    value ^= 0b00001000
        # Turn off 'Numeric Only' Flag (Bit 5) if Set
        if self.hack_rnr:
            self.logger.debug("Flipping Numeric bit")
            if value & 0b00010000 == 0b00010000:
                value ^= 0b00010000
        self.logger.debug("Flipped bits: {:02X}".format(tn3270_data))
        return(value)

    def check_hidden(self, tn3270_data):
        '''
        Checks for the existence of the hidden bit

        Args:
            tn3270_data (byte): a tn3270 byte
        
        Returns:
            True if hidden bit is found otherwise False
        '''
        #if passed_value & 0b00001100 == 0b00001100:
        if tn3270_data & 12 == 12:
            self.logger.debug("Hidden TN3270 Flag detected")
            return True
        else:
            self.logger.debug("Hidden TN3270 Flag not detected")
            return False

    def manipulate(self, tn3270_data):

        self.current_state_debug_msg()
        found_hidden_data = 0
        # Don't manipulate data if telnet
        if tn3270_data[0] == 255:
            self.logger.debug("Received Telnet data, returning")
            return(tn3270_data)

        data = bytearray(len(tn3270_data))
        data[:] = tn3270_data

        self.logger.debug("Data recieved: {}".format(data.hex()))
        self.logger.debug("Hack on: {}".format(self.hack_on))
        # Process hacking of Basic Field Attributes
        if self.hack_on:
            for x in range(len(data)):
                #self.logger.debug("Current Byte: {}".format(data[x]))

                if self.hack_sf and data[x] == 0x1d: # Start Field
                    self.logger.debug("Start Field found")

                    data[x + 1] = self.flip_bits(data[x + 1])
                    if self.hack_hf and self.check_hidden(data[x + 1]):
                        #self.logger.debug("Disabling found Hidden Field")
                        bfa_byte = data[x + 1].to_bytes(1, byteorder='little')
                        if self.hack_hv:
                            self.logger.debug("Enabling High Visibility")
                            data2 = bytearray(len(data) + 6)
                            data2 = data[:x] + b'\x29\x03\xc0' + bfa_byte + b'\x41\xf2\x42\xf6' + data[x + 2:]
                            data = data2
                            x = x + 6
                        else:
                            data2 = bytearray(len(data) + 4)
                            data2 = data[:x + 2] + b'\x28\x42\xf6' + data[x + 2:]
                            data2 = data[:x] + b'\x29\x02\xc0' + bfa_byte + b'\x42\xf6' + data[x + 2:]
                            x = x + 4

                elif data[x] == 0x29: # Start Field Extended
                    self.logger.debug("Start Field Extended found, looping over {} fields".format(data[x + 1]))

                    for y in range(data[x + 1]):
                        
                        if(len(data) < ((x + 3) + (y * 2))):
                            continue
                        if self.hack_sfe and data[((x + 3) + (y * 2)) - 1] == 0xc0: # Basic 3270 field attributes
                            if self.check_hidden(data[((x + 3) + (y * 2))]) and self.hack_hv:
                                found_hidden_data = 1
                            data[((x + 3) + (y * 2))] = self.flip_bits(data[((x + 3) + (y * 2))])
                    if self.hack_sfe and found_hidden_data:
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
                        if self.hack_mf and data[((x + 3) + (y * 2)) - 1] == 0xc0: # Basic 3270 field attributes
                            if self.check_hidden(data[((x + 3) + (y * 2))]) and self.hack_hv:
                                found_hidden_data = 1
                            data[((x + 3) + (y * 2))] = self.flip_bits(data[((x + 3) + (y * 2))])
                    if self.hack_mf and found_hidden_data:
                        data[x + 1] = data[x + 1] + 2
                        data2 = bytearray(len(data) + 4)
                        data2 = data[:x + (data[x + 1] * 2) - 2] + b'\x41\xf2\x42\xf6' + data[x + (data[x + 1] * 2) - 2:]
                        data = data2
                        x = x + 4
                        found_hidden_data = 0
                    continue

        # Process hacking of Colors
        self.logger.debug("Hack Colors on: {}".format(self.hack_color_on))
        if self.hack_color_on:
            for x in range(len(data)):
                if data[x] == 0x29: # Start Field Extended
                    for y in range(data[x + 1]):
                        if(len(data) < ((x + 3) + (y * 2))):
                            continue
                        if self.hack_color_sfe and data[((x + 3) + (y * 2)) - 1] == 0x42: # Color
                            if data[((x + 3) + (y * 2))] == 0xf8: # Black
                                if self.hack_color_hv:
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
                    if self.hack_color_sa and data[x + 1] == 0x42: # Color
                        if data[x + 2] == 0xf8: # Black
                            if self.hack_color_hv:
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
                        if self.hack_color_mf and data[((x + 3) + (y * 2)) - 1] == 0x42: # Color
                            if data[((x + 3) + (y * 2))] == 0xf8: # Black
                                if self.hack_color_hv:
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
        
    def parse_telnet(self, ebcdic_string):
        self.logger.debug("Parsing Telnet bytes: {}".format(ebcdic_string))
        result = ebcdic_string
        for pattern, replacement in TELNET_PATTERNS:
            result = pattern.sub(replacement, result)
        self.logger.debug("Converted to: {}".format(result))
        return result

    def parse_3270(self, ebcdic_string):
        self.logger.debug("Parsing TN3270 bytes: {}".format(ebcdic_string))
        result = ebcdic_string
        for pattern, replacement in TN3270_PATTERNS:
            result = pattern.sub(replacement, result)
        self.logger.debug("Converted to: {}".format(result))
        return result
