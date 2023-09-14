"""
Hack3270 Python Library
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This python library was developed to create an interoperable object
used to test 3270 based applications. This object manages the logging
database, connectivity and tracking state of the connections. There is no user
interface provided by this class, the example UI is included in tk.py
"""
__version__ = '1.2.5-2'
__author__ = 'Garland Glessner'
__license__ = "GPL"
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
        self.server_ip  = server_ip
        self.server_port = int(server_port)
        self.proxy_ip = proxy_ip
        self.proxy_port = proxy_port
        self.tls_enabled = tls_enabled
        self.offline_mode = offline_mode
        self.offline = offline_mode

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

        # Create the Loggers (file and stderr)
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        if logfile is not None:
            logger_formatter = logging.Formatter(
                '%(levelname)s :: {} :: %(funcName)s'
                ' :: %(message)s'.format(self.filename))
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
            raise Exception("Attempt to intialize without a server IP or port")

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
                    raise Exception("Error! IP setting doesn't match server " 
                                    "IP address in existing project file! "
                                    "Server IP: {} != Project IP: {}".format(
                                            self.server_ip, row[1]
                                    ))
                self.server_ip = row[1]

                self.logger.debug('{} {}'.format(type(self.server_port),type(row[2])))
                if self.server_port != int(row[2])  and self.offline_mode == 0:
                    raise Exception("Error! -p setting doesn't match server " 
                                   "TCP port address in existing project file! "
                                    "Server port: {} != Project IP: {}".format(
                                            self.server_port, row[2]
                                    ))
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
            self.sql_cur.execute("SELECT * FROM Logs WHERE ID > {}".format(start))
        else:
            self.logger.debug("Getting all records from database")
            self.sql_cur.execute("SELECT * FROM Logs")

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

    def reset_hack_variables_state(self):
        '''
        Resets all the variables back to False
        '''
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

    def toggle_hack(self):
        '''Toggles the 'hack_toggled' variable'''
        self.logger.debug("Changing hack_toggled from {} to {}".format(
            self.hack_toggled, not self.hack_toggled))
        self.hack_toggled = not self.hack_toggled
        
    def toggle_hack_color(self):
        '''Toggles the 'hack_color_toggled' variable'''
        self.logger.debug("Changing hack_toggled from {} to {}".format(
            self.hack_color_toggled, not self.hack_color_toggled))
        self.hack_color_toggled = not self.hack_color_toggled

    def set_offline(self):
        '''Sets the offline flag'''
        self.offline = True
    
    def is_offline(self):
        ''' Returns True if offline, False if not'''
        return self.offline

    def toggle_hack_on(self):
        '''
        Inverts the hack_on state
        '''
        self.logger.debug("Changing hack_on from {} to {}".format(
            self.hack_on, not self.hack_on))
        self.hack_on = not self.hack_on

    def toggle_hack_color_on(self):
        '''
        Inverts the hack_color_on state
        '''
        self.logger.debug("Changing hack_color_on from {} to {}".format(
            self.hack_color_on, not self.hack_color_on))
        self.hack_color_on = not self.hack_color_on

    def toggle_hack_prot(self):
        '''
        Inverts the hack_prot state
        '''
        self.logger.debug("Changing hack_prot from {} to {}".format(
            self.hack_prot, not self.hack_prot))
        self.hack_prot = not self.hack_prot

    def toggle_hack_hf(self):
        '''
        Inverts the hack_hf state
        '''
        self.logger.debug("Changing hack_hf from {} to {}".format(
            self.hack_hf, not self.hack_hf))
        self.hack_hf = not self.hack_hf

    def toggle_hack_rnr(self):
        '''
        Inverts the hack_rnr state
        '''
        self.logger.debug("Changing hack_rnr from {} to {}".format(
            self.hack_rnr, not self.hack_rnr))
        self.hack_rnr = not self.hack_rnr

    def toggle_hack_ei(self):
        '''
        Inverts the hack_ei state
        '''
        self.logger.debug("Changing hack_ei from {} to {}".format(
            self.hack_ei, not self.hack_ei))
        self.hack_ei = not self.hack_ei

    def toggle_hack_sf(self):
        '''
        Inverts the hack_sf state
        '''
        self.logger.debug("Changing hack_sf from {} to {}".format(
            self.hack_sf, not self.hack_sf))
        self.hack_sf = not self.hack_sf

    def toggle_hack_sfe(self):
        '''
        Inverts the hack_sfe state
        '''
        self.logger.debug("Changing from {} to {}".format(
            self.hack_sfe, not self.hack_sfe))
        self.hack_sfe = not self.hack_sfe

    def toggle_hack_mf(self):
        '''
        Inverts the hack_mf state
        '''
        self.logger.debug("Changing hack_mf from {} to {}".format(
            self.hack_mf, not self.hack_mf))
        self.hack_mf = not self.hack_mf

    def toggle_hack_hv(self):
        '''
        Inverts the hack_prot state
        '''
        self.logger.debug("Changing from {} to {}".format(
            self.hack_hv, not self.hack_hv))
        self.hack_hv = not self.hack_hv

    def toggle_hack_color_sfe(self):
        '''
        Inverts the hack_color_sfe state
        '''
        self.logger.debug("Changing hack_color_sfe from {} to {}".format(
            self.hack_color_sfe, not self.hack_color_sfe))
        self.hack_color_sfe = not self.hack_color_sfe

    def toggle_hack_color_mf(self):
        '''
        Inverts the hack_color_mf state
        '''
        self.logger.debug("Changing hack_color_mf from {} to {}".format(
            self.hack_color_mf, not self.hack_color_mf))
        self.hack_color_mf = not self.hack_color_mf

    def toggle_hack_color_sa(self):
        '''
        Inverts the hack_color_sa state
        '''
        self.logger.debug("Changing hack_color_sa from {} to {}".format(
            self.hack_color_sa, not self.hack_color_sa))
        self.hack_color_sa = not self.hack_color_sa

    def toggle_hack_color_hv(self):
        '''
        Inverts the hack_color_hv state
        '''
        self.logger.debug("Changing hack_color_hv from {} to {}".format(
            self.hack_color_hv, not self.hack_color_hv))
        self.hack_color_hv = not self.hack_color_hv

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
            raise Exception("Cannot connect when in Offline Mode")
        
        self.logger.debug("Connecting to {}:{}".format(
            self.server_ip,self.server_port))
        
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        if self.tls_enabled:
            self.logger.debug(self.tls_enabled)
            self.logger.debug("Connecting with TLS")
            self.server = ssl.wrap_socket(
                server_sock, ssl_version=ssl.PROTOCOL_SSLv23)
        else:
            self.server = server_sock

        self.server.connect((self.server_ip, self.server_port))
        self.logger.debug("Connected to {}:{}".format(
            self.server_ip,self.server_port))

    def handle_server(self,server_data):
        log_line = ''
        if len(server_data) > 0:
            if self.hack_on:
                log_line = self.hack_on_logline()
            
            if self.hack_color_on:
                log_line = log_line + self.hack_color_on_logline()
            
            if self.hack_on and self.hack_color_on:
                hacked_server = self.manipulate(server_data)
                self.client.send(hacked_server)
            elif self.hack_on and not self.hack_color_on:
                hacked_server = self.manipulate(server_data)
                self.client.send(hacked_server)
            elif not self.hack_on and self.hack_color_on:
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

        # Tend to client sending data
        rlist, w, e = select.select([self.client, self.server], [], [], 0)
        if self.client in rlist:

            self.logger.debug("Client Data Detected")
            client_data = self.client.recv(BUFFER_MAX)
            if len(client_data) > 0:
                self.logger.debug("Client: {}".format(bytes(client_data)))
                self.logger.debug("Client: {}".format(self.get_ascii(client_data)))
                if self.inject_setup_capture:
                    self.capture_mask(client_data)
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
        my_string = ""
        for x in range(0, len(ebcdic_string)):
            my_string += e2a[ebcdic_string[x]]
        return my_string

    def get_ebcdic(self, string):
        ''' Converts ASCII to EBCDIC, returns EBCDIC bytes'''
        my_string = b''
        for x in range(0, len(string)):
            for y in range(0, len(e2a)):
                if string[x] == e2a[y]:
                    my_string += y.to_bytes(1, 'little')
        return(my_string)
        
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
        self.logger.debug("Converted to: {}".format(return_string))
        return(return_string)

    def parse_3270(self, ebcdic_string):
        self.logger.debug("Parsing TN3270 bytes: {}".format(ebcdic_string))
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
        self.logger.debug("Converted to: {}".format(return_string))
        return(return_string)