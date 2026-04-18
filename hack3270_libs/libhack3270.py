"""
Hack3270 Python Library
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This python library was developed to create an interoperable object
used to test 3270 based applications. This object manages the logging
database, connectivity and tracking state of the connections. There is no user
interface provided by this class, the example UI is included in tk.py
"""
__version__ = '2.6.7'
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

from hackterm_core import EbcdicCodec, Storage, ProxyDaemon, MutateOpts, MaskInjector
from tn3270_legacy import TN3270Legacy
# Phase 3: attack modules. Wired in __init__ after _daemon exists.
from tn3270_v2 import TN3270
from attacks.esm_passive import ESMFingerprinter
from attacks.negotiation import LUSpoofer
from attacks.structured import QueryReplyLiar, IndFileInterceptor
from attacks.state_fuzz import StateFuzzer


class Hack3270Error(Exception):
    """Base exception for hack3270 errors."""
    pass


class ConnectionError(Hack3270Error):
    """Raised when connection to the TN3270 server fails."""
    pass


class ProjectConfigError(Hack3270Error):
    """Raised when project configuration doesn't match existing database."""
    pass


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

        # Phase 1: hackterm-core delegation. get_ascii/get_ebcdic route
        # through this codec (cp037). The legacy module-level e2a/a2e
        # tables were deleted in Task 6.
        self._codec = EbcdicCodec("cp037")

        # Phase 1 Task 5: MaskInjector. capture_mask delegates to this.
        # Recreated by set_inject_mask when the mask char changes.
        self._injector = MaskInjector(self._codec, mask_char="*")

        # Initialize the database
        self.db_init()

        # Phase 1 Task 4: protocol + proxy daemon. Created AFTER db_init
        # because (a) self._storage is created there, (b) db_init may
        # overwrite proxy_port/server_ip/server_port/tls_enabled from
        # the project file's stored config.
        self._protocol = TN3270Legacy()
        self._daemon = ProxyDaemon(
            protocol=self._protocol,
            storage=self._storage,
            listen_addr=(self.proxy_ip, self.proxy_port),
            target_addr=(self.server_ip or "", self.server_port or 0),
            use_tls=bool(self.tls_enabled),
        )
        # Observer: stash last server bytes for hack_toggled resend
        # and gui.py direct reads. Also drives refresh_aids() — legacy
        # daemon() called it inline (L1322) after every server recv.
        def _stash_server(data, direction):
            if direction == "s2c":
                self.server_data = data
                self.refresh_aids(data)
        self._daemon.add_observer(_stash_server)

        # Phase 3: attack objects. Each .attach() registers an observer
        # on _daemon, so MUST come after _daemon exists. _proto_v2 is
        # the new clean parser — separate from TN3270Legacy because the
        # legacy one carries shim baggage. indfile.protocol is set so
        # its IDLE→ARMED screen-text scan can render EBCDIC.
        self._proto_v2 = TN3270()
        self.esm = ESMFingerprinter(self._proto_v2)
        self.lu_spoofer = LUSpoofer(self._proto_v2)
        self.qr_liar = QueryReplyLiar()
        self.indfile = IndFileInterceptor(
            capture_dir=str(Path(self.db_filename).with_suffix("")) + "_captures"
        )
        self.indfile.protocol = self._proto_v2
        self.esm.attach(self._daemon)
        self.lu_spoofer.attach(self._daemon)
        self.qr_liar.attach(self._daemon)
        self.indfile.attach(self._daemon)
        # StateFuzzer needs a SQLite conn — use a separate db file to avoid
        # polluting the main Logs table with Flows/Steps tables.
        self._fuzz_db = sqlite3.connect(f"{self.project_name}_flows.db")
        self.state_fuzzer = StateFuzzer(self._proto_v2, self._fuzz_db)
        self.state_fuzzer.attach(self._daemon)

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
        self.logger.debug("Shutting Down fuzzer database")
        self._fuzz_db.close()
        self.logger.debug("Shutting Down API listener")
        self.api_stop()

    def db_init(self):
        '''Phase 1 Task 3: delegates to hackterm_core.Storage.

        Re-adds legacy offline-mode + config-mismatch validation that
        Storage intentionally omits (those are tool-specific policy,
        not core protocol concerns). Storage handles the schema.
        '''
        # Legacy validation L311-318: offline + no db + no IP → die
        if not Path(self.db_filename).is_file() and not self.server_ip:
            if self.offline_mode:
                print(f"Error: Project file '{self.db_filename}' not found.")
                print(f"Offline mode requires an existing project database.")
                print(f"Use -n to specify a project name: python hack3270.py -n <project> -o")
                raise SystemExit(1)
            else:
                raise Exception("Cannot initialize without a server IP and port")

        self.logger.debug("Opening database file: {}".format(self.db_filename))

        # Probe for existing Config BEFORE Storage opens the file —
        # Storage creates the table if missing, so we can't check after.
        _has_config = False
        if Path(self.db_filename).is_file():
            _probe = sqlite3.connect(self.db_filename)
            _has_config = _probe.execute(
                "SELECT count(name) FROM sqlite_master "
                "WHERE TYPE='table' AND NAME='Config'"
            ).fetchone()[0] == 1
            _probe.close()

        self._storage = Storage(
            self.db_filename,
            server_ip=self.server_ip or "",
            server_port=self.server_port or 0,
            proxy_port=self.proxy_port,
            tls_enabled=self.tls_enabled,
        )

        # Legacy attr aliases — gui.py and on_closing() read these directly.
        # check_inject_3270e() / export_csv() also use sql_cur.
        self.sql_con = self._storage.conn
        self.sql_cur = self._storage.conn.cursor()

        # Legacy config-mismatch validation (was L341-357). Storage already
        # loaded values from the existing Config row; compare against what
        # the caller passed in. Skip when offline (legacy: offline_mode == 0).
        if _has_config:
            if self.server_ip != self._storage.server_ip and self.offline_mode == 0:
                raise ProjectConfigError(
                    f"IP address mismatch with existing project '{self.project_name}.db'.\n"
                    f"  Command line: {self.server_ip}\n"
                    f"  Project file: {self._storage.server_ip}\n"
                    f"Either use the correct IP or delete '{self.project_name}.db' to start fresh."
                )
            if self.server_port != self._storage.server_port and self.offline_mode == 0:
                raise ProjectConfigError(
                    f"Server port mismatch with existing project '{self.project_name}.db'.\n"
                    f"  Command line: {self.server_port}\n"
                    f"  Project file: {self._storage.server_port}\n"
                    f"Either use the correct port or delete '{self.project_name}.db' to start fresh."
                )

        # Adopt config from db (legacy L348/364-366). Storage.tls_enabled
        # is bool; legacy stored int — preserve legacy type.
        self.server_ip = self._storage.server_ip
        self.server_port = self._storage.server_port
        self.proxy_port = self._storage.proxy_port
        self.tls_enabled = int(self._storage.tls_enabled)

    def write_database_log(self, direction, notes, data):
        '''Phase 1 Task 3: delegates to Storage.log, EXCEPT for IAC traffic.

        Storage.log auto-tags 0xFF data with "telnet negotiation" but
        gui.py:1423 string-matches "tn3270 negotiation". For IAC packets
        we bypass Storage.log and write directly with the legacy tag.
        '''
        if data and data[0] == 255:
            notes = notes + "tn3270 negotiation"
            self.sql_cur.execute(
                "INSERT INTO Logs (TIMESTAMP, C_S, NOTES, DATA_LEN, RAW_DATA) "
                "VALUES (?, ?, ?, ?, ?)",
                (str(time.time()), direction, notes, len(data),
                 sqlite3.Binary(data)),
            )
            self.sql_con.commit()
            return
        self._storage.log(direction, notes, data)

    def all_logs(self,start=0):
        return self._storage.all_logs(start)

    def get_log(self, record_id):
        '''Storage.get_log returns Optional[tuple]; legacy returned a
        fetchall() list. gui.py iterates the result, so wrap it.'''
        row = self._storage.get_log(record_id)
        return [row] if row else []

    def check_inject_3270e(self):
        '''Replaces SQLite-row-1 inspection with TN3270Legacy.is_tn3270e.

        Fallback: gui.py:3794 calls this BEFORE daemon() runs, so the
        protocol may not have detected yet. If handshake isn't complete
        but a previous session left row 1 in the db, use that.

        Returns:
            True if the connection is in TN3270E mode, False otherwise.
        '''
        if self._daemon.handshake_complete:
            return self._protocol.is_tn3270e
        # Fallback to legacy row-1 check for the pre-handshake window
        row = self._storage.get_log(1)
        if row and row[5] and len(row[5]) >= 3 and row[5][2] == 40:
            self.logger.debug("TN3270E Detected (row-1 fallback).")
            # Sync the cached state too so subsequent calls are fast
            self._protocol._is_tn3270e = True
            return True
        return self._protocol.is_tn3270e

    def check_server(self,record_id):
        return self._storage.is_server_record(record_id)

    def check_record(self, record_id):
        return self._storage.is_telnet_record(record_id)

    def play_record(self,record_id):
        raw = self._storage.get_raw(record_id)
        if raw and self.client:
            self.client.send(raw)

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
        '''Sets the mask char. Recreates MaskInjector since mask_char
        is bound at construction (it caches _mask_byte).'''
        self.logger.debug("Setting mask to '{}'".format(mask))
        self.inject_mask = mask
        self._injector = MaskInjector(self._codec, mask_char=mask)

    ## TCP/IP Functions

    def client_connect(self):
        '''Delegates to ProxyDaemon.wait_for_client.
        Aliases socket back so tend_server/send_key keep working.'''
        self.logger.debug("Setting up proxy listener on {}:{}".format(
            self.proxy_ip, self.proxy_port
        ))
        self._daemon.wait_for_client()
        self.client = self._daemon.client

    def server_connect(self):
        '''Delegates to ProxyDaemon.connect_to_server.'''
        if self.offline_mode:
            raise Hack3270Error("Cannot connect when in Offline Mode")

        self.logger.debug("Connecting to {}:{}".format(
            self.server_ip, self.server_port))

        try:
            self._daemon.connect_to_server()
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

        self.server = self._daemon.server
        self.logger.debug("Connected to {}:{}".format(
            self.server_ip, self.server_port))

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
            
            # Convert ASCII mask char to EBCDIC byte value (int)
            try:
                ebcdic_mask = self._codec.to_ebcdic(mask_char)[0]
            except (UnicodeEncodeError, IndexError):
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
        '''Drives ProxyDaemon.tick(). Replaces the 142-line monolith.

        Steps each call:
          1. Sync hack_* flags → daemon.mutate_opts (5-field subset)
          2. Build client-intercept callback from current state
          3. Pump API listener (still inline — Phase 2 moves to ApiServer)
          4. tick()
          5. Handle hack_toggled resend (not modeled by ProxyDaemon)
        '''
        # ── 1. Sync flags ──
        # Map 14 legacy flags onto 5 MutateOpts. Lossy on purpose:
        # the full-fidelity path is hack_toggled → manipulate() →
        # _do_manipulate(self). The tick() path uses MutateOpts so
        # future Phase 3 attacks see a clean interface.
        opts = self._daemon.mutate_opts
        opts.unprotect       = bool(self.hack_on and self.hack_prot)
        opts.reveal_hidden   = bool(self.hack_on and self.hack_hf)
        opts.remove_numeric  = bool(self.hack_on and self.hack_rnr)
        opts.high_visibility = bool(self.hack_on and self.hack_hv)
        opts.color_reveal    = bool(self.hack_color_on)

        # ── 2. Client intercept ──
        # Replaces inline branches at legacy L1291-1312.
        intercept = None
        if self.inject_setup_capture:
            def intercept(data):
                self.capture_mask(data)
                return None  # drop, don't forward
        elif (self.aid_spoof_enabled
              and self.aid_spoof_mode == 'FUZZER'
              and self.aid_fuzzer_armed
              and not self.aid_fuzzer_running):
            def intercept(data):
                self.aid_fuzzer_captured_data = data
                self.aid_fuzzer_armed = False
                self.aid_fuzzer_running = True
                self.aid_fuzzer_progress = 0
                self.logger.debug("AID Fuzzer: Captured transmission, starting fuzz")
                if self.aid_fuzzer_callback:
                    self.aid_fuzzer_callback('captured', 0, 256, None)
                return None  # drop — fuzzer loop sends
        elif (self.aid_spoof_enabled
              and self.aid_spoof_mode == 'MANUAL'):
            def intercept(data):
                if len(data) < 1:
                    return data
                modified, orig, spoofed = self.spoof_aid(data)
                self.write_database_log(
                    'C', f"AID Spoofed: {orig} -> {spoofed}", modified)
                # Send directly + return None to preserve single-log
                # semantics (returning modified would make ProxyDaemon
                # log it again via storage.log).
                self.server.send(modified)
                return None
        self._daemon.set_client_intercept(intercept)

        # ── 3. API listener (kept inline for Phase 1) ──
        # The legacy daemon() embedded API handling. ProxyDaemon doesn't
        # know about it. Pump it separately. Phase 2 → hackterm_core.ApiServer.
        if self.api_listener:
            self._pump_api()

        # ── 4. Tick ──
        self._daemon.tick()

        # Re-alias in case daemon swapped sockets (it doesn't, but be safe)
        self.client = self._daemon.client
        self.server = self._daemon.server

        # ── 5. hack_toggled resend (legacy L1324-1381) ──
        if (self.hack_toggled or self.hack_color_toggled) and self.server_data:
            log_line = ''
            if self.hack_toggled:
                if self.hack_on:
                    log_line = self.hack_on_logline()
                else:
                    log_line = 'Hack Fields Attributes: TOGGLED OFF '
                self.hack_toggled = 0
            if self.hack_color_toggled:
                if self.hack_color_on:
                    log_line = log_line + self.hack_color_on_logline()
                else:
                    log_line = log_line + 'Hack Text Color: TOGGLED OFF '
                self.hack_color_toggled = 0
            hacked = self.manipulate(self.server_data)
            self._daemon.inject_to_client(hacked)
            self.write_database_log('S', log_line, hacked)

    def _pump_api(self):
        '''Legacy API listener pump — extracted from daemon() L1255-1282.
        Phase 2 replaces with hackterm_core.ApiServer.'''
        readable = [self.api_listener] + self.api_clients
        try:
            rlist, _, _ = select.select(readable, [], [], 0)
        except (ValueError, OSError):
            return
        if self.api_listener in rlist:
            try:
                api_client, addr = self.api_listener.accept()
                api_client.setblocking(False)
                self.api_clients.append(api_client)
                self.logger.debug(f"API client connected from {addr}")
            except Exception as e:
                self.logger.error(f"Error accepting API connection: {e}")
        for api_client in self.api_clients[:]:
            if api_client in rlist:
                try:
                    data = api_client.recv(BUFFER_MAX)
                    if len(data) > 0:
                        self.handle_api_request(api_client, data)
                    else:
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
        '''Delegates to MaskInjector.capture, copies results back to
        legacy attributes (inject_preamble/postamble/mask_len/config_set)
        that gui.py:3334 reads via get_inject_*.'''
        self.logger.debug("Capturing Mask location with mask {}".format(
                        self.inject_mask))

        found = self._injector.capture(client_data)

        if found:
            self.inject_mask_len = self._injector.mask_len
            self.inject_preamble = self._injector.preamble
            self.inject_postamble = self._injector.postamble
            self.inject_config_set = 1
            log = 'Inject setup - Mask: {} - Length: {}'.format(
                self.inject_mask, self._injector.mask_len)
        else:
            self.inject_mask_len = 0
            self.inject_config_set = 0
            log = 'Inject setup - Mask: {} - Mask not found!'.format(
                self.inject_mask)

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
        ''' Converts EBCDIC to ASCII — delegates to EbcdicCodec.

        Phase 1 Task 2: replaced hand-rolled e2a lookup with cp037 codec.
        See tests/test_shim_ebcdic.py::ACCEPTED_DIVERGENCES for the 7 bytes
        whose display string changed (all cosmetic; no TELNET_PATTERNS impact).
        '''
        return self._codec.to_ascii(ebcdic_string)

    def get_ebcdic(self, string):
        ''' Converts ASCII to EBCDIC — delegates to EbcdicCodec.

        BEHAVIOR CHANGE vs legacy: chars not in cp037 now raise
        UnicodeEncodeError instead of being silently dropped. Legacy
        silently dropping was a bug — it produced short/malformed packets.
        '''
        return self._codec.to_ebcdic(string)
        
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
        '''Delegates to TN3270Legacy._do_manipulate, passing self as
        the flags object. Full-fidelity 14-flag path — _do_manipulate
        duck-types `flags` so it works identically whether passed a
        SimpleNamespace (mutate() path) or this hack3270 instance.'''
        self.current_state_debug_msg()
        return self._protocol._do_manipulate(tn3270_data, self)
        
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
