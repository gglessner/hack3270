"""
SQLite-backed packet logging.

Schema is byte-identical to hack3270 so existing .db files open
without migration. Extracted from libhack3270.py:287-513.

Changes from legacy:
  - Parameterized queries (legacy used string formatting at L449/458/486/497/509)
  - get_log returns one row or None (legacy: list of rows)
  - play_record split into get_raw (returns bytes; caller sends)
  - Negotiation auto-tag generalized from "tn3270 negotiation" to
    "telnet negotiation" since this serves both protocols
"""
import sqlite3
import time
import logging
from typing import Optional


class Storage:
    """SQLite packet log + configuration store.

    Schema (must match libhack3270.py:362-411 exactly):

      Config:
        CREATION_TS TEXT NOT NULL
        SERVER_IP   TEXT NOT NULL
        SERVER_PORT INT  NOT NULL
        PROXY_PORT  INT  NOT NULL
        TLS_ENABLED INT  NOT NULL

      Logs:
        ID        INTEGER PRIMARY KEY AUTOINCREMENT
        TIMESTAMP TEXT
        C_S       CHAR(1)         -- 'C' (client->server) or 'S' (server->client)
        NOTES     TEXT
        DATA_LEN  INT
        RAW_DATA  BLOB(4000)
    """

    def __init__(self, db_path: str, server_ip: str, server_port: int,
                 proxy_port: int, tls_enabled: bool):
        self._log = logging.getLogger(__name__)
        self.conn = sqlite3.connect(db_path)
        self.conn.set_trace_callback(self._log.debug)

        self.server_ip = server_ip
        self.server_port = server_port
        self.proxy_port = proxy_port
        self.tls_enabled = tls_enabled

        self._init_config()
        self._init_logs()

    def _init_config(self):
        cur = self.conn.cursor()
        cur.execute(
            "SELECT count(name) FROM sqlite_master "
            "WHERE TYPE='table' AND NAME='Config'"
        )
        if cur.fetchone()[0] == 1:
            cur.execute("SELECT * FROM Config")
            row = cur.fetchone()
            if row:
                # Legacy column order: CREATION_TS, SERVER_IP, SERVER_PORT,
                # PROXY_PORT, TLS_ENABLED (libhack3270.py:362-369)
                self.server_ip = row[1]
                self.server_port = int(row[2])
                self.proxy_port = int(row[3])
                self.tls_enabled = bool(row[4])
        else:
            cur.execute(
                "CREATE TABLE Config ("
                "CREATION_TS TEXT NOT NULL, "
                "SERVER_IP TEXT NOT NULL, "
                "SERVER_PORT INT NOT NULL, "
                "PROXY_PORT INT NOT NULL, "
                "TLS_ENABLED INT NOT NULL)"
            )
            cur.execute(
                "INSERT INTO Config "
                "(CREATION_TS, SERVER_IP, SERVER_PORT, PROXY_PORT, TLS_ENABLED) "
                "VALUES (?, ?, ?, ?, ?)",
                (str(time.time()), self.server_ip, self.server_port,
                 self.proxy_port, int(self.tls_enabled)),
            )
            self.conn.commit()

    def _init_logs(self):
        cur = self.conn.cursor()
        cur.execute(
            "SELECT count(name) FROM sqlite_master "
            "WHERE TYPE='table' AND NAME='Logs'"
        )
        if cur.fetchone()[0] != 1:
            cur.execute(
                "CREATE TABLE Logs ("
                "ID INTEGER PRIMARY KEY AUTOINCREMENT, "
                "TIMESTAMP TEXT, "
                "C_S CHAR(1), "
                "NOTES TEXT, "
                "DATA_LEN INT, "
                "RAW_DATA BLOB(4000))"
            )
            self.conn.commit()

    def log(self, direction: str, notes: str, data: bytes) -> None:
        """Append a packet to the log.

        direction: 'C' (client->server) or 'S' (server->client)
        """
        # Legacy auto-tag (libhack3270.py:416-417): IAC byte means negotiation
        if data and data[0] == 0xFF:
            notes = notes + "telnet negotiation"
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO Logs (TIMESTAMP, C_S, NOTES, DATA_LEN, RAW_DATA) "
            "VALUES (?, ?, ?, ?, ?)",
            (str(time.time()), direction, notes, len(data),
             sqlite3.Binary(data)),
        )
        self.conn.commit()

    def all_logs(self, start: int = 0) -> list[tuple]:
        """Get all log rows with ID > start."""
        cur = self.conn.cursor()
        if start > 0:
            cur.execute("SELECT * FROM Logs WHERE ID > ? ORDER BY ID ASC",
                        (start,))
        else:
            cur.execute("SELECT * FROM Logs ORDER BY ID ASC")
        return cur.fetchall()

    def get_log(self, log_id) -> Optional[tuple]:
        """Get one log row by ID, or None if not found."""
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM Logs WHERE ID = ?", (log_id,))
        return cur.fetchone()

    def get_raw(self, log_id: int) -> Optional[bytes]:
        """Get just the RAW_DATA blob for replay."""
        row = self.get_log(log_id)
        return row[5] if row else None

    def is_server_record(self, log_id: int) -> bool:
        """Was this packet sent by the server (host)?"""
        row = self.get_log(log_id)
        return bool(row and row[2] == "S")

    def is_telnet_record(self, log_id: int) -> bool:
        """Is this packet telnet negotiation (starts with IAC)?"""
        row = self.get_log(log_id)
        return bool(row and row[5] and row[5][0] == 0xFF)

    def close(self) -> None:
        self.conn.close()
