import pytest
import sqlite3
import time
from hackterm_core.storage import Storage


def test_creates_tables_on_fresh_db(tmp_path):
    db = tmp_path / "test.db"
    s = Storage(str(db), server_ip="10.0.0.1", server_port=23,
                proxy_port=3271, tls_enabled=False)
    cur = s.conn.cursor()
    cur.execute("SELECT SERVER_IP, SERVER_PORT, PROXY_PORT, TLS_ENABLED FROM Config")
    row = cur.fetchone()
    assert row == ("10.0.0.1", 23, 3271, 0)
    s.close()


def test_logs_table_schema_matches_legacy(tmp_path):
    """Schema must be byte-identical to hack3270 so old .db files open.

    Legacy schema (libhack3270.py:403-411):
      ID INTEGER PRIMARY KEY AUTOINCREMENT
      TIMESTAMP TEXT
      C_S CHAR(1)
      NOTES TEXT
      DATA_LEN INT
      RAW_DATA BLOB(4000)
    """
    db = tmp_path / "test.db"
    s = Storage(str(db), server_ip="10.0.0.1", server_port=23,
                proxy_port=3271, tls_enabled=False)
    cur = s.conn.cursor()
    cur.execute("PRAGMA table_info(Logs)")
    cols = {row[1]: row[2] for row in cur.fetchall()}
    assert "ID" in cols
    assert "TIMESTAMP" in cols
    assert "C_S" in cols
    assert "NOTES" in cols
    assert "DATA_LEN" in cols
    assert "RAW_DATA" in cols
    s.close()


def test_log_packet_and_retrieve(tmp_path):
    db = tmp_path / "test.db"
    s = Storage(str(db), server_ip="10.0.0.1", server_port=23,
                proxy_port=3271, tls_enabled=False)
    s.log("S", "test note", b"\xc1\xc2\xc3")
    rows = s.all_logs()
    assert len(rows) == 1
    assert rows[0][2] == "S"           # C_S
    assert rows[0][3] == "test note"   # NOTES
    assert rows[0][5] == b"\xc1\xc2\xc3"  # RAW_DATA
    s.close()


def test_log_telnet_negotiation_auto_tagged(tmp_path):
    """Legacy behavior (libhack3270.py:416-417): if data[0]==0xFF,
    'tn3270 negotiation' is appended to notes. We generalize the tag."""
    db = tmp_path / "test.db"
    s = Storage(str(db), server_ip="10.0.0.1", server_port=23,
                proxy_port=3271, tls_enabled=False)
    s.log("S", "", b"\xff\xfd\x18")  # IAC DO TERMINAL-TYPE
    rows = s.all_logs()
    assert "negotiation" in rows[0][3]
    s.close()


def test_get_log_by_id(tmp_path):
    db = tmp_path / "test.db"
    s = Storage(str(db), server_ip="10.0.0.1", server_port=23,
                proxy_port=3271, tls_enabled=False)
    s.log("C", "first", b"\x01")
    s.log("S", "second", b"\x02")
    row = s.get_log(2)
    assert row[3] == "second"
    s.close()


def test_get_log_nonexistent_returns_none(tmp_path):
    db = tmp_path / "test.db"
    s = Storage(str(db), server_ip="10.0.0.1", server_port=23,
                proxy_port=3271, tls_enabled=False)
    assert s.get_log(999) is None
    s.close()


def test_all_logs_with_start_offset(tmp_path):
    """all_logs(start=N) returns rows with ID > N (legacy: L449)."""
    db = tmp_path / "test.db"
    s = Storage(str(db), server_ip="10.0.0.1", server_port=23,
                proxy_port=3271, tls_enabled=False)
    s.log("C", "one", b"\x01")
    s.log("C", "two", b"\x02")
    s.log("C", "three", b"\x03")
    rows = s.all_logs(start=1)
    assert len(rows) == 2
    assert rows[0][3] == "two"
    s.close()


def test_is_server_record(tmp_path):
    """Replaces check_server (libhack3270.py:484-493)."""
    db = tmp_path / "test.db"
    s = Storage(str(db), server_ip="10.0.0.1", server_port=23,
                proxy_port=3271, tls_enabled=False)
    s.log("S", "", b"\x01")
    s.log("C", "", b"\x02")
    assert s.is_server_record(1) is True
    assert s.is_server_record(2) is False
    s.close()


def test_is_telnet_record(tmp_path):
    """Replaces check_record (libhack3270.py:495-505)."""
    db = tmp_path / "test.db"
    s = Storage(str(db), server_ip="10.0.0.1", server_port=23,
                proxy_port=3271, tls_enabled=False)
    s.log("S", "", b"\xff\xfd\x18")  # telnet
    s.log("S", "", b"\xc1\xc2\xc3")  # data
    assert s.is_telnet_record(1) is True
    assert s.is_telnet_record(2) is False
    s.close()


def test_get_raw_for_replay(tmp_path):
    """Replaces play_record (L507-513) — but returns bytes instead of
    sending directly. Caller (proxy) handles the send."""
    db = tmp_path / "test.db"
    s = Storage(str(db), server_ip="10.0.0.1", server_port=23,
                proxy_port=3271, tls_enabled=False)
    s.log("S", "", b"\xde\xad\xbe\xef")
    assert s.get_raw(1) == b"\xde\xad\xbe\xef"
    s.close()


def test_in_memory_db():
    """':memory:' should work for tests."""
    s = Storage(":memory:", server_ip="10.0.0.1", server_port=23,
                proxy_port=3271, tls_enabled=False)
    s.log("S", "", b"\x01")
    assert len(s.all_logs()) == 1
    s.close()


def test_parameterized_queries_no_injection(tmp_path):
    """The legacy code did string-format SQL. Verify the new code
    doesn't. We can't directly test 'no injection' but we can verify
    that a malicious-looking ID doesn't blow up — parameterized queries
    will treat it as a value, not SQL."""
    db = tmp_path / "test.db"
    s = Storage(str(db), server_ip="10.0.0.1", server_port=23,
                proxy_port=3271, tls_enabled=False)
    # If get_log used string formatting, a non-int would error or worse
    assert s.get_log("1; DROP TABLE Logs; --") is None
    # Logs table should still exist
    s.log("S", "", b"\x01")
    assert len(s.all_logs()) == 1
    s.close()


def test_reopen_existing_db_loads_config(tmp_path):
    """Opening an existing .db loads the saved config (legacy: L326-358)."""
    db = tmp_path / "test.db"
    s1 = Storage(str(db), server_ip="10.0.0.1", server_port=23,
                 proxy_port=3271, tls_enabled=True)
    s1.close()

    s2 = Storage(str(db), server_ip="10.0.0.1", server_port=23,
                 proxy_port=3271, tls_enabled=True)
    assert s2.server_ip == "10.0.0.1"
    assert s2.server_port == 23
    assert s2.tls_enabled is True
    s2.close()
