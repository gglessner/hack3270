"""
Storage shim tests.

Verify libhack3270.hack3270 delegates db operations to
hackterm_core.Storage while preserving exact GUI-facing semantics.
"""
import sqlite3
import pytest


def test_shim_has_storage_instance(legacy_hack3270):
    from hackterm_core import Storage
    h = legacy_hack3270
    assert hasattr(h, "_storage")
    assert isinstance(h._storage, Storage)


def test_write_database_log_delegates(legacy_hack3270):
    h = legacy_hack3270
    h.write_database_log("S", "test note", b"\x05hello")
    rows = h.all_logs()
    assert len(rows) == 1
    assert rows[0][2] == "S"
    assert rows[0][3] == "test note"
    assert rows[0][5] == b"\x05hello"


def test_write_database_log_legacy_negotiation_tag(legacy_hack3270):
    """L416-417: data starting 0xFF gets 'tn3270 negotiation' appended.
    Storage.log uses 'telnet negotiation'. Shim must override to keep
    legacy tag — gui.py:1423 string-matches it."""
    h = legacy_hack3270
    h.write_database_log("S", "", b"\xFF\xFD\x28")
    rows = h.all_logs()
    assert "tn3270 negotiation" in rows[0][3]
    # And NOT double-tagged with Storage's variant
    assert "telnet negotiation" not in rows[0][3]


def test_get_log_returns_list_not_tuple(legacy_hack3270):
    """Storage.get_log returns Optional[tuple]. Legacy returns list
    (fetchall). gui.py iterates: `for row in get_log(id):` — must iterate."""
    h = legacy_hack3270
    h.write_database_log("S", "", b"data")
    result = h.get_log(1)
    assert isinstance(result, list)
    assert len(result) == 1
    assert result[0][5] == b"data"


def test_get_log_missing_returns_empty_list(legacy_hack3270):
    h = legacy_hack3270
    assert h.get_log(99999) == []


def test_check_server_delegates(legacy_hack3270):
    h = legacy_hack3270
    h.write_database_log("S", "", b"server")
    h.write_database_log("C", "", b"client")
    assert h.check_server(1) is True
    assert h.check_server(2) is False


def test_check_record_delegates(legacy_hack3270):
    """check_record (L495-505): True if first byte is 0xFF (telnet)."""
    h = legacy_hack3270
    h.write_database_log("S", "", b"\xFF\xFD\x28")
    h.write_database_log("S", "", b"\x05data")
    assert h.check_record(1) is True
    assert h.check_record(2) is False


def test_old_db_file_opens(tmp_path, monkeypatch):
    """Spec §5.1.4: existing .db files replay.
    Create a db with raw sqlite3 using the LEGACY schema, then open
    it via the shim."""
    monkeypatch.chdir(tmp_path)
    db = tmp_path / "oldproj.db"
    conn = sqlite3.connect(str(db))
    conn.execute(
        "CREATE TABLE Config (CREATION_TS TEXT NOT NULL, "
        "SERVER_IP TEXT NOT NULL, SERVER_PORT INT NOT NULL, "
        "PROXY_PORT INT NOT NULL, TLS_ENABLED INT NOT NULL)"
    )
    conn.execute(
        "INSERT INTO Config VALUES (?, ?, ?, ?, ?)",
        ("123.456", "10.0.0.1", 23, 3271, 0),
    )
    conn.execute(
        "CREATE TABLE Logs (ID INTEGER PRIMARY KEY AUTOINCREMENT, "
        "TIMESTAMP TEXT, C_S CHAR(1), NOTES TEXT, DATA_LEN INT, "
        "RAW_DATA BLOB(4000))"
    )
    conn.execute(
        "INSERT INTO Logs (TIMESTAMP, C_S, NOTES, DATA_LEN, RAW_DATA) "
        "VALUES (?, ?, ?, ?, ?)",
        ("123.456", "S", "old packet", 5, b"\x05old!"),
    )
    conn.commit()
    conn.close()

    import libhack3270, logging
    h = libhack3270.hack3270(
        server_ip="10.0.0.1", server_port=23, proxy_port=3271,
        project_name="oldproj", loglevel=logging.CRITICAL,
    )
    rows = h.all_logs()
    assert len(rows) == 1
    assert rows[0][5] == b"\x05old!"
    h.sql_con.close()


def test_sql_con_attr_still_exists(legacy_hack3270):
    """gui.py and on_closing (L284) reference self.sql_con directly.
    Shim must keep this alias to Storage's connection."""
    h = legacy_hack3270
    assert h.sql_con is h._storage.conn


def test_offline_mode_no_db_no_ip_raises(tmp_path, monkeypatch):
    """L311-316: offline mode + no existing db + no IP → SystemExit."""
    monkeypatch.chdir(tmp_path)
    import libhack3270, logging
    with pytest.raises(SystemExit):
        libhack3270.hack3270(
            server_ip=None, server_port=None, proxy_port=3271,
            offline_mode=True, project_name="nonexistent",
            loglevel=logging.CRITICAL,
        )
