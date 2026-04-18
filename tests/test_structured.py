"""
Structured Field attacks: Query Reply lying + IND$FILE intercept.

QR side: builds synthetic Query Reply structured fields with
operator-chosen lies (screen size, color support, RPQ name).

IND$FILE side: detects File Transfer SFs (type 0xD0), reassembles
32K blocks. Tested in Task 5.
"""
import pytest
import struct
from hackterm_core.protocol import QueryLies


# ---------------------------------------------------------------------------
# Individual SF builders — each is <len:2> <0x81> <qcode> <payload>
# ---------------------------------------------------------------------------

def test_sf_null_terminator():
    """Null SF is the terminator: len=0x0004, id=0x81, qcode=0xFF."""
    from hack3270_libs.attacks.structured import _sf_null
    assert _sf_null() == b"\x00\x04\x81\xff"


def test_sf_usable_area_basic():
    """Usable Area encodes screen dimensions. GA23-0059 §6.42.
    Minimal payload: flags(1) + addr-mode(1) + cols(2) + rows(2) + units(1)
                   + Xr(4) + Yr(4) + AW(1) + AH(1) + buffer-size(2)."""
    from hack3270_libs.attacks.structured import _sf_usable_area
    sf = _sf_usable_area(rows=24, cols=80)
    # Length prefix: 2 bytes big-endian, includes itself
    length = struct.unpack(">H", sf[:2])[0]
    assert length == len(sf)
    # SFID + qcode
    assert sf[2] == 0x81
    assert sf[3] == 0x81  # Usable Area qcode
    # Cols and rows are in there (24=0x18, 80=0x50)
    assert b"\x00\x50" in sf  # cols=80
    assert b"\x00\x18" in sf  # rows=24


def test_sf_usable_area_alternate_size():
    """Lying about screen size: claim 62×160 (model 5 + extra)."""
    from hack3270_libs.attacks.structured import _sf_usable_area
    sf = _sf_usable_area(rows=62, cols=160)
    assert b"\x00\xa0" in sf  # 160 = 0xA0
    assert b"\x00\x3e" in sf  # 62 = 0x3E


def test_sf_implicit_partition():
    """Implicit Partition carries default + alternate screen sizes.
    GA23-0059 §6.31. qcode = 0xA6."""
    from hack3270_libs.attacks.structured import _sf_implicit_partition
    sf = _sf_implicit_partition(alt_rows=43, alt_cols=132)
    assert sf[2] == 0x81
    assert sf[3] == 0xA6  # Implicit Partition qcode
    # 132 = 0x84, 43 = 0x2B — both should appear
    assert 0x84 in sf
    assert 0x2B in sf


def test_sf_color():
    """Color SF lists supported color-attribute pairs.
    GA23-0059 §6.13. qcode = 0x86."""
    from hack3270_libs.attacks.structured import _sf_color
    sf = _sf_color()
    assert sf[2] == 0x81
    assert sf[3] == 0x86
    # Claims standard 8 colors (0xF1-0xF8)
    for c in range(0xF1, 0xF9):
        assert c in sf


def test_sf_highlighting():
    """Highlighting SF lists supported highlight values.
    GA23-0059 §6.29. qcode = 0x87."""
    from hack3270_libs.attacks.structured import _sf_highlighting
    sf = _sf_highlighting()
    assert sf[2] == 0x81
    assert sf[3] == 0x87


def test_sf_rpq_names():
    """RPQ Names SF carries terminal model identifier.
    GA23-0059 §6.36. qcode = 0xA1."""
    from hack3270_libs.attacks.structured import _sf_rpq
    sf = _sf_rpq("HACK3270")
    assert sf[2] == 0x81
    assert sf[3] == 0xA1
    # RPQ name is EBCDIC inside the payload
    from hackterm_core.ebcdic import EbcdicCodec
    codec = EbcdicCodec()
    assert codec.to_ebcdic("HACK3270") in sf


def test_sf_summary():
    """Summary SF lists which qcodes we'll respond to. GA23-0059 §6.41.
    qcode = 0x80. Payload is a list of single-byte qcodes."""
    from hack3270_libs.attacks.structured import _sf_summary
    sf = _sf_summary([0x81, 0x86, 0x87])
    assert sf[2] == 0x81
    assert sf[3] == 0x80
    # The qcodes we passed appear in the payload
    assert sf[4:7] == bytes([0x81, 0x86, 0x87])


# ---------------------------------------------------------------------------
# Full Query Reply assembly
# ---------------------------------------------------------------------------

def test_build_query_reply_minimal():
    """No lies → standard 24×80 reply with all capabilities."""
    from hack3270_libs.attacks.structured import build_query_reply
    pkt = build_query_reply(QueryLies())
    # Starts with AID 0x88 (structured field AID)
    assert pkt[0] == 0x88
    # Ends with IAC EOR
    assert pkt.endswith(b"\xff\xef")
    # Contains a Null SF terminator
    assert b"\x00\x04\x81\xff" in pkt


def test_build_query_reply_deny_color():
    """deny_color=True → no Color SF in output."""
    from hack3270_libs.attacks.structured import build_query_reply
    pkt = build_query_reply(QueryLies(deny_color=True))
    # qcode 0x86 should NOT appear after a 0x81 SFID
    # (cheap check: the byte sequence 81 86 shouldn't be there)
    assert b"\x81\x86" not in pkt


def test_build_query_reply_includes_color_by_default():
    from hack3270_libs.attacks.structured import build_query_reply
    pkt = build_query_reply(QueryLies(deny_color=False))
    assert b"\x81\x86" in pkt


def test_build_query_reply_deny_highlighting():
    from hack3270_libs.attacks.structured import build_query_reply
    pkt = build_query_reply(QueryLies(deny_highlighting=True))
    assert b"\x81\x87" not in pkt


def test_build_query_reply_alt_dimensions():
    """alt_rows/alt_cols set → Implicit Partition SF included."""
    from hack3270_libs.attacks.structured import build_query_reply
    pkt = build_query_reply(QueryLies(alt_rows=62, alt_cols=160))
    assert b"\x81\xa6" in pkt  # Implicit Partition qcode


def test_build_query_reply_no_implicit_partition_at_default():
    """24×80 with no alt → no Implicit Partition SF."""
    from hack3270_libs.attacks.structured import build_query_reply
    pkt = build_query_reply(QueryLies())
    assert b"\x81\xa6" not in pkt


def test_build_query_reply_rpq_name():
    from hack3270_libs.attacks.structured import build_query_reply
    pkt = build_query_reply(QueryLies(rpq_name="EVILTERM"))
    assert b"\x81\xa1" in pkt  # RPQ Names qcode


def test_build_query_reply_tn3270e_header():
    """When TN3270E mode, prepend the 5-byte header."""
    from hack3270_libs.attacks.structured import build_query_reply
    pkt = build_query_reply(QueryLies(), tn3270e=True, seq=5)
    assert pkt[:5] == bytes([0x00, 0x00, 0x00, 0x00, 0x05])
    assert pkt[5] == 0x88  # AID after header


# ---------------------------------------------------------------------------
# Read Partition Query detection — what triggers our reply
# ---------------------------------------------------------------------------

# Read Partition (Query) wire format:
# [TN3270E hdr] F3 <len:2> 01 FF 02
#               ^^ WSF     ^^ ^^ ^^
#               cmd        SF Read-Partition Query
RP_QUERY = bytes([0xF3, 0x00, 0x05, 0x01, 0xFF, 0x02, 0xFF, 0xEF])
RP_QUERY_TN3270E = bytes([0x00, 0x00, 0x00, 0x00, 0x01]) + RP_QUERY


def test_detect_read_partition_query():
    from hack3270_libs.attacks.structured import is_read_partition_query
    assert is_read_partition_query(RP_QUERY) is True


def test_detect_read_partition_query_tn3270e():
    from hack3270_libs.attacks.structured import is_read_partition_query
    assert is_read_partition_query(RP_QUERY_TN3270E) is True


def test_detect_not_read_partition_query():
    from hack3270_libs.attacks.structured import is_read_partition_query
    # Regular Erase/Write — not WSF
    assert is_read_partition_query(b"\xf5\xc3\x1d\x60\xff\xef") is False


def test_detect_wsf_but_not_query():
    """WSF with a different SFID — not Read Partition."""
    from hack3270_libs.attacks.structured import is_read_partition_query
    # WSF + len + SFID 0xD0 (file transfer, not read partition)
    pkt = bytes([0xF3, 0x00, 0x05, 0xD0, 0x47, 0x00, 0xFF, 0xEF])
    assert is_read_partition_query(pkt) is False


def test_detect_short_packet():
    """Truncated packet — must not crash."""
    from hack3270_libs.attacks.structured import is_read_partition_query
    assert is_read_partition_query(b"\xf3") is False
    assert is_read_partition_query(b"") is False


# ---------------------------------------------------------------------------
# QueryReplyLiar — the campaign object
# ---------------------------------------------------------------------------

@pytest.fixture
def liar():
    from hack3270_libs.attacks.structured import QueryReplyLiar
    return QueryReplyLiar()


def test_liar_starts_disarmed(liar):
    assert liar.armed is False


def test_liar_arm(liar):
    liar.arm(QueryLies(alt_rows=62, deny_color=True))
    assert liar.armed is True
    assert liar.lies.alt_rows == 62


def test_liar_disarm(liar):
    liar.arm(QueryLies())
    liar.disarm()
    assert liar.armed is False


def test_liar_intercepts_when_armed(liar, fake_daemon):
    """When armed and we see a Read Partition Query (s2c), we EAT it
    (don't forward to client) and inject our reply (c2s)."""
    liar.arm(QueryLies())
    liar.attach(fake_daemon)

    # Simulate the host sending a Read Partition Query.
    # The liar's intercept eats it (returns None) and synthesizes a reply.
    result = liar._intercept_s2c(RP_QUERY)
    assert result is None  # eaten — not forwarded to client
    assert len(fake_daemon.sent_to_server) == 1  # our synthetic reply
    reply = fake_daemon.sent_to_server[0]
    assert reply[0] == 0x88  # structured-field AID


def test_liar_passes_through_when_disarmed(liar, fake_daemon):
    liar.attach(fake_daemon)
    result = liar._intercept_s2c(RP_QUERY)
    assert result == RP_QUERY  # passed through unchanged
    assert fake_daemon.sent_to_server == []


def test_liar_passes_through_non_query(liar, fake_daemon):
    """Even when armed, non-WSF traffic passes through."""
    liar.arm(QueryLies())
    liar.attach(fake_daemon)
    other = b"\xf5\xc3\x1d\x60\xc1\xff\xef"
    result = liar._intercept_s2c(other)
    assert result == other


def test_liar_tn3270e_reply_has_header(liar, fake_daemon):
    """If the inbound query had a TN3270E header, our reply has one too."""
    liar.arm(QueryLies())
    liar.attach(fake_daemon)
    liar._intercept_s2c(RP_QUERY_TN3270E)
    reply = fake_daemon.sent_to_server[0]
    # 5-byte TN3270E header before AID
    assert reply[5] == 0x88
    # seq number echoed
    assert reply[3:5] == bytes([0x00, 0x01])


# ===========================================================================
# Task 5: IND$FILE detector
# ===========================================================================

# IND$FILE uses File Transfer SFs (SFID = 0xD0).
# Wire format inside WSF: <len:2> <0xD0> <subtype:1> <data...>
# Subtypes (de-facto from x3270 source / Wireshark):
#   0x00 = open request    0x47 = data block (download s2c)
#   0x46 = data block      0x45 = close/EOF
# We don't care which is which for carbon-copy mode — just reassemble.

def _make_indfile_block(payload: bytes, subtype: int = 0x47) -> bytes:
    """Build a File Transfer SF wrapped in WSF + IAC EOR."""
    sf_body = bytes([0xD0, subtype]) + payload
    sf_len = struct.pack(">H", 2 + len(sf_body))
    return bytes([0xF3]) + sf_len + sf_body + b"\xff\xef"


def test_parse_wsf_extracts_sf():
    """parse_wsf returns the StructuredField inside a WSF datastream."""
    from hack3270_libs.attacks.structured import parse_wsf
    pkt = _make_indfile_block(b"hello", subtype=0x47)
    sf = parse_wsf(pkt)
    assert sf is not None
    assert sf.sf_type == 0xD0
    # Payload includes the subtype byte + data
    assert sf.payload == b"\x47hello"


def test_parse_wsf_handles_tn3270e_header():
    from hack3270_libs.attacks.structured import parse_wsf
    pkt = bytes([0x00, 0x00, 0x00, 0x00, 0x01]) + _make_indfile_block(b"data")
    sf = parse_wsf(pkt)
    assert sf is not None
    assert sf.sf_type == 0xD0


def test_parse_wsf_non_wsf_returns_none():
    from hack3270_libs.attacks.structured import parse_wsf
    assert parse_wsf(b"\xf5\xc3\x1d\x60\xff\xef") is None


def test_parse_wsf_short_packet():
    from hack3270_libs.attacks.structured import parse_wsf
    assert parse_wsf(b"\xf3") is None
    assert parse_wsf(b"") is None


# ---------------------------------------------------------------------------
# IndFileInterceptor state machine
# ---------------------------------------------------------------------------

@pytest.fixture
def indfile(tmp_path):
    from hack3270_libs.attacks.structured import IndFileInterceptor
    return IndFileInterceptor(capture_dir=str(tmp_path))


def test_indfile_starts_idle(indfile):
    assert indfile.state == "IDLE"


def test_indfile_default_mode_alert(indfile):
    assert indfile.mode == "alert"


def test_indfile_arm_on_command_text(indfile, fake_daemon):
    """Seeing 'IND$FILE PUT' or 'IND$FILE GET' in a screen → ARMED.
    Note: $ in EBCDIC cp037 is 0x5B."""
    from hack3270_libs.tn3270_v2 import TN3270
    indfile.protocol = TN3270()
    indfile.attach(fake_daemon)

    from hackterm_core.ebcdic import EbcdicCodec
    codec = EbcdicCodec()
    text_pkt = (bytes([0xF5, 0xC3, 0x1D, 0x40])
                + codec.to_ebcdic("IND$FILE PUT MY.DATA")
                + b"\xff\xef")
    fake_daemon.fire_s2c(text_pkt)
    assert indfile.state == "ARMED"
    assert indfile.direction == "PUT"


def test_indfile_arm_get_direction(indfile, fake_daemon):
    from hack3270_libs.tn3270_v2 import TN3270
    indfile.protocol = TN3270()
    indfile.attach(fake_daemon)

    from hackterm_core.ebcdic import EbcdicCodec
    codec = EbcdicCodec()
    text_pkt = (bytes([0xF5, 0xC3, 0x1D, 0x40])
                + codec.to_ebcdic("IND$FILE GET HOST.DATA")
                + b"\xff\xef")
    fake_daemon.fire_s2c(text_pkt)
    assert indfile.state == "ARMED"
    assert indfile.direction == "GET"
    assert indfile.dataset_name == "HOST.DATA"


def test_indfile_armed_to_transferring(indfile, fake_daemon):
    """ARMED + see 0xD0 SF → TRANSFERRING."""
    indfile.state = "ARMED"
    indfile.attach(fake_daemon)
    fake_daemon.fire_s2c(_make_indfile_block(b"block one"))
    assert indfile.state == "TRANSFERRING"
    assert b"block one" in indfile.buffer


def test_indfile_accumulates_blocks(indfile, fake_daemon):
    indfile.state = "ARMED"
    indfile.attach(fake_daemon)
    fake_daemon.fire_s2c(_make_indfile_block(b"AAA"))
    fake_daemon.fire_s2c(_make_indfile_block(b"BBB"))
    fake_daemon.fire_s2c(_make_indfile_block(b"CCC"))
    assert indfile.buffer == b"AAABBBCCC"


def test_indfile_eof_returns_to_idle(indfile, fake_daemon):
    """Subtype 0x45 (or empty payload) = EOF → write file → IDLE."""
    indfile.state = "ARMED"
    indfile.mode = "carbon_copy"
    indfile.attach(fake_daemon)
    fake_daemon.fire_s2c(_make_indfile_block(b"data"))
    fake_daemon.fire_s2c(_make_indfile_block(b"", subtype=0x45))
    assert indfile.state == "IDLE"
    assert len(indfile.captures) == 1


def test_indfile_carbon_copy_writes_file(indfile, fake_daemon, tmp_path):
    indfile.state = "ARMED"
    indfile.mode = "carbon_copy"
    indfile.direction = "GET"
    indfile.attach(fake_daemon)
    fake_daemon.fire_s2c(_make_indfile_block(b"file content here"))
    fake_daemon.fire_s2c(_make_indfile_block(b"", subtype=0x45))
    # File written to capture_dir
    files = list(tmp_path.glob("*.bin"))
    assert len(files) == 1
    assert files[0].read_bytes() == b"file content here"


def test_indfile_alert_mode_no_file(indfile, fake_daemon, tmp_path):
    """alert mode: log to captures list but don't write disk."""
    indfile.state = "ARMED"
    indfile.mode = "alert"
    indfile.attach(fake_daemon)
    fake_daemon.fire_s2c(_make_indfile_block(b"data"))
    fake_daemon.fire_s2c(_make_indfile_block(b"", subtype=0x45))
    assert len(indfile.captures) == 1
    assert list(tmp_path.glob("*.bin")) == []  # no files written


def test_indfile_idle_ignores_blocks(indfile, fake_daemon):
    """In IDLE state, 0xD0 SFs we didn't see the command for are ignored
    (could be some other WSF use)."""
    indfile.attach(fake_daemon)
    fake_daemon.fire_s2c(_make_indfile_block(b"orphan"))
    assert indfile.state == "IDLE"
    assert indfile.buffer == b""


def test_indfile_inject_mode_replaces_upload(indfile, fake_daemon):
    """inject mode (PUT only): replace user's blocks with our payload."""
    indfile.state = "ARMED"
    indfile.mode = "inject"
    indfile.direction = "PUT"
    indfile.inject_payload = b"EVIL CONTENT"
    indfile.attach(fake_daemon)

    # User sends a block c2s — intercept rewrites it
    user_block = _make_indfile_block(b"original content", subtype=0x46)
    result = indfile._intercept_c2s(user_block)
    # Result should contain our payload, not the user's
    assert b"EVIL CONTENT" in result
    assert b"original content" not in result


def test_indfile_inject_passes_through_non_indfile(indfile, fake_daemon):
    """inject mode leaves non-WSF traffic alone."""
    indfile.state = "ARMED"
    indfile.mode = "inject"
    indfile.direction = "PUT"
    indfile.inject_payload = b"EVIL"
    indfile.attach(fake_daemon)
    other = b"\x7d\x40\x40\xff\xef"  # AID enter, not WSF
    assert indfile._intercept_c2s(other) == other


def test_indfile_capture_metadata(indfile, fake_daemon):
    """Captures record direction, size, dataset name."""
    indfile.state = "ARMED"
    indfile.direction = "GET"
    indfile.dataset_name = "MY.PDS.MEMBER"
    indfile.attach(fake_daemon)
    fake_daemon.fire_s2c(_make_indfile_block(b"hello world"))
    fake_daemon.fire_s2c(_make_indfile_block(b"", subtype=0x45))
    cap = indfile.captures[0]
    assert cap["direction"] == "GET"
    assert cap["size"] == 11
    assert cap["dataset"] == "MY.PDS.MEMBER"
