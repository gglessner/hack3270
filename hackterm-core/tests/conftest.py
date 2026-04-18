import pytest
from hackterm_core.protocol import (
    Protocol, Screen, MutateOpts, NegotiateOpts, FieldWrite,
)


class MockProtocol(Protocol):
    """Test protocol that uppercases bytes in mutate()."""
    name = "mock"
    aid_table = {"ENTER": 0x0D}
    default_codepage = "ascii"

    def __init__(self):
        self.detect_called_with = None
        self.negotiate_calls = []

    def detect(self, first_bytes):
        self.detect_called_with = first_bytes
        return b"MOCK" in first_bytes

    def negotiate_hook(self, data, direction, opts):
        self.negotiate_calls.append((data, direction))
        return data

    def parse(self, data):
        return Screen.empty()

    def mutate(self, data, opts):
        if opts.unprotect:
            return data.upper()
        return data

    def build_inbound(self, aid, cursor, fields):
        parts = bytes([aid, cursor[0], cursor[1]])
        for fw in fields:
            parts += bytes([fw.row, fw.col]) + fw.data
        return parts

    def spoof_aid(self, original, new_aid):
        return bytes([new_aid]) + original[1:]


@pytest.fixture
def mock_protocol():
    return MockProtocol()


from hackterm_core.storage import Storage


@pytest.fixture
def tmp_storage(tmp_path):
    s = Storage(
        str(tmp_path / "test.db"),
        server_ip="127.0.0.1", server_port=23,
        proxy_port=3271, tls_enabled=False,
    )
    yield s
    s.close()
