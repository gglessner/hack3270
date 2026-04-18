import pytest
import socket
import time
from hackterm_core.api_server import ApiServer


@pytest.fixture
def api_server():
    s = ApiServer(port=0)  # port 0 = OS-assigned
    s.start()
    yield s
    s.stop()


def _pump(server, n=20, delay=0.01):
    for _ in range(n):
        server.tick()
        time.sleep(delay)


def test_starts_and_reports_port(api_server):
    assert api_server.port > 0


def test_register_handler_and_dispatch(api_server):
    api_server.register("PING", lambda args: "PONG")

    client = socket.socket()
    client.connect(("127.0.0.1", api_server.port))
    client.send(b"PING\n")
    _pump(api_server)
    client.setblocking(False)
    resp = client.recv(1024)
    assert resp == b"PONG\n"
    client.close()


def test_handler_receives_arguments(api_server):
    received = []
    api_server.register("ECHO", lambda args: (received.append(args), args)[1])

    client = socket.socket()
    client.connect(("127.0.0.1", api_server.port))
    client.send(b"ECHO hello world\n")
    _pump(api_server)
    client.setblocking(False)
    resp = client.recv(1024)
    assert resp == b"hello world\n"
    assert received == ["hello world"]
    client.close()


def test_unknown_command_returns_error(api_server):
    client = socket.socket()
    client.connect(("127.0.0.1", api_server.port))
    client.send(b"NONEXISTENT\n")
    _pump(api_server)
    client.setblocking(False)
    resp = client.recv(1024)
    assert b"ERROR" in resp
    client.close()


def test_multiple_clients(api_server):
    api_server.register("PING", lambda args: "PONG")

    c1 = socket.socket()
    c1.connect(("127.0.0.1", api_server.port))
    c2 = socket.socket()
    c2.connect(("127.0.0.1", api_server.port))
    _pump(api_server)

    c1.send(b"PING\n")
    c2.send(b"PING\n")
    _pump(api_server)

    c1.setblocking(False)
    c2.setblocking(False)
    assert c1.recv(1024) == b"PONG\n"
    assert c2.recv(1024) == b"PONG\n"
    c1.close()
    c2.close()


def test_client_disconnect_handled(api_server):
    """Client closing mid-session shouldn't crash the server."""
    api_server.register("PING", lambda args: "PONG")

    c = socket.socket()
    c.connect(("127.0.0.1", api_server.port))
    _pump(api_server)
    c.close()
    _pump(api_server)  # should not raise

    # Server still works for new clients
    c2 = socket.socket()
    c2.connect(("127.0.0.1", api_server.port))
    c2.send(b"PING\n")
    _pump(api_server)
    c2.setblocking(False)
    assert c2.recv(1024) == b"PONG\n"
    c2.close()


def test_handler_exception_returns_error_not_crash(api_server):
    api_server.register("BOOM", lambda args: 1 / 0)

    client = socket.socket()
    client.connect(("127.0.0.1", api_server.port))
    client.send(b"BOOM\n")
    _pump(api_server)
    client.setblocking(False)
    resp = client.recv(1024)
    assert b"ERROR" in resp
    client.close()


def test_binary_response_via_hex():
    """The legacy API returns binary data hex-encoded (e.g.
    GET_LAST_SERVER_RAW). Verify that hex strings work as responses."""
    s = ApiServer(port=0)
    s.start()
    s.register("RAW", lambda args: b"\xde\xad\xbe\xef".hex())

    client = socket.socket()
    client.connect(("127.0.0.1", s.port))
    client.send(b"RAW\n")
    _pump(s)
    client.setblocking(False)
    resp = client.recv(1024)
    assert resp == b"deadbeef\n"
    client.close()
    s.stop()


def test_stop_idempotent():
    s = ApiServer(port=0)
    s.start()
    s.stop()
    s.stop()  # should not raise
