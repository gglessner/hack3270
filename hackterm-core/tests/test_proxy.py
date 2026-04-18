import pytest
import socket
import threading
import time
from hackterm_core.proxy import ProxyDaemon
from hackterm_core.protocol import MutateOpts


@pytest.fixture
def free_port():
    """Bind to port 0 to get a free port from the OS, then release it."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _pump(daemon, n=50, delay=0.01):
    """Drive the select() loop. select() with 0 timeout is non-blocking
    so we tick repeatedly to give bytes time to arrive."""
    for _ in range(n):
        daemon.tick()
        time.sleep(delay)


def _setup(mock_protocol, tmp_storage, free_port):
    """Boilerplate: spin up server listener, daemon, client thread.
    Returns (daemon, client_sock, server_conn, server_listener) for cleanup."""
    server_listener = socket.socket()
    server_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_listener.bind(("127.0.0.1", 0))
    server_listener.listen(1)
    server_port = server_listener.getsockname()[1]

    daemon = ProxyDaemon(
        protocol=mock_protocol,
        storage=tmp_storage,
        listen_addr=("127.0.0.1", free_port),
        target_addr=("127.0.0.1", server_port),
    )

    holder = {}
    def client_thread():
        time.sleep(0.1)
        c = socket.socket()
        c.connect(("127.0.0.1", free_port))
        holder["sock"] = c
    t = threading.Thread(target=client_thread)
    t.start()
    daemon.wait_for_client()
    t.join()

    daemon.connect_to_server()
    server_conn, _ = server_listener.accept()
    return daemon, holder["sock"], server_conn, server_listener


def _teardown(daemon, client, server_conn, listener):
    daemon.close()
    client.close()
    server_conn.close()
    listener.close()


def test_proxy_passes_bytes_through(mock_protocol, tmp_storage, free_port):
    """End-to-end: server sends bytes, client receives them."""
    daemon, client, server_conn, listener = _setup(mock_protocol, tmp_storage, free_port)

    server_conn.send(b"hello from MOCK server")
    _pump(daemon)

    client.setblocking(False)
    received = client.recv(1024)
    assert b"hello" in received

    _teardown(daemon, client, server_conn, listener)


def test_mutate_applied_to_server_traffic(mock_protocol, tmp_storage, free_port):
    """MockProtocol.mutate() uppercases when unprotect=True. Verify the
    proxy actually calls it on server->client traffic."""
    daemon, client, server_conn, listener = _setup(mock_protocol, tmp_storage, free_port)

    # Send handshake first to complete negotiation phase
    server_conn.send(b"MOCK handshake")
    _pump(daemon)
    client.setblocking(False)
    try:
        client.recv(1024)  # drain handshake
    except BlockingIOError:
        pass

    # Now arm the mutation and send data
    daemon.mutate_opts.unprotect = True
    server_conn.send(b"hello world")
    _pump(daemon)

    received = client.recv(1024)
    assert received == b"HELLO WORLD"

    _teardown(daemon, client, server_conn, listener)


def test_negotiate_hook_called_before_handshake_complete(
        mock_protocol, tmp_storage, free_port):
    """Until detect() returns True, traffic goes through negotiate_hook
    instead of mutate."""
    daemon, client, server_conn, listener = _setup(mock_protocol, tmp_storage, free_port)

    # First server send: doesn't contain "MOCK" so detect()=False,
    # negotiate_hook should be called
    server_conn.send(b"telnet stuff")
    _pump(daemon)
    assert any(d == b"telnet stuff" for d, _ in mock_protocol.negotiate_calls)

    # Second send: contains "MOCK" so detect()=True, handshake complete
    server_conn.send(b"MOCK ready")
    _pump(daemon)
    assert daemon.handshake_complete is True

    _teardown(daemon, client, server_conn, listener)


def test_observer_receives_server_traffic(mock_protocol, tmp_storage, free_port):
    """Observers are called for post-handshake server->client traffic.
    This is how ESM passive fingerprinter and IND$FILE detector hook in."""
    daemon, client, server_conn, listener = _setup(mock_protocol, tmp_storage, free_port)

    seen = []
    daemon.add_observer(lambda data, direction: seen.append((data, direction)))

    # Complete handshake
    server_conn.send(b"MOCK")
    _pump(daemon)
    # Now send observable traffic
    server_conn.send(b"observable data")
    _pump(daemon)

    assert any(d == b"observable data" and dr == "s2c" for d, dr in seen)

    _teardown(daemon, client, server_conn, listener)


def test_storage_logs_unmutated_bytes(mock_protocol, tmp_storage, free_port):
    """Critical: storage gets the ORIGINAL bytes, not the mutated ones.
    Replay must be faithful."""
    daemon, client, server_conn, listener = _setup(mock_protocol, tmp_storage, free_port)

    server_conn.send(b"MOCK")  # complete handshake
    _pump(daemon)
    daemon.mutate_opts.unprotect = True
    server_conn.send(b"hello")
    _pump(daemon)

    # Storage should have the lowercase original
    rows = tmp_storage.all_logs()
    raw_blobs = [r[5] for r in rows]
    assert b"hello" in raw_blobs
    # And NOT the mutated version
    assert b"HELLO" not in raw_blobs

    _teardown(daemon, client, server_conn, listener)


def test_inject_to_server(mock_protocol, tmp_storage, free_port):
    """Direct injection to server. Used by AID fuzzing, field injection."""
    daemon, client, server_conn, listener = _setup(mock_protocol, tmp_storage, free_port)

    daemon.inject_to_server(b"injected payload")
    server_conn.setblocking(False)
    time.sleep(0.1)
    received = server_conn.recv(1024)
    assert received == b"injected payload"

    _teardown(daemon, client, server_conn, listener)


def test_client_intercept_callback(mock_protocol, tmp_storage, free_port):
    """The c2s intercept replaces inline branches (capture_mask, aid_spoof).
    Returning bytes means 'forward this instead'."""
    daemon, client, server_conn, listener = _setup(mock_protocol, tmp_storage, free_port)

    # Complete handshake first (intercept only fires post-handshake)
    server_conn.send(b"MOCK")
    _pump(daemon)

    intercepted = []
    def intercept(data):
        intercepted.append(data)
        return data.replace(b"foo", b"BAR")
    daemon.set_client_intercept(intercept)

    client.send(b"foo bar")
    _pump(daemon)

    assert intercepted == [b"foo bar"]
    server_conn.setblocking(False)
    received = server_conn.recv(1024)
    assert received == b"BAR bar"

    _teardown(daemon, client, server_conn, listener)


def test_client_intercept_none_drops_packet(mock_protocol, tmp_storage, free_port):
    """Returning None means 'don't forward' (e.g. mask capture mode)."""
    daemon, client, server_conn, listener = _setup(mock_protocol, tmp_storage, free_port)

    server_conn.send(b"MOCK")  # complete handshake
    _pump(daemon)

    daemon.set_client_intercept(lambda data: None)
    client.send(b"should be dropped")
    _pump(daemon)

    server_conn.setblocking(False)
    with pytest.raises(BlockingIOError):
        server_conn.recv(1024)  # nothing should arrive

    # But it WAS logged (with 'intercepted' note)
    rows = tmp_storage.all_logs()
    assert any(b"should be dropped" == r[5] for r in rows)

    _teardown(daemon, client, server_conn, listener)


def test_close_idempotent(mock_protocol, tmp_storage, free_port):
    daemon = ProxyDaemon(
        protocol=mock_protocol,
        storage=tmp_storage,
        listen_addr=("127.0.0.1", free_port),
        target_addr=("127.0.0.1", 9),
    )
    daemon.close()
    daemon.close()  # should not raise


def test_remove_observer(mock_protocol, tmp_storage, free_port):
    """remove_observer unregisters; subsequent traffic doesn't fire it."""
    daemon, client, server_conn, listener = _setup(mock_protocol, tmp_storage, free_port)

    seen = []
    obs = lambda data, direction: seen.append((data, direction))
    daemon.add_observer(obs)

    server_conn.send(b"MOCK")  # complete handshake
    _pump(daemon)
    server_conn.send(b"first")
    _pump(daemon)
    assert any(d == b"first" for d, _ in seen)

    seen.clear()
    daemon.remove_observer(obs)
    server_conn.send(b"second")
    _pump(daemon)
    assert not any(d == b"second" for d, _ in seen)  # observer gone

    _teardown(daemon, client, server_conn, listener)


def test_remove_observer_idempotent(mock_protocol, tmp_storage, free_port):
    """Removing an unregistered observer doesn't raise."""
    daemon = ProxyDaemon(
        protocol=mock_protocol, storage=tmp_storage,
        listen_addr=("127.0.0.1", free_port),
        target_addr=("127.0.0.1", 9),
    )
    daemon.remove_observer(lambda d, dr: None)  # never added — should not raise
    daemon.close()


def test_remove_observer_double_remove(mock_protocol, tmp_storage, free_port):
    daemon = ProxyDaemon(
        protocol=mock_protocol, storage=tmp_storage,
        listen_addr=("127.0.0.1", free_port),
        target_addr=("127.0.0.1", 9),
    )
    obs = lambda d, dr: None
    daemon.add_observer(obs)
    daemon.remove_observer(obs)
    daemon.remove_observer(obs)  # second remove — should not raise
    daemon.close()


def test_server_disconnect_stops_busyloop(mock_protocol, tmp_storage, free_port):
    """When the server closes, daemon.server is set to None so tick()
    early-returns instead of busy-looping on a closed socket forever.

    Before the fix: closed socket stays select()-readable, recv() returns
    b"", _handle_server() returns without clearing — next tick() does it
    again at 100% CPU.
    """
    daemon, client, server_conn, listener = _setup(mock_protocol, tmp_storage, free_port)

    server_conn.send(b"MOCK")  # complete handshake
    _pump(daemon)

    # Server closes
    server_conn.close()
    _pump(daemon, n=10)

    # daemon.server should now be None — tick() will early-return
    assert daemon.server is None

    # tick() after disconnect should be a no-op (no exception, no busy-loop)
    for _ in range(100):
        daemon.tick()  # should be ~free now

    daemon.close()
    client.close()
    listener.close()


def test_client_disconnect_stops_busyloop(mock_protocol, tmp_storage, free_port):
    """Symmetric to server disconnect — client closing sets daemon.client = None."""
    daemon, client, server_conn, listener = _setup(mock_protocol, tmp_storage, free_port)

    server_conn.send(b"MOCK")
    _pump(daemon)

    client.close()
    _pump(daemon, n=10)

    assert daemon.client is None

    daemon.close()
    server_conn.close()
    listener.close()
