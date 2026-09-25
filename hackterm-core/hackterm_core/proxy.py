"""
Headless MITM proxy daemon.

Owns the client+server socket pair and runs the select() event loop.
No GUI dependency — drive via .tick() from any scheduler (QTimer,
asyncio, threading.Timer, while-True loop).

Extracted from hack3270_libs/libhack3270.py:
  - client_connect (L779-801): blocking accept()
  - server_connect (L803-845): outbound connect, optional TLS
  - daemon (L1329-1471): the select() pump

What's stripped vs. legacy daemon():
  - Inline branches at L1381-1399 (capture_mask, aid_fuzzer, aid_spoof)
    become a single set_client_intercept() callback.
  - Inline hack_toggled block at L1414-1471 becomes the standard
    mutate() path — no toggle re-send, just always mutate.
  - API listener (L1334-1372) moves to api_server.py.

What's added:
  - Negotiation phase: until protocol.detect() returns True, traffic
    flows through protocol.negotiate_hook() instead of mutate().
    This is where LU-name spoofing (3270) and IBMRSEED stripping
    (5250) hook in.
  - Observer pattern: ESM passive fingerprinter, IND$FILE detector
    register via add_observer().
"""
import socket
import select
import ssl
import logging
from typing import Callable, Optional

from hackterm_core.protocol import Protocol, MutateOpts, NegotiateOpts
from hackterm_core.storage import Storage

BUFFER_SIZE = 16384  # legacy was 10000; bump slightly but keep modest
Observer = Callable[[bytes, str], None]
ClientIntercept = Callable[[bytes], Optional[bytes]]


class ProxyDaemon:
    """Single-connection MITM proxy.

    Lifecycle:
        d = ProxyDaemon(protocol, storage, listen_addr, target_addr)
        d.wait_for_client()      # blocks until emulator connects
        d.connect_to_server()    # connects to mainframe
        while running:
            d.tick()             # one select() pass, non-blocking
        d.close()
    """

    def __init__(self, protocol: Protocol, storage: Storage,
                 listen_addr: tuple[str, int],
                 target_addr: tuple[str, int],
                 use_tls: bool = False):
        self.protocol = protocol
        self.storage = storage
        self.listen_addr = listen_addr
        self.target_addr = target_addr
        self.use_tls = use_tls

        self.mutate_opts = MutateOpts()
        self.negotiate_opts = NegotiateOpts()
        self.handshake_complete = False

        self._observers: list[Observer] = []
        self._client_intercept: Optional[ClientIntercept] = None

        self._listener: Optional[socket.socket] = None
        self.client: Optional[socket.socket] = None
        self.server: Optional[socket.socket] = None

        self._log = logging.getLogger(__name__)

    # --- Connection lifecycle ----------------------------------------

    def wait_for_client(self) -> None:
        """Blocking accept(). Replaces client_connect (L779-801)."""
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(self.listen_addr)
        self._listener.listen(1)
        self._log.debug("waiting for client on %s", self.listen_addr)
        conn, peer = self._listener.accept()
        self._log.debug("client connected from %s", peer)
        self.client = conn

    def connect_to_server(self) -> None:
        """Connect to the mainframe. Replaces server_connect (L803-845)."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if self.use_tls:
            ctx = ssl._create_unverified_context()
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            ctx.set_ciphers("DEFAULT@SECLEVEL=0")
            sock = ctx.wrap_socket(sock, server_hostname=self.target_addr[0])
        sock.connect(self.target_addr)
        self.server = sock
        self._log.debug("connected to server %s", self.target_addr)

    def close(self) -> None:
        for s in (self.client, self.server, self._listener):
            if s:
                try:
                    s.close()
                except OSError:
                    pass
        self.client = None
        self.server = None
        self._listener = None

    # --- Hooks -------------------------------------------------------

    def add_observer(self, fn: Observer) -> None:
        """Register a callback for post-handshake traffic.
        fn(data: bytes, direction: 's2c'|'c2s')
        Used by: ESM passive fingerprinter, IND$FILE detector,
        state-machine recorder.
        """
        self._observers.append(fn)

    def remove_observer(self, fn: Observer) -> None:
        """Unregister a callback. Safe to call even if fn was never added
        or was already removed (idempotent). Used by short-lived observers
        like StateFuzzer._wait_for_response.
        """
        try:
            self._observers.remove(fn)
        except ValueError:
            pass

    def set_client_intercept(self, fn: Optional[ClientIntercept]) -> None:
        """Register a callback for client->server traffic.
        fn(data) -> bytes (modified) | None (drop, don't forward)
        Replaces the inline branches at libhack3270.py:1381-1399.
        Used by: MaskInjector capture, AID spoofing, AID fuzzer.
        """
        self._client_intercept = fn

    def inject_to_server(self, data: bytes) -> None:
        """Send bytes directly to the server. Used by attack modules."""
        if not self.server:
            raise RuntimeError("not connected to server")
        self.storage.log("C", "injected", data)
        self.server.send(data)

    def inject_to_client(self, data: bytes) -> None:
        """Send bytes directly to the client. Used for replay."""
        if not self.client:
            raise RuntimeError("no client connected")
        self.client.send(data)

    # --- Event loop --------------------------------------------------

    def tick(self) -> None:
        """One select() pass, zero timeout. Call repeatedly.
        Replaces daemon (L1329-1471).
        """
        if not (self.client and self.server):
            return

        readable = [self.client, self.server]
        rlist, _, _ = select.select(readable, [], [], 0)

        if self.client in rlist:
            self._handle_client()

        if self.server in rlist:
            self._handle_server()

    def _handle_client(self) -> None:
        try:
            data = self.client.recv(BUFFER_SIZE)
        except (ConnectionResetError, OSError):
            # Abrupt close (RST) raises instead of returning b"". Treat same.
            data = b""
        if not data:
            # Empty recv = peer closed. Without this, the closed socket stays
            # in the select() readables and tick() busy-loops at 100% CPU
            # reading 0 bytes forever. Setting to None makes tick() early-return.
            self._log.debug("client disconnected")
            try:
                self.client.close()
            except OSError:
                pass
            self.client = None
            return

        if not self.handshake_complete:
            data = self.protocol.negotiate_hook(data, "c2s", self.negotiate_opts)
            self.storage.log("C", "", data)
            self.server.send(data)
            return

        # Client intercept (capture_mask, aid_spoof, aid_fuzzer all live here)
        if self._client_intercept:
            modified = self._client_intercept(data)
            if modified is None:
                # Intercept consumed it (e.g. capture mode). Still log original.
                self.storage.log("C", "intercepted", data)
                return
            data = modified

        for obs in self._observers:
            obs(data, "c2s")
        self.storage.log("C", "", data)
        self.server.send(data)

    def _handle_server(self) -> None:
        try:
            data = self.server.recv(BUFFER_SIZE)
        except (ConnectionResetError, OSError):
            data = b""
        if not data:
            self._log.debug("server disconnected")
            try:
                self.server.close()
            except OSError:
                pass
            self.server = None
            return

        if not self.handshake_complete:
            data = self.protocol.negotiate_hook(data, "s2c", self.negotiate_opts)
            self.storage.log("S", "", data)
            if self.protocol.detect(data):
                self.handshake_complete = True
                self._log.debug("handshake complete")
            self.client.send(data)
            return

        # Log ORIGINAL bytes before mutation — replay must be faithful
        self.storage.log("S", "", data)
        for obs in self._observers:
            obs(data, "s2c")

        mutated = self.protocol.mutate(data, self.mutate_opts)
        self.client.send(mutated)
