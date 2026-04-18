"""
Non-blocking TCP API server.

Line-based text protocol on localhost. Each line is:
    COMMAND [args...]\\n
Response is one line ending in \\n. Binary data is hex-encoded.

Extracted from hack3270_libs/libhack3270.py:
  - api_start (L847-865): non-blocking listener setup
  - daemon API block (L1344-1372): accept + dispatch loop

Generalization: handler registry instead of a hardcoded
handle_api_request method with a giant if/elif chain. Both
hack3270 and hack5250 register their own handlers.
"""
import socket
import select
import logging
from typing import Callable, Optional

Handler = Callable[[str], str]


class ApiServer:
    """Localhost-only line-based command server.

    Drive via .tick() alongside ProxyDaemon — same select()-based
    non-blocking pattern.
    """

    def __init__(self, port: int = 31337):
        self._requested_port = port
        self.port: int = 0
        self._listener: Optional[socket.socket] = None
        self._clients: list[socket.socket] = []
        self._handlers: dict[str, Handler] = {}
        self._log = logging.getLogger(__name__)

    def start(self) -> None:
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.setblocking(False)
        self._listener.bind(("127.0.0.1", self._requested_port))
        self._listener.listen(5)
        self.port = self._listener.getsockname()[1]
        self._log.info("API server listening on 127.0.0.1:%d", self.port)

    def stop(self) -> None:
        for c in self._clients:
            try:
                c.close()
            except OSError:
                pass
        self._clients = []
        if self._listener:
            try:
                self._listener.close()
            except OSError:
                pass
        self._listener = None

    def register(self, command: str, handler: Handler) -> None:
        """Register a command handler. handler(args_str) -> response_str."""
        self._handlers[command] = handler

    def tick(self) -> None:
        """One select() pass. Call alongside ProxyDaemon.tick()."""
        if not self._listener:
            return

        readable = [self._listener] + self._clients
        rlist, _, _ = select.select(readable, [], [], 0)

        if self._listener in rlist:
            try:
                conn, _ = self._listener.accept()
                conn.setblocking(False)
                self._clients.append(conn)
            except OSError:
                pass

        for client in list(self._clients):
            if client not in rlist:
                continue
            try:
                data = client.recv(4096)
            except OSError:
                self._drop(client)
                continue
            if not data:
                self._drop(client)
                continue
            self._dispatch(client, data)

    def _dispatch(self, client: socket.socket, data: bytes) -> None:
        try:
            line = data.decode("utf-8", errors="replace").strip()
        except Exception:
            self._send(client, "ERROR: bad encoding")
            return
        if not line:
            return

        parts = line.split(" ", 1)
        cmd = parts[0]
        args = parts[1] if len(parts) > 1 else ""

        handler = self._handlers.get(cmd)
        if not handler:
            self._send(client, f"ERROR: unknown command {cmd!r}")
            return
        try:
            resp = handler(args)
        except Exception as e:
            self._log.exception("handler %s raised", cmd)
            self._send(client, f"ERROR: {e}")
            return
        self._send(client, resp)

    def _send(self, client: socket.socket, resp: str) -> None:
        try:
            client.send((resp + "\n").encode("utf-8"))
        except OSError:
            self._drop(client)

    def _drop(self, client: socket.socket) -> None:
        try:
            client.close()
        except OSError:
            pass
        if client in self._clients:
            self._clients.remove(client)
