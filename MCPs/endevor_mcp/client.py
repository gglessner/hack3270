# Endevor-MCP - An Endevor REST API MCP Server
# Copyright (C) 2026 Garland Glessner
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

"""
Endevor REST API Client

Manages persistent HTTP sessions to Endevor REST API instances with full
support for authentication, TLS, and connection pooling.

Authentication:
    - Basic Auth (username/password)
    - Bearer Token (JWT from Endevor /auth endpoint)

TLS Options:
    - Custom CA certificate for server verification
    - Client certificate + key for mutual TLS (mTLS)
    - Skip verification for test environments

Base URL pattern:
    {protocol}://{host}:{port}/EndevorService/api/v2
"""

import os
import sys
import threading
import time
from typing import Optional, Dict, Any, Tuple

import requests
import urllib3

# ── Debug toggle ──────────────────────────────────────────────────────
# Set to True to log all HTTP request/response traffic to stderr.
DEBUG_HTTP = False


def _debug(msg: str) -> None:
    if DEBUG_HTTP:
        print(f"[ENDEVOR-DEBUG] {msg}", file=sys.stderr, flush=True)


class EndevorConnection:
    """A single managed connection to an Endevor REST API instance."""

    def __init__(
        self,
        conn_id: str,
        host: str,
        port: int = 443,
        datasource: str = "",
        use_ssl: bool = True,
        username: Optional[str] = None,
        password: Optional[str] = None,
        bearer_token: Optional[str] = None,
        base_path: str = "/EndevorService/api/v2",
        ssl_cafile: Optional[str] = None,
        ssl_certfile: Optional[str] = None,
        ssl_keyfile: Optional[str] = None,
        ssl_no_verify: bool = False,
        reject_unauthorized: bool = True,
        timeout: float = 60.0,
    ):
        self.conn_id = conn_id
        self.host = host
        self.port = port
        self.datasource = datasource
        self.use_ssl = use_ssl
        self.username = username
        self.password = password
        self.bearer_token = bearer_token
        self.base_path = base_path.rstrip("/")
        self.ssl_cafile = ssl_cafile
        self.ssl_certfile = ssl_certfile
        self.ssl_keyfile = ssl_keyfile
        self.ssl_no_verify = ssl_no_verify
        self.reject_unauthorized = reject_unauthorized
        self.timeout = timeout

        self._session: Optional[requests.Session] = None
        self._lock = threading.RLock()
        self._connected = False
        self._authenticated = False
        self._connect_time: Optional[float] = None
        self._request_count = 0
        self._jwt_token: Optional[str] = None

    @property
    def base_url(self) -> str:
        protocol = "https" if self.use_ssl else "http"
        return f"{protocol}://{self.host}:{self.port}{self.base_path}"

    @property
    def connected(self) -> bool:
        return self._connected

    @property
    def authenticated(self) -> bool:
        return self._authenticated

    def connect(self) -> Dict[str, Any]:
        """Establish HTTP session and verify connectivity."""
        with self._lock:
            if self._connected:
                return {"status": "already_connected", "host": self.host, "port": self.port}

            session = requests.Session()

            if self.ssl_no_verify or not self.reject_unauthorized:
                session.verify = False
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            elif self.ssl_cafile:
                session.verify = self.ssl_cafile
            else:
                session.verify = True

            if self.ssl_certfile:
                if self.ssl_keyfile:
                    session.cert = (self.ssl_certfile, self.ssl_keyfile)
                else:
                    session.cert = self.ssl_certfile

            if self.bearer_token:
                session.headers["Authorization"] = f"Bearer {self.bearer_token}"
                self._authenticated = True
            elif self.username and self.password:
                session.auth = (self.username, self.password)
                self._authenticated = True

            session.headers["Accept"] = "application/json"

            self._session = session
            self._connected = True
            self._connect_time = time.time()

            result = {
                "status": "connected",
                "host": self.host,
                "port": self.port,
                "base_url": self.base_url,
                "protocol": "HTTPS" if self.use_ssl else "HTTP",
                "authenticated": self._authenticated,
            }

            if self.datasource:
                result["datasource"] = self.datasource
            if self.username:
                result["auth_method"] = "basic"
                result["username"] = self.username
            elif self.bearer_token:
                result["auth_method"] = "bearer_token"
            if self.ssl_certfile:
                result["client_cert"] = os.path.basename(self.ssl_certfile)

            try:
                resp = self._do_request("GET", "/")
                if resp.status_code == 200:
                    result["connectivity"] = "verified"
                    data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
                    if isinstance(data, dict) and data.get("data"):
                        result["datasources_found"] = len(data["data"]) if isinstance(data["data"], list) else 1
                else:
                    result["connectivity"] = f"response_code_{resp.status_code}"
            except requests.exceptions.SSLError as e:
                self.disconnect()
                raise ConnectionError(f"SSL/TLS error connecting to {self.base_url}: {e}")
            except requests.exceptions.ConnectionError as e:
                self.disconnect()
                raise ConnectionError(f"Cannot reach {self.base_url}: {e}")
            except Exception as e:
                result["connectivity_warning"] = str(e)

            return result

    def disconnect(self) -> Dict[str, Any]:
        """Close the HTTP session."""
        with self._lock:
            was_connected = self._connected
            if self._session:
                try:
                    self._session.close()
                except Exception:
                    pass
                self._session = None
            self._connected = False
            self._authenticated = False
            uptime = time.time() - self._connect_time if self._connect_time else 0
            return {
                "status": "disconnected" if was_connected else "was_not_connected",
                "requests_sent": self._request_count,
                "uptime_seconds": round(uptime, 1),
            }

    def _do_request(
        self,
        method: str,
        path: str,
        params: Optional[Dict] = None,
        json_body: Optional[Dict] = None,
        data: Optional[Any] = None,
        files: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        timeout: Optional[float] = None,
        accept: Optional[str] = None,
    ) -> requests.Response:
        """Execute an HTTP request against the Endevor REST API."""
        if not self._connected or not self._session:
            raise ConnectionError("Not connected. Call endevor_connect first.")

        url = f"{self.base_url}{path}"
        req_headers = dict(headers or {})
        if accept:
            req_headers["Accept"] = accept

        # Enforce auth on every request via per-request headers so it
        # survives regardless of session state, redirects, etc.
        if "Authorization" not in req_headers:
            if self._jwt_token:
                req_headers["Authorization"] = f"Bearer {self._jwt_token}"
            elif self._session.auth:
                pass  # requests will apply session.auth automatically
            elif self.bearer_token:
                req_headers["Authorization"] = f"Bearer {self.bearer_token}"

        self._request_count += 1

        if DEBUG_HTTP:
            _debug(f">>> {method} {url}")
            if params:
                _debug(f"    params: {params}")
            if json_body:
                _debug(f"    body: {json_body}")
            auth_hdr = req_headers.get("Authorization")
            if auth_hdr:
                kind = auth_hdr.split()[0] if " " in auth_hdr else auth_hdr
                _debug(f"    auth header: {kind} (len={len(auth_hdr)})")
            if self._session.auth:
                _debug(f"    session.auth: Basic ({self._session.auth[0]}:****)")
            if not auth_hdr and not self._session.auth:
                _debug("    WARNING: no auth on this request!")
            for k, v in req_headers.items():
                if k.lower() != "authorization":
                    _debug(f"    header: {k}: {v}")

        resp = self._session.request(
            method=method,
            url=url,
            params=params,
            json=json_body,
            data=data,
            files=files,
            headers=req_headers,
            timeout=timeout or self.timeout,
        )

        if DEBUG_HTTP:
            _debug(f"<<< {resp.status_code} {resp.reason} ({len(resp.content)} bytes)")
            for k, v in resp.headers.items():
                _debug(f"    {k}: {v}")
            ct = resp.headers.get("content-type", "")
            if "json" in ct:
                body = resp.text[:2000]
                _debug(f"    body: {body}")
            elif "text" in ct or "octet-stream" in ct:
                _debug(f"    body: ({len(resp.content)} bytes, first 200): {resp.text[:200]}")
            _debug("")

        return resp

    def request(
        self,
        method: str,
        path: str,
        params: Optional[Dict] = None,
        json_body: Optional[Dict] = None,
        data: Optional[Any] = None,
        files: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        timeout: Optional[float] = None,
        accept: Optional[str] = None,
    ) -> requests.Response:
        """Public request method with datasource prefix handling."""
        if self.datasource and not path.startswith(f"/{self.datasource}"):
            if path == "/" or path == "":
                pass
            else:
                path = f"/{self.datasource}{path}"
        return self._do_request(method, path, params, json_body, data, files, headers, timeout, accept)

    def get(self, path: str, params: Optional[Dict] = None, **kwargs) -> requests.Response:
        return self.request("GET", path, params=params, **kwargs)

    def post(self, path: str, **kwargs) -> requests.Response:
        return self.request("POST", path, **kwargs)

    def put(self, path: str, **kwargs) -> requests.Response:
        return self.request("PUT", path, **kwargs)

    def delete(self, path: str, **kwargs) -> requests.Response:
        return self.request("DELETE", path, **kwargs)

    def authenticate(
        self,
        username: Optional[str] = None,
        password: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Get a JWT token from the Endevor /auth endpoint.

        The /auth endpoint requires Basic Auth credentials to issue a JWT.
        This method builds a Basic Auth header explicitly for the /auth
        call, then stores the JWT in self._jwt_token.  All subsequent
        requests pick up the token in _do_request() automatically.

        If username/password are provided, they override (and update) the
        stored credentials on this connection.
        """
        if username:
            self.username = username
        if password:
            self.password = password

        if not self.datasource:
            return {"error": "datasource is required for authentication"}
        if not self.username or not self.password:
            return {"error": "username/password required for JWT authentication"}

        import base64 as _b64
        basic_cred = _b64.b64encode(
            f"{self.username}:{self.password}".encode()
        ).decode()
        auth_headers = {"Authorization": f"Basic {basic_cred}"}

        _debug(f"Authenticating with Basic Auth as {self.username}")

        resp = self._do_request(
            "GET", f"/{self.datasource}/auth", headers=auth_headers,
        )

        if resp.status_code == 200:
            data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
            token = None
            if isinstance(data, dict):
                token = data.get("token")
                if not token:
                    d = data.get("data")
                    if isinstance(d, dict):
                        token = d.get("token")
                    elif isinstance(d, list):
                        for item in d:
                            if isinstance(item, dict) and item.get("token"):
                                token = item["token"]
                                break
            if token:
                self._jwt_token = token
                self._session.auth = None
                self._authenticated = True
                _debug(f"JWT obtained (len={len(token)}), Bearer auth active")
                return {"status": "authenticated", "token_received": True}
            return {"status": "response_ok", "data": data}
        elif resp.status_code == 401:
            return {"status": "unauthorized", "message": "Invalid credentials"}
        else:
            return {"status": f"error_{resp.status_code}", "body": resp.text[:500]}

    def status(self) -> Dict[str, Any]:
        info = {
            "conn_id": self.conn_id,
            "host": self.host,
            "port": self.port,
            "base_url": self.base_url,
            "datasource": self.datasource,
            "protocol": "HTTPS" if self.use_ssl else "HTTP",
            "connected": self._connected,
            "authenticated": self._authenticated,
            "requests_sent": self._request_count,
            "uptime_seconds": round(time.time() - self._connect_time, 1) if self._connect_time and self._connected else 0,
        }
        if self._jwt_token:
            info["auth_method"] = "bearer_token"
            if self.username:
                info["username"] = self.username
        elif self.username:
            info["auth_method"] = "basic"
            info["username"] = self.username
        elif self.bearer_token:
            info["auth_method"] = "bearer_token"
        if self.ssl_certfile:
            info["client_cert"] = os.path.basename(self.ssl_certfile)
        return info


class ConnectionManager:
    """Manages multiple named Endevor connections."""

    def __init__(self):
        self._connections: Dict[str, EndevorConnection] = {}
        self._counter = 0
        self._lock = threading.RLock()

    def create(
        self,
        host: str,
        port: int = 443,
        datasource: str = "",
        name: str = "",
        use_ssl: bool = True,
        username: Optional[str] = None,
        password: Optional[str] = None,
        bearer_token: Optional[str] = None,
        base_path: str = "/EndevorService/api/v2",
        ssl_cafile: Optional[str] = None,
        ssl_certfile: Optional[str] = None,
        ssl_keyfile: Optional[str] = None,
        ssl_no_verify: bool = False,
        reject_unauthorized: bool = True,
        timeout: float = 60.0,
    ) -> Tuple[str, EndevorConnection]:
        """Create a new connection (does not connect yet)."""
        with self._lock:
            self._counter += 1
            conn_id = name or f"conn-{self._counter}"
            if conn_id in self._connections:
                try:
                    self._connections[conn_id].disconnect()
                except Exception:
                    pass

            conn = EndevorConnection(
                conn_id=conn_id,
                host=host,
                port=port,
                datasource=datasource,
                use_ssl=use_ssl,
                username=username,
                password=password,
                bearer_token=bearer_token,
                base_path=base_path,
                ssl_cafile=ssl_cafile,
                ssl_certfile=ssl_certfile,
                ssl_keyfile=ssl_keyfile,
                ssl_no_verify=ssl_no_verify,
                reject_unauthorized=reject_unauthorized,
                timeout=timeout,
            )
            self._connections[conn_id] = conn
            return conn_id, conn

    def get(self, conn_id: str) -> EndevorConnection:
        conn = self._connections.get(conn_id)
        if not conn:
            available = list(self._connections.keys())
            raise KeyError(
                f"Connection '{conn_id}' not found. "
                f"Available: {available if available else '(none - use endevor_connect first)'}"
            )
        return conn

    def remove(self, conn_id: str) -> Dict[str, Any]:
        conn = self._connections.pop(conn_id, None)
        if conn:
            return conn.disconnect()
        return {"status": "not_found"}

    def list_all(self) -> list:
        return [conn.status() for conn in self._connections.values()]

    def shutdown_all(self):
        for conn in self._connections.values():
            try:
                conn.disconnect()
            except Exception:
                pass
        self._connections.clear()
