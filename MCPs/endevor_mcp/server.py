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
Endevor-MCP Server v1.0.0 (Read-Only)

Read-only MCP server providing AI-driven Endevor SCM interaction via the
Endevor REST API v2. Supports Basic Auth, Bearer Token (JWT), and TLS.

Tools cover: connection management, authentication, inventory browsing,
element retrieval and inspection (retrieve/print/components), package
listing, async task management, fingerprint validation, health checks,
and report retrieval. All write operations have been intentionally removed.
"""

import atexit
import json
import os
import sys

from mcp.server.fastmcp import FastMCP

_pkg_dir = os.path.dirname(os.path.abspath(__file__))
_parent_dir = os.path.dirname(_pkg_dir)
if _parent_dir not in sys.path:
    sys.path.insert(0, _parent_dir)

from endevor_mcp.client import ConnectionManager, EndevorConnection

# =====================================================================
# Initialize
# =====================================================================

conn_mgr = ConnectionManager()
atexit.register(conn_mgr.shutdown_all)

mcp = FastMCP(
    "Endevor-MCP",
    instructions=(
        "Endevor-MCP provides read-only interaction with Broadcom Endevor SCM "
        "via the REST API v2. If ENDEVOR_HOST environment variables were "
        "configured, connection 'auto' is pre-established — use conn_id='auto' "
        "immediately. Otherwise: endevor_connect -> browse inventory with "
        "endevor_list_* tools -> retrieve/print elements -> endevor_disconnect. "
        "This is a read-only server: no add, update, delete, move, generate, "
        "sign-out, package mutation, or SCL submission tools are available."
    ),
)


def _auto_connect():
    """Auto-connect using ENDEVOR_* environment variables if configured.

    Reads ENDEVOR_HOST (required), ENDEVOR_PORT, ENDEVOR_DATASOURCE,
    ENDEVOR_USERNAME, ENDEVOR_PASSWORD, ENDEVOR_BEARER_TOKEN,
    ENDEVOR_BASE_PATH, ENDEVOR_SSL_NO_VERIFY, ENDEVOR_SSL_CAFILE,
    ENDEVOR_SSL_CERTFILE, ENDEVOR_SSL_KEYFILE, and
    ENDEVOR_REJECT_UNAUTHORIZED from the environment.

    If ENDEVOR_HOST is set, creates connection 'auto', connects,
    and authenticates (obtains JWT) if Basic Auth credentials are present.
    """
    host = os.environ.get("ENDEVOR_HOST", "").strip()
    if not host:
        return

    port = int(os.environ.get("ENDEVOR_PORT", "443"))
    datasource = os.environ.get("ENDEVOR_DATASOURCE", "").strip()
    username = os.environ.get("ENDEVOR_USERNAME", "").strip() or None
    password = os.environ.get("ENDEVOR_PASSWORD", "").strip() or None
    bearer_token = os.environ.get("ENDEVOR_BEARER_TOKEN", "").strip() or None
    base_path = os.environ.get("ENDEVOR_BASE_PATH", "/EndevorService/api/v2").strip()
    ssl_no_verify = os.environ.get("ENDEVOR_SSL_NO_VERIFY", "").strip().lower() in ("true", "1", "yes")
    ssl_cafile = os.environ.get("ENDEVOR_SSL_CAFILE", "").strip() or None
    ssl_certfile = os.environ.get("ENDEVOR_SSL_CERTFILE", "").strip() or None
    ssl_keyfile = os.environ.get("ENDEVOR_SSL_KEYFILE", "").strip() or None
    reject_unauth = os.environ.get("ENDEVOR_REJECT_UNAUTHORIZED", "").strip().lower()
    reject_unauthorized = reject_unauth not in ("false", "0", "no")

    use_ssl = port == 443 or os.environ.get("ENDEVOR_USE_SSL", "true").strip().lower() not in ("false", "0", "no")

    print(
        f"[Endevor-MCP] Auto-connect config:\n"
        f"  host={host} port={port} datasource={datasource}\n"
        f"  username={'(set)' if username else '(NOT SET)'}\n"
        f"  password={'(set, len=' + str(len(password)) + ')' if password else '(NOT SET)'}\n"
        f"  bearer_token={'(set)' if bearer_token else '(not set)'}\n"
        f"  use_ssl={use_ssl} ssl_no_verify={ssl_no_verify}",
        file=sys.stderr,
    )

    try:
        conn_id, conn = conn_mgr.create(
            host=host, port=port, datasource=datasource, name="auto",
            use_ssl=use_ssl, username=username, password=password,
            bearer_token=bearer_token, base_path=base_path,
            ssl_cafile=ssl_cafile, ssl_certfile=ssl_certfile,
            ssl_keyfile=ssl_keyfile, ssl_no_verify=ssl_no_verify,
            reject_unauthorized=reject_unauthorized,
        )
        result = conn.connect()
        print(
            f"[Endevor-MCP] Auto-connected to {host}:{port} "
            f"(conn_id='auto', datasource='{datasource}')",
            file=sys.stderr,
        )

        if username and password and datasource:
            auth_result = conn.authenticate()
            print(
                f"[Endevor-MCP] authenticate() returned: {auth_result}",
                file=sys.stderr,
            )
            if auth_result.get("status") == "authenticated":
                print(
                    "[Endevor-MCP] JWT token obtained — Bearer auth active",
                    file=sys.stderr,
                )
            else:
                print(
                    f"[Endevor-MCP] JWT auth attempted but: {auth_result.get('status', 'unknown')} "
                    f"— falling back to Basic Auth",
                    file=sys.stderr,
                )
        else:
            print(
                f"[Endevor-MCP] Skipping JWT auth: "
                f"username={'yes' if username else 'NO'} "
                f"password={'yes' if password else 'NO'} "
                f"datasource={'yes' if datasource else 'NO'}",
                file=sys.stderr,
            )
    except Exception as e:
        import traceback
        print(f"[Endevor-MCP] Auto-connect failed: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)


# =====================================================================
# Helpers
# =====================================================================

def _get_conn(conn_id: str) -> EndevorConnection:
    """Get a connected connection or raise helpful error."""
    conn = conn_mgr.get(conn_id)
    if not conn.connected:
        raise ConnectionError(
            f"Connection '{conn_id}' exists but is not connected. "
            f"Call endevor_connect again."
        )
    return conn


def _fmt_json(obj, indent=2) -> str:
    return json.dumps(obj, indent=indent, default=str)


def _parse_response(resp, label: str = "Result") -> str:
    """Parse an Endevor API response into readable output."""
    lines = [f"{label}:  (HTTP {resp.status_code})\n"]

    ct = resp.headers.get("content-type", "")
    if "application/json" in ct:
        try:
            data = resp.json()
            if isinstance(data, dict):
                if data.get("returnCode") is not None:
                    lines.append(f"  Return Code  : {data['returnCode']}")
                if data.get("reasonCode") is not None:
                    lines.append(f"  Reason Code  : {data['reasonCode']}")
                if data.get("reports"):
                    for rpt_name, rpt_url in data["reports"].items():
                        lines.append(f"  Report       : {rpt_name} -> {rpt_url}")
                msgs = data.get("messages") or data.get("data", {}).get("messages") if isinstance(data.get("data"), dict) else None
                if msgs and isinstance(msgs, list):
                    lines.append(f"\n  Messages ({len(msgs)}):")
                    for m in msgs[:50]:
                        lines.append(f"    {m}")
                if data.get("data") is not None:
                    d = data["data"]
                    if isinstance(d, list):
                        lines.append(f"\n  Results ({len(d)} items):")
                        for item in d[:100]:
                            if isinstance(item, dict):
                                parts = [f"{k}={v}" for k, v in item.items() if k != "messages"]
                                lines.append(f"    {', '.join(parts[:10])}")
                            else:
                                lines.append(f"    {item}")
                        if len(d) > 100:
                            lines.append(f"    ... and {len(d) - 100} more")
                    elif isinstance(d, dict) and d:
                        for k, v in list(d.items())[:30]:
                            if isinstance(v, (str, int, float, bool)):
                                lines.append(f"  {k}: {v}")
                            elif isinstance(v, list) and len(v) <= 5:
                                lines.append(f"  {k}: {v}")
                            elif isinstance(v, list):
                                lines.append(f"  {k}: [{len(v)} items]")
                            else:
                                lines.append(f"  {k}: {str(v)[:200]}")
                elif not data.get("returnCode") and not data.get("messages"):
                    lines.append(f"\n  {_fmt_json(data)[:2000]}")
            elif isinstance(data, list):
                lines.append(f"\n  Results ({len(data)} items):")
                for item in data[:100]:
                    if isinstance(item, dict):
                        parts = [f"{k}={v}" for k, v in item.items()]
                        lines.append(f"    {', '.join(parts[:10])}")
                    else:
                        lines.append(f"    {item}")
            else:
                lines.append(f"  {data}")
        except (json.JSONDecodeError, ValueError):
            lines.append(f"  {resp.text[:2000]}")
    elif "text/plain" in ct or "application/octet-stream" in ct:
        text = resp.text[:5000] if resp.text else "(empty body)"
        lines.append(f"\n{text}")
    else:
        lines.append(f"  Content-Type: {ct}")
        lines.append(f"  Body: {resp.text[:2000]}")

    return "\n".join(lines)


def _element_path(environment: str, stage: str, system: str,
                  subsystem: str, type_name: str, element: str) -> str:
    """Build the element URL path segment."""
    return (
        f"/env/{environment}/stgnum/{stage}/sys/{system}"
        f"/subsys/{subsystem}/type/{type_name}/ele/{element}"
    )


def _build_query_params(**kwargs) -> dict:
    """Build query params dict, omitting empty/None values."""
    return {k: v for k, v in kwargs.items() if v not in (None, "", False)}


# =====================================================================
# CONNECTION MANAGEMENT
# =====================================================================

@mcp.tool()
def endevor_connect(
    host: str,
    port: int = 443,
    datasource: str = "",
    name: str = "",
    use_ssl: bool = True,
    username: str = "",
    password: str = "",
    bearer_token: str = "",
    base_path: str = "/EndevorService/api/v2",
    ssl_cafile: str = "",
    ssl_certfile: str = "",
    ssl_keyfile: str = "",
    ssl_no_verify: bool = False,
    reject_unauthorized: bool = True,
    timeout: float = 60.0,
) -> str:
    """Connect to an Endevor REST API instance.

    Establishes a persistent HTTP session to the Endevor web services
    endpoint. The connection persists across tool calls until
    endevor_disconnect is called.

    Authentication Methods:
        - Basic Auth: Provide username and password
        - Bearer Token: Provide a pre-obtained JWT token
        - None: Connect without auth (limited operations)

    After connecting, use endevor_authenticate to obtain a JWT token
    from the /auth endpoint if needed.

    Args:
        host: Endevor web services hostname or IP
        port: Port number (default: 443 for HTTPS)
        datasource: Default Endevor datasource/configuration name
        name: Optional connection name (auto-generated if empty)
        use_ssl: Use HTTPS (default: true)
        username: Username for Basic Auth
        password: Password for Basic Auth
        bearer_token: Pre-obtained JWT bearer token
        base_path: REST API base path (default: /EndevorService/api/v2)
        ssl_cafile: Path to CA certificate file for server verification
        ssl_certfile: Path to client certificate for mutual TLS
        ssl_keyfile: Path to client private key for mTLS
        ssl_no_verify: Skip SSL certificate verification
        reject_unauthorized: Reject unauthorized SSL certificates (default: true)
        timeout: Default request timeout in seconds
    """
    conn_id, conn = conn_mgr.create(
        host=host, port=port, datasource=datasource, name=name,
        use_ssl=use_ssl,
        username=username or None, password=password or None,
        bearer_token=bearer_token or None,
        base_path=base_path,
        ssl_cafile=ssl_cafile or None,
        ssl_certfile=ssl_certfile or None,
        ssl_keyfile=ssl_keyfile or None,
        ssl_no_verify=ssl_no_verify,
        reject_unauthorized=reject_unauthorized,
        timeout=timeout,
    )
    try:
        result = conn.connect()
        lines = [
            f"Connected to Endevor REST API.\n",
            f"  Connection ID : {conn_id}",
            f"  Base URL      : {result.get('base_url', '')}",
            f"  Protocol      : {result.get('protocol', '')}",
            f"  Authenticated : {result.get('authenticated', False)}",
        ]
        if result.get("datasource"):
            lines.append(f"  Datasource    : {result['datasource']}")
        if result.get("auth_method"):
            lines.append(f"  Auth method   : {result['auth_method']}")
        if result.get("username"):
            lines.append(f"  Username      : {result['username']}")
        if result.get("client_cert"):
            lines.append(f"  Client cert   : {result['client_cert']}")
        if result.get("connectivity"):
            lines.append(f"  Connectivity  : {result['connectivity']}")
        if result.get("datasources_found"):
            lines.append(f"  Datasources   : {result['datasources_found']} found")
        if not result.get("authenticated"):
            lines.append(
                "\n  WARNING: No credentials provided. You must call "
                "endevor_authenticate with username and password before "
                "any authenticated operations will work."
            )
        lines.append(f"\nUse connection ID '{conn_id}' for subsequent operations.")
        if result.get("authenticated") and result.get("auth_method") == "basic":
            lines.append(
                f"Call endevor_authenticate(conn_id='{conn_id}') to obtain "
                f"a JWT token for Bearer auth."
            )
        return "\n".join(lines)
    except Exception as e:
        conn_mgr.remove(conn_id)
        return f"Connection failed: {e}"


@mcp.tool()
def endevor_disconnect(conn_id: str) -> str:
    """Disconnect from an Endevor REST API instance.

    Args:
        conn_id: Connection ID from endevor_connect
    """
    result = conn_mgr.remove(conn_id)
    return (
        f"Disconnected.\n"
        f"  Requests sent : {result.get('requests_sent', 0)}\n"
        f"  Uptime        : {result.get('uptime_seconds', 0)}s"
    )


@mcp.tool()
def endevor_connections() -> str:
    """List all active Endevor connections with status."""
    conns = conn_mgr.list_all()
    if not conns:
        return "No active connections. Use endevor_connect to establish one."
    lines = ["Active Endevor Connections:\n"]
    for c in conns:
        if c["authenticated"]:
            method = c.get("auth_method", "unknown")
            auth = f"authenticated via {method}"
        else:
            auth = "NOT authenticated"
        lines.append(
            f"  {c['conn_id']}: {c['base_url']} [{c['protocol']}]\n"
            f"    Status       : {auth}\n"
            f"    Datasource   : {c.get('datasource', '(none)')}\n"
            f"    Requests sent: {c['requests_sent']}\n"
            f"    Uptime       : {c['uptime_seconds']}s"
        )
        if c.get("username"):
            lines.append(f"    Username     : {c['username']}")
    return "\n".join(lines)


# =====================================================================
# AUTHENTICATION & HEALTH
# =====================================================================

@mcp.tool()
def endevor_authenticate(
    conn_id: str,
    username: str = "",
    password: str = "",
) -> str:
    """Obtain a JWT authentication token from Endevor.

    Calls the /{datasource}/auth endpoint to get a JWT token.
    Credentials can be provided here if they were not set at connect time.
    The token is automatically applied to all subsequent requests.

    Args:
        conn_id: Connection ID from endevor_connect
        username: Username for Basic Auth (overrides connect-time value)
        password: Password for Basic Auth (overrides connect-time value)
    """
    conn = _get_conn(conn_id)
    result = conn.authenticate(
        username=username or None,
        password=password or None,
    )
    if result.get("status") == "authenticated":
        return (
            "Authentication successful.\n"
            "  Method : Bearer Token (JWT)\n"
            "  Status : AUTHENTICATED — token is applied to all subsequent requests\n"
            f"  Conn ID: {conn_id}"
        )
    elif result.get("status") == "unauthorized":
        return "Authentication failed: Invalid credentials (HTTP 401)."
    else:
        return f"Authentication result: {_fmt_json(result)}"


@mcp.tool()
def endevor_healthcheck(conn_id: str) -> str:
    """Run a health check on an Endevor datasource.

    Validates that the datasource configuration is correct and the
    Endevor instance is reachable.

    Args:
        conn_id: Connection ID from endevor_connect
    """
    conn = _get_conn(conn_id)
    resp = conn.get("/check")
    return _parse_response(resp, "Health Check")


@mcp.tool()
def endevor_get_report(conn_id: str, report_name: str) -> str:
    """Get a report from a previous Endevor request.

    Reports are generated by various Endevor actions and can be
    retrieved using the report file name.

    Args:
        conn_id: Connection ID from endevor_connect
        report_name: Report file name (from action response)
    """
    conn = _get_conn(conn_id)
    resp = conn.get(f"/reports/{report_name}", accept="text/plain")
    return _parse_response(resp, f"Report: {report_name}")


@mcp.tool()
def endevor_list_tasks(
    conn_id: str,
    status: str = "",
) -> str:
    """List asynchronous tasks submitted by the current user.

    Returns all finished or running async tasks. Tasks are created
    when requests use the X-Broadcom-Asynchronous header.

    Args:
        conn_id: Connection ID from endevor_connect
        status: Filter by task status: INP (in-progress), FIN (finished)
    """
    conn = _get_conn(conn_id)
    params = _build_query_params(status=status)
    resp = conn.get("/tasks", params=params)
    return _parse_response(resp, "Async Tasks")


@mcp.tool()
def endevor_get_task_status(
    conn_id: str,
    task_id: str,
) -> str:
    """Get the status of an asynchronous task.

    Args:
        conn_id: Connection ID from endevor_connect
        task_id: Task ID returned from an async request
    """
    conn = _get_conn(conn_id)
    resp = conn.get(f"/tasks/{task_id}")
    return _parse_response(resp, f"Task Status: {task_id}")


@mcp.tool()
def endevor_get_task_result(
    conn_id: str,
    task_id: str,
) -> str:
    """Get the result of a finished asynchronous task.

    Returns the result if the task is finished, or the current
    status if still in progress.

    Args:
        conn_id: Connection ID from endevor_connect
        task_id: Task ID returned from an async request
    """
    conn = _get_conn(conn_id)
    resp = conn.get(f"/tasks/{task_id}/result")
    return _parse_response(resp, f"Task Result: {task_id}")


# =====================================================================
# INVENTORY / LIST TOOLS
# =====================================================================

@mcp.tool()
def endevor_list_datasources(conn_id: str) -> str:
    """List all available Endevor datasource configurations.

    Returns the configuration details of all datasources defined
    on the Endevor web services server.

    Args:
        conn_id: Connection ID from endevor_connect
    """
    conn = _get_conn(conn_id)
    resp = conn._do_request("GET", "/")
    return _parse_response(resp, "Datasource Configurations")


@mcp.tool()
def endevor_list_environments(
    conn_id: str,
    environment: str = "*",
    path: str = "",
    search: str = "",
    return_opt: str = "",
) -> str:
    """List Endevor environments.

    Args:
        conn_id: Connection ID from endevor_connect
        environment: Environment name filter (wildcard * supported, default: all)
        path: Mapping path option (LOG or PHY)
        search: Search up the map (yes/no)
        return_opt: Return option (FIR=first found, ALL=return all)
    """
    conn = _get_conn(conn_id)
    params = _build_query_params(path=path, search=search, **{"return": return_opt})
    resp = conn.get(f"/env/{environment}", params=params)
    return _parse_response(resp, "Environments")


@mcp.tool()
def endevor_list_stages(
    conn_id: str,
    environment: str = "*",
    stage: str = "*",
    path: str = "",
    search: str = "",
    return_opt: str = "",
) -> str:
    """List Endevor stage numbers.

    Args:
        conn_id: Connection ID from endevor_connect
        environment: Environment name (wildcard supported)
        stage: Stage number filter (wildcard supported, default: all)
        path: Mapping path option (LOG or PHY)
        search: Search up the map (yes/no)
        return_opt: Return option (FIR/ALL)
    """
    conn = _get_conn(conn_id)
    params = _build_query_params(path=path, search=search, **{"return": return_opt})
    resp = conn.get(f"/env/{environment}/stgnum/{stage}", params=params)
    return _parse_response(resp, "Stages")


@mcp.tool()
def endevor_list_systems(
    conn_id: str,
    environment: str = "*",
    stage: str = "*",
    system: str = "*",
    path: str = "",
    search: str = "",
    return_opt: str = "",
) -> str:
    """List Endevor systems.

    Args:
        conn_id: Connection ID from endevor_connect
        environment: Environment name (wildcard supported)
        stage: Stage number (wildcard supported)
        system: System name filter (wildcard supported, default: all)
        path: Mapping path option (LOG or PHY)
        search: Search up the map (yes/no)
        return_opt: Return option (FIR/ALL)
    """
    conn = _get_conn(conn_id)
    params = _build_query_params(path=path, search=search, **{"return": return_opt})
    resp = conn.get(f"/env/{environment}/stgnum/{stage}/sys/{system}", params=params)
    return _parse_response(resp, "Systems")


@mcp.tool()
def endevor_list_subsystems(
    conn_id: str,
    environment: str = "*",
    stage: str = "*",
    system: str = "*",
    subsystem: str = "*",
    path: str = "",
    search: str = "",
    return_opt: str = "",
) -> str:
    """List Endevor subsystems.

    Args:
        conn_id: Connection ID from endevor_connect
        environment: Environment name (wildcard supported)
        stage: Stage number (wildcard supported)
        system: System name (wildcard supported)
        subsystem: Subsystem name filter (wildcard supported, default: all)
        path: Mapping path option (LOG or PHY)
        search: Search up the map (yes/no)
        return_opt: Return option (FIR/ALL)
    """
    conn = _get_conn(conn_id)
    params = _build_query_params(path=path, search=search, **{"return": return_opt})
    resp = conn.get(f"/env/{environment}/stgnum/{stage}/sys/{system}/subsys/{subsystem}", params=params)
    return _parse_response(resp, "Subsystems")


@mcp.tool()
def endevor_list_types(
    conn_id: str,
    environment: str = "*",
    stage: str = "*",
    system: str = "*",
    type_name: str = "*",
    path: str = "",
    search: str = "",
    return_opt: str = "",
) -> str:
    """List Endevor element types.

    Args:
        conn_id: Connection ID from endevor_connect
        environment: Environment name (wildcard supported)
        stage: Stage number (wildcard supported)
        system: System name (wildcard supported)
        type_name: Type name filter (wildcard supported, default: all)
        path: Mapping path option (LOG or PHY)
        search: Search up the map (yes/no)
        return_opt: Return option (FIR/ALL)
    """
    conn = _get_conn(conn_id)
    params = _build_query_params(path=path, search=search, **{"return": return_opt})
    resp = conn.get(f"/env/{environment}/stgnum/{stage}/sys/{system}/type/{type_name}", params=params)
    return _parse_response(resp, "Types")


@mcp.tool()
def endevor_list_elements(
    conn_id: str,
    environment: str = "*",
    stage: str = "*",
    system: str = "*",
    subsystem: str = "*",
    type_name: str = "*",
    element: str = "*",
    path: str = "",
    search: str = "",
    return_opt: str = "",
    where_ccid_current: str = "",
    where_ccid_all: str = "",
    where_ccid_retrieve: str = "",
    where_proc_group: str = "",
    limit: int = 0,
) -> str:
    """List Endevor elements.

    Browse the Endevor inventory to find elements matching your criteria.
    Supports wildcards in all path segments.

    Args:
        conn_id: Connection ID from endevor_connect
        environment: Environment name (wildcard supported)
        stage: Stage number (wildcard supported)
        system: System name (wildcard supported)
        subsystem: Subsystem name (wildcard supported)
        type_name: Element type (wildcard supported)
        element: Element name filter (wildcard supported, default: all)
        path: Mapping path option (LOG or PHY)
        search: Search up the map (yes/no)
        return_opt: Return option (FIR/ALL)
        where_ccid_current: Filter by CCID in MCF (comma-separated)
        where_ccid_all: Filter by CCID in MCF and deltas (comma-separated)
        where_ccid_retrieve: Filter by retrieve CCID
        where_proc_group: Filter by processor group (comma-separated)
        limit: Max number of elements to return (0 = no limit)
    """
    conn = _get_conn(conn_id)
    params = _build_query_params(
        path=path, search=search,
        whereCcidCurrent=where_ccid_current,
        whereCcidAll=where_ccid_all,
        whereCcidRetrieve=where_ccid_retrieve,
        whereProcGroup=where_proc_group,
        **{"return": return_opt},
    )
    if limit > 0:
        params["limit"] = limit
    resp = conn.get(
        f"/env/{environment}/stgnum/{stage}/sys/{system}/subsys/{subsystem}"
        f"/type/{type_name}/ele/{element}",
        params=params,
    )
    return _parse_response(resp, "Elements")


@mcp.tool()
def endevor_list_members(
    conn_id: str,
    environment: str,
    stage: str,
    system: str,
    subsystem: str,
    type_name: str,
    member: str = "*",
) -> str:
    """List members for an Endevor element type.

    Args:
        conn_id: Connection ID from endevor_connect
        environment: Environment name
        stage: Stage number
        system: System name
        subsystem: Subsystem name
        type_name: Element type name
        member: Member name filter (wildcard supported)
    """
    conn = _get_conn(conn_id)
    resp = conn.get(
        f"/env/{environment}/stgnum/{stage}/sys/{system}/subsys/{subsystem}"
        f"/type/{type_name}/mem/{member}",
    )
    return _parse_response(resp, "Members")


# =====================================================================
# ELEMENT READ TOOLS
# =====================================================================

@mcp.tool()
def endevor_retrieve_element(
    conn_id: str,
    environment: str,
    stage: str,
    system: str,
    subsystem: str,
    type_name: str,
    element: str,
    version: str = "",
    level: str = "",
    search: str = "",
    expand_includes: str = "",
    source_charset: str = "",
    accept_charset: str = "",
) -> str:
    """Retrieve (download) an element's source from Endevor.

    Returns the element's source content in the response body.

    Args:
        conn_id: Connection ID from endevor_connect
        environment: Environment name
        stage: Stage number
        system: System name
        subsystem: Subsystem name
        type_name: Element type name
        element: Element name to retrieve
        version: Version number (1-99, use with level)
        level: Level number (00-99, use with version)
        search: Search up the map (yes/no)
        expand_includes: Expand INCLUDE statements (yes/no)
        source_charset: EBCDIC charset for translation
        accept_charset: Desired response character set
    """
    conn = _get_conn(conn_id)
    path = _element_path(environment, stage, system, subsystem, type_name, element)
    params = _build_query_params(
        version=version, level=level, search=search,
        expandIncludes=expand_includes,
    )
    headers = {}
    if source_charset:
        headers["X-Broadcom-Source-Charset"] = source_charset
    if accept_charset:
        headers["Accept-Charset"] = accept_charset

    resp = conn.get(path, params=params, accept="application/octet-stream",
                    headers=headers if headers else None)

    if resp.status_code == 200:
        ct = resp.headers.get("content-type", "")
        if "application/octet-stream" in ct or "text/plain" in ct:
            try:
                text = resp.content.decode("utf-8", errors="replace")
            except Exception:
                text = resp.text
            lines = [
                f"Retrieved Element: {element}  (HTTP {resp.status_code})\n",
                f"  Size: {len(resp.content)} bytes",
                f"\n--- Source Content ---\n",
                text[:50000],
            ]
            if len(resp.content) > 50000:
                lines.append(f"\n... truncated ({len(resp.content)} total bytes)")
            return "\n".join(lines)
        else:
            return _parse_response(resp, f"Retrieve Element: {element}")
    else:
        return _parse_response(resp, f"Retrieve Element: {element}")


@mcp.tool()
def endevor_print_element(
    conn_id: str,
    environment: str,
    stage: str,
    system: str,
    subsystem: str,
    type_name: str,
    element: str,
    print_option: str = "browse",
    version: str = "",
    level: str = "",
    search: str = "",
    headings: str = "",
    explode: str = "",
    expand_includes: str = "",
    where_ccid_current: str = "",
    where_ccid_all: str = "",
    where_proc_group: str = "",
) -> str:
    """Print element information (browse, changes, history, summary, master, listing).

    Retrieves formatted information about an element's content, change
    history, or master control file data.

    Args:
        conn_id: Connection ID from endevor_connect
        environment: Environment name
        stage: Stage number
        system: System name
        subsystem: Subsystem name
        type_name: Element type name
        element: Element name
        print_option: Print type: browse, changes, history, summary, master, listing
        version: Version number (1-99, use with level)
        level: Level number (00-99, use with version)
        search: Search up the map (yes/no)
        headings: Include page headings (yes/no)
        explode: Print input component info (yes/no)
        expand_includes: Expand INCLUDE statements (yes/no, browse only)
        where_ccid_current: Filter by CCID in MCF
        where_ccid_all: Filter by CCID in MCF and deltas
        where_proc_group: Filter by processor group
    """
    conn = _get_conn(conn_id)
    path = _element_path(environment, stage, system, subsystem, type_name, element)
    params = _build_query_params(
        print=print_option, version=version, level=level,
        search=search, headings=headings, explode=explode,
        expandIncludes=expand_includes,
        whereCcidCurrent=where_ccid_current,
        whereCcidAll=where_ccid_all,
        whereProcGroup=where_proc_group,
    )
    resp = conn.get(path, params=params, accept="text/plain")
    return _parse_response(resp, f"Print Element ({print_option}): {element}")


@mcp.tool()
def endevor_print_element_components(
    conn_id: str,
    environment: str,
    stage: str,
    system: str,
    subsystem: str,
    type_name: str,
    element: str,
    print_option: str = "browse",
    version: str = "",
    level: str = "",
    search: str = "",
    headings: str = "",
    explode: str = "",
    where_ccid_current: str = "",
    where_ccid_all: str = "",
    where_proc_group: str = "",
) -> str:
    """Print element component information (requires Endevor ACM option).

    Prints input/output component information extracted from ACMQ files.
    Supports browse, changes, history, and summary views.

    Args:
        conn_id: Connection ID from endevor_connect
        environment: Environment name
        stage: Stage number
        system: System name
        subsystem: Subsystem name
        type_name: Element type name
        element: Element name
        print_option: Print type: browse, changes, history, summary
        version: Version number (1-99, use with level)
        level: Level number (00-99, use with version)
        search: Search up the map (yes/no)
        headings: Include page headings (yes/no)
        explode: Print input component info (yes/no)
        where_ccid_current: Filter by CCID in MCF
        where_ccid_all: Filter by CCID in MCF and deltas
        where_proc_group: Filter by processor group
    """
    conn = _get_conn(conn_id)
    path = _element_path(environment, stage, system, subsystem, type_name, element)
    path += "/components"
    params = _build_query_params(
        print=print_option, version=version, level=level,
        search=search, headings=headings, explode=explode,
        whereCcidCurrent=where_ccid_current,
        whereCcidAll=where_ccid_all,
        whereProcGroup=where_proc_group,
    )
    resp = conn.get(path, params=params, accept="text/plain")
    return _parse_response(resp, f"Print Element Components ({print_option}): {element}")


# =====================================================================
# PACKAGE READ TOOLS
# =====================================================================

@mcp.tool()
def endevor_list_packages(
    conn_id: str,
    package: str = "*",
    status: str = "",
    pkg_type: str = "",
    enterprise: str = "",
    promotion: str = "",
    target_env: str = "",
    target_stg: str = "",
    approver: str = "",
    detail: str = "",
    limit: int = 0,
) -> str:
    """List Endevor packages.

    Lists packages with optional filtering by status, type, and other
    criteria. Use the detail parameter to get SCL, actions, ship data,
    or approver information for a specific package.

    Args:
        conn_id: Connection ID from endevor_connect
        package: Package name filter (wildcard supported, default: all)
        status: Filter by status (comma-separated): INEDIT, INAPPROVAL,
                APPROVED, INEXECUTION, EXECUTED, COMMITTED, DENIED, EXECFAILED
        pkg_type: Package type: S=Standard, E=Emergency
        enterprise: Enterprise filter: A=All, E=Enterprise, X=Exclude
        promotion: Promotion filter: A=All, P=Promotion, X=Exclude
        target_env: Target environment (promotion packages only)
        target_stg: Target stage (promotion packages only)
        approver: Filter by approver ID
        detail: Detail view for specific package: SCL, Action, Ship, Approver
        limit: Max number of packages to return (0 = no limit)
    """
    conn = _get_conn(conn_id)
    params = _build_query_params(
        status=status, type=pkg_type, enterprise=enterprise,
        promotion=promotion, targetenv=target_env,
        targetstg=target_stg, approver=approver,
    )
    if limit > 0:
        params["limit"] = limit

    base = "/packages"
    if package and package != "*":
        base += f"/{package}"
        if detail:
            base += f"/{detail}"
    resp = conn.get(base, params=params)
    return _parse_response(resp, "Packages")


# =====================================================================
# FINGERPRINT
# =====================================================================

@mcp.tool()
def endevor_validate_fingerprint(
    conn_id: str,
    fingerprints: str,
) -> str:
    """Validate element fingerprints in Endevor.

    Compares element fingerprints to detect concurrent modifications.
    Useful for optimistic concurrency control.

    Args:
        conn_id: Connection ID from endevor_connect
        fingerprints: JSON array of fingerprint objects, each containing:
            elmName, envName, stgNum, sysName, sbsName, typeName, fingerprint
            Example: [{"elmName":"ELEM1","envName":"DEV","stgNum":"1",
            "sysName":"SYS","sbsName":"SUB","typeName":"COBOL",
            "fingerprint":"0123456789ABCDEF"}]
    """
    conn = _get_conn(conn_id)
    try:
        fp_list = json.loads(fingerprints)
    except json.JSONDecodeError as e:
        return f"Invalid JSON for fingerprints: {e}"

    body = {
        "action": "validate",
        "fingerprints": fp_list,
    }
    resp = conn.put("/fingerprints", json_body=body)
    return _parse_response(resp, "Validate Fingerprints")


# =====================================================================
# Entry Point
# =====================================================================

def main():
    _auto_connect()
    mcp.run()


if __name__ == "__main__":
    main()
