---
name: endevor-mcp
description: Read-only interaction with Broadcom Endevor SCM via the Endevor-MCP server. Provides 22 read-only tools for inventory browsing, element retrieval and inspection, package listing, async task management, and fingerprint validation. Use when the user asks about Endevor source code review, mainframe security assessments, or augmenting TN3270/hack3270 penetration testing with source code analysis. This server cannot modify Endevor — no add, update, delete, move, generate, sign-out, package mutations, or SCL submission.
---

# Endevor-MCP: Endevor REST API v2 Integration

22 read-only MCP tools for Endevor SCM interaction via the REST API v2. Designed for AI-driven source code review and security assessments. This server is intentionally read-only — no write operations are available.

## Quick Start

**If `ENDEVOR_*` env vars are configured in `.cursor/mcp.json`**, connection `auto` is pre-established. Use `conn_id="auto"` immediately — no `endevor_connect` call needed:

```
endevor_list_environments(conn_id="auto")
endevor_list_elements(conn_id="auto", environment="DEV", stage="1",
                      system="FINANCE", subsystem="ACCTS", type_name="COBOL")
endevor_retrieve_element(conn_id="auto", environment="DEV", stage="1",
                         system="FINANCE", subsystem="ACCTS", type_name="COBOL",
                         element="PAYCALC")
```

**Manual connect** (if env vars are not configured, or connecting to a second instance):

```
endevor_connect(host="mainframe.example.com", port=443, datasource="ENDVCONF",
                username="USER01", password="secret")
# Then use conn_id="conn-1"
```

## Authentication

The server supports auto-authentication via environment variables. When `ENDEVOR_HOST`, `ENDEVOR_USERNAME`, `ENDEVOR_PASSWORD`, and `ENDEVOR_DATASOURCE` are set in `.cursor/mcp.json`, the server automatically connects with Basic Auth and calls the `/auth` endpoint to obtain a JWT bearer token. All subsequent API calls use the JWT.

| Method | Configuration |
|--------|-------------|
| Auto (env vars) | Set `ENDEVOR_HOST`, `ENDEVOR_USERNAME`, `ENDEVOR_PASSWORD`, `ENDEVOR_DATASOURCE` in mcp.json `env` |
| Basic Auth | `endevor_connect(username="...", password="...")` |
| Bearer Token | `endevor_connect(bearer_token="...")` (pre-obtained JWT) |
| JWT via API | Connect with Basic Auth, then call `endevor_authenticate` |
| mTLS | `ssl_certfile`, `ssl_keyfile` (or `ENDEVOR_SSL_CERTFILE`, `ENDEVOR_SSL_KEYFILE`) |
| No verify (test) | `ssl_no_verify=True` (or `ENDEVOR_SSL_NO_VERIFY=true`) |
| Custom CA | `ssl_cafile="/path/to/ca.pem"` (or `ENDEVOR_SSL_CAFILE`) |

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `ENDEVOR_HOST` | Yes (for auto) | Endevor web services hostname |
| `ENDEVOR_PORT` | No (default: 443) | Port number |
| `ENDEVOR_DATASOURCE` | Yes (for JWT) | Datasource/configuration name |
| `ENDEVOR_USERNAME` | Yes (for auth) | Basic Auth username |
| `ENDEVOR_PASSWORD` | Yes (for auth) | Basic Auth password |
| `ENDEVOR_BEARER_TOKEN` | No | Pre-obtained JWT (alternative to user/pass) |
| `ENDEVOR_BASE_PATH` | No | REST API base path (default: /EndevorService/api/v2) |
| `ENDEVOR_SSL_NO_VERIFY` | No | Skip SSL verification (true/false) |
| `ENDEVOR_SSL_CAFILE` | No | CA certificate file path |
| `ENDEVOR_SSL_CERTFILE` | No | Client certificate for mTLS |
| `ENDEVOR_SSL_KEYFILE` | No | Client private key for mTLS |
| `ENDEVOR_USE_SSL` | No | Use HTTPS (default: true) |
| `ENDEVOR_REJECT_UNAUTHORIZED` | No | Reject unauthorized certs (default: true) |

## Complete Tool Reference (22 read-only tools)

### Connection Management (3 tools)

| Tool | Purpose |
|------|---------|
| `endevor_connect` | Connect to Endevor REST API with full auth support |
| `endevor_disconnect` | Close connection |
| `endevor_connections` | List active connections |

### Authentication & Health (3 tools)

| Tool | Purpose |
|------|---------|
| `endevor_authenticate` | Get JWT token from /auth endpoint |
| `endevor_healthcheck` | Run datasource health check |
| `endevor_get_report` | Get report from previous request |

### Async Task Management (3 tools)

| Tool | Purpose |
|------|---------|
| `endevor_list_tasks` | List async tasks (in-progress/finished) |
| `endevor_get_task_status` | Get status of an async task by ID |
| `endevor_get_task_result` | Get result of a finished async task |

### Inventory / List Tools (8 tools)

| Tool | Purpose |
|------|---------|
| `endevor_list_datasources` | List all datasource configurations |
| `endevor_list_environments` | List environments (DEV, QA, PROD, etc.) |
| `endevor_list_stages` | List stage numbers within environments |
| `endevor_list_systems` | List systems (application groups) |
| `endevor_list_subsystems` | List subsystems within systems |
| `endevor_list_types` | List element types (COBOL, COPYBOOK, JCL, etc.) |
| `endevor_list_elements` | List elements with wildcard and CCID filtering |
| `endevor_list_members` | List members for an element type |

### Element Read Tools (3 tools)

| Tool | Purpose |
|------|---------|
| `endevor_retrieve_element` | Retrieve (download) element source content |
| `endevor_print_element` | Print element info (browse/changes/history/summary/master/listing) |
| `endevor_print_element_components` | Print element component info (requires ACM) |

### Package Read Tools (1 tool)

| Tool | Purpose |
|------|---------|
| `endevor_list_packages` | List packages with filtering and detail views (SCL/Action/Ship/Approver) |

### Fingerprint (1 tool)

| Tool | Purpose |
|------|---------|
| `endevor_validate_fingerprint` | Validate element fingerprints for concurrency control |

## Endevor Inventory Hierarchy

```
Datasource (configuration — points to an Endevor instance)
└── Environment (DEV, QA, PROD, ...)
    └── Stage Number (1, 2, ...)
        └── System (FINANCE, HR, PAYMENTS, ...)
            ├── Subsystem (ACCTS, PAYROLL, CLAIMS, ...)
            │   └── Element (PAYCALC, EMPRPT, CUSTMNT, ...)
            └── Type (COBOL, COPYBOOK, JCL, ASMPGM, PLI, BMS, ...)
```

All list tools support wildcards (`*`) in path segments. Use `*` to browse broadly, then narrow down.

## Common Element Types

| Type | Description | Security Relevance |
|------|-------------|-------------------|
| `COBOL` | COBOL source programs | Application logic, SQL queries, CICS calls, auth checks |
| `COPYBOOK` / `COPY` | COBOL copybooks (included headers) | Data structures, record layouts, field definitions |
| `JCL` | Job Control Language | Batch jobs, STEPLIB/PROCLIB, dataset references, job scheduling |
| `ASMPGM` / `ASM` | Assembler programs | Low-level system calls, SVC routines, authorized programs |
| `PLI` / `PL1` | PL/I programs | Application logic (less common than COBOL) |
| `BMS` | BMS mapsets (screen definitions) | TN3270 screen layouts, hidden fields, field attributes |
| `CLIST` / `REXX` | TSO command procedures | Automation scripts, may contain credentials |
| `PROC` | JCL procedures | Reusable JCL, compile/link steps, PROCLIB members |
| `LMOD` / `LOAD` | Load modules (compiled output) | Executable binaries |
| `DBRM` | DB2 Database Request Modules | SQL access paths, DB2 plan bindings |
| `SRCCTL` | Source control metadata | Processor definitions, compile options |

Note: Exact type names vary by installation. Use `endevor_list_types` to discover what's configured.

## Parameter Reference

### Common Parameters (All Element Tools)

| Parameter | Description |
|-----------|-------------|
| `conn_id` | Connection ID from `endevor_connect` |
| `environment` | Endevor environment name (DEV, QA, PROD) |
| `stage` | Stage number (1, 2) |
| `system` | System name (application group) |
| `subsystem` | Subsystem name (application subdivision) |
| `type_name` | Element type (COBOL, COPYBOOK, JCL, etc.) |
| `element` | Element name (program name, up to 255 chars in v19+) |

### Search & Filter Parameters

| Parameter | Description |
|-----------|-------------|
| `search` | Search up the Endevor map for elements (yes/no) |
| `path` | Mapping path: LOG (logical) or PHY (physical) |
| `return_opt` | Return option: FIR (first found) or ALL |
| `where_ccid_current` | Filter by CCID in Master Control File |
| `where_ccid_all` | Filter by CCID in MCF and delta levels |
| `where_ccid_retrieve` | Filter by retrieve CCID |
| `where_proc_group` | Filter by processor group |
| `limit` | Max number of results (0 = no limit) |

### Print Options

| Value | Description |
|-------|-------------|
| `browse` | Current source with level annotations (default) |
| `changes` | Inserts/deletes at a specific level |
| `history` | All lines ever in the source across all levels |
| `summary` | One-line summary per level (inserts, deletes, dates) |
| `master` | Master Control File data (processor info, dates, signout) |
| `listing` | Output listing from last generate (requires ACM) |

### Package Statuses

| Status | Description |
|--------|-------------|
| `INEDIT` | Package is being edited, SCL can be modified |
| `INAPPROVAL` | Cast and awaiting approval |
| `APPROVED` | Approved, ready for execution |
| `INEXECUTION` | Currently executing |
| `EXECUTED` | Successfully executed |
| `EXECFAILED` | Execution failed |
| `COMMITTED` | Committed (no backout possible) |
| `DENIED` | Approval was denied |

## Common Workflows

### 1. Browse and Retrieve Source

```
endevor_connect(host="...", datasource="CONF1", username="...", password="...")
endevor_list_environments(conn_id="conn-1")
endevor_list_systems(conn_id="conn-1", environment="DEV", stage="1")
endevor_list_subsystems(conn_id="conn-1", environment="DEV", stage="1", system="FINANCE")
endevor_list_types(conn_id="conn-1", environment="DEV", stage="1", system="FINANCE")
endevor_list_elements(conn_id="conn-1", environment="DEV", stage="1",
                      system="FINANCE", subsystem="ACCTS", type_name="COBOL")
endevor_retrieve_element(conn_id="conn-1", environment="DEV", stage="1",
                         system="FINANCE", subsystem="ACCTS", type_name="COBOL",
                         element="PAYCALC")
```

### 2. View Element Change History

```
endevor_print_element(conn_id="conn-1", environment="DEV", stage="1",
    system="SYS1", subsystem="SUB1", type_name="COBOL", element="MYPROG",
    print_option="history")

endevor_print_element(conn_id="conn-1", environment="DEV", stage="1",
    system="SYS1", subsystem="SUB1", type_name="COBOL", element="MYPROG",
    print_option="summary")
```

### 3. Component Dependency Analysis (requires ACM)

```
endevor_print_element_components(conn_id="conn-1", environment="DEV", stage="1",
    system="SYS1", subsystem="SUB1", type_name="COBOL", element="MYPROG",
    print_option="browse")
```

## When to Use Which Tool

| Task | Tool |
|------|------|
| First-time inventory exploration | `endevor_list_environments` -> `_systems` -> `_subsystems` -> `_types` -> `_elements` |
| Get element source code | `endevor_retrieve_element` |
| See who changed what | `endevor_print_element` with `print_option="summary"` or `"changes"` |
| See element metadata (dates, signout, processor) | `endevor_print_element` with `print_option="master"` |
| See full source with level annotations | `endevor_print_element` with `print_option="browse"` |
| Find elements by change ticket | `endevor_list_elements` with `where_ccid_all="TICKET"` |
| See element dependencies | `endevor_print_element_components` |
| Track pending changes | `endevor_list_packages` with `status="APPROVED,INAPPROVAL"` |
| See what a package will do | `endevor_list_packages` with `detail="SCL"` |
| Monitor long-running operations | `endevor_list_tasks` -> `endevor_get_task_status` -> `endevor_get_task_result` |

## JSON Argument Formats

- `endevor_validate_fingerprint` fingerprints: `[{"elmName":"E","envName":"DEV","stgNum":"1","sysName":"SYS","sbsName":"SUB","typeName":"COBOL","fingerprint":"0123456789ABCDEF"}]`

## Additional Resources

- For mainframe application security assessment, penetration testing, or hack3270 integration, see [mainframe-security.md](mainframe-security.md) — 19 vulnerability classes with COBOL source code patterns, Endevor retrieval commands, and hack3270 exploitation steps
- For the source code review checklist and hack3270 cross-reference table, see [security-checklist.md](security-checklist.md) — 10-category review checklist and 21-row tool cross-reference
