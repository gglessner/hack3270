---
name: endevor-mcp
description: Read-only interaction with Broadcom Endevor SCM via the Endevor-MCP server. Provides 22 read-only tools for inventory browsing, element retrieval and inspection, package listing, async task management, and fingerprint validation. Use when the user asks about Endevor source code review, mainframe security assessments, or augmenting TN3270/hack3270 penetration testing with source code analysis. This server cannot modify Endevor — no add, update, delete, move, generate, sign-out, package mutations, or SCL submission.
---

# Endevor-MCP: Endevor REST API v2 Integration

## CRITICAL: DO NOT CALL endevor_connect

The connection is **already established and authenticated** when the MCP starts.
You do **NOT** need to connect. You do **NOT** need to authenticate.
Just start calling tools directly. All tools default to the pre-configured connection.

**WRONG — never do this:**
```
endevor_connect(host="...", ...)       # WRONG - do not call this
endevor_authenticate(conn_id="auto")   # WRONG - already authenticated
```

**RIGHT — just start using tools:**
```
endevor_list_environments()
endevor_list_elements(environment="DEV", stage="1", system="SYS", subsystem="SUB", type_name="COBOL")
endevor_retrieve_element(environment="DEV", stage="1", system="SYS", subsystem="SUB", type_name="COBOL", element="MYPROG")
```

The only time you should call `endevor_authenticate()` is if a request fails
with HTTP 401, meaning the JWT token has expired. Then call
`endevor_authenticate()` (no arguments needed) to refresh it.

## Finding Source Code

### 1. Element path provided (fastest — preferred)

The application team typically provides the Endevor element path for the
application under test. If the user gives you an element path (environment,
stage, system, subsystem, type), go directly to listing and retrieving:

```
# List all elements at the provided path:
endevor_list_elements(environment="PROD", stage="1", system="FINANCE",
                      subsystem="ACCTS", type_name="COBOL")

# Retrieve a specific element:
endevor_retrieve_element(environment="PROD", stage="1", system="FINANCE",
                         subsystem="ACCTS", type_name="COBOL", element="PAYCALC")
```

Ask the user for the element path if they haven't provided one. App teams
always know their Endevor location.

### 2. Search by name (when you know a program/transaction name)

Use context from the pen test (transaction names, program names from screens,
error messages) to search directly with wildcards:

```
endevor_list_elements(element="MCGM*")
endevor_list_elements(type_name="COBOL", element="PAY*")
endevor_list_elements(type_name="BMS", element="CSGM*")
```

### 3. Hierarchy walk (last resort — REQUIRES HUMAN APPROVAL)

**You MUST ask the user for permission before walking the Endevor hierarchy.**
Large environments have thousands of systems and tens of thousands of elements.
An unscoped hierarchy walk can produce overwhelming output and waste time.

Before calling `endevor_list_environments()`, `endevor_list_systems()`, or
any broad wildcard list, tell the user what you intend to do and wait for
explicit approval. Example: "I don't have an element path or program name.
Can I browse the Endevor inventory to find the application source code?"

## Step-by-Step Hierarchy Walk (for targeted browsing)

Follow this sequence. Each step's output tells you what values to use in the next step:

```
Step 1: endevor_list_environments()
        → returns environment names like DEV, QA, PROD

Step 2: endevor_list_stages(environment="DEV")
        → returns stage numbers like 1, 2

Step 3: endevor_list_systems(environment="DEV", stage="1")
        → returns system names like FINANCE, HR

Step 4: endevor_list_subsystems(environment="DEV", stage="1", system="FINANCE")
        → returns subsystem names like ACCTS, PAYROLL

Step 5: endevor_list_types(environment="DEV", stage="1", system="FINANCE")
        → returns type names like COBOL, COPYBOOK, JCL, BMS

Step 6: endevor_list_elements(environment="DEV", stage="1", system="FINANCE",
                              subsystem="ACCTS", type_name="COBOL")
        → returns element names like PAYCALC, EMPRPT

Step 7: endevor_retrieve_element(environment="DEV", stage="1", system="FINANCE",
                                 subsystem="ACCTS", type_name="COBOL",
                                 element="PAYCALC")
        → returns the actual source code
```

You can skip steps and use wildcards (`*`) to search broadly:
```
endevor_list_elements(environment="*", stage="*", system="*",
                      subsystem="*", type_name="COBOL", element="PAY*")
```

## Authentication

Authentication is handled automatically via environment variables configured
in `.cursor/mcp.json`. When the MCP starts, it reads `ENDEVOR_HOST`,
`ENDEVOR_USERNAME`, `ENDEVOR_PASSWORD`, and `ENDEVOR_DATASOURCE`, connects,
and obtains a JWT bearer token. All subsequent API calls use the JWT.

| Variable | Required | Description |
|----------|----------|-------------|
| `ENDEVOR_HOST` | Yes | Endevor web services hostname |
| `ENDEVOR_PORT` | No (default: 443) | Port number |
| `ENDEVOR_DATASOURCE` | Yes | Datasource/configuration name |
| `ENDEVOR_USERNAME` | Yes | Username |
| `ENDEVOR_PASSWORD` | Yes | Password |
| `ENDEVOR_BASE_PATH` | No | REST API base path (default: /EndevorService/api/v2) |
| `ENDEVOR_SSL_NO_VERIFY` | No | Skip SSL verification (true/false) |
| `ENDEVOR_USE_SSL` | No | Use HTTPS (default: true) |

## Complete Tool Reference (22 read-only tools)

### Connection Management (3 tools — rarely needed)

| Tool | Purpose |
|------|---------|
| `endevor_connect` | (Advanced) Connect to a SECOND Endevor instance. Do NOT call for normal use. |
| `endevor_disconnect` | Close a connection |
| `endevor_connections` | List active connections and their status |

### Authentication & Health (3 tools)

| Tool | Purpose |
|------|---------|
| `endevor_authenticate` | Refresh JWT token (only if HTTP 401 occurs) |
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
| `endevor_list_environments` | List environments (DEV, QA, PROD, etc.) — **start here** |
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

## When to Use Which Tool

| Task | Tool |
|------|------|
| First-time inventory exploration | `endevor_list_environments` -> `_stages` -> `_systems` -> `_subsystems` -> `_types` -> `_elements` |
| Get element source code | `endevor_retrieve_element` |
| See who changed what | `endevor_print_element` with `print_option="summary"` or `"changes"` |
| See element metadata (dates, signout, processor) | `endevor_print_element` with `print_option="master"` |
| See full source with level annotations | `endevor_print_element` with `print_option="browse"` |
| Find elements by change ticket | `endevor_list_elements` with `where_ccid_all="TICKET"` |
| See element dependencies | `endevor_print_element_components` |
| Track pending changes | `endevor_list_packages` with `status="APPROVED,INAPPROVAL"` |
| See what a package will do | `endevor_list_packages` with `detail="SCL"` |
| Monitor long-running operations | `endevor_list_tasks` -> `endevor_get_task_status` -> `endevor_get_task_result` |

## Print Options

| Value | Description |
|-------|-------------|
| `browse` | Current source with level annotations (default) |
| `changes` | Inserts/deletes at a specific level |
| `history` | All lines ever in the source across all levels |
| `summary` | One-line summary per level (inserts, deletes, dates) |
| `master` | Master Control File data (processor info, dates, signout) |
| `listing` | Output listing from last generate (requires ACM) |

## Package Statuses

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

## Additional Resources

- For mainframe application security assessment, penetration testing, or hack3270 integration, see [mainframe-security.md](mainframe-security.md) — 19 vulnerability classes with COBOL source code patterns, Endevor retrieval commands, and hack3270 exploitation steps
- For the source code review checklist and hack3270 cross-reference table, see [security-checklist.md](security-checklist.md) — 10-category review checklist and 21-row tool cross-reference
