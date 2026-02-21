# Mainframe Application Security Assessment

Endevor-MCP transforms mainframe penetration testing from black-box TN3270 interaction into white-box source-informed analysis. This covers the full field of mainframe application security — applicable to banking, insurance, government, healthcare, retail, telecommunications, and any z/OS environment running CICS, IMS, or batch applications.

## Architecture: Endevor-MCP + hack3270

When both tools are available, they form a complete mainframe application testing platform:

```
[AI Agent]
    ├── hack3270 MCP (52 tools) ──TCP:31337──> [hack3270 Proxy] ──TN3270──> [Mainframe CICS/IMS]
    │   Screen reading, field manipulation, fuzzing, brute force, AID scanning
    │
    └── Endevor-MCP (22 read-only tools) ──HTTPS──> [Endevor REST API] ──> [Source Repository]
        COBOL, BMS, copybooks, JCL, ASM, PL/I — change history, dependencies
```

hack3270 operates the live application; Endevor-MCP reads the source code behind it. Every finding from hack3270 can be source-confirmed, and every source code vulnerability can be live-tested through hack3270.

## Phase 1: Reconnaissance — Map the Application Landscape

```
endevor_list_environments(conn_id="conn-1")
endevor_list_systems(conn_id="conn-1", environment="PROD", stage="1")
endevor_list_subsystems(conn_id="conn-1", environment="PROD", stage="1", system="*")
endevor_list_types(conn_id="conn-1", environment="PROD", stage="1", system="*")
endevor_list_elements(conn_id="conn-1", environment="PROD", stage="1",
    system="*", subsystem="*", type_name="COBOL")
endevor_list_elements(conn_id="conn-1", environment="PROD", stage="1",
    system="*", subsystem="*", type_name="BMS")
endevor_list_elements(conn_id="conn-1", environment="PROD", stage="1",
    system="*", subsystem="*", type_name="JCL")
```

Build a map: system -> subsystem -> programs -> BMS maps -> copybooks -> JCL. This reveals the full attack surface before touching the live application.

## Phase 2: BMS Map Analysis — Screen Layout Intelligence

Retrieve BMS mapsets to understand every field on every screen before testing with hack3270.

```
endevor_retrieve_element(conn_id="conn-1", ..., type_name="BMS", element="MENUMAP")
```

**What to look for in BMS source:**

| BMS Pattern | Meaning | Security Relevance |
|-------------|---------|-------------------|
| `ATTRB=(ASKIP,DRK)` | Hidden/dark field | Data hidden from user but present in data stream — hack3270 reveals it |
| `ATTRB=(PROT)` | Protected (read-only) field | Terminal prevents modification but `send_field_data()` bypasses this |
| `ATTRB=(PROT,NUM)` | Protected numeric | Expected numeric input; test with non-numeric to trigger SOC7 |
| `ATTRB=(UNPROT)` | Unprotected input field | Normal input — direct attack target |
| `ATTRB=(UNPROT,NUM)` | Numeric-only input | Terminal enforces numeric; hack3270 bypasses, test with alpha/special chars |
| `INITIAL='value'` | Default field value | Server-set defaults — may be trusted without validation |
| `LENGTH=n` | Field buffer size | Inputs longer than this test buffer assumptions |
| `PICIN='...'` / `PICOUT='...'` | Edit pattern | Reveals expected data format for targeted input |

After BMS analysis, retrieve the COBOL program to check if the server validates field values:

```
endevor_retrieve_element(conn_id="conn-1", ..., type_name="COBOL", element="MENUPGM")
```

Find `EXEC CICS RECEIVE MAP` and trace every field from the symbolic map through the program logic.

## Phase 3: Vulnerability Class — Missing Input Validation

**The most common mainframe application vulnerability.** CICS applications built in the 1980s-2000s were designed with the assumption that the 3270 terminal was a trusted device. Field protection, numeric restrictions, and field lengths were enforced at the terminal — not the server.

**Source code pattern — VULNERABLE:**
```cobol
EXEC CICS RECEIVE MAP('ORDERMAP') MAPSET('ORDERSET') END-EXEC
MOVE ORDQTYI  TO WS-QUANTITY
MOVE ORDPRCEI TO WS-PRICE
COMPUTE WS-TOTAL = WS-QUANTITY * WS-PRICE
EXEC CICS WRITE FILE('ORDERS') FROM(WS-ORDER-REC) ...
```

No validation of ORDQTYI or ORDPRCEI. The program trusts MAP input blindly.

**Source code pattern — SAFER:**
```cobol
EXEC CICS RECEIVE MAP('ORDERMAP') MAPSET('ORDERSET') END-EXEC
IF ORDQTYI IS NOT NUMERIC OR ORDQTYI < 1 OR ORDQTYI > 999
    MOVE 'INVALID QUANTITY' TO ERRMSGO
    EXEC CICS SEND MAP('ORDERMAP') ...
    EXEC CICS RETURN
END-IF
```

**What to check after RECEIVE MAP in every program:**
- Is every field validated before use?
- Are numeric fields checked with `IS NUMERIC` before arithmetic?
- Are length checks performed?
- Are range checks applied to business-critical values (prices, quantities, dates)?
- Are status/flag fields validated against expected values (88-level conditions)?

## Phase 4: Vulnerability Class — SQL Injection (COBOL-DB2)

**Dynamic SQL with string concatenation from MAP input is exploitable.**

```
endevor_retrieve_element(conn_id="conn-1", ..., type_name="COBOL", element="SRCHPGM")
```

**VULNERABLE — dynamic SQL from user input:**
```cobol
STRING 'SELECT * FROM CUSTOMER WHERE NAME LIKE '''
       WS-SEARCH-INPUT '''%'''
       DELIMITED BY SIZE INTO WS-SQL-STMT
EXEC SQL PREPARE DYN-STMT FROM :WS-SQL-STMT END-EXEC
EXEC SQL EXECUTE DYN-STMT END-EXEC
```

**VULNERABLE — EXECUTE IMMEDIATE (highest risk):**
```cobol
EXEC SQL EXECUTE IMMEDIATE :WS-SQL-STMT END-EXEC
```

**SAFE — static SQL with host variables:**
```cobol
EXEC SQL SELECT * FROM CUSTOMER WHERE CUSTID = :WS-CUST-ID END-EXEC
```

**SAFE — parameterized dynamic SQL:**
```cobol
EXEC SQL PREPARE DYN-STMT FROM :WS-SQL-TEMPLATE END-EXEC
EXEC SQL EXECUTE DYN-STMT USING :WS-PARAM1 END-EXEC
```

**Search patterns in retrieved source:**
- `EXEC SQL PREPARE` — dynamic SQL; trace the FROM variable back to input
- `EXEC SQL EXECUTE IMMEDIATE` — direct execution of constructed SQL
- `STRING ... DELIMITED` before `EXEC SQL` — string concatenation building SQL
- `EXEC SQL CALL` — stored procedure calls; are parameters sanitized?

**DB2 authorization review:**
- Check DBRM elements for plan binding — what authority does the plan run under?
- `EXEC SQL` statements with GRANT/REVOKE — who has what access?
- Plan owners retain BIND and EXECUTE even after ownership change — privilege persistence

## Phase 5: Vulnerability Class — Hardcoded Credentials

```
endevor_retrieve_element(conn_id="conn-1", ..., element="DBCONN")
```

**Search patterns in COBOL source:**
- `MOVE 'password' TO WS-PASSWORD` / `MOVE 'SYSADM' TO WS-USERID`
- `EXEC SQL CONNECT ... IDENTIFIED BY ...`
- `CALL 'IKJEFT01'` with inline credentials in SYSIN
- Data items named `*-PASSWORD`, `*-PASSWD`, `*-PWD`, `*-SECRET`, `*-KEY`, `*-TOKEN`, `*-APIKEY`
- `VALUE 'password'` in WORKING-STORAGE definitions

**Search patterns in JCL:**
- `//SYSIN DD *` with `USER` and `PASS` values (FTP)
- `PARM='...'` containing credentials
- `SET PASSWORD=` or `SET USERID=` symbolic parameters
- `EXEC PGM=IKJEFT01,PARM=('...')` with commands containing credentials
- `EXEC PGM=BPXBATCH,PARM='SH ...'` with inline secrets

**Search patterns in REXX/CLIST:**
- `ADDRESS TSO "..."` with hardcoded credentials
- Variables named `password`, `pwd`, `secret` with assigned values

## Phase 6: Vulnerability Class — Missing Authorization

**Critical question: does the program check WHO is making the request before performing the action?**

```
endevor_retrieve_element(conn_id="conn-1", ..., type_name="COBOL", element="XFERPGM")
```

**VULNERABLE — no authorization check:**
```cobol
EXEC CICS RECEIVE MAP('XFERMAP') ...
MOVE XFERAMTI TO WS-AMOUNT
PERFORM TRANSFER-FUNDS
```

**SAFER — RACF/security check present:**
```cobol
EXEC CICS QUERY SECURITY RESTYPE('TRANSEC') RESID('XFER')
    RESIDLENGTH(4) LOGMESSAGE('LOG') END-EXEC
IF EIBRESP NOT = DFHRESP(NORMAL)
    PERFORM UNAUTHORIZED-ACCESS
END-IF
```

**Source patterns indicating authorization:**
- `EXEC CICS QUERY SECURITY` — CICS resource security check
- `EXEC CICS VERIFY PASSWORD` — password verification
- `EXEC CICS SIGNON` — sign-on processing
- `CALL 'IRRSPK00'` / `CALL 'IRRSAF00'` — RACF SAF interface calls
- `CALL 'ICHEINTY'` — RACF authorization check routine
- Checking `EIBTRMID`, `EIBUSRID` against allowed lists

**Source patterns indicating MISSING authorization:**
- `EXEC CICS RECEIVE MAP` followed immediately by data access with no security check
- `EXEC CICS READ FILE(...)` without prior `QUERY SECURITY`
- `EXEC CICS LINK PROGRAM(...)` without checking caller's authority
- Financial transactions (amount fields, account operations) with no RACF calls
- Programs that jump directly from MAP input to `EXEC SQL` or `EXEC CICS WRITE`

## Phase 7: Vulnerability Class — COMMAREA / Channel Data Leakage

COMMAREA is how CICS programs pass data to each other. Misuse leaks data or enables tampering.

```
endevor_retrieve_element(conn_id="conn-1", ..., element="LINKPGM")
```

**VULNERABLE — COMMAREA length mismatch (data leakage):**
```cobol
EXEC CICS LINK PROGRAM('SUBPROG') COMMAREA(WS-SMALL-AREA)
    LENGTH(32000) END-EXEC
```

If `WS-SMALL-AREA` is only 100 bytes but LENGTH says 32000, the called program reads 31900 bytes of adjacent WORKING-STORAGE — potentially including credentials, keys, or other sensitive data.

**VULNERABLE — no EIBCALEN check (blind trust of caller):**
```cobol
PROCEDURE DIVISION USING DFHCOMMAREA.
    MOVE DFHCOMMAREA TO WS-INPUT-REC
    PERFORM PROCESS-REQUEST
```

The called program should verify `EIBCALEN` matches the expected length before processing.

**VULNERABLE — COMMAREA returned with extra data:**
```cobol
EXEC CICS RETURN TRANSID('NEXT') COMMAREA(WS-COMM-AREA)
    LENGTH(WS-COMM-LEN) END-EXEC
```

If `WS-COMM-AREA` contains more data than needed (debug info, internal flags, security tokens), it's passed to the next transaction invocation where it may be visible.

**What to check:**
- Does every called program verify `EIBCALEN`?
- Do COMMAREA sizes match between caller and callee?
- Is sensitive data cleared from COMMAREA before `RETURN`?
- Are channels/containers used for large data? Are they secured?

## Phase 8: Vulnerability Class — Temporary Storage Queue Exposure

TSQ data is accessible to any authorized transaction in the CICS region. If queue names are predictable, any user can read another user's session data.

```
endevor_retrieve_element(conn_id="conn-1", ..., element="SESSMGR")
```

**VULNERABLE — predictable queue names:**
```cobol
STRING 'SESS' EIBTRMID DELIMITED BY SIZE INTO WS-QUEUE-NAME
EXEC CICS WRITEQ TS QUEUE(WS-QUEUE-NAME)
    FROM(WS-SESSION-DATA) LENGTH(WS-DATA-LEN) END-EXEC
```

Queue name is `SESS` + terminal ID — predictable. Another user knowing your terminal ID reads your session.

**VULNERABLE — sensitive data in queues:**
```cobol
MOVE WS-CUSTOMER-SSN  TO WS-SESS-SSN
MOVE WS-ACCOUNT-BAL   TO WS-SESS-BAL
EXEC CICS WRITEQ TS QUEUE('CUSTDATA') FROM(WS-SESS-REC) ...
```

SSN and balance stored in a queue with a fixed name — any transaction can `READQ TS QUEUE('CUSTDATA')`.

**What to check:**
- Are queue names constructed from unpredictable values?
- Is sensitive data encrypted before storage?
- Are queues explicitly deleted after use (`DELETEQ TS`)?
- Can CEBR (queue browser) read application queues?

## Phase 9: Vulnerability Class — Pseudo-Conversational State Tampering

Most CICS applications are pseudo-conversational: they terminate after each screen interaction and restart when the user responds. State is passed via COMMAREA or TSQ.

```
endevor_retrieve_element(conn_id="conn-1", ..., element="MAINPGM")
```

**VULNERABLE — trusted state in COMMAREA:**
```cobol
EXEC CICS RETURN TRANSID('MAIN') COMMAREA(WS-STATE)
    LENGTH(WS-STATE-LEN) END-EXEC
...
EXEC CICS RECEIVE ...
IF WS-STATE-AUTH-LEVEL = 'ADMIN'
    PERFORM ADMIN-FUNCTIONS
END-IF
```

The auth level is stored in COMMAREA and trusted on the next invocation. An attacker modifying the data stream between transactions can change the auth level.

**What to check:**
- Is authorization re-verified on every transaction invocation (not just stored in COMMAREA)?
- Can COMMAREA state be tampered with (it passes through the TN3270 data stream in some configurations)?
- Are session tokens validated server-side or just trusted?

## Phase 10: Vulnerability Class — Transaction Routing / Application Escape

The most dangerous form of protected field tampering. If a protected field contains the current transaction code and the server reads it without validation, replacing it with an unrecognized value can escape to TSO.

```
endevor_retrieve_element(conn_id="conn-1", ..., element="MAINPGM")
```

**VULNERABLE — transaction code used without validation:**
```cobol
EVALUATE WS-TRANS-CODE
    WHEN 'MCMM'  EXEC CICS XCTL PROGRAM('MAINMENU') END-EXEC
    WHEN 'MCAD'  EXEC CICS XCTL PROGRAM('ADDRPGM')  END-EXEC
    WHEN OTHER    CONTINUE
END-EVALUATE
```

`WHEN OTHER` falls through — on KICKS/MVS, unrecognized codes in certain byte ranges escape to TSO (the `READY` prompt). With hack3270: `send_field_data(text="ABCD", field_address=1)`.

**Also look for:**
- Missing `WHEN OTHER` in EVALUATE blocks
- `EXEC CICS RETURN TRANSID(WS-NEXT-TRANS)` where `WS-NEXT-TRANS` comes from user input
- Direct transaction invocation bypassing menu-level access controls

## Phase 11: Vulnerability Class — EVALUATE EIBAID / Hidden Functionality

```
endevor_retrieve_element(conn_id="conn-1", ..., element="MAINPGM")
```

Find the `EVALUATE EIBAID` block and document every handler:

```cobol
EVALUATE EIBAID
    WHEN DFHENTER  PERFORM PROCESS-INPUT
    WHEN DFHPF3    PERFORM EXIT-PROGRAM
    WHEN DFHPF12   PERFORM CANCEL
    WHEN DFHPA1    PERFORM ADMIN-MENU         *hidden admin access
    WHEN DFHPA3    PERFORM DEBUG-DUMP         *hidden debug function
    WHEN DFHPF24   PERFORM MAINT-MODE         *hidden maintenance
    WHEN OTHER     PERFORM INVALID-KEY
END-EVALUATE
```

Every AID handler is an attack surface. Check each handler's code for authorization, especially PA keys (PA1-PA3) and high PF keys (PF13-PF24) — these are commonly used for undocumented admin/debug functions.

## Phase 12: Vulnerability Class — Numeric Data Exceptions (SOC7/S0C7)

Sending non-numeric data to COMP-3 (packed decimal) or numeric fields causes S0C7 abends. These are critical findings — they prove the application doesn't validate input before arithmetic operations.

```
endevor_retrieve_element(conn_id="conn-1", ..., type_name="COPYBOOK", element="CUSTREC")
```

**Target fields from copybooks:**

| PIC Clause | Data Type | Fuzz With |
|-----------|-----------|-----------|
| `PIC 9(n)` | Zoned decimal | Alphabetic chars, special chars |
| `PIC S9(n) COMP-3` | Packed decimal | Invalid packed bytes (xFF, x0F0F) |
| `PIC S9(n) COMP` / `COMP-4` | Binary | Values exceeding range |
| `PIC 9(n)V9(m)` | Decimal with implied point | Non-numeric, extreme values |
| Level 88 conditions | Flag field | Values outside defined 88-level set |

**Source pattern indicating vulnerability:**
```cobol
MOVE AMOUNTI TO WS-AMOUNT     *no IS NUMERIC check
COMPUTE WS-TOTAL = WS-AMOUNT * WS-RATE  *SOC7 if non-numeric
```

## Phase 13: Vulnerability Class — VSAM File Access

CICS programs access VSAM files. Check if file access is authorized and whether key values can be manipulated.

```
endevor_retrieve_element(conn_id="conn-1", ..., element="FILEPGM")
```

**VULNERABLE — user-supplied key to file read:**
```cobol
MOVE CUSTIDI TO WS-KEY
EXEC CICS READ FILE('CUSTFILE') INTO(WS-CUST-REC)
    RIDFLD(WS-KEY) END-EXEC
```

If `CUSTIDI` comes from the MAP with no authorization check, any user can read any customer record by supplying different keys — an IDOR (Insecure Direct Object Reference).

**What to check:**
- Does the program validate that the user is authorized to access the specific record?
- Can BROWSE operations enumerate all records in the file?
- Is file-level security enforced via RACF, or only at the application level?
- Are WRITE/REWRITE/DELETE operations properly authorized?

## Phase 14: Vulnerability Class — CICS ASSIGN Information Disclosure

```
endevor_retrieve_element(conn_id="conn-1", ..., element="UTILPGM")
```

**Information available via EXEC CICS ASSIGN:**
- `USERID` — current user ID
- `APPLID` / `SYSID` — CICS region identifier
- `NETNAME` — network terminal name
- `TERMID` — terminal ID
- `FACILITY` — facility name

If a program displays these values (even in error messages), it reveals system topology useful for further exploitation. Look for:
```cobol
EXEC CICS ASSIGN APPLID(WS-APPLID) SYSID(WS-SYSID) END-EXEC
MOVE WS-APPLID TO ERR-MSG-SYSID
EXEC CICS SEND TEXT FROM(ERR-MSG) ...
```

## Phase 15: Vulnerability Class — Error Handling Information Disclosure

```
endevor_retrieve_element(conn_id="conn-1", ..., element="ERRPGM")
```

**VULNERABLE — detailed error messages:**
```cobol
IF EIBRESP NOT = DFHRESP(NORMAL)
    STRING 'ERROR: RESP=' EIBRESP ' RESP2=' EIBRESP2
           ' FILE=' WS-FILENAME ' KEY=' WS-KEY-VALUE
           DELIMITED BY SIZE INTO WS-ERR-MSG
    EXEC CICS SEND TEXT FROM(WS-ERR-MSG) ...
END-IF
```

RESP/RESP2 codes, file names, and key values revealed to the user. Also check:
- `EXEC CICS HANDLE ABEND` — does the abend handler display system internals?
- `EXEC CICS DUMP` — is transaction dumping enabled?
- Stack traces, CICS region info, or dataset names in error screens

## Phase 16: Vulnerability Class — COBOL REDEFINES Type Confusion

```
endevor_retrieve_element(conn_id="conn-1", ..., type_name="COPYBOOK", element="TRANSREC")
```

REDEFINES allows the same storage to be interpreted as different data types:

```cobol
05 TRANS-AMOUNT    PIC S9(7)V99 COMP-3.
05 TRANS-AMT-TEXT  REDEFINES TRANS-AMOUNT PIC X(5).
```

If `TRANS-AMT-TEXT` is populated from user input and then `TRANS-AMOUNT` is used in arithmetic, the program interprets arbitrary bytes as packed decimal — causing SOC7 or corrupt calculations.

## Phase 17: Vulnerability Class — Batch JCL Security

```
endevor_list_elements(conn_id="conn-1", ..., type_name="JCL")
endevor_retrieve_element(conn_id="conn-1", ..., type_name="JCL", element="NIGHTRUN")
```

**What to check in JCL:**

| JCL Pattern | Security Concern |
|-------------|-----------------|
| `//STEPLIB DD DSN=` | Load library references — APF-authorized? |
| `EXEC PGM=IKJEFT01` | TSO in batch — what commands are executed? |
| `EXEC PGM=BPXBATCH,PARM='SH ...'` | Unix command execution — injection risk? |
| `EXEC PGM=IRXJCL` | REXX in batch — script injection? |
| `//SYSIN DD *` + `USER`/`PASS` | FTP with inline credentials |
| `PARM='...'` | Sensitive parameters visible in JCL |
| `SET PASSWORD=` | Symbolic variables with credentials |
| `USER=` on JOBCARD | Surrogate submission — SURROGAT class check |
| `DSN=SYS1.*` | References to system datasets |
| `DISP=(OLD,DELETE)` | Destructive operations on datasets |

**Post-exploitation value:** If TSO escape is achieved via hack3270, Endevor JCL provides:
- Valid JOBCARD format for the environment
- Dataset naming conventions (HLQ patterns)
- STEPLIB concatenations revealing load libraries
- Which user IDs run batch jobs (targets for SURROGAT abuse)

## Phase 18: Vulnerability Class — Program Flow / Authorization Bypass

```
endevor_retrieve_element(conn_id="conn-1", ..., element="MAINPGM")
```

Trace `EXEC CICS LINK` and `EXEC CICS XCTL` chains:

```cobol
EXEC CICS LINK PROGRAM('AUTHCHK') COMMAREA(WS-AUTH) ...
IF WS-AUTH-RESULT = 'OK'
    EXEC CICS LINK PROGRAM('PROCDATA') COMMAREA(WS-DATA) ...
END-IF
```

**Question:** Can `PROCDATA` be invoked directly via its own transaction, bypassing `AUTHCHK`? Use Endevor to find if `PROCDATA` is defined as a standalone transaction or only called via LINK.

**Component analysis:** Use `endevor_print_element_components(conn_id="conn-1", ..., element="MAINPGM", print_option="browse")` to see all dependencies.

For change intelligence and testing prioritization workflows, see [security-checklist.md](security-checklist.md).
