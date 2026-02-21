# Source Code Review Checklist & hack3270 Cross-Reference

After retrieving source from Endevor, systematically search for these patterns. For detailed vulnerability descriptions, COBOL code patterns, and exploitation steps, see [mainframe-security.md](mainframe-security.md).

## Comprehensive Source Code Review Checklist

### 1. Credential Exposure
- `PASSWORD`, `PASSWD`, `PWD`, `SECRET`, `API-KEY`, `TOKEN`, `APIKEY`
- `MOVE '...' TO *-PASSWORD` — hardcoded values
- `EXEC SQL CONNECT ... IDENTIFIED BY ...` — DB2 credentials
- `VALUE 'password'` in WORKING-STORAGE definitions
- FTP/SMTP credentials in JCL SYSIN

### 2. SQL Injection
- `EXEC SQL PREPARE` — trace FROM variable to input source
- `EXEC SQL EXECUTE IMMEDIATE` — direct execution of constructed SQL
- `STRING ... DELIMITED` before `EXEC SQL` — concatenation building SQL
- `EXEC SQL CALL` with unsanitized parameters

### 3. Missing Input Validation
- `EXEC CICS RECEIVE MAP` not followed by field validation
- Missing `IS NUMERIC` checks before arithmetic on MAP fields
- Missing length checks, range checks, or value validation
- No `INSPECT` or validation before data is used in business logic

### 4. Missing Authorization
- Programs with `RECEIVE MAP` but no `QUERY SECURITY` or RACF calls
- `EXEC CICS READ/WRITE FILE` without authorization check
- `EXEC CICS LINK/XCTL` to sensitive programs without security verification
- Financial operations without RACF `IRRSPK00`/`IRRSAF00` calls

### 5. Data Exposure
- `EXEC CICS WRITEQ TS` with sensitive data (TSQ exposure)
- `DISPLAY ... UPON CONSOLE` with sensitive data in batch
- COMMAREA containing more data than needed
- Error handlers exposing RESP/RESP2 codes, file names, keys
- `EXEC CICS DUMP` enabled in production

### 6. CICS Dangerous Operations
- `EXEC CICS SPOOLOPEN` / `SPOOLWRITE` — JES spool access (RCE vector)
- `EXEC CICS START TRANSID(...)` — transaction initiation from user input
- `EXEC CICS LINK PROGRAM(variable)` — dynamic program invocation
- `EXEC CICS ASSIGN` output displayed to users

### 7. Buffer / Storage Issues
- COMMAREA LENGTH mismatch between caller and callee
- EIBCALEN not verified in called programs
- REDEFINES creating type confusion
- COMP-3 fields populated from unvalidated input

### 8. State Management
- Authorization level stored in COMMAREA (tamperable between transactions)
- Predictable TSQ names for session data
- Missing re-authentication on sensitive operations
- `EXEC CICS RETURN TRANSID(variable)` from user input

### 9. Batch / JCL Issues
- `EXEC PGM=IKJEFT01` — TSO in batch with inline commands
- `EXEC PGM=BPXBATCH` — USS commands, injection risk
- Inline credentials in SYSIN/PARM
- References to APF-authorized libraries
- SURROGAT-capable job submission

### 10. Application Logic
- `EVALUATE EIBAID` — hidden AID key handlers (PA keys, high PF keys)
- `EVALUATE` with missing/fallthrough `WHEN OTHER` (transaction escape)
- VSAM file access with user-supplied keys (IDOR)
- Race conditions in ENQ/DEQ sequences
- `EXEC CICS HANDLE ABEND` error paths that bypass security checks

## Change Intelligence — Prioritize Testing

Recently changed code and pending deployments are high-value targets — new code has new bugs.

```
endevor_print_element(conn_id="conn-1", ..., element="PAYPGM", print_option="summary")
endevor_print_element(conn_id="conn-1", ..., element="PAYPGM", print_option="changes")
endevor_list_elements(conn_id="conn-1", ..., where_ccid_all="HOTFIX*")
endevor_list_packages(conn_id="conn-1", status="APPROVED,INAPPROVAL")
endevor_list_packages(conn_id="conn-1", package="PKG001", detail="SCL")
```

## hack3270 + Endevor-MCP Cross-Reference

| Testing Activity | hack3270 Tool | Endevor-MCP Tool |
|-----------------|---------------|-----------------|
| See what's on screen | `get_screen()` | — |
| Understand screen layout | `analyze_screen_fields()` | `endevor_retrieve_element(..., type_name="BMS")` |
| Find hidden fields | `analyze_hidden()`, `get_hidden_fields()` | BMS source: `ATTRB=(ASKIP,DRK)` |
| Understand hidden field purpose | — | COBOL source: trace symbolic map field name |
| Test hidden field tampering | `send_field_data()` | COBOL source: check if field is validated after RECEIVE MAP |
| Discover AID key behavior | `scan_aid_keys()` | COBOL source: `EVALUATE EIBAID` block — all handlers |
| Test protected field tampering | `send_field_data()`, `send_raw_hex()` | COBOL source: does program validate MAP input? |
| Test TSO escape | `send_field_data()` on transaction code field | COBOL source: `EVALUATE WS-TRANS-CODE` and WHEN OTHER |
| SQL injection | `send_field_data()`, `fuzz_field()` | COBOL source: `EXEC SQL PREPARE` from MAP input |
| Fuzz with informed payloads | `fuzz_field()`, `fuzz_all_input_fields()` | Copybook: `PIC`, `COMP-3` definitions |
| Brute force credentials | `brute_force_field()` | COBOL source: where/how auth is checked |
| Trace program flow | — | `endevor_retrieve_element` chain + `_print_element_components` |
| Identify recent changes | — | `endevor_print_element(..., print_option="changes"/"summary")` |
| JCL for post-exploitation | — | `endevor_retrieve_element(..., type_name="JCL")` |
| Enumerate transactions | `fuzz_transaction_codes()` | COBOL source: EVALUATE routing tables |
| Understand data formats | — | Copybook: field PIC clauses, COMP-3, REDEFINES |
| Find hardcoded credentials | — | COBOL/JCL/REXX source: PASSWORD, PASSWD patterns |
| Verify authorization | — | COBOL source: QUERY SECURITY, RACF calls present/absent |
| Test numeric overflow | `fuzz_field()` | Copybook: COMP-3 and PIC 9 field definitions |
| Check COMMAREA safety | — | COBOL source: EIBCALEN check, LENGTH parameters |
| Check TSQ exposure | `get_screen()` after `CEBR` | COBOL source: WRITEQ TS queue names, data content |
| Verify VSAM access control | — | COBOL source: READ/WRITE FILE with user-supplied keys |
