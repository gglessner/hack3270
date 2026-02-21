# hack3270 AI Instructions

This project is a mainframe penetration testing toolkit built around the TN3270 protocol. It includes an MCP (Model Context Protocol) server that gives you direct access to a mainframe terminal via 53 specialized tools.

## AI Skill Files

Before performing any mainframe-related tasks, read the appropriate skill files from the `skills/` directory:

1. **`skills/hack3270-mcp-tutorial.md`** -- **READ THIS FIRST.** A complete tutorial on how to use every hack3270 MCP tool. Covers connecting, reading screens, sending data, analyzing fields, fuzzing, brute forcing, session database analysis, and troubleshooting. Written with detailed examples and a decision tree for choosing the right tool.

2. **`skills/hack3270.md`** -- **Guardrailed pen testing.** Use this for production or authorized application testing. It constrains your scope to the target application's transaction prefix, prevents denial-of-service, avoids account lockouts, and requires human approval before risky actions.

3. **`skills/tn3270-pentest.md`** -- **Unrestricted pen testing.** Use this for labs, CTFs, and full-scope engagements. Covers CICS system transaction exploitation, TSO post-exploitation, VTAM enumeration, RACF bypass, JCL submission, and all attack patterns.

4. **`skills/endevor-mcp.md`** -- **Endevor SCM integration.** 22 read-only tools for browsing Endevor inventory, retrieving source code, inspecting element history, and listing packages. Use for AI-driven source code review and security assessments alongside hack3270 pen testing.

5. **`skills/mainframe-security.md`** -- 19 vulnerability classes with COBOL source code patterns and hack3270 exploitation steps.

6. **`skills/security-checklist.md`** -- 10-category source code review checklist and hack3270 tool cross-reference.

See `skills/README.md` for guidance on which skill to use.

## Quick Tips

- The hack3270 proxy must be running and connected to a mainframe before you can use the MCP tools.
- When the human says "read the logs" or "check the session database," they mean the SQLite `.db` files. Use the `list_databases` tool to find them, then `load_database` and `get_logs` to browse.
- Always call `get_screen()` after sending any data to see the result.
- Always call `analyze_screen_fields()` before trying to type into a field -- you need the field address.
- Use `send_command()` on unformatted screens (after CLEAR). Use `send_field_data()` on formatted screens (with fields). Mixing these up causes APCT abend errors.
