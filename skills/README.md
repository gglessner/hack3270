# hack3270 AI Skills

This directory contains skill files that teach AI assistants how to use hack3270 for mainframe penetration testing.

## Files

### hack3270 (TN3270 Pen Testing)

| File | Purpose | Read When |
|------|---------|-----------|
| `hack3270-mcp-tutorial.md` | Complete tutorial on operating hack3270 MCP tools | **Always read first** -- covers all 53 tools, common patterns, gotchas, and protocol reference |
| `hack3270.md` | Guardrailed pen testing skill | Production/authorized application testing with scope constraints, safety limits, and human approval requirements |
| `tn3270-pentest.md` | Unrestricted pen testing skill | Labs, CTFs, and full-scope engagements with no restrictions |

### Endevor-MCP (Source Code Review)

| File | Purpose | Read When |
|------|---------|-----------|
| `endevor-mcp.md` | Endevor SCM integration -- 22 read-only tools | Source code retrieval, inventory browsing, element inspection, package listing |
| `mainframe-security.md` | 19 vulnerability classes with COBOL code patterns | Security assessment of mainframe source code retrieved via Endevor |
| `security-checklist.md` | 10-category review checklist + hack3270 cross-reference | Structured source code review with pen testing integration |

## Which Skill Do I Use?

**For most pen tests**, use `hack3270.md`. It constrains your scope to the target application, prevents denial-of-service conditions, avoids account lockouts, and requires human approval before risky actions. This is the safe, professional approach.

**For labs and CTFs**, use `tn3270-pentest.md`. It covers system transaction exploitation, TSO post-exploitation, VTAM enumeration, JCL submission, and other techniques that would be inappropriate on production systems.

**Always read `hack3270-mcp-tutorial.md` first**, regardless of which skill you use. It teaches you how to actually operate the tools.

## IDE Integration

- **Cursor**: Skills auto-load via `.cursor/skills/` pointer files. No manual action needed.
- **VS Code + GitHub Copilot**: Skills auto-load via `.github/copilot-instructions.md`. No manual action needed.
- **Other AI tools**: Point the AI to this directory and tell it which skill to use.
