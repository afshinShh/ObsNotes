---
title: Source Note - SQL Injection
created: 2026-09-24
updated: 2026-09-24
type: source
tags:
  - sqli
  - bug-bounty
sources:
  - unprocessed-obsidians/sql-injection.md
extracted_concepts:
  - "[[sql-injection-testing]]"
---

# Source Note: SQL Injection

> **Provenance Anchor**: Ingested from canonical vault file `[[unprocessed-obsidians/sql-injection]]`.
> **Compiled Wiki Pages**:
> - Concept: [[sql-injection-testing]]

---

## Original Material Overview
The source note synthesizes SQL Injection identification, exploitation methodologies, and database target specificities:
- **Mechanisms**: Types of SQLi (In-band / Union-based, Error-based, Blind / Inferential boolean & time-based, Out-of-band OOB).
- **Database Targets**: MySQL, PostgreSQL, Microsoft SQL Server (MSSQL), Oracle, SQLite, and NoSQL injection.
- **Hunting Workflow**: Recon, endpoint discovery, parameter fuzzing, error analysis, response differential testing.
- **Bypass Techniques**: WAF bypass (comment injection, whitespace manipulation, case variation, encoding, inline comments), character restrictions.
- **Exploitation & Escalation**: Data exfiltration, privilege escalation, database-specific RCE vectors (MSSQL `xp_cmdshell`, PostgreSQL `COPY ... PROGRAM`, MySQL `INTO OUTFILE`).

## Related Pages
- [[sql-injection-testing]]
- [[graphql-security]]
