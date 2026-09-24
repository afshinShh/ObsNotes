---
type: llm-wiki-review
status: needs-review
decision: pending
revision: 1
operation: create
target: sources/sql-injection.md
sources:
  - raw/articles/sql-injection.md
---

# Proposed Wiki change

## What will change
Establishes the provenance anchor for SQL Injection notes ingested from `unprocessed-obsidians/sql-injection.md`, linking primary source notes to compiled concepts.

## Proposed content

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

## Evidence and uncertainty
Directly transcribed and normalized from `unprocessed-obsidians/sql-injection.md`. Covers standard SQL injection methodologies across relational DBMS engines and NoSQL operators.

## Human feedback
Optionally explain or edit what should change.
