---
type: llm-wiki-review
status: needs-review
decision: approve
revision: 1
operation: create
target: web-and-bug-bounty/sources/sql-injection-notes.md
sources:
  - Notes/OLD Notes/WEB/vulnerabilities/SQL Injection/concepts.md
  - Notes/OLD Notes/WEB/vulnerabilities/SQL Injection/attack/METHODOLOGY.md
  - Notes/OLD Notes/WEB/vulnerabilities/SQL Injection/attack/Examples.md
  - Notes/OLD Notes/WEB/vulnerabilities/SQL Injection/cheatsheet(portswigger).md
  - Notes/OLD Notes/WEB/vulnerabilities/SQL Injection/defense.md
---
# Proposed Wiki change

## What will change
Create provenance source anchor for SQL Injection notes in Notes/OLD Notes/WEB/vulnerabilities/SQL Injection/.

## Proposed content
```markdown
---
title: "Source Note - SQL Injection: Multi-Database Cheatsheet, Exploitation & Defenses"
created: 2026-10-01
updated: 2026-10-01
type: source
tags:
  - sqli
  - payload
  - web-security
  - bug-bounty
sources:
  - Notes/OLD Notes/WEB/vulnerabilities/SQL Injection/concepts.md
  - Notes/OLD Notes/WEB/vulnerabilities/SQL Injection/attack/METHODOLOGY.md
  - Notes/OLD Notes/WEB/vulnerabilities/SQL Injection/attack/Examples.md
  - Notes/OLD Notes/WEB/vulnerabilities/SQL Injection/cheatsheet(portswigger).md
  - Notes/OLD Notes/WEB/vulnerabilities/SQL Injection/defense.md
extracted_concepts:
  - "[[sql-injection-testing-methodologies]]"
extracted_entities:
  []
extracted_comparisons:
  []
confidence: high
contested: false
contradictions: []
parent: "[[web-and-bug-bounty]]"
cluster: web-and-bug-bounty
---
# Source Note - SQL Injection: Multi-Database Cheatsheet, Exploitation & Defenses

> **Provenance Anchor**: Ingested from canonical vault files under `Notes/OLD Notes/WEB/vulnerabilities/SQL Injection/`.
> - `concepts.md` (101 lines, SHA-256: `6c41b8f047f3b8f673f47e224e754a233b8a1c6a282928fa8e202574e98f0607`)
> - `attack/METHODOLOGY.md` (82 lines, SHA-256: `59fa99003848b61ca01a2fdf0dbb6443689408b0451ffceb2b35a39626ca3d88`)
> - `attack/Examples.md` (112 lines, SHA-256: `ad3a8ecff066487e4162075fc034440026e6328ae92da3db5976b92f7636e2f1`)
> - `cheatsheet(portswigger).md` (141 lines, SHA-256: `3b4698305ff4c9b13998b31f79fba50a3cc1ca5957388cf64e21a221f7dbf170`)
> - `defense.md` (27 lines, SHA-256: `a937a346e29eeebcba4cae6973950d99efaa78a87679ad396d997235555e10dc`)
> **Total Raw Lines**: 463 lines

---

<!-- TOC_START -->
## Table of Contents
- [Compiled Wiki Layers](#compiled-wiki-layers)
  - [Concepts](#concepts)
- [Source Content Topic Breakdown](#source-content-topic-breakdown)
- [Related Pages](#related-pages)
<!-- TOC_END -->

## Compiled Wiki Layers
### Concepts
- [[sql-injection-testing-methodologies]] — Database-specific fingerprinting (Oracle, Microsoft SQL Server, PostgreSQL, MySQL), multi-database syntax cheatsheets, string concatenation operators, substring extraction, comment termination styles, database version queries, table schema enumeration, conditional error triggers, time delay commands, and OAST DNS exfiltration vectors.

## Source Content Topic Breakdown
1. **Core Query & Subquery Mechanics**: Union-based column counting, null-injection data type determination, and subquery exfiltration.
2. **Multi-Database Syntax Cheatsheet**:
   - String concatenation: `||` (Oracle), `+` (MSSQL), space or `CONCAT()` (MySQL/PostgreSQL).
   - Substring functions: `SUBSTR()` vs `SUBSTRING()`.
   - Comment delimiters: `--`, `/*...*/`, `#`.
   - Version extraction: `v$version`, `@@version`, `version()`.
   - Database schema enumeration: `information_schema.tables`, `all_tables`.
3. **Inference & Blind Primitives**:
   - Conditional error triggers (`1/0` division, `TO_CHAR(1/0)`).
   - Time-based blind execution: `dbms_pipe.receive_message()` (Oracle), `WAITFOR DELAY` (MSSQL), `pg_sleep()` (PostgreSQL), `sleep()` (MySQL).
   - Out-of-band DNS exfiltration: `UTL_HTTP`, `UTL_INADDR`, `xp_dirtree`, `LOAD_FILE('\\\\...')`.
4. **Remediation**: Parameterized queries and prepared statements.

## Related Pages
- Parent Domain Hub: [[web-and-bug-bounty]]
- Target Concepts: [[sql-injection-testing]], [[sql-injection-testing-methodologies]], [[sql-injection-testing-exploitation-and-attack-vectors]]
```

## Evidence and uncertainty
Sourced directly from canonical vault notes in Notes/OLD Notes/WEB/.
Validated against schema with zero structural contradictions.

## Human feedback
Human decision required via Decision Studio (http://127.0.0.1:20888) or command line.
