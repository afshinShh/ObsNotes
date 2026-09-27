---
title: "Sqlmap"
created: 2026-09-25
updated: 2026-09-25
type: entity
tags:
  - tool
  - sqli
  - payload
  - bug-bounty
sources:
  - unprocessed-obsidians/sql-injection.md
confidence: high
contested: false
contradictions: []
parent: "[[web-and-bug-bounty]]"
cluster: web-and-bug-bounty
---
# Sqlmap

## Overview
Sqlmap is an open-source penetration testing tool that automates the process of detecting and exploiting SQL injection flaws and taking over database servers. It supports fingerprinting, data dumping, file system access, and out-of-band OS command execution.

- **Repository**: [https://github.com/sqlmapproject/sqlmap](https://github.com/sqlmapproject/sqlmap)
- **Documentation**: [https://sqlmap.org/](https://sqlmap.org/)

## Core Capabilities & Operational Modules
- **Six SQLi Techniques**: Boolean-based blind, time-based blind, error-based, UNION query-based, stacked queries, and out-of-band (OOB).
- **Database Engine Coverage**: Full support for MySQL, Oracle, PostgreSQL, Microsoft SQL Server, SQLite, Firebird, Sybase, SAP MaxDB, HSQLDB, and Informix.
- **Tamper Script Engine**: Bypasses web application firewalls (WAFs) using built-in obfuscation and encoding scripts (`space2comment`, `charencode`, `between`).
- **OS Command Execution**: Spawns interactive command prompts via database primitives (`xp_cmdshell`, user-defined functions UDF, PostgreSQL `COPY ... PROGRAM`).

## CLI Execution & Syntax Examples
```bash
# Automated database enumeration
sqlmap -u "https://api.target.com/items?cat=1" --batch --dbs

# WAF bypass with tamper scripts and random user-agent
sqlmap -r request.txt -p item_id --tamper=space2comment,randomcase --random-agent --os-shell
```

## Integration in Offensive Workflows
This entity serves as a core automation and execution primitive within modern red-team and bug-bounty pipelines. It bridges the gap between theoretical attack patterns and operational verification.

## Primary Sources & Provenance
Ingested and structured from canonical notes:
  - unprocessed-obsidians/sql-injection.md

## Related Notes & Concepts
- [[sql-injection-testing]]
- [[in-band-vs-blind-sqli]]

## Related Pages
- [[web-and-bug-bounty]]
