---
title: "In-Band vs Blind SQL Injection Exfiltration Trade-offs"
created: 2026-09-25
updated: 2026-09-25
type: comparison
tags:
  - sqli
  - bug-bounty
  - payload
sources:
  - unprocessed-obsidians/sql-injection.md
confidence: high
contested: false
contradictions: []
parent: "[[web-and-bug-bounty]]"
cluster: web-and-bug-bounty
---
# In-Band vs Blind SQL Injection Exfiltration Trade-offs

## Overview
Technical trade-off analysis comparing direct In-Band (Union-based, Error-based) SQLi with Inferential/Blind (Boolean, Time-based, Out-of-Band) SQLi methodologies.

## Comparative Technical Matrix

| Evaluation Dimension | Variant / Paradigm A | Variant / Paradigm B |
| :--- | :--- | :--- |
| **Exfiltration Channel** | Direct HTTP response data or database error message | Binary response differentials, response time delays, or DNS/SMB callbacks |
| **Bandwidth / Speed** | High speed (entire tables exfiltrated in single queries) | Slow (bit-by-bit extraction: 10-50 bits/sec for time-based, faster for OOB DNS) |
| **Network Footprint** | Small request volume, highly visible in logs | Massive request volume (hundreds to thousands of HTTP requests per character) |
| **WAF Evasion Complexity** | Difficult (requires union keyword and schema matching) | Moderate (can use mathematical comparisons and sleep primitives) |
| **Dialect Reliance** | Depends on column count and type casting | Relies on procedural delays (`pg_sleep()`, `WAITFOR DELAY`, `SLEEP()`) or OOB functions (`xp_dirtree`) |

## Technical Analysis & Operational Verdict
When in-band reflection is suppressed by production error handling, Out-of-Band (OOB) DNS exfiltration provides the fastest extraction method. When all outbound ports are egress-filtered, binary search boolean-blind extraction minimizes server load and log anomalies.

## Primary Sources & Provenance
Ingested and synthesized from canonical notes:
  - unprocessed-obsidians/sql-injection.md

## Related Concepts & Notes
- [[sql-injection-testing]]
- [[sqlmap]]
