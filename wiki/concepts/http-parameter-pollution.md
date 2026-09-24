---
title: HTTP Parameter Pollution (HPP) & Server Precedence Flaws
created: 2026-09-24
updated: 2026-09-24
type: concept
tags:
  - api
  - business-logic
  - bug-bounty
sources:
  - unprocessed-obsidians/parameter-pollution.md
confidence: high
contested: false
contradictions: []
---

# HTTP Parameter Pollution (HPP) & Server Precedence Flaws

## Overview
HTTP Parameter Pollution (HPP) occurs when an application receives multiple parameters sharing the identical name (e.g. `?id=1&id=2`) and processes them inconsistently between edge gateways (WAFs, reverse proxies) and backend application runtimes. By exploiting differing parameter precedence policies across technologies, attackers can evade security filters, override backend logic constraints, and tamper with internal API requests.

## Technology Parameter Precedence Matrix

When presented with `GET /test?param=val1&param=val2`:

| Technology / Server | Parsing Behavior | Resulting Evaluated Value |
| :--- | :--- | :--- |
| **PHP / Apache** | Last parameter takes precedence | `val2` |
| **ASP.NET / IIS** | Concatenates all values with comma | `val1,val2` |
| **Node.js (Express / qs)** | Converts into an array | `['val1', 'val2']` |
| **Python (Flask / Werkzeug)** | First parameter takes precedence (`get()`) | `val1` |
| **Python (Django)** | Last parameter takes precedence | `val2` |
| **Java (Tomcat / Servlet)** | First parameter takes precedence | `val1` |
| **Go (net/http)** | First parameter takes precedence (`FormValue`) | `val1` |
| **Ruby on Rails** | Last parameter takes precedence | `val2` |

## Primary Vulnerability Patterns & Impact Scenarios

### 1. WAF Evasion via Keyword Fragmentation
In environments using ASP.NET or technologies that concatenate duplicate parameters with commas:
```http
GET /items?query=SELECT/**/id,password&query=FROM/**/users HTTP/1.1
```
- The WAF inspects each `query` parameter individually; neither parameter alone contains a full SQL query signature (`SELECT ... FROM ...`), allowing the request to pass.
- ASP.NET merges the parameters into:
  ```sql
  SELECT id,password, FROM users
  ```
  Executing the SQL injection query on the database.

### 2. Overriding Hardcoded Backend Parameters (Server-Side HPP)
When a frontend application constructs an HTTP request to an internal backend service using string concatenation:
```text
https://internal-api.bank/transfer?from=USER_ACC&to=RECIPIENT_INPUT&amount=AMOUNT
```
If `RECIPIENT_INPUT` contains unencoded parameter delimiters:
```text
recipient=12345&from=ATTACKER_OVERRIDE_ACCOUNT
```
The internal API receives:
```text
https://internal-api.bank/transfer?from=1001&to=12345&from=ATTACKER_OVERRIDE_ACCOUNT&amount=500
```
If the internal backend obeys the **last parameter**, `from` is overridden, transferring funds from the victim's account.

### 3. Type Confusion & Logic Bypasses (Array Injection)
In Node.js / Express applications:
- Normal parameter evaluates to string: `typeof req.query.role === 'string'`
- Duplicated parameter evaluates to array: `req.query.role = ['user', 'admin']`
- If authentication logic performs regex or string comparison (`req.query.role.indexOf('admin')`), supplying an array can bypass validation or throw unhandled exceptions causing denial of service.

## Defensive Hardening
- Enforce strict parameter validation: explicitly reject requests containing duplicate parameters with HTTP 400 Bad Request.
- Maintain consistent parameter parsing semantics across proxy/WAF layers and backend application services.
- Never construct internal backend API URLs via string concatenation; utilize structured HTTP client builders with URL-encoded query maps.

## Related Pages
- [[parameter-pollution]]
- [[sql-injection-testing]]
- [[http-request-smuggling]]
- [[insecure-direct-object-reference]]
