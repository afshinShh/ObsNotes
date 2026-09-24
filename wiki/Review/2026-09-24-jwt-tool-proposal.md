---
type: llm-wiki-review
status: needs-review
decision: pending
revision: 1
operation: create
target: entities/jwt-tool.md
sources:
  - raw/articles/jwt.md
---

# Proposed Wiki change

## What will change
Compiles a dedicated entity profile documenting `jwt_tool` by ticarpi, a specialized security toolkit for testing, auditing, and exploiting JSON Web Tokens in penetration testing and bug bounty workflows.

## Proposed content

---
title: "JWT Tool (ticarpi)"
created: 2026-09-24
updated: 2026-09-24
type: entity
tags:
  - jwt
  - tool
  - payload
  - bug-bounty
sources:
  - unprocessed-obsidians/jwt.md
confidence: high
contested: false
contradictions: []
---

# JWT Tool (ticarpi)

## Overview
**JWT Tool** (`jwt_tool`) is a Python-based security auditing and exploitation utility authored by [ticarpi](https://github.com/ticarpi/jwt_tool). It is the standard specialized CLI tool used by red teams and bug bounty researchers to analyze, tamper with, crack, and forge JSON Web Tokens across web applications and API endpoints.

## Core Capabilities & Attack Modules

| Flag / Option | Operation | Technical Description |
| :--- | :--- | :--- |
| `<token>` | Token Analysis | Decodes header and payload claims; identifies algorithm, key parameters, and timestamp expirations. |
| `-M all` | Automated Scanning | Executes a battery of automated security checks against a target endpoint using the provided token. |
| `-X a` | Algorithm Confusion | Automatically attempts RS256 to HS256 switching using a target's public verification key as the HMAC secret. |
| `-X n` | Null Signature / None | Strips signature and tests multiple case permutations of the `none` algorithm (`none`, `None`, `NONE`, `nOnE`). |
| `-X i` | Claim Tampering / Spoofing | Generates forged tokens with modified identity claims (e.g. elevating privileges or changing user identity). |
| `-X k` | Key ID / Confusion Testing | Injects key parameter payloads into `kid`, `jwk`, and `jku` headers (e.g. path traversal, SQLi). |
| `-C -d <wordlist>` | HMAC Dictionary Cracking | Executes high-speed dictionary brute-force attacks against HMAC secrets (`HS256`, `HS384`, `HS512`). |

## CLI Execution Examples

### 1. Basic Token Inspection
```bash
python3 jwt_tool.py "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### 2. Comprehensive Automated Vulnerability Scan
```bash
python3 jwt_tool.py "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." -M all -t https://api.target.com/user/profile -rh "Authorization: Bearer"
```

### 3. Algorithm Confusion Attack (RSA to HMAC)
```bash
python3 jwt_tool.py "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." -X a -pk public_key.pem
```

### 4. Offline HMAC Secret Cracking
```bash
python3 jwt_tool.py "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." -C -d /usr/share/wordlists/rockyou.txt
```

## Integration in Security Workflows
- **Bug Bounty & API Testing**: Complements web proxy tools (Burp Suite JWT Editor, Autorize, Auth Analyzer) by providing scriptable command-line automation for CI/CD pipeline auditing and batch token fuzzing.
- **Payload Generation**: Interoperates with Burp Suite Intruder for mass header injection fuzzing.

## Primary Source References
- **Repository**: [https://github.com/ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool)
- **Ingested Source**: Transcribed and normalized from [[jwt]].

## Related Pages
- [[jwt]]
- [[jwt-security-mechanisms]]
- [[jwt-attack-vectors]]

## Evidence and uncertainty
Documented directly from tool usage specifications and attack patterns in `unprocessed-obsidians/jwt.md` and official tool repository.

## Human feedback
Optionally explain or edit what should change.
