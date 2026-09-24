---
title: Server-Side Request Forgery (SSRF) & Filter Evasion
created: 2026-09-24
updated: 2026-09-24
type: concept
tags:
  - ssrf
  - bug-bounty
  - payload
sources:
  - unprocessed-obsidians/ssrf.md
confidence: high
contested: false
contradictions: []
---

# Server-Side Request Forgery (SSRF) & Filter Evasion

## Overview
Server-Side Request Forgery (SSRF) occurs when a web application accepts a user-controlled URL and fetches data from that address using server-side network libraries without validating that the target is a safe, external endpoint. Attackers leverage the vulnerable server as a network proxy to access internal loopback services (`localhost`), scan private subnet ranges, query cloud metadata APIs, or pivot into unauthenticated database backends.

## SSRF Classification Matrix

| Variant | Detection Signal | Exploitation Scope |
| :--- | :--- | :--- |
| **In-Band (Regular) SSRF** | Response data from internal target is reflected directly in the HTTP response. | Immediate reading of cloud metadata, internal administration dashboards, and local files. |
| **Blind SSRF** | No response body is returned; server fetches resource in the background. | Requires Out-of-Band (OOB) listener (Burp Collaborator) or timing/status code inference. |
| **Semi-Blind SSRF** | HTTP status codes, error messages, or response latencies differ based on target availability. | Port scanning internal subnets and fingerprinting internal service presence. |

## Filter Evasion & Bypass Taxonomy

When applications implement blocklists restricting access to `127.0.0.1`, `localhost`, or private subnets (`10.0.0.0/8`, `192.168.0.0/16`):

```
+---------------------------------------------------------------+
|                    SSRF Filter Evasion                        |
+---------------------------------------------------------------+
        |                       |                       |
        v                       v                       v
[ IP Obfuscation ]     [ DNS Rebinding ]       [ URL Parser Tricks ]
- Dotted Hex / Octal   - Public domain with    - Userinfo (@ symbol)
- Dword / Integer IP     dual TTL=0 records    - Fragment / Slash tricks
- IPv6 Mappings        - Rebinds to 127.0.0.1  - Scheme manipulation
```

### 1. Alternative IP Address Encodings (Targeting 127.0.0.1)
- **Octal Representation**: `http://0177.0.0.1/` or `http://017700000001/`
- **Hexadecimal Representation**: `http://0x7f.0.0.1/` or `http://0x7f000001/`
- **Dword / Decimal Integer**: `http://2130706433/` (`(127*256^3) + 1`)
- **Single-Digit Localhost**: `http://127.1/` (resolves to 127.0.0.1 in Linux/C runtimes)
- **Zero Representation**: `http://0.0.0.0/` or `http://0/` (binds to loopback on Linux)
- **IPv6 Localhost**: `http://[::1]/` or IPv4-mapped IPv6 `http://[::ffff:127.0.0.1]/`

### 2. DNS Rebinding Attacks
Overcoming IP allowlist checks that perform a preliminary DNS lookup:
1. Attacker controls a domain (`rebind.attacker.com`) configured with two `A` records and a Time-To-Live (TTL) of 0 seconds:
   - First lookup returns: `203.0.113.1` (Whitelisted public IP).
   - Second lookup returns: `127.0.0.1` (Loopback IP).
2. The application validates the public IP during initial inspection, passes the security filter, and forwards the request to the HTTP client.
3. The HTTP client resolves the domain a second time, connecting to `127.0.0.1`.

### 3. Open Redirect Chaining
If the server validates that initial URLs belong to external whitelist domains, provide an allowed external endpoint that hosts an open redirect:
```text
https://whitelisted.com/redirect?url=http://169.254.169.254/latest/meta-data/
```
The application connects to `whitelisted.com`, follows the HTTP 302 redirect, and queries the internal metadata service.

## High-Value Internal Targets

### 1. Cloud Instance Metadata Services (IMDS)
- **AWS IMDSv1**: `http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME`
- **GCP Metadata**: `http://metadata.google.internal/computeMetadata/v1/` (requires header `Metadata-Flavor: Google`, often reachable via header-injection SSRFs).
- **Azure Instance Metadata**: `http://169.254.169.254/metadata/instance?api-version=2021-02-01` (requires header `Metadata: true`).

### 2. Protocol Smuggling via Gopher
When SSRF supports the `gopher://` URL scheme, attackers transmit raw TCP bytes:
- Pivoting to Redis to achieve unauthenticated RCE as documented in [[blind-ssrf-gopher-redis-rce]].
- Pivoting to FastCGI to execute PHP directives as documented in [[fastcgi-ssrf-exploitation]].

## Defensive Hardening
1. **Network-Layer Isolation**: Block server egress traffic to private IP ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`) and link-local ranges (`169.254.0.0/16`) via firewall/security group rules.
2. **Disable Redirection Following**: Configure HTTP client libraries to reject HTTP 3xx redirects automatically.
3. **Mandate AWS IMDSv2**: Enforce token-backed session headers (`X-aws-ec2-metadata-token`) on cloud instances, neutralizing standard SSRF GET requests.

## Related Pages
- [[ssrf]]
- [[xml-external-entity-injection]]
- [[blind-ssrf-gopher-redis-rce]]
- [[fastcgi-ssrf-exploitation]]
