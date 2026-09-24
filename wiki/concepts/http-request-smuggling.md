---
title: HTTP Request Smuggling & Pipeline Desynchronization
created: 2026-09-24
updated: 2026-09-24
type: concept
tags:
  - request-smuggling
  - api
  - bug-bounty
sources:
  - unprocessed-obsidians/req-smuggle.md
confidence: high
contested: false
contradictions: []
---

# HTTP Request Smuggling & Pipeline Desynchronization

## Overview
HTTP Request Smuggling occurs when chained HTTP intermediaries (reverse proxies, load balancers, CDNs, and backend web servers) interpret the boundary of an HTTP request differently. By sending ambiguous requests specifying conflicting length boundaries (`Content-Length` vs `Transfer-Encoding`), an attacker can cause the front-end to forward a request that the back-end splits into multiple distinct requests. The unsynchronized trailing bytes remain in the back-end TCP connection socket, prepending malicious data to the subsequent user's request.

## Core Desynchronization Primitives

```
+--------+            +-------------------+            +------------------+
| Client | ---------> | Front-End Gateway | ---------> |  Backend Server  |
+--------+            +-------------------+            +------------------+
                          (Uses CL)                         (Uses TE)
                                \                              /
                                 +-- Boundary Disagreement ---+
                                                |
                                   Smuggled Prefix Sits in
                                   Backend Connection Buffer
```

### 1. CL.TE Vulnerability
- **Front-end**: Prioritizes `Content-Length`. Reads the entire request body as a single request.
- **Back-end**: Prioritizes `Transfer-Encoding: chunked`. Reads up to the terminating `0

` chunk.
- **Smuggled Data**: The data following the zero-chunk remains unparsed in the backend socket, prepending itself to the next inbound HTTP request.
- **Attack Payload**:
  ```http
  POST / HTTP/1.1
  Host: vulnerable.com
  Content-Length: 30
  Transfer-Encoding: chunked

  0

  GET /admin HTTP/1.1
  X-Ignore: X
  ```

### 2. TE.CL Vulnerability
- **Front-end**: Prioritizes `Transfer-Encoding: chunked`. Reads until the terminating chunk.
- **Back-end**: Prioritizes `Content-Length`. Reads only the specified byte length, leaving remaining bytes in the connection queue.
- **Attack Payload**:
  ```http
  POST / HTTP/1.1
  Host: vulnerable.com
  Content-Length: 4
  Transfer-Encoding: chunked

  5c
  GET /admin HTTP/1.1
  Host: vulnerable.com
  Content-Length: 15

  x=1
  0
  ```

### 3. TE.TE (Header Obfuscation)
Both servers support chunked encoding, but the front-end or back-end can be induced to ignore the `Transfer-Encoding` header via obfuscation:
- `Transfer-Encoding: xchunked`
- `Transfer-Encoding : chunked` (space before colon)
- `Transfer-Encoding: chunked
Transfer-Encoding: identity`
- `Transfer-Encoding:chunked` (vertical tab)

## Modern Desynchronization Variants
- **H2.CL / H2.TE (HTTP/2 Downgrade)**: Modern front-ends receive HTTP/2 (where request length is explicit in frame data) and downgrade to HTTP/1.1 when speaking to legacy backends. Injecting `content-length` or `transfer-encoding` pseudo-headers in H2 frames causes desync when rewritten to HTTP/1.1 streams.
- **Cleartext HTTP/2 (`h2c`) Upgrade**: Intermediaries blindly forwarding `Upgrade: h2c` headers allow direct HTTP/2 multiplexed streams past WAF inspection rules.
- **Pause-Based / Client Connection Desync**: Manipulating TCP packet chunk delivery timing to stall server reads and exploit connection reuse.

## High-Impact Exploitation Scenarios
1. **Bypassing Front-End Security Controls**: Accessing administrative endpoints (`/admin`) normally blocked by edge reverse proxies by smuggling the request through an authorized public path.
2. **Request Queue Poisoning & Credential Theft**: Prepending an incomplete POST request (`POST /comment?body=`). When a victim user sends their request, their cookies, headers, and authentication tokens are appended as the comment body and stored publicly.
3. **Web Cache Poisoning**: Smuggling requests that trigger redirect loops or error pages, causing the reverse proxy cache to store malicious responses for legitimate URLs.

## Defensive Hardening
- Mandate HTTP/2 end-to-end from the edge proxy to internal backend services without HTTP/1.1 downgrades.
- Reject requests containing both `Content-Length` and `Transfer-Encoding` headers with HTTP 400 Bad Request.
- Normalize HTTP headers: strip duplicate headers, normalize whitespace, and enforce strict RFC parsing.

## Related Pages
- [[req-smuggle]]
- [[http-parameter-pollution]]
- [[insecure-direct-object-reference]]
- [[cl-te-vs-te-cl]]
