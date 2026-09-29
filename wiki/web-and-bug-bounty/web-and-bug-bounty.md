---
title: "Web Application Security & Bug Bounty"
created: 2026-09-25
updated: 2026-09-25
type: hub
tags:
  - web-security
  - bug-bounty
  - api
  - payload
cluster: web-and-bug-bounty
sources:
  - sources/sql-injection.md
  - sources/xss.md
  - sources/ssti.md
  - sources/xxe.md
  - sources/parameter-pollution.md
  - sources/req-smuggle.md
  - sources/graphql.md
  - sources/idor.md
  - sources/race-condition.md
  - sources/open-redirect.md
  - sources/insecure-deserialization.md
  - sources/ssrf.md
  - sources/jwt.md
  - sources/oauth.md
  - sources/performance monitor.md
---

# Web Application Security & Bug Bounty

> **Domain Hub & Map of Content**
> Comprehensive catalog of web application vulnerabilities, protocol desynchronization, authentication and authorization mechanisms, business logic flaws, and server-side exploitation.

## Architecture & Hierarchy

- **Parent Directory**: `wiki/web-and-bug-bounty/`
- **Root Index**: [[index|Wiki Master Index]]
- **Domain Cluster**: `web-and-bug-bounty`

---

## Core Concepts & Vulnerability Classes

### 1. Web Injection Primitives
- [[sql-injection-testing]] — Core SQL injection primitive, root causes, query mechanics, and exploitation lifecycle.
  - [[sql-injection-testing-detection-methodology]] — Reconnaissance workflows, parameter fuzzing, error-based detection, and blind time-delay inference.
  - [[sql-injection-testing-exploitation-and-attack-vectors]] — In-band, blind boolean, time-based, out-of-band exfiltration, and WAF bypass techniques.
  - [[sql-injection-testing-defense-and-remediation]] — Parameterized queries, ORM security controls, stored procedure hardening, and privilege separation.
  - [[sql-injection-testing-methodologies]] — Database-specific fingerprinting (MySQL, PostgreSQL, MSSQL, Oracle), syntax references, and privilege escalation.
- [[cross-site-scripting]] — DOM-based sinks, context-aware HTML/attribute/script breakouts, and tag/parentheses WAF bypasses.
  - [[xss-and-waf-evasion-tradecraft]] — Comprehensive checklist: DOM state pausing, whitespace fuzzing, tag normalization, string concatenation, and parentheses-less execution.
- [[dom-debugging-and-sink-analysis]] — DevTools 80% rule, global handler discovery, conditional breakpoints, postMessage regex bypasses, and chunked parameter fuzzing.
- [[server-side-template-injection]] — Jinja2, Twig, FreeMarker, Pebble template evaluation probes, and Python MRO object sandbox escapes.
- [[xml-external-entity-injection]] — In-band file retrieval, CDATA wrapping, blind out-of-band (OOB) DTD parameter entity exfiltration, and Billion Laughs DoS.
- [[http-parameter-pollution]] — Precedence matrix across web servers (Apache, IIS, Node.js), parameter overriding, and WAF token splitting bypasses.

### 2. Protocol Desynchronization & Request Smuggling
- [[http-request-smuggling]] — Core HTTP message parsing discrepancies, Content-Length vs Transfer-Encoding desync.
  - [[http-request-smuggling-detection-methodology]] — Architecture reconnaissance, time-delay probes, GPOST confirmation, differential testing.
  - [[http-request-smuggling-advanced-desync]] — HTTP/2 downgrading (H2.CL, H2.TE), HTTP/3 QUIC streams, Client-Side Desync, WebSocket tunnel hijacking.
  - [[http-request-smuggling-defense-and-remediation]] — Real-world CVEs, reverse proxy normalization, defense testing, and why partial mitigations fail. — Front-end and back-end header boundary desync (CL.TE, TE.CL, TE.TE), HTTP/2 downgrading flaws (H2.CL, H2.TE), and request queue hijacking.

### 3. Business Logic, APIs & Concurrency
- [[graphql-security]] — Introspection query reconstruction, directive flooding DoS, batching attack loops, and field-level authorization flaws.
- [[insecure-direct-object-reference]] — Horizontal and vertical privilege escalation, identifier tampering, and dual-account validation matrices.
- [[race-condition-attacks]] — Time-of-Check to Time-of-Use (TOCTOU), Limit-Overrun concurrency, and HTTP/2 single-packet synchronization.
- [[open-redirect-attacks]] — URL parameter parsing confusion, regex/allowlist bypasses, and OAuth authorization code theft chains.
- [[client-side-path-traversal]] — Client-Side Path Traversal (CSPT), dynamic fetch/XHR steering, 8-framework parameter decoding matrix, and hDOM request hijacking.

### 4. Authentication, Tokens & Identity
- [[jwt-security-mechanisms]] — RFC 7519 architecture, JOSE header specifications, signing matrices (RS256 vs HS256), token binding, and claim lifecycles.
- [[jwt-attack-vectors]] — `none` algorithm injection, asymmetric-to-symmetric key confusion, embedded JWK/JKU header tampering, and HMAC brute forcing.
- [[oauth-grant-types-and-flows]] — RFC 6749 grant types, Authorization Code Flow with PKCE (RFC 7636), Implicit Flow deprecation, and Token Exchange.
- [[oauth-attack-vectors]] — `redirect_uri` validation manipulation, State CSRF, authorization code leakage, and account takeover (ATO) chains.
- [[account-takeover-and-auth-flaws]] — Comprehensive ATO checklist: email normalization padding, 2FA state skipping, OAuth state misuse, and app-to-app transfer polling.

### 5. Server-Side Exploitation & Deserialization
- [[server-side-request-forgery]] — Cloud metadata extraction (IMDSv1 vs IMDSv2), alternative IP encoding formats, DNS rebinding, and protocol smuggling via Gopher.
- [[blind-ssrf-gopher-redis-rce]] — Weaponizing SSRF via Gopher to issue Redis commands, write PHP webshells, or execute Lua scripts.
- [[fastcgi-ssrf-exploitation]] — Pivoting SSRF into local FastCGI/PHP-FPM instances (port 9000) using binary record packet generation for RCE.
- [[deserialization-attacks]] — Java, PHP, Python, and Node.js serialization formats, magic methods, and remote code execution gadget chains.
- [[file-upload-attack-matrix]] — Document root vs route-based uploaders, magic byte polyglots, S3 dynamic Content-Type reflection, and CSP evaluation.

### 6. Live Assessments & Case Studies
- [[bug-bounty-recon-and-threat-modeling]] — Core hunter mindset axioms, TLD expansion oneliners, Wayback CDX digest collapsing, and architectural threat modeling.
- [[bug-bounty-live-hunts-case-studies]] — Granular bug bounty case studies from live targets (CapCut, Superbet, Amazon Hiring, Experian, Windsurf, Romwe, TikTok, BytePlus).

---

## Comparative Trade-off Analyses
- [[blind-ssrf-gopher-redis-rce-vs-fastcgi-ssrf-exploitation]]
- [[cspt-vs-path-traversal]] — Client-Side Path Traversal (browser DOM routing, token leakage) vs Server-Side Path Traversal (/etc/passwd, LFI).
- [[cl-te-vs-te-cl]] — Architectural and exploitation differences between CL.TE and TE.CL request smuggling desynchronization.
- [[classic-vs-blind-xxe]] — Direct in-band entity reflection vs out-of-band DTD callback exfiltration.
- [[in-band-vs-blind-sqli]] — Direct result set extraction vs binary search boolean/time-based inference trade-offs.
- [[stored-vs-reflected-vs-dom-xss]] — Persistence mechanisms, server-side reflection vs client-side DOM sink evaluation.
- [[redis-vs-fastcgi-ssrf-pivoting]] — Comparison of internal service exploitation vectors via Gopher SSRF (memory store vs application processor).
- [[imdsv1-vs-imdsv2-ssrf]] — AWS instance metadata security boundaries: stateless GET requests vs session-token PUT headers.
- [[jwt-vs-session-cookies]] — Architectural trade-offs between stateless cryptographic tokens and stateful server-managed sessions.
- [[authorization-code-vs-implicit-flow]] — OAuth grant flow security: secure server exchange with PKCE vs insecure browser-exposed tokens.
- [[jwt-in-oauth2-architecture]] — Architecture and trust boundaries when JWTs are deployed as OAuth 2.0 access and identity tokens.
- [[open-redirect-in-oauth-flows]] — Exploiting open redirects to hijack authorization codes and complete seamless account takeovers.

---

## Entities & Tooling Catalog
- [[jwt-tool]] — CLI utility for testing, attacking, and modifying JSON Web Tokens.
- [[wordpress-performance-monitor]] — Vulnerable WordPress plugin exhibiting blind SSRF via IP parameter injection.
- [[sqlmap]] — Automatic SQL injection and database takeover engine.
- [[tplmap]] — Automatic Server-Side Template Injection exploitation and sandbox escape tool.
- [[smuggler]] — HTTP Request Smuggling scanner and payload tester.
- [[turbo-intruder]] — High-speed HTTP request engine for testing race conditions and single-packet sync.
- [[recollapse]] — Advanced input normalization permutation and regex bypass fuzzing engine by 0xacb.
- [[ysoserial]] — Proof-of-concept tool for generating Java deserialization exploit payloads.

---

## Primary Sources & Ingestion Provenance
- [[narroto-guts-hunt-live-hunts]] — Case studies across CapCut, Superbet, Amazon, Experian, Windsurf, Romwe, TikTok, BytePlus.
- [[narroto-guts-hunt-structures]] — Core hunting mindset, wide vs narrow recon, architectural threat modeling, and reporting discipline.
- [[narroto-guts-hunt-tips-and-tricks]] — Advanced XSS WAF evasion, client-side debugging, postMessage analysis, Android mobile pentesting, and file upload matrix.
- [[sql-injection]] — Primary source note on SQL injection vectors.
- [[xss]] — Primary source note on cross-site scripting vectors.
- [[ssti]] — Primary source note on template injection.
- [[xxe]] — Primary source note on XML external entities.
- [[parameter-pollution]] — Primary source note on HTTP parameter pollution.
- [[req-smuggle]] — Primary source note on request smuggling.
- [[graphql]] — Primary source note on GraphQL security.
- [[idor]] — Primary source note on IDOR and access control.
- [[race-condition]] — Primary source note on concurrency and race conditions.
- [[open-redirect]] — Primary source note on open redirection vulnerabilities.
- [[insecure-deserialization]] — Primary source note on object deserialization.
- [[ssrf]] — Primary source note on server-side request forgery.
- [[jwt]] — Primary source note on JSON Web Token mechanics and attacks.
- [[oauth]] — Primary source note on OAuth 2.0 and OpenID Connect flows.
- [[performance monitor]] — Primary source note on WordPress Performance Monitor vulnerability.

---

## Cross-Domain Attack Chains & Related Domains
- [[recon-and-osint]] — External reconnaissance feeding discovered attack surface into web hunting workflows ([[osint-reconnaissance]]).
- [[ai-security]] — Web application endpoints integrating LLM APIs and agentic workflows ([[ai-security-testing]]).
- [[defense-and-evasion]] — Evasion of Web Application Firewalls (WAFs) and endpoint monitoring during server-side command execution.
- [[binary-exploitation]] — Escalating web RCE into kernel exploitation or local privilege escalation.
