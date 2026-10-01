---
type: llm-wiki-review
status: needs-review
decision: approve
revision: 1
operation: create
target: web-and-bug-bounty/sources/websockets.md
sources:
  - Notes/OLD Notes/WEB/vulnerabilities/WebSockets/concepts.md
  - Notes/OLD Notes/WEB/vulnerabilities/WebSockets/methodology.md
  - Notes/OLD Notes/WEB/vulnerabilities/WebSockets/Examples.md
---
# Proposed Wiki change

## What will change
Create provenance source anchor for WebSockets notes in Notes/OLD Notes/WEB/vulnerabilities/WebSockets/.

## Proposed content
```markdown
---
title: "Source Note - WebSockets: Protocol Mechanics, Vulnerabilities, and CSWSH"
created: 2026-10-01
updated: 2026-10-01
type: source
tags:
  - web-security
  - api
  - payload
  - bug-bounty
sources:
  - Notes/OLD Notes/WEB/vulnerabilities/WebSockets/concepts.md
  - Notes/OLD Notes/WEB/vulnerabilities/WebSockets/methodology.md
  - Notes/OLD Notes/WEB/vulnerabilities/WebSockets/Examples.md
extracted_concepts:
  - "[[websocket-security-and-cross-site-hijacking]]"
extracted_entities:
  []
extracted_comparisons:
  []
confidence: high
contested: false
contradictions: []
parent: "[[web-and-bug-bounty]]"
cluster: web-and-bug-bounty
---
# Source Note - WebSockets: Protocol Mechanics, Vulnerabilities, and CSWSH

> **Provenance Anchor**: Ingested from canonical vault files under `Notes/OLD Notes/WEB/vulnerabilities/WebSockets/`.
> - `concepts.md` (149 lines, SHA-256: `f6c67939a63b05caee544b2a8706e514bb5cdfe860d42ede58cb49ef21071351`)
> - `methodology.md` (31 lines, SHA-256: `f818329332b980fc4b252154c4b4361977484d0f06e13f7a11a059b8cc1cfbf7`)
> - `Examples.md` (67 lines, SHA-256: `f067d9a3e11a7de0c4ef6ace5841d020c3c5ca9d5d40beae5eb4fc03ca67ab14`)
> **Total Raw Lines**: 247 lines

---

<!-- TOC_START -->
## Table of Contents
- [Compiled Wiki Layers](#compiled-wiki-layers)
  - [Concepts](#concepts)
- [Source Content Topic Breakdown](#source-content-topic-breakdown)
- [Related Pages](#related-pages)
<!-- TOC_END -->

## Compiled Wiki Layers
### Concepts
- [[websocket-security-and-cross-site-hijacking]] — Full-duplex WebSocket architecture, handshake headers (Sec-WebSocket-Key / Accept), Socket.IO frame structures, web vulnerability injection over WebSocket messages (SQLi, XSS, Command Injection, XXE, SSRF, IDOR), Cross-Site WebSocket Hijacking (CSWSH) exploitation, testing tooling (Burp Suite, WebSocket Turbo Intruder, wsrepl), and defense controls.

## Source Content Topic Breakdown
1. **Protocol Fundamentals**: HTTP vs WebSocket comparison, bidirectional full-duplex communication over single TCP connection, frame structures, text vs binary messages.
2. **Handshake Architecture**: `101 Switching Protocols`, `Upgrade: websocket`, Base64 key generation, and SHA-1 GUID challenge validation.
3. **Socket.IO Framing & Fuzzing**: Engine.IO handshake (`?EIO=4`), frame packet codes (`40` open, `2`/`3` ping/pong, `42` custom event data), and event-level input validation.
4. **Vulnerability Vectors**:
   - Web application vulnerabilities transported inside WebSocket JSON messages (XSS, SQLi, RCE, XXE, IDOR).
   - Cross-Site WebSocket Hijacking (CSWSH) arising from ambient cookie transmission without CSRF tokens during the upgrade handshake.
5. **Tooling & Automation**:
   - Burp Suite Repeater / Interceptor for WebSocket connections.
   - WebSocket Turbo Intruder and `wsrepl` REPL testing.
   - Backslash Powered Scanner fuzzing methodology.
6. **Hardening**: `wss://` TLS enforcement, strict Origin header validation, anti-CSRF handshake tokens, and bidirectional message sanitization.

## Related Pages
- Parent Domain Hub: [[web-and-bug-bounty]]
- Target Concepts: [[websocket-security-and-cross-site-hijacking]], [[csrf-attacks-and-prevention]], [[cross-site-scripting]]
```

## Evidence and uncertainty
Sourced directly from canonical vault notes in Notes/OLD Notes/WEB/vulnerabilities/.
Validated against schema with zero structural contradictions.

## Human feedback
Human decision required via Decision Studio (http://127.0.0.1:20888) or command line.
