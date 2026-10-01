---
type: llm-wiki-review
status: needs-review
decision: approve
revision: 1
operation: create
target: web-and-bug-bounty/sources/cors.md
sources:
  - Notes/OLD Notes/WEB/vulnerabilities/CORS/concepts.md
  - Notes/OLD Notes/WEB/vulnerabilities/CORS/METHODOLOGY.md
  - Notes/OLD Notes/WEB/vulnerabilities/CORS/Examples.md
---
# Proposed Wiki change

## What will change
Create provenance source anchor for CORS notes in Notes/OLD Notes/WEB/vulnerabilities/CORS/.

## Proposed content
```markdown
---
title: "Source Note - CORS: Concepts, Methodology, and Exploitation"
created: 2026-10-01
updated: 2026-10-01
type: source
tags:
  - web-security
  - api
  - payload
  - bug-bounty
sources:
  - Notes/OLD Notes/WEB/vulnerabilities/CORS/concepts.md
  - Notes/OLD Notes/WEB/vulnerabilities/CORS/METHODOLOGY.md
  - Notes/OLD Notes/WEB/vulnerabilities/CORS/Examples.md
extracted_concepts:
  - "[[cors-vulnerabilities-and-exploitation]]"
extracted_entities:
  []
extracted_comparisons:
  - "[[csrf-vs-cors-security]]"
confidence: high
contested: false
contradictions: []
parent: "[[web-and-bug-bounty]]"
cluster: web-and-bug-bounty
---
# Source Note - CORS: Concepts, Methodology, and Exploitation

> **Provenance Anchor**: Ingested from canonical vault files under `Notes/OLD Notes/WEB/vulnerabilities/CORS/`.
> - `concepts.md` (85 lines, SHA-256: `6b06ee4d7c056dc1c66bab793aef0bfc86dccda91189a8d21687f562cc60b83f`)
> - `METHODOLOGY.md` (16 lines, SHA-256: `993c7bf42013f775d63b2c7f1abad3aa73f0dfed6cbdb7e120a97aa92a3e6e9e`)
> - `Examples.md` (64 lines, SHA-256: `ddbd04212dbc1f863775ae6276a1deb03f9f3a5e2248e4df395bd262ecaae702`)
> **Total Raw Lines**: 165 lines

---

<!-- TOC_START -->
## Table of Contents
- [Compiled Wiki Layers](#compiled-wiki-layers)
  - [Concepts](#concepts)
  - [Comparisons](#comparisons)
- [Source Content Topic Breakdown](#source-content-topic-breakdown)
- [Related Pages](#related-pages)
<!-- TOC_END -->

## Compiled Wiki Layers
### Concepts
- [[cors-vulnerabilities-and-exploitation]] — Core mechanics of Same-Origin Policy (SOP), CORS headers, preflight requests, arbitrary origin reflection with ACAC, null origin trust via sandboxed iframes, flawed regex bypasses, and data exfiltration PoCs.

### Comparisons
- [[csrf-vs-cors-security]] — Structural comparison between CSRF (unauthorized state-changing actions) and CORS misconfigurations (unauthorized cross-origin data extraction).

## Source Content Topic Breakdown
1. **SOP Foundations & Workarounds**: PostMessage, JSONP, and CORS header specifications.
2. **Preflight Mechanics**: Simple requests (`GET`, `POST`, `HEAD` with safe Content-Types) vs preflight `OPTIONS` requests (`Access-Control-Request-Method`, `Access-Control-Request-Headers`).
3. **Four Primary Misconfigurations**:
   - Case 1: Arbitrary origin reflection with `Access-Control-Allow-Credentials: true`.
   - Case 2: Flawed regex matching prefix/suffix bypasses (`company.com.attacker.com`).
   - Case 3: Whitelisting `null` origin exploitable via local files or sandboxed iframes.
   - Case 4: Insecure subdomain trust / XSS chaining.
4. **Weaponized PoCs**: Full asynchronous XMLHttpRequest and Fetch exfiltration payloads using base64 data URLs in iframe sandboxes.

## Related Pages
- Parent Domain Hub: [[web-and-bug-bounty]]
- Target Concepts: [[cors-vulnerabilities-and-exploitation]], [[csrf-attacks-and-prevention]], [[cross-site-scripting]]
```

## Evidence and uncertainty
Sourced directly from canonical vault notes in Notes/OLD Notes/WEB/vulnerabilities/.
Validated against schema with zero structural contradictions.

## Human feedback
Human decision required via Decision Studio (http://127.0.0.1:20888) or command line.
