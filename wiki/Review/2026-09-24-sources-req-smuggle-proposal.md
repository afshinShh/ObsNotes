---
type: llm-wiki-review
status: needs-review
decision: pending
revision: 1
operation: create
target: sources/req-smuggle.md
sources:
  - raw/articles/req-smuggle.md
---

# Proposed Wiki change

## What will change
Establishes the provenance anchor for HTTP Request Smuggling notes ingested from `unprocessed-obsidians/req-smuggle.md`, linking primary source notes to compiled concepts and side-by-side comparisons.

## Proposed content

---
title: Source Note - HTTP Request Smuggling
created: 2026-09-24
updated: 2026-09-24
type: source
tags:
  - request-smuggling
  - bug-bounty
sources:
  - unprocessed-obsidians/req-smuggle.md
extracted_concepts:
  - "[[http-request-smuggling]]"
extracted_comparisons:
  - "[[cl-te-vs-te-cl]]"
---

# Source Note: HTTP Request Smuggling

> **Provenance Anchor**: Ingested from canonical vault file `[[unprocessed-obsidians/req-smuggle]]`.
> **Compiled Wiki Pages**:
> - Concept: [[http-request-smuggling]]
> - Comparison: [[cl-te-vs-te-cl]]

---

## Original Material Overview
The source note covers HTTP Request Smuggling and message desynchronization across multi-tier HTTP architectures:
- **Mechanisms**: Disagreements between Content-Length (CL) and Transfer-Encoding (TE) headers; CL.TE, TE.CL, and TE.TE desync conditions.
- **HTTP/2 & Modern Desync**: H2.CL and H2.TE downgrades, cleartext HTTP/2 (`h2c`) upgrade smuggling, authority vs Host normalization mismatches.
- **Exploitation Impact**: Request queue poisoning, response harvesting, security control bypass, client credential hijacking, cache poisoning.
- **Testing & Tooling**: Differential timing probes, Smuggler, HTTP Request Smuggler (Burp Suite), turbo-intruder.

## Related Pages
- [[http-request-smuggling]]
- [[cl-te-vs-te-cl]]

## Evidence and uncertainty
Directly transcribed and normalized from `unprocessed-obsidians/req-smuggle.md`. Grounded in RFC 7230, RFC 9112, and PortSwigger HTTP request smuggling research.

## Human feedback
Optionally explain or edit what should change.
