---
title: Source Note - Server-Side Request Forgery (SSRF)
created: 2026-09-24
updated: 2026-09-24
type: source
tags:
  - ssrf
  - bug-bounty
sources:
  - unprocessed-obsidians/ssrf.md
extracted_concepts:
  - "[[server-side-request-forgery]]"
---

# Source Note: Server-Side Request Forgery (SSRF)

> **Provenance Anchor**: Ingested from canonical vault file `[[unprocessed-obsidians/ssrf]]`.
> **Compiled Wiki Pages**:
> - Concept: [[server-side-request-forgery]]

---

## Original Material Overview
The source note covers Server-Side Request Forgery (SSRF) detection, bypasses, and exploitation tactics:
- **SSRF Types**: In-band SSRF (reflected response), Blind SSRF (out-of-band callback listeners), Semi-blind (timing and error differentials).
- **Filter Evasion Taxonomy**: Denylist bypasses (alternative IP representations: decimal, octal, hex, IPv6, 0.0.0.0, 127.1), DNS rebinding attacks, open redirect chaining, parser confusion (URL schemes, userinfo `@` trick).
- **Cloud Metadata Targets**: AWS IMDSv1 vs IMDSv2, GCP metadata, Azure instance metadata, Kubernetes pod identity APIs.
- **Specialized Primitives**: PDF rendering engines SSRF, protocol smuggling via `gopher://` (cross-linked to `[[blind-ssrf-gopher-redis-rce]]` and `[[fastcgi-ssrf-exploitation]]`).

## Related Pages
- [[server-side-request-forgery]]
- [[xml-external-entity-injection]]
