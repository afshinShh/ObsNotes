---
title: "Source Note - SSRF: Loopback Attacks, Defense Bypasses, and REST Pivoting"
created: 2026-10-01
updated: 2026-10-01
type: source
tags:
  - ssrf
  - payload
  - cloud-iam
  - bug-bounty
sources:
  - Notes/OLD Notes/WEB/vulnerabilities/SSRF/concepts and defense.md
  - Notes/OLD Notes/WEB/vulnerabilities/SSRF/METHODOLOGY.md
  - Notes/OLD Notes/WEB/vulnerabilities/SSRF/Examples.md
extracted_concepts:
  - "[[server-side-request-forgery]]"
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
# Source Note - SSRF: Loopback Attacks, Defense Bypasses, and REST Pivoting

> **Provenance Anchor**: Ingested from canonical vault files under `Notes/OLD Notes/WEB/vulnerabilities/SSRF/`.
> - `concepts and defense.md` (9 lines, SHA-256: `6cff81816e81fbb4ef0c60f2fa5001ff800c7324bfbca5a6e87fec19894e666a`)
> - `METHODOLOGY.md` (59 lines, SHA-256: `a93b4f6b21659a58406560ee1f47f2db43df07856cbf260aebcce9cf3e1c9451`)
> - `Examples.md` (40 lines, SHA-256: `65cfda7ebc4e366da9bcba58a74ec4101c107c8a49c6cb4b88b0f72382f1c841`)
> **Total Raw Lines**: 108 lines

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
- [[server-side-request-forgery]] — Enriched SSRF concepts detailing loopback attacks against local REST APIs, trust relationship exploitation, IP representation bypasses (decimal, octal, dotted shorthand), whitelist circumvention via credentials and URL fragments, open redirect chaining, and administrative action execution.

## Source Content Topic Breakdown
1. **SSRF Against the Server**: Loopback interface exploitation (`http://localhost/admin`, `http://127.0.0.1/admin/deleteUser?username=carlos`).
2. **SSRF Against Backend Systems**: Scanning private non-routable subnets (`192.168.0.X:8080`) through stock check REST proxies.
3. **Bypassing Blacklists**:
   - Alternative loopback IP formats: Decimal `2130706433`, Octal `017700000001`, Shorthand `127.1`.
   - Domain-based loopback resolution: `localhost.attacker.com`.
   - URL encoding and case sensitivity tricks.
4. **Bypassing Whitelists via Open Redirect**:
   - Chaining an open redirect on an approved domain: `stockApi=http://whitelisted.target.com/redirect?url=http://127.0.0.1/admin`.
5. **Blind SSRF Testing**: Triggering out-of-band HTTP/DNS lookups to Burp Collaborator.

## Related Pages
- Parent Domain Hub: [[web-and-bug-bounty]]
- Target Concepts: [[server-side-request-forgery]], [[blind-ssrf-gopher-redis-rce]], [[fastcgi-ssrf-exploitation]]
