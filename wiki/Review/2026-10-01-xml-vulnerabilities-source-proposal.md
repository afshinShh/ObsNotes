---
type: llm-wiki-review
status: needs-review
decision: approve
revision: 1
operation: create
target: web-and-bug-bounty/sources/xml-vulnerabilities.md
sources:
  - Notes/OLD Notes/WEB/vulnerabilities/XML vulnerabilities/concepts.md
  - Notes/OLD Notes/WEB/vulnerabilities/XML vulnerabilities/XXE/concepts and defense.md
  - Notes/OLD Notes/WEB/vulnerabilities/XML vulnerabilities/XXE/METHODOLOGY.md
  - Notes/OLD Notes/WEB/vulnerabilities/XML vulnerabilities/XXE/Examples.md
---
# Proposed Wiki change

## What will change
Create provenance source anchor for XML & XXE notes in Notes/OLD Notes/WEB/vulnerabilities/XML vulnerabilities/.

## Proposed content
```markdown
---
title: "Source Note - XML & XXE: Document Type Definitions, File Retrieval, and Parser Hardening"
created: 2026-10-01
updated: 2026-10-01
type: source
tags:
  - xxe
  - payload
  - web-security
  - bug-bounty
sources:
  - Notes/OLD Notes/WEB/vulnerabilities/XML vulnerabilities/concepts.md
  - Notes/OLD Notes/WEB/vulnerabilities/XML vulnerabilities/XXE/concepts and defense.md
  - Notes/OLD Notes/WEB/vulnerabilities/XML vulnerabilities/XXE/METHODOLOGY.md
  - Notes/OLD Notes/WEB/vulnerabilities/XML vulnerabilities/XXE/Examples.md
extracted_concepts:
  - "[[xml-external-entity-injection]]"
extracted_entities:
  []
extracted_comparisons:
  - "[[classic-vs-blind-xxe]]"
confidence: high
contested: false
contradictions: []
parent: "[[web-and-bug-bounty]]"
cluster: web-and-bug-bounty
---
# Source Note - XML & XXE: Document Type Definitions, File Retrieval, and Parser Hardening

> **Provenance Anchor**: Ingested from canonical vault files under `Notes/OLD Notes/WEB/vulnerabilities/XML vulnerabilities/`.
> - `concepts.md` (126 lines, SHA-256: `64d3600f7223692d99d12bbd6fc29b82bf580436d2222e847c2a74c43ba77f11`)
> - `XXE/concepts and defense.md` (24 lines, SHA-256: `c89a69fa1249fa6b30f0e74f1cfc0fbe640e029aa8784d169a8427f7173b22cf`)
> - `XXE/METHODOLOGY.md` (45 lines, SHA-256: `2b1db1eb44d8b671cc813959c5d0130ceca3fae99ba195b0559e35d1f8f30740`)
> - `XXE/Examples.md` (104 lines, SHA-256: `7d04e5482eef1c1da91845bb08f22fa256037aee1ebc48839b1a5e171b305c48`)
> **Total Raw Lines**: 299 lines

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
- [[xml-external-entity-injection]] — Enriched XML External Entity (XXE) architecture incorporating XML element structures, DTD syntax, general vs parameter entities, SYSTEM entity file exfiltration (`/etc/passwd`), SSRF against cloud metadata, blind out-of-band DTD hosting, error-based extraction, XInclude attacks, and parser feature disablement (`disallow-doctype-decl`).

### Comparisons
- [[classic-vs-blind-xxe]] — In-band response reflection vs blind out-of-band exfiltration and error-based data harvesting.

## Source Content Topic Breakdown
1. **XML Syntax & Architecture**: Elements, empty tags, attributes, comments, namespaces, and Document Type Definitions (DTD).
2. **XXE Root Cause**: XML parsers enabling external entity resolution by default.
3. **Exploitation Vectors**:
   - In-band arbitrary file retrieval (`SYSTEM "file:///etc/passwd"`).
   - SSRF against internal services and cloud link-local metadata (`http://169.254.169.254/latest/meta-data/`).
   - Blind XXE via out-of-band external DTDs and parameter entities (`%eval;`).
   - Error-based extraction triggering intentional parsing exceptions containing file contents.
4. **Remediation**: Disabling external DTDs and entity processing across XML parsers (`FEATURE_SECURE_PROCESSING`, `disallow-doctype-decl`).

## Related Pages
- Parent Domain Hub: [[web-and-bug-bounty]]
- Target Concepts: [[xml-external-entity-injection]], [[server-side-request-forgery]]
- Comparisons: [[classic-vs-blind-xxe]]
```

## Evidence and uncertainty
Sourced directly from canonical vault notes in Notes/OLD Notes/WEB/.
Validated against schema with zero structural contradictions.

## Human feedback
Human decision required via Decision Studio (http://127.0.0.1:20888) or command line.
