---
type: llm-wiki-review
status: needs-review
decision: pending
revision: 1
operation: create
target: sources/xxe.md
sources:
  - raw/articles/xxe.md
---

# Proposed Wiki change

## What will change
Establishes the provenance anchor for XML External Entity (XXE) notes ingested from `unprocessed-obsidians/xxe.md`, linking primary source notes to compiled concepts.

## Proposed content

---
title: Source Note - XML External Entity (XXE) Injection
created: 2026-09-24
updated: 2026-09-24
type: source
tags:
  - xxe
  - bug-bounty
sources:
  - unprocessed-obsidians/xxe.md
extracted_concepts:
  - "[[xml-external-entity-injection]]"
---

# Source Note: XML External Entity (XXE) Injection

> **Provenance Anchor**: Ingested from canonical vault file `[[unprocessed-obsidians/xxe]]`.
> **Compiled Wiki Pages**:
> - Concept: [[xml-external-entity-injection]]

---

## Original Material Overview
The source note synthesizes XML parser vulnerabilities, DTD declaration mechanics, and external entity exploitation:
- **Mechanisms**: XML Document Type Definition (DTD), internal vs external entities, parameter entities (`%entity;`), system identifiers (`SYSTEM`).
- **Exploitation Vectors**: Local file disclosure, SSRF via external entity resolution, denial of service (Billion Laughs XML bomb).
- **Advanced Attack Scenarios**: Out-of-band (OOB) XXE extraction via external DTD hosting, CDATA wrapping for binary/multiline file extraction, error-based XXE exfiltration.
- **Environment Contexts**: Cloud metadata access via XXE, container & Kubernetes environments, SVG upload parsing, Excel (.xlsx) / Office document unpacking.
- **Filter Evasion**: UTF-16 encoding, external parameter entity recursion, character entity references.

## Related Pages
- [[xml-external-entity-injection]]
- [[server-side-request-forgery]]

## Evidence and uncertainty
Directly transcribed and normalized from `unprocessed-obsidians/xxe.md`. Standard XML parsing vulnerabilities and parser configuration hardening.

## Human feedback
Optionally explain or edit what should change.
