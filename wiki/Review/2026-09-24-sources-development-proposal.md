---
type: llm-wiki-review
status: needs-review
decision: pending
revision: 1
operation: create
target: sources/development.md
sources:
  - raw/articles/development.md
---

# Proposed Wiki change

## What will change
Establishes the provenance anchor for Exploit Development notes ingested from `unprocessed-obsidians/development.md`, linking primary source notes to compiled concepts.

## Proposed content

---
title: Source Note - Exploit Development
created: 2026-09-24
updated: 2026-09-24
type: source
tags:
  - rce
  - red-team
sources:
  - unprocessed-obsidians/development.md
extracted_concepts:
  - "[[exploit-development]]"
---

# Source Note: Exploit Development

> **Provenance Anchor**: Ingested from canonical vault file `[[unprocessed-obsidians/development]]`.
> **Compiled Wiki Pages**:
> - Concept: [[exploit-development]]

---

## Original Material Overview
The source note covers binary exploitation engineering, vulnerability root cause classification, and weaponization:
- **Exploit Development Lifecycle**: Bug identification, vulnerability analysis (root cause, trigger identification, impact assessment), weaponization (mitigation bypass, payload development, reliability), and deployment.
- **Memory Corruption Bug Taxonomy**: Stack buffer overflows (SEH overwrite case studies, e.g. CVE-2025-0910 TinyFTP), Use-After-Free (UAF), Heap overflows, concurrency race issues, integer overflows/underflows, incomplete pointer validation, format string flaws, and type confusion.
- **Mitigation Bypasses**: ROP (Return-Oriented Programming) chains to disable DEP/NX, ASLR information leaks, SEHOP considerations.

## Related Pages
- [[exploit-development]]
- [[exploit-mitigations]]

## Evidence and uncertainty
Directly transcribed and normalized from `unprocessed-obsidians/development.md`. Core binary software exploitation primitives.

## Human feedback
Optionally explain or edit what should change.
