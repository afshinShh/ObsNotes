---
type: llm-wiki-review
status: needs-review
decision: pending
revision: 1
operation: create
target: sources/idor.md
sources:
  - raw/articles/idor.md
---

# Proposed Wiki change

## What will change
Establishes the provenance anchor for Insecure Direct Object References (IDOR) notes ingested from `unprocessed-obsidians/idor.md`, linking primary source notes to compiled concepts.

## Proposed content

---
title: Source Note - Insecure Direct Object References (IDOR)
created: 2026-09-24
updated: 2026-09-24
type: source
tags:
  - idor
  - bug-bounty
sources:
  - unprocessed-obsidians/idor.md
extracted_concepts:
  - "[[insecure-direct-object-reference]]"
---

# Source Note: Insecure Direct Object References (IDOR)

> **Provenance Anchor**: Ingested from canonical vault file `[[unprocessed-obsidians/idor]]`.
> **Compiled Wiki Pages**:
> - Concept: [[insecure-direct-object-reference]]

---

## Original Material Overview
The source note covers Insecure Direct Object References (IDOR) identification, testing methodologies, and bypass mechanisms:
- **Core Concepts**: Missing authorization checks, client-side identifier transmission, predictable sequential IDs, reliance on obfuscation (UUIDs, hashes).
- **Two-Account Hunting Methodology**: Setting up dual accounts per role (Attacker vs Victim), intercepting traffic, swapping object identifiers across GET/POST/PUT/DELETE requests.
- **Bypass Techniques**: ID obfuscation bypass (predictable hashes, GUID/UUID leakage via APIs/exports), HTTP verb tampering, file extension manipulation (`.json` vs `.xml`), parameter pollution to bypass access filters, mass assignment combined with IDOR.
- **Architectural Manifestations**: REST APIs, GraphQL mutations, PDF invoice exports, batch operations, multi-tenant boundaries.

## Related Pages
- [[insecure-direct-object-reference]]
- [[graphql-security]]

## Evidence and uncertainty
Directly transcribed and normalized from `unprocessed-obsidians/idor.md`. Standard broken object-level authorization (BOLA) patterns.

## Human feedback
Optionally explain or edit what should change.
