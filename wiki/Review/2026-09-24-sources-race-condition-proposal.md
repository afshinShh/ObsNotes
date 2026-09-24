---
type: llm-wiki-review
status: needs-review
decision: pending
revision: 1
operation: create
target: sources/race-condition.md
sources:
  - raw/articles/race-condition.md
---

# Proposed Wiki change

## What will change
Establishes the provenance anchor for Race Condition security notes ingested from `unprocessed-obsidians/race-condition.md`, linking primary source notes to compiled concepts.

## Proposed content

---
title: Source Note - Race Conditions
created: 2026-09-24
updated: 2026-09-24
type: source
tags:
  - race-condition
  - bug-bounty
sources:
  - unprocessed-obsidians/race-condition.md
extracted_concepts:
  - "[[race-condition-attacks]]"
---

# Source Note: Race Conditions

> **Provenance Anchor**: Ingested from canonical vault file `[[unprocessed-obsidians/race-condition]]`.
> **Compiled Wiki Pages**:
> - Concept: [[race-condition-attacks]]

---

## Original Material Overview
The source note covers race conditions and concurrency flaws in web applications:
- **Mechanisms**: Time-of-Check to Time-of-Use (TOCTOU), Read-Modify-Write desynchronization, thread safety issues, resource allocation races.
- **Vulnerable Business Logic**: Account balance manipulation, coupon/voucher reuse, multi-redemption gifts, file upload validation race windows, single-use token exhaustion.
- **Testing & Exploitation Methodology**: Turbo Intruder concurrency scripting, HTTP/2 single-packet attack (synchronizing multiple requests in one TCP packet via stream multiplexing), database transaction isolation testing (Read Committed vs Serializable).
- **Environment Contexts**: Microservices distributed state, WebSocket race conditions, cloud and serverless concurrency limits.

## Related Pages
- [[race-condition-attacks]]
- [[insecure-direct-object-reference]]

## Evidence and uncertainty
Directly transcribed and normalized from `unprocessed-obsidians/race-condition.md`. Standard web application concurrency testing.

## Human feedback
Optionally explain or edit what should change.
