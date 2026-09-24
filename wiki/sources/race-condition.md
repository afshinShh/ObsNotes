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
