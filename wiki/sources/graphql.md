---
title: Source Note - GraphQL Security Testing
created: 2026-09-24
updated: 2026-09-24
type: source
tags:
  - graphql
  - api
sources:
  - unprocessed-obsidians/graphql.md
extracted_concepts:
  - "[[graphql-security]]"
---

# Source Note: GraphQL Security Testing

> **Provenance Anchor**: Ingested from canonical vault file `[[unprocessed-obsidians/graphql]]`.
> **Compiled Wiki Pages**:
> - Concept: [[graphql-security]]

---

## Original Material Overview
The source note covers GraphQL architecture, endpoint discovery, reconnaissance, and exploitation attack vectors:
- **Introspection & Reconnaissance**: Enabling introspection queries (`__schema`), schema scraping tools (InQL, GraphQL Voyager, Clairvoyance), field suggestions leakage when introspection is disabled.
- **Authorization & Access Control**: IDOR in GraphQL arguments, missing resolver authorization, over-fetching and sensitive field disclosure, Relay global ID decoding.
- **Denial of Service (DoS)**: Nested recursive query abuse, directive flooding (`@include`/`@skip` parser exhaustion CVE-2024-47614), query batching abuse, circular relationship exploitation.
- **Injection Vectors**: SQLi, NoSQLi, and OS command injection embedded inside GraphQL field arguments; subscription WebSocket vulnerabilities; Apollo / Hasura configuration leakage.

## Related Pages
- [[graphql-security]]
- [[insecure-direct-object-reference]]
