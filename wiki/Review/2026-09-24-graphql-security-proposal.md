---
type: llm-wiki-review
status: needs-review
decision: pending
revision: 1
operation: create
target: concepts/graphql-security.md
sources:
  - raw/articles/graphql.md
---

# Proposed Wiki change

## What will change
Compiles a dedicated concept page detailing GraphQL security risks, introspection extraction, field suggestion harvesting, directive flooding DoS, batching abuse, and resolver authorization flaws.

## Proposed content

---
title: GraphQL Security Architecture & Exploitation Vectors
created: 2026-09-24
updated: 2026-09-24
type: concept
tags:
  - graphql
  - api
  - bug-bounty
sources:
  - unprocessed-obsidians/graphql.md
confidence: high
contested: false
contradictions: []
---

# GraphQL Security Architecture & Exploitation Vectors

## Overview
GraphQL is a query language and server-side runtime for APIs that executes queries using a type system defined for the application data. Unlike REST architectures that expose fixed endpoint structures, GraphQL allows clients to define the exact shape and nesting of responses. This flexibility introduces distinct attack surfaces: schema disclosure via introspection, parser resource exhaustion via recursive queries, batching abuse, and inconsistent authorization checks at the field and resolver layers.

## Core Vulnerability Taxonomy

```
+---------------------------------------------------------------+
|                    GraphQL Vulnerabilities                    |
+---------------------------------------------------------------+
        |                     |                       |
        v                     v                       v
[ Recon & Info Leak ]   [ Resource DoS ]    [ Authorization Flaws ]
- Introspection Query   - Nested Queries    - Resolver IDOR
- Field Suggestions     - Batching Abuse    - Broken Field Auth
- Error Messages        - Directive Flood   - Apollo/Hasura Gaps
```

### 1. Schema Reconnaissance & Introspection
If introspection is enabled in production, attackers can extract the complete API schema:
```graphql
query {
  __schema {
    types {
      name
      fields {
        name
        args { name type { name kind } }
      }
    }
  }
}
```
**Bypassing Disabled Introspection via Field Suggestions**:
When introspection is disabled, GraphQL engines (such as Apollo) often provide "Did you mean..." suggestions in error responses when querying non-existent fields:
```json
{"errors": [{"message": "Cannot query field 'pass' on type 'User'. Did you mean 'password'?"}]}
```
Tools like `clairvoyance` automate dictionary-based brute forcing against field suggestions to reconstruct the schema without introspection.

### 2. Denial of Service (DoS) Vectors
- **Circular Nested Queries**: Exploiting relational links to force expensive deep database queries:
  ```graphql
  query {
    user(id: 1) {
      friends {
        friends {
          friends {
            friends { name }
          }
        }
      }
    }
  }
  ```
- **Query Batching Abuse**: Sending an array of queries in a single HTTP request to bypass rate limiting or trigger backend exhaustion:
  ```json
  [{"query": "mutation { login(...) }"}, {"query": "mutation { login(...) }"}]
  ```
- **Directive Flooding**: Appending thousands of directives (`@include(if: true)`) in a single query exhausts the AST validation parser before execution (e.g. CVE-2024-47614 in async-graphql).

### 3. Resolver Authorization Flaws & IDOR
In GraphQL, authorization must be validated at the **field / resolver level**, not merely at the HTTP gateway:
- If a root query `user(id: Int)` validates user permissions, but an associated nested field `order { invoice { downloadUrl } }` fails to enforce ownership checks on the requested invoice ID, attackers manipulate parameters in nested queries to achieve horizontal or vertical privilege escalation.
- **Relay Global ID Exposure**: Base64-encoded strings (`base64("User:42")`) can be decoded, manipulated to target other users (`base64("User:1")`), and re-injected.

### 4. Injection in Resolver Arguments
GraphQL types validate input format (e.g. `String`, `Int`), but do not sanitize semantic content. If a resolver takes a `filter: String` argument and passes it into a raw database query, classic SQL injection, NoSQL injection, or command injection occurs.

## Defensive Hardening
1. **Disable Introspection in Production**: Restrict `__schema` and `__type` queries to development environments.
2. **Disable Field Suggestions**: Suppress descriptive error hints in production configurations.
3. **Enforce Query Depth and Cost Analysis**: Reject queries exceeding maximum depth (e.g. max depth 5) and assign complexity weights to fields.
4. **Enforce Persisted Queries (Allowlisting)**: Only execute pre-registered query hashes approved by the frontend build pipeline.
5. **Resolver-Level Access Control**: Validate authorization inside every resolver function independently.

## Related Pages
- [[graphql]]
- [[insecure-direct-object-reference]]
- [[sql-injection-testing]]
- [[race-condition-attacks]]

## Evidence and uncertainty
Synthesized from `unprocessed-obsidians/graphql.md`. Covers schema reconnaissance, query complexity DoS, and resolver-level authorization vulnerabilities.

## Human feedback
Optionally explain or edit what should change.
