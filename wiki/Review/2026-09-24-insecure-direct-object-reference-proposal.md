---
type: llm-wiki-review
status: needs-review
decision: pending
revision: 1
operation: create
target: concepts/insecure-direct-object-reference.md
sources:
  - raw/articles/idor.md
---

# Proposed Wiki change

## What will change
Compiles a dedicated concept page detailing Insecure Direct Object References (IDOR / BOLA) attack mechanics, testing methodology, identifier obfuscation bypasses, and access control validation.

## Proposed content

---
title: Insecure Direct Object References (IDOR / BOLA)
created: 2026-09-24
updated: 2026-09-24
type: concept
tags:
  - idor
  - business-logic
  - bug-bounty
sources:
  - unprocessed-obsidians/idor.md
confidence: high
contested: false
contradictions: []
---

# Insecure Direct Object References (IDOR / BOLA)

## Overview
Insecure Direct Object References (IDOR)—categorized in the OWASP API Top 10 as Broken Object Level Authorization (BOLA)—occur when an application accepts a user-supplied identifier to access or manipulate a backend database record or file without verifying that the authenticated user possesses authorization for that specific object. Exploitation results in unauthorized data access (horizontal privilege escalation) or administrative action execution (vertical privilege escalation).

## IDOR Classification Matrix

| Access Control Failure | Attack Pattern | Example Scenario |
| :--- | :--- | :--- |
| **Horizontal Escalation** | User accesses resources belonging to another user with identical role privileges. | User A requests `GET /api/documents/102` (belonging to User B) and receives User B's file. |
| **Vertical Escalation** | Regular user modifies identifiers to access administrative or restricted resources. | User A requests `POST /api/roles/1` with payload `{"user_id": 42}` and assigns admin rights. |
| **Contextual / Multi-Tenant** | User bypasses tenant boundaries in multi-tenant SaaS environments. | Organization A accesses Organization B's billing records by substituting `org_id` in headers or URL. |

## Systematic Hunting Methodology (Dual-Account Flow)

```
+--------------------+        +---------------------+
| Attacker Account A |        |   Victim Account B  |
+--------------------+        +---------------------+
          |                              |
    1. Intercept Traffic           2. Note Target IDs
          |                              |
          +-----------> [ Proxy ] <------+
                            |
                 3. Swap IDs in Request
                    (A's Token + B's ID)
                            |
                            v
               +--------------------------+
               |  Server Evaluates IDOR   |
               +--------------------------+
                 /                            200 OK (Data Leaked)       403 Forbidden / 404
      [ IDOR Confirmed ]         [ Try Bypass Techniques ]
```

## Advanced IDOR Bypass Techniques

### 1. Obfuscated / Non-Sequential Identifier Bypasses
- **Public Reference Leakage**: Applications that use UUIDs or hashes often expose them in public profiles, user activity feeds, comment metadata, or export files.
- **Numeric ID Substitution**: Even if APIs display UUIDs (`/users/a9b8c7...`), internal endpoints may still accept legacy sequential integer IDs (`/users/102` or `?user_id=102`).
- **Hash Prediction**: Check if hashes are MD5/SHA1 of sequential IDs, email addresses, or timestamps.

### 2. HTTP Method & Content-Type Tampering
- Changing HTTP verbs: If `GET /api/user/102` is forbidden, try `POST /api/user/102`, `PUT`, `PATCH`, or `DELETE`.
- Content-Type switching: Requesting `application/xml` instead of `application/json` may trigger a secondary parser with missing authorization checks.

### 3. Parameter Pollution & Array Wrapping
- Injecting duplicate parameters: `GET /api/data?id=OWN_ID&id=VICTIM_ID`
- Injecting arrays: `{"id": [OWN_ID, VICTIM_ID]}`

### 4. Mass Assignment Combined with IDOR
Modifying user profiles where unvalidated JSON keys bind to underlying database models:
```json
{
  "name": "Attacker",
  "account_id": 1002,
  "is_admin": true
}
```

## Defensive Hardening
1. **Validate Authorization at Object Level**: Always check that `resource.owner_id == session.user_id` on every database query.
2. **Indirect Object References**: Utilize session-mapped reference maps (e.g. mapping `item_1` to real ID `94821` inside the user session) instead of exposing database primary keys.
3. **Enforce Tenant Context in Queries**: Prepend tenant ID constraints automatically to all database lookups: `SELECT * FROM invoices WHERE id = :id AND organization_id = :current_org_id`.

## Related Pages
- [[idor]]
- [[graphql-security]]
- [[http-request-smuggling]]
- [[http-parameter-pollution]]
- [[race-condition-attacks]]

## Evidence and uncertainty
Synthesized from `unprocessed-obsidians/idor.md`. Covers horizontal/vertical access control failures, dual-account testing workflow, and identifier obfuscation bypasses.

## Human feedback
Optionally explain or edit what should change.
