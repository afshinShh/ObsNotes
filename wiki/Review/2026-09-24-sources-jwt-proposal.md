---
type: llm-wiki-review
status: needs-review
decision: pending
revision: 1
operation: create
target: sources/jwt.md
sources:
  - raw/articles/jwt.md
---

# Proposed Wiki change

## What will change
Establishes the provenance anchor for JSON Web Tokens (JWT) security notes ingested from `unprocessed-obsidians/jwt.md`. Links the primary source to compiled entity, concept, and comparison pages.

## Proposed content

---
title: Source Note - JSON Web Tokens (JWT) Security
created: 2026-09-24
updated: 2026-09-24
type: source
tags:
  - jwt
  - bug-bounty
  - api
sources:
  - unprocessed-obsidians/jwt.md
extracted_entities:
  - "[[jwt-tool]]"
extracted_concepts:
  - "[[jwt-security-mechanisms]]"
  - "[[jwt-attack-vectors]]"
extracted_comparisons:
  - "[[jwt-vs-session-cookies]]"
---

# Source Note: JSON Web Tokens (JWT) Security

> **Provenance Anchor**: Ingested from canonical vault file `[[unprocessed-obsidians/jwt]]`.
> **Compiled Wiki Pages**:
> - Entity: [[jwt-tool]]
> - Concept: [[jwt-security-mechanisms]]
> - Concept: [[jwt-attack-vectors]]
> - Comparison: [[jwt-vs-session-cookies]]

---

## Original Material Overview
The source note synthesizes JSON Web Token (RFC 7519) security architectures, attack vectors, and penetration testing methodologies:
- **Mechanisms**: Header, payload, and cryptographic signature breakdown; asymmetric vs symmetric algorithms (HS*, RS*, ES*, PS*, EdDSA, none); JWS vs JWE handling; sender-constrained token binding (DPoP RFC 9449, mTLS).
- **Vulnerabilities**: Algorithm `none` bypasses; RS256 to HS256 key confusion; header injection (`jwk`, `jku`, `x5u`, `kid`); HMAC weak key brute forcing and timing attacks; multi-auth confusion (SAML, API keys, session cookies, OAuth ID vs access tokens).
- **Storage & Transport**: Mobile insecure token storage (Android SharedPreferences, iOS Keychain/backups); URL parameter leakage in GET queries and Referer headers.
- **Tooling**: `jwt_tool`, `jwt.io`, Burp Suite JWT extensions, and `c-jwt-cracker`.

## Related Pages
- [[jwt-security-mechanisms]]
- [[jwt-attack-vectors]]
- [[jwt-vs-session-cookies]]
- [[jwt-tool]]

## Evidence and uncertainty
Directly transcribed and normalized from `unprocessed-obsidians/jwt.md`. The note represents established offensive security knowledge and standard RFC specifications (RFC 7519, RFC 9449). No unresolved contradictions exist.

## Human feedback
Optionally explain or edit what should change.
