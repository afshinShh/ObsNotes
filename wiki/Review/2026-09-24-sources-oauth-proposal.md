---
type: llm-wiki-review
status: needs-review
decision: pending
revision: 1
operation: create
target: sources/oauth.md
sources:
  - raw/articles/oauth.md
---

# Proposed Wiki change

## What will change
Establishes the provenance anchor for OAuth 2.0 and OIDC security testing notes ingested from `unprocessed-obsidians/oauth.md`. Binds the primary vault document to compiled concept and comparison pages.

## Proposed content

---
title: Source Note - OAuth Security Testing
created: 2026-09-24
updated: 2026-09-24
type: source
tags:
  - oauth
  - oidc
  - bug-bounty
  - api
sources:
  - unprocessed-obsidians/oauth.md
extracted_concepts:
  - "[[oauth-grant-types-and-flows]]"
  - "[[oauth-attack-vectors]]"
extracted_comparisons:
  - "[[authorization-code-vs-implicit-flow]]"
---

# Source Note: OAuth Security Testing

> **Provenance Anchor**: Ingested from canonical vault file `[[unprocessed-obsidians/oauth]]`.
> **Compiled Wiki Pages**:
> - Concept: [[oauth-grant-types-and-flows]]
> - Concept: [[oauth-attack-vectors]]
> - Comparison: [[authorization-code-vs-implicit-flow]]

---

## Original Material Overview
The source note covers OAuth 2.0 and OpenID Connect (OIDC) security testing, authorization workflows, vulnerability patterns, and modern hardening standards:
- **Core Flows & Architecture**: Roles (Resource Owner, Client, Authorization Server, Resource Server); Authorization Code Flow with PKCE; Client Credentials; legacy/deprecated Implicit and ROPC flows.
- **Standards & Extensions**: OAuth 2.1 specifications (deprecation of Implicit/ROPC, mandatory PKCE, exact redirect matching, refresh token sender constraint); FAPI 1.0/2.0; PAR (RFC 9126); JAR (RFC 9101); JARM; DPoP (RFC 9449); mTLS.
- **Vulnerability Surface**: `redirect_uri` manipulation (open redirects, path traversal, regex/subdomain bypasses); CSRF & missing `state` parameter leading to forced account linking; authorization code injection / substitution; implicit flow user impersonation; token theft via XSS; scope escalation; IdP confusion in multi-tenant environments; SSRF via `redirect_uri`.

## Related Pages
- [[oauth-grant-types-and-flows]]
- [[oauth-attack-vectors]]
- [[authorization-code-vs-implicit-flow]]

## Evidence and uncertainty
Directly transcribed and normalized from `unprocessed-obsidians/oauth.md`. References RFC 6749, RFC 6819, RFC 7636, RFC 8252, RFC 8628, RFC 8693, RFC 9101, RFC 9126, RFC 9449, and OAuth 2.1 drafts. No factual contradictions.

## Human feedback
Optionally explain or edit what should change.
