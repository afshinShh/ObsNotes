---
title: JWT Bearer Tokens in OAuth 2.0 & OIDC Architecture
created: 2026-09-25
updated: 2026-09-25
type: comparison
tags:
  - jwt
  - oauth
  - oidc
  - authentication
sources:
  - concepts/jwt-security-mechanisms.md
  - concepts/oauth-grant-types-and-flows.md
---

# JWT Bearer Tokens in OAuth 2.0 & OIDC Architecture

## Conceptual Integration
In modern identity systems, JSON Web Tokens ([[jwt-security-mechanisms]]) provide the self-contained token format powering OAuth 2.0 grant types ([[oauth-grant-types-and-flows]]):

1. **Access Tokens:** Authorization servers issue signed JWT access tokens containing user scopes, roles, and expiration claims (`exp`, `sub`, `aud`), enabling stateless verification by resource servers.
2. **ID Tokens (OIDC):** OpenID Connect strictly mandates JWT formatted ID tokens signed by the IdP (using RS256/ES256) asserting user identity.
3. **Client Assertions (RFC 7523):** Clients use private-key signed JWTs instead of client secrets for mTLS and high-assurance OAuth client authentication.

## Attack Surface Intersection
- **Signature Stripping in Callback:** If the OAuth client receives an ID token or access token and fails to verify `alg: none` ([[jwt-attack-vectors]]), identity impersonation succeeds.
- **Key Confusion across Providers:** In multi-tenant OAuth, using the authorization server's public key as an HMAC secret allows forging valid client tokens.

## Related Notes
- [[jwt-security-mechanisms]]
- [[jwt-attack-vectors]]
- [[oauth-grant-types-and-flows]]
- [[oauth-attack-vectors]]
- [[authorization-code-vs-implicit-flow]]
