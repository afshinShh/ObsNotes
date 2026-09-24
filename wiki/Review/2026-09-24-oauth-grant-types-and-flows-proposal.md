---
type: llm-wiki-review
status: needs-review
decision: pending
revision: 1
operation: create
target: concepts/oauth-grant-types-and-flows.md
sources:
  - raw/articles/oauth.md
---

# Proposed Wiki change

## What will change
Compiles a dedicated concept page documenting OAuth 2.0 and OpenID Connect (OIDC) architecture, primary grant types, flow sequence mechanics, OAuth 2.1 modern specifications, and advanced enterprise extensions (PAR, JAR, JARM, FAPI).

## Proposed content

---
title: OAuth 2.0 & OIDC Grant Types and Flow Architecture
created: 2026-09-24
updated: 2026-09-24
type: concept
tags:
  - oauth
  - oidc
  - api
  - business-logic
sources:
  - unprocessed-obsidians/oauth.md
confidence: high
contested: false
contradictions: []
---

# OAuth 2.0 & OIDC Grant Types and Flow Architecture

## Overview
OAuth 2.0 ([RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)) is an authorization framework that enables third-party applications to obtain limited access to an HTTP service on behalf of a resource owner. OpenID Connect (OIDC) builds on OAuth 2.0 to provide identity authentication via standardized JSON Web Tokens (`id_token`).

## Architectural Roles
```
                +-------------------+
                |   Resource Owner  |
                |    (End User)     |
                +-------------------+
                     ^         |
        (Consent)    |         | (Authorization)
                     |         v
+--------------+  Authorization   +----------------------+
|    Client    | --------------> | Authorization Server |
|  (App/SPA)   | <-------------- |  (Issues Tokens)     |
+--------------+   Access Token   +----------------------+
       |
       | Access Token
       v
+----------------------+
|   Resource Server    |
| (Hosts Protected API)|
+----------------------+
```
- **Resource Owner**: The entity capable of granting access to a protected resource (end-user).
- **Client**: The application requesting access to protected resources (web app, mobile app, SPA).
- **Authorization Server**: The server issuing access tokens to the client after successfully authenticating the resource owner.
- **Resource Server**: The server hosting protected resources, accepting and validating access tokens.

## Token Types
- **Access Token**: Short-lived credential granting specific scopes to protected APIs. May be opaque or structured (JWT).
- **Refresh Token**: Long-lived credential used to obtain new access tokens without prompting the user.
- **ID Token (OIDC)**: Cryptographically signed JWT containing user authentication assertions (`sub`, `iss`, `aud`, `auth_time`).

## Primary Grant Types & Flow Analysis

### 1. Authorization Code Flow with PKCE (RFC 7636)
The standard, secure authorization grant for web applications, mobile native clients, and SPAs:
1. **Authorization Request**:
   ```http
   GET /authorize?response_type=code
     &client_id=12345
     &redirect_uri=https://client.com/callback
     &scope=openid%20profile%20email
     &state=xyzSecretNonce
     &code_challenge=E9Mel-2O2...
     &code_challenge_method=S256 HTTP/1.1
   Host: auth.example.com
   ```
2. **User Consent & Redirect**: Authorization server authenticates user and redirects with authorization code:
   ```http
   HTTP/1.1 302 Found
   Location: https://client.com/callback?code=AUTH_CODE_abc123&state=xyzSecretNonce
   ```
3. **Back-Channel Token Exchange**:
   ```http
   POST /token HTTP/1.1
   Host: auth.example.com
   Content-Type: application/x-www-form-urlencoded

   grant_type=authorization_code
     &code=AUTH_CODE_abc123
     &redirect_uri=https://client.com/callback
     &client_id=12345
     &client_secret=SECRET_KEY
     &code_verifier=dBjftJeZ4CVP-mB92K...
   ```
4. **Token Response**: Server validates `code_verifier` hash against `code_challenge` and returns `access_token` and `refresh_token`.

### 2. Client Credentials Flow
Used for machine-to-machine (M2M) server communications without user context. The client authenticates directly to the token endpoint using `client_id` and `client_secret` to obtain an access token.

### 3. Implicit Flow (RFC 6749 — Deprecated)
Legacy flow where tokens are returned directly in the URL fragment (`#access_token=...`) on the front-channel. It lacks client authentication, exposes tokens to browser history and Referer headers, and cannot issue refresh tokens securely. Deprecated in OAuth 2.1.

### 4. Resource Owner Password Credentials (ROPC — Deprecated)
Legacy flow where the client collects the user's raw username and password directly. Violates separation of credentials and prevents MFA/federation. Deprecated in OAuth 2.1.

### 5. Device Authorization Flow (RFC 8628)
Designed for browserless or input-constrained devices (smart TVs, CLI tools). The device obtains a user code and verification URI, prompting the user to complete authorization on a secondary browser.

## OAuth 2.1 Modern Security Profile
OAuth 2.1 consolidates and updates OAuth 2.0 specifications to eliminate established attack vectors:
- **Implicit Grant Completely Removed**: No `response_type=token`.
- **ROPC Grant Completely Removed**: Direct password exchange prohibited.
- **PKCE Mandatory for All Clients**: Required for both public and confidential clients.
- **Exact Redirect URI Matching**: Authorization servers must require exact string matching of `redirect_uri` against pre-registered URIs; wildcards and path matching are forbidden.
- **Refresh Token Sender-Constraining**: Refresh tokens must either be sender-constrained (via DPoP or mTLS) or implement Refresh Token Rotation with automatic reuse detection.

## Advanced Security Extensions

### PAR (Pushed Authorization Requests - RFC 9126)
Instead of passing authorization parameters via HTTP GET query strings in the front-channel browser URL, the client pushes parameters directly to the authorization server via a secure back-channel HTTP POST. The server returns a short-lived `request_uri` reference used in the front-channel redirect, shielding sensitive data from URL leakage and interception.

### JAR (JWT-Secured Authorization Request - RFC 9101) & JARM
- **JAR**: Encapsulates authorization request parameters into a cryptographically signed JWT (`request` parameter), ensuring integrity and non-repudiation.
- **JARM**: Signs and optionally encrypts authorization responses from the authorization server, preventing response tampering and parameter injection.

### FAPI (Financial-grade API)
Security profile designed for high-risk financial environments (Open Banking). FAPI 1.0/2.0 mandates PAR, MTLS or DPoP token binding, private_key_jwt client authentication, and strict cryptographic suites.

## Related Pages
- [[oauth]]
- [[oauth-attack-vectors]]
- [[authorization-code-vs-implicit-flow]]
- [[jwt-security-mechanisms]]
- [[jwt-attack-vectors]]

## Evidence and uncertainty
Synthesized from `unprocessed-obsidians/oauth.md` cross-referenced with RFC 6749, RFC 6819, RFC 7636, RFC 8252, RFC 9101, RFC 9126, RFC 9449, and OAuth 2.1 specifications.

## Human feedback
Optionally explain or edit what should change.
