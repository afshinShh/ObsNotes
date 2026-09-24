---
type: llm-wiki-review
status: needs-review
decision: pending
revision: 1
operation: create
target: concepts/oauth-attack-vectors.md
sources:
  - raw/articles/oauth.md
---

# Proposed Wiki change

## What will change
Compiles a dedicated concept page detailing OAuth 2.0 and OIDC attack surfaces: `redirect_uri` manipulation (open redirects, path traversal), CSRF and missing `state` parameter, authorization code injection/substitution, implicit flow vulnerabilities, scope elevation, multi-tenant IdP confusion, SSRF via redirect URIs, and full Account Takeover (ATO) exploitation chains.

## Proposed content

---
title: OAuth 2.0 & OIDC Vulnerabilities & Exploitation Vectors
created: 2026-09-24
updated: 2026-09-24
type: concept
tags:
  - oauth
  - oidc
  - csrf
  - open-redirect
  - ato
  - bug-bounty
sources:
  - unprocessed-obsidians/oauth.md
confidence: high
contested: false
contradictions: []
---

# OAuth 2.0 & OIDC Vulnerabilities & Exploitation Vectors

## Overview
OAuth 2.0 and OpenID Connect (OIDC) implementations frequently suffer from integration logic flaws, inadequate input validation on redirection endpoints, misconfigured state bindings, and weak token verification. Flaws in OAuth implementations represent critical vulnerabilities often leading to complete Account Takeover (ATO), private data exfiltration, and lateral privilege escalation.

## Primary Attack Vectors & Primitives

### 1. `redirect_uri` Manipulation & Token/Code Theft
The authorization server redirects the user's browser with the authorization code or access token to the URI specified in `redirect_uri`. Weak validation enables attacker redirection:
- **Open Redirect Chaining**: If the authorization server validates that `redirect_uri` begins with `https://client.com/`, but `client.com` hosts an open redirect (e.g. `/login?next=https://attacker.com`), the attacker chains the parameters:
  ```text
  redirect_uri=https://client.com/oauth/callback?continue=https://attacker.com
  ```
  The authorization code is delivered to `client.com` and immediately forwarded to `attacker.com` via the open redirect.
- **Path Traversal in Redirection**: If regex matching allows directory traversal:
  ```text
  redirect_uri=https://client.com/oauth/callback/../../attacker-endpoint
  ```
- **Subdomain Takeover & Loose Regex Matching**:
  - `https://client.com.attacker.com` (missing regex delimiter anchor)
  - `https://attacker-client.com`
  - Unclaimed subdomains (`https://dev.client.com`) vulnerable to CNAME takeover.
- **Parameter Pollution & Scheme Smuggling**: Injecting duplicate `redirect_uri` parameters or exploiting custom mobile schemes (`app://`).

### 2. Cross-Site Request Forgery (CSRF) & State Manipulation
The `state` parameter acts as a client-side CSRF token binding the authorization response to the user's current session:
- **Missing or Static `state`**: If `state` is omitted or static across requests, an attacker can initiate an OAuth flow against their own social account, capture the resulting callback URL (`/callback?code=ATTACKER_CODE`), and trick a victim into visiting it.
- **Forced Profile Linking**: The victim's application account is bound to the attacker's third-party identity. The attacker subsequently logs in using their third-party credentials and accesses the victim's account.
- **Login CSRF**: Forcing a victim to authenticate as the attacker, enabling session tracking and harvesting sensitive victim activity.

### 3. Authorization Code Injection & Substitution
An attacker intercepts or generates a valid authorization code for Account A and injects it into Account B's callback flow:
- Without PKCE or nonce binding, the backend client exchanges the attacker's code under the victim's session context, linking accounts or escalating permissions.
- **Mitigation**: Require PKCE for all clients; bind `state` and OIDC `nonce` cryptographically to the user's session cookie.

### 4. Implicit Flow Exploitation & User Parameter Tampering
In legacy implicit flows, tokens return in the browser URL fragment:
```text
https://client.com/callback#access_token=y0uR_t0k3n&token_type=Bearer
```
- **Fragment Leakage**: URL fragments leak via `Referer` headers when external scripts or third-party images load, and remain stored in browser history.
- **Client-Side Identity Tampering**: Client applications often receive an access token and simultaneously submit user profile parameters (e.g. `POST /api/login` with `{"email": "admin@target.com", "access_token": "..."}`). If the server relies on the client-supplied email without validating that the access token belongs to that specific user, full user impersonation occurs.

### 5. Scope Escalation & Permission Hijacking
- **Dynamic Scope Expansion**: Manipulating `scope` parameters during authorization requests or refresh token exchanges. If backend authorization servers do not validate requested scopes against pre-assigned client privileges, elevated permissions (e.g. `read` -> `write,admin`) are granted.
- **Pre-Existing Refresh Token Manipulation**: Re-exchanging refresh tokens with upgraded scopes.

### 6. IdP Confusion in Multi-Tenant Deployments
When an application integrates multiple Identity Providers (IdPs) or multi-tenant authorization servers:
- An attacker initiates an authorization flow using IdP A (e.g. attacker-controlled tenant).
- The returned authorization code is submitted to the application's callback configured for IdP B.
- If the application fails to verify the token issuer (`iss`) against the expected IdP, cross-tenant account takeover or unauthorized access occurs.

### 7. SSRF via `redirect_uri`
Certain authorization servers make automated back-channel requests to validate or notify `redirect_uri` endpoints (or during dynamic client registration). Providing internal addresses (`http://169.254.169.254` or `http://localhost:6379`) can trigger Server-Side Request Forgery, connecting to [[blind-ssrf-gopher-redis-rce]].

## Full Account Takeover (ATO) Attack Chains

### Chain A: Open Redirect to Code Theft
```
Victim clicks Malicious Link
   |
   v
Authorization Request: redirect_uri points to Client's Open Redirect
   |
   v
Auth Server issues Authorization Code to Client
   |
   v
Client Open Redirect forwards Code to Attacker Webhook
   |
   v
Attacker exchanges Code at /token endpoint -> Obtains Access Token -> Full ATO
```

### Chain B: CSRF Forced Profile Linking
```
Attacker initiates OAuth with their Google Account -> Halts before /callback
   |
   v
Attacker delivers /callback?code=ATTACKER_CODE to logged-in Victim via CSRF
   |
   v
Victim's session consumes code -> Links Attacker's Google ID to Victim's Account
   |
   v
Attacker logs in via "Sign in with Google" -> Enters Victim's Account
```

### Chain C: XSS to Token Exfiltration & Persistent Access
```
Attacker exploits XSS flaw on Client web application
   |
   v
Script extracts Access and Refresh tokens from localStorage
   |
   v
Exfiltrates tokens to remote C2 server
   |
   v
Attacker uses Refresh Token with rotation bypass to maintain indefinite access
```

## Defensive Hardening Checklist
1. **Enforce OAuth 2.1 Standards**: Deprecate Implicit and ROPC flows completely.
2. **Strict Exact Redirect URI Allowlisting**: No wildcards, no path traversal, exact string matching only.
3. **Mandate Cryptographic State & Nonce**: Enforce unguessable, single-use, session-bound `state` parameters.
4. **Mandate PKCE Everywhere**: Enforce `code_challenge` / `code_verifier` across all clients.
5. **Sender-Constrained Tokens**: Implement DPoP (RFC 9449) or mTLS (RFC 8705).
6. **Refresh Token Rotation (RTR)**: Invalidate family chains upon detecting token reuse.
7. **Secure Token Storage**: Use `__Host-` prefixed `HttpOnly; Secure; SameSite=Strict` cookies or memory-only storage.

## Related Pages
- [[oauth]]
- [[oauth-grant-types-and-flows]]
- [[authorization-code-vs-implicit-flow]]
- [[jwt-attack-vectors]]
- [[jwt-security-mechanisms]]
- [[blind-ssrf-gopher-redis-rce]]

## Evidence and uncertainty
Synthesized from `unprocessed-obsidians/oauth.md` cross-referenced with RFC 6819 (OAuth 2.0 Threat Model), PortSwigger OAuth research, and OAuth 2.1 specifications.

## Human feedback
Optionally explain or edit what should change.
