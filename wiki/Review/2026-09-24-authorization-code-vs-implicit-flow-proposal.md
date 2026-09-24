---
type: llm-wiki-review
status: needs-review
decision: approve
revision: 1
operation: create
target: comparisons/authorization-code-vs-implicit-flow.md
sources:
  - raw/articles/oauth.md
---

# Proposed Wiki change

## What will change
Compiles a technical comparison evaluating the OAuth 2.0 Authorization Code Flow (enhanced with PKCE) versus the legacy Implicit Flow, detailing security boundaries and explaining the technical rationale behind the deprecation of the Implicit Flow in OAuth 2.1.

## Proposed content

---
title: Authorization Code Flow (with PKCE) vs Implicit Flow
created: 2026-09-24
updated: 2026-09-24
type: comparison
tags:
  - oauth
  - oidc
  - api
sources:
  - unprocessed-obsidians/oauth.md
confidence: high
contested: false
contradictions: []
---

# Authorization Code Flow (with PKCE) vs Implicit Flow

## Overview
OAuth 2.0 ([RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)) originally defined the Implicit Flow for single-page applications (SPAs) and client-side web apps that could not securely maintain a client secret. Subsequent security analyses revealed fundamental vulnerabilities in transmitting access tokens via front-channel browser redirects. Consequently, the OAuth Working Group deprecated the Implicit Flow in OAuth 2.1 in favor of the Authorization Code Flow with Proof Key for Code Exchange (PKCE / RFC 7636).

## Side-by-Side Comparison Matrix

| Technical Dimension | Authorization Code Flow (with PKCE) | Legacy Implicit Flow | Security Impact |
| :--- | :--- | :--- | :--- |
| **Response Type** | `response_type=code` | `response_type=token` | Authorization code is a temporary intermediate ticket; implicit returns raw access token directly. |
| **Token Delivery Channel** | **Back-Channel**: Direct TLS POST request from client backend (or SPA) to `/token` endpoint. | **Front-Channel**: Returned in URL fragment (`#access_token=...`) via browser redirect. | Front-channel delivery exposes tokens to browser history, proxy logs, and `Referer` headers. |
| **Client Authentication** | Supported via `client_secret` (confidential clients) or verified cryptographically via PKCE `code_verifier` (public clients). | None; tokens are issued directly based solely on `client_id` and `redirect_uri`. | Implicit grant cannot authenticate the identity of the requesting application. |
| **Refresh Token Support** | Fully supported; authorization server issues refresh tokens during back-channel exchange. | Not supported; refresh tokens must never be issued over the front-channel. | Applications using implicit flow must repeatedly re-authenticate or use hidden iframes. |
| **PKCE Protection** | Mandatory in OAuth 2.1; cryptographically binds authorization code to initial authorization request. | Inapplicable; no code exchange step exists. | PKCE prevents authorization code interception and injection attacks. |
| **Access Token Leakage Surface** | Minimal; tokens are delivered directly in HTTP response bodies over encrypted TLS channels. | High; tokens sit in URL fragments, visible to browser extensions, DOM scripts, and server access logs. | Major attack vector for token theft leading to account takeover. |
| **OAuth 2.1 Specification Status** | **Standard & Mandatory** for all OAuth clients. | **Formally Deprecated & Disallowed**. | Modern implementations must reject `response_type=token`. |

## Security Rationale for Deprecation

### 1. Token Exposure in Browser History and Logs
In the Implicit Flow, the authorization server redirects the user back to the client application:
```text
HTTP/1.1 302 Found
Location: https://client.com/callback#access_token=2YotnFZFEjr1zCsicMWpAA&token_type=Bearer
```
While browsers do not send URL fragments (`#...`) to servers in HTTP requests, client-side JavaScript extracts the token from `window.location.hash`. However, the fragment is recorded in the browser's navigation history and can be leaked to external origins if the page redirects or includes third-party analytics scripts.

### 2. Lack of Sender Authentication & Token Injection
Because the Implicit Flow does not involve client credentials or PKCE, an authorization server cannot verify that the client receiving the token is the same client that initiated the flow. Attackers can inject a stolen access token into a victim's session or exploit open redirects to siphon tokens directly.

### 3. Cross-Origin Resource Sharing (CORS) Evolution
When RFC 6749 was published in 2012, browser support for Cross-Origin Resource Sharing (CORS) was limited, preventing SPAs from making cross-origin POST requests to `/token` endpoints. Modern universal CORS support allows SPAs to execute the standard Authorization Code Flow with PKCE directly against the authorization server without a backend proxy.

## Verdict & Migration Guidance
- **Modern Verdict**: The Implicit Flow must not be used for new deployments and should be migrated immediately in legacy systems.
- **Migration Path**:
  1. Update authorization endpoints to require `response_type=code`.
  2. Implement PKCE (`code_challenge` / `code_verifier` using `S256`).
  3. Enable CORS on the authorization server's `/token` endpoint for registered client origins.
  4. Store tokens securely in memory or `HttpOnly` cookies, avoiding browser storage.

## Related Pages
- [[oauth]]
- [[oauth-grant-types-and-flows]]
- [[oauth-attack-vectors]]

## Evidence and uncertainty
Synthesized from `unprocessed-obsidians/oauth.md` cross-referenced with RFC 6749, RFC 7636, RFC 8252, and the OAuth 2.1 specification.

## Human feedback
Optionally explain or edit what should change.
