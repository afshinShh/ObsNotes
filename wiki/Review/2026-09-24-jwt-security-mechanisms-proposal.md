---
type: llm-wiki-review
status: needs-review
decision: pending
revision: 1
operation: create
target: concepts/jwt-security-mechanisms.md
sources:
  - raw/articles/jwt.md
---

# Proposed Wiki change

## What will change
Compiles a dedicated concept page documenting JSON Web Token (RFC 7519) security architecture, token structure, cryptographic signing algorithms, standard claims validation, token binding extensions (DPoP, mTLS), and secure storage guidelines.

## Proposed content

---
title: JSON Web Token (JWT) Security Architecture & Mechanisms
created: 2026-09-24
updated: 2026-09-24
type: concept
tags:
  - jwt
  - session
  - api
sources:
  - unprocessed-obsidians/jwt.md
confidence: high
contested: false
contradictions: []
---

# JSON Web Token (JWT) Security Architecture & Mechanisms

## Overview
JSON Web Tokens (JWT) are an open standard defined in [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) for transmitting information between parties as a compact, URL-safe JSON object. JWTs are predominantly used for stateless authentication and fine-grained authorization. A fundamental tenet of JWT architecture is that standard tokens provide **integrity** (via cryptographic signatures), not **confidentiality**; any party possessing the token can decode and inspect the unencrypted payload claims unless paired with JSON Web Encryption (JWE / RFC 7516).

## Token Structure
A standard compact JWT is composed of three Base64URL-encoded components separated by periods (`.`):
```text
base64url(Header) . base64url(Payload) . Signature
```

```
+------------------------------------------------------------------------+
|                                HEADER                                  |
| Specifies token type ("typ": "JWT") and cryptographic algorithm ("alg")|
+------------------------------------------------------------------------+
                                   |
+------------------------------------------------------------------------+
|                                PAYLOAD                                 |
| Contains statements/claims (iss, sub, aud, exp, nbf, iat, custom data) |
+------------------------------------------------------------------------+
                                   |
+------------------------------------------------------------------------+
|                               SIGNATURE                                |
| Cryptographic signature computed over header + payload using secret/key|
+------------------------------------------------------------------------+
```

### 1. Header
Identifies the cryptographic operations applied to the token:
- `alg`: The cryptographic algorithm used for signing (e.g. `HS256`, `RS256`, `ES256`, `none`).
- `typ`: Token type, conventionally `JWT` or `dpop+jwt`.
- `cty`: Content type, used in nested tokens.
- `kid`: Key ID, pointing to the key material needed for validation.
- `jku` / `x5u`: URLs to JWK sets or X.509 public key certificates.

### 2. Payload (Claims)
Contains identity attributes and operational constraints:
- **Registered Claims**:
  - `iss` (Issuer): Principal that issued the token.
  - `sub` (Subject): Principal that is the subject of the token (e.g. user ID).
  - `aud` (Audience): Target recipient(s) for which the token is intended.
  - `exp` (Expiration Time): Unix timestamp after which the token must be rejected.
  - `nbf` (Not Before): Unix timestamp before which the token must not be accepted.
  - `iat` (Issued At): Unix timestamp when the token was created.
  - `jti` (JWT ID): Unique identifier for one-time use or revocation tracking.
- **Public & Private Claims**: Application-specific attributes (roles, permissions, tenant IDs).

### 3. Signature
Ensures the message has not been altered in transit:
- **HMAC (HS256)**: `HMACSHA256(base64UrlEncode(header) + "." + base64UrlEncode(payload), secret)`
- **Asymmetric (RS256/ES256)**: Digital signature computed by private key and verified by public key.

## Cryptographic Algorithm Matrix

| Algorithm Family | Identifier | Cryptographic Primitive | Key Type | Security Considerations |
| :--- | :--- | :--- | :--- | :--- |
| **HMAC** | `HS256`, `HS384`, `HS512` | HMAC with SHA-2 | Symmetric Secret | Vulnerable to dictionary brute-forcing if secret is short (<256 bits). Secret must be shared between issuer and verifier. |
| **RSA PKCS#1 v1.5** | `RS256`, `RS384`, `RS512` | RSASSA-PKCS1-v1_5 | Asymmetric (Public/Private) | Susceptible to Algorithm Confusion attacks if server misinterprets public key as HMAC secret. |
| **ECDSA** | `ES256`, `ES384`, `ES512` | ECDSA using P-curves | Asymmetric (Public/Private) | High cryptographic strength with smaller key sizes. Requires high-entropy nonces to avoid private key leakage. |
| **RSA-PSS** | `PS256`, `PS384`, `PS512` | RSASSA-PSS with MGF1 | Asymmetric (Public/Private) | Probabilistic signature scheme; immune to PKCS#1 v1.5 padding flaws. Recommended for modern RSA deployments. |
| **Edwards-curve** | `EdDSA` (Ed25519, Ed448) | EdDSA | Asymmetric (Public/Private) | Modern, fast, and resistant to side-channel and timing attacks. |
| **None** | `none` | No Signature | None | Highly insecure; disables cryptographic verification entirely. |

## Claims Verification Lifecycle
Secure validation requires adhering to strict operational checks:
1. **Algorithm Validation**: Enforce an explicit whitelist of allowed algorithms per client/tenant. Reject `none` and unexpected algorithm families.
2. **Clock Skew & Temporal Claims**: Validate `exp` and `nbf` with an allowable clock skew tolerance (typically ≤ 60 seconds).
3. **Audience & Issuer Enforcement**: Verify `iss` against authorized identity providers and verify `aud` strictly matches the consuming resource server's URI/identifier.
4. **Token Length & Complexity Limits**: Enforce maximum token size boundaries (e.g. 8KB) to prevent DoS via bloated header parsing or decompression bombs.
5. **Revocation Tracking**: Stateless JWTs cannot be revoked natively. Systems requiring early revocation must maintain a fast distributed deny-list keyed by `jti` or user credential revision counter.

## Sender-Constrained Token Binding & Modern Specs

### DPoP (RFC 9449)
Demonstrating Proof-of-Possession at the Application Layer (DPoP) binds access tokens to a client's private key. The client generates an asymmetric key pair, attaches a signed DPoP proof header (`typ: dpop+jwt`) to each HTTP request, and the server verifies that:
- The proof signature matches the public key embedded in the proof.
- The `htm` (HTTP method) and `htu` (HTTP URI) match the current request.
- The `jti` nonce prevents replay.

### mTLS (RFC 8705)
Mutual TLS client certificate-bound access tokens cryptographically bind the token to the TLS channel established between the client and server, preventing stolen tokens from being replayed from any other machine.

### Modern Alternatives
- **PASETO (Platform-Agnostic Security Tokens)**: Eliminates cipher agility and algorithm negotiation completely, preventing algorithm confusion and `none` attacks by design.
- **Macaroons**: Decentralized bearer tokens supporting attenuable caveats and contextual delegation.

## Storage and Transport Security
- **Transport**: Transmit tokens exclusively over TLS (`https://`). Never accept tokens over plaintext HTTP.
- **Web Storage**: Avoid storing access tokens in `localStorage` or `sessionStorage` due to complete accessibility via Cross-Site Scripting (XSS). Store tokens in `HttpOnly; Secure; SameSite=Lax/Strict` cookies, or hold them in JavaScript memory backed by a Backend-for-Frontend (BFF) proxy.
- **Mobile Storage**: Avoid `MODE_WORLD_READABLE` Android `SharedPreferences` or unencrypted iOS backups. Utilize the Android Keystore or iOS Keychain with `kSecAttrAccessibleWhenUnlocked`.

## Related Pages
- [[jwt]]
- [[jwt-attack-vectors]]
- [[jwt-vs-session-cookies]]
- [[jwt-tool]]
- [[oauth-grant-types-and-flows]]
- [[oauth-attack-vectors]]

## Evidence and uncertainty
Synthesized from `unprocessed-obsidians/jwt.md` cross-referenced with RFC 7519, RFC 7516, RFC 7518, RFC 8705, and RFC 9449. All claims are grounded in primary sources.

## Human feedback
Optionally explain or edit what should change.
