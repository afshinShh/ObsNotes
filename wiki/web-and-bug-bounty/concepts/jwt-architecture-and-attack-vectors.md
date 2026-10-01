---
title: "JSON Web Token (JWT) Architecture, Cryptographic Verification & Attack Vectors"
created: 2026-09-25
updated: 2026-10-01
type: concept
tags:
  - jwt
  - api
  - payload
  - bug-bounty
sources:
  - sources/jwt.md
confidence: high
contested: false
contradictions: []
parent: "[[web-and-bug-bounty]]"
cluster: web-and-bug-bounty
---
# JSON Web Token (JWT) Architecture, Cryptographic Verification & Attack Vectors

> **Classification**: RFC 7519 (JSON Web Token), RFC 7515 (JSON Web Signature), CWE-287 (Improper Authentication), CWE-347 (Improper Verification of Cryptographic Signature).
> **Primary Impact**: Authentication bypass, privilege escalation to administrator, arbitrary claim tampering, and remote code execution via header injection sinks.

---

<!-- TOC_START -->
## Table of Contents
- [Overview](#overview)
- [Cryptographic & Architectural Mechanics](#cryptographic-architectural-mechanics)
- [Shortcut](#shortcut)
  - [Mis-Configurations](#mis-configurations)
  - [Read Sensitive Information](#read-sensitive-information)
  - [Header Injection](#header-injection)
  - [Same Origin Policy](#same-origin-policy)
- [Mechanisms](#mechanisms)
- [Hunt](#hunt)
  - [Identify JWT Usage](#identify-jwt-usage)
  - [Inspect Token Structure](#inspect-token-structure)
  - [Testing for Vulnerabilities](#testing-for-vulnerabilities)
- [Vulnerabilities](#vulnerabilities)
  - [Algorithm Vulnerabilities](#algorithm-vulnerabilities)
  - [Signature Vulnerabilities](#signature-vulnerabilities)
  - [Implementation Issues](#implementation-issues)
  - [Header Injection Attacks](#header-injection-attacks)
  - [Information Disclosure](#information-disclosure)
- [Additional Attack Vectors](#additional-attack-vectors)
  - [Mobile App JWT Storage](#mobile-app-jwt-storage)
  - [JWT Confusion Attacks](#jwt-confusion-attacks)
  - [Timing Attacks on HMAC](#timing-attacks-on-hmac)
  - [JWT in URL Parameters](#jwt-in-url-parameters)
- [ETC](#etc)
- [Methodologies](#methodologies)
  - [Tools](#tools)
  - [Manual Testing Steps](#manual-testing-steps)
  - [Automated Testing with JWT_Tool](#automated-testing-with-jwt_tool)
- [Remediation Recommendations](#remediation-recommendations)
- [Primary Sources & Provenance](#primary-sources-provenance)
- [Related Concepts & Entities](#related-concepts-entities)
<!-- TOC_END -->

## Overview
JSON Web Tokens (JWT) defined in RFC 7519 provide compact, URL-safe means of representing claims between two parties. This reference documents token structure, header parameters, payload claims, signature verification semantics, cryptographic algorithm choices, and practical attack execution utilizing [[jwt-tool]].

## Cryptographic & Architectural Mechanics

## Shortcut

- Don't forget that jwt can be inside cookies and local storage!
- The signature is calculated by taking the base64-encoded header and payload, hashing them with a secret key using the specified algorithm, and then base64-encoding the resulting hash.

### Mis-Configurations
- None Algorithm (Change the algorithm to None and remove the signature)
- Change Algorithm from RS256 (Asymmetric) to HS256 (Symmetric) and sign the token with the public key
- Strip the signature and send the token without it
- Weak HMAC Secret (Brute-force the secret key using Hashcat or John the Ripper)
- Check for weak HMAC secret keys using a list of common keys or a dictionary attack
- Send an empty signature (e.g. `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.`)

### Read Sensitive Information
- The payload can be decoded using base64 decoding. Check if it contains any sensitive information, such as passwords, API keys, or personal information.

### Header Injection
- JKU (JSON Web Key Set URL) Injection: If the token contains a `jku` header parameter, you can change the URL to your own server containing a valid JWKS and sign the token with your own private key
- X5U (X.509 URL) Injection: If the token contains an `x5u` header parameter, you can change the URL to your own server containing a valid certificate and sign the token with your own private key
- KID (Key ID) Injection: The `kid` header parameter is used to specify the key to verify the signature. You can inject SQL injection or directory traversal in the `kid` parameter to bypass verification or achieve RCE

### Same Origin Policy
- Check if the token is transmitted in a secure way (e.g. via HTTPS) and not susceptible to man-in-the-middle attacks. If the token is stored in localStorage or sessionStorage, it might be vulnerable to XSS attacks.

## Mechanisms

- Structure: `Header.Payload.Signature` (Base64URL-encoded).
- Header: contains algorithm (`alg`) and token type (`typ`).
- Payload: claims (registered: `iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`; public/private claims).
- Signature: computed over `base64Url(header) + "." + base64Url(payload)` using secret or private key.
- Common algs: `HS256` (HMAC-SHA256), `RS256` (RSA-SHA256), `ES256` (ECDSA), `none` (unsigned).

## Hunt

### Identify JWT Usage
- Look for Bearer tokens in `Authorization` headers.
- Inspect cookies and local/session storage for three-part dot-separated base64 strings.
- Check WebSocket handshakes and URL query parameters for token passing.

### Inspect Token Structure
- Decode Header and Payload with base64url.
- Note `alg`, `typ`, `kid`, `jku`, `x5u` in the header.
- Identify sensitive claims: roles, permissions, user IDs, expiration times (`exp`).

### Testing for Vulnerabilities
1. Signature Stripping: Remove signature and test if backend accepts unsigned tokens.
2. None Algorithm: Set `"alg": "none"` (or permutations: `None`, `NONE`, `nOnE`) and remove signature.
3. Key Confusion: If server uses RS256, forge token using HS256 signed with server's public key.
4. Secret Brute-forcing: Run hashcat or jwt_tool against HS256 tokens using wordlists.
5. Header Injection: Test `kid` for path traversal (point to `/dev/null` or known file), SQLi, or command injection.
6. JKU/X5U Spoofing: Host malicious jwks.json/cert, point `jku`/`x5u` to attacker domain, sign with attacker private key.
7. Expiration/Replay: Test if expired tokens (`exp` in past) are accepted; test token reuse after logout.

## Vulnerabilities

### Algorithm Vulnerabilities
- `none` Algorithm Accepted: Server fails to enforce signature check if `alg` is set to `none`.
- Algorithm Switching / Key Confusion: Server supports both HMAC and RSA; accepts HS256 signed with public RSA key instead of enforcing RS256.

### Signature Vulnerabilities
- Signature Not Verified: Server decodes payload without validating the cryptographic signature.
- Weak HMAC Secret: Secret key easily cracked via offline dictionary attacks.

### Implementation Issues
- Token Expiration Ignored: Server does not validate `exp` or `nbf` claims, allowing replay attacks.
- Sensitive Data in Payload: Credentials, PII, or internal tokens exposed in base64 payload without encryption (JWE).

### Header Injection Attacks
- `kid` Injection:
  - Path traversal: `"kid": "../../../dev/null"` (server uses empty key).
  - SQL injection: `"kid": "key1' UNION SELECT 'my_secret'--"` (server uses returned secret to verify).
- `jku` / `x5u` Injection: Server trusts arbitrary external URLs for public key fetching without whitelist validation.

### Information Disclosure
- Token stored in insecure client-side storage (localStorage) accessible via XSS.
- Sensitive backend logic revealed through custom claims.

## Additional Attack Vectors

### Mobile App JWT Storage
- Hardcoded signing keys inside mobile binaries (decompiled APK/IPA).
- Insecure storage in SharedPreferences or NSUserDefaults.

### JWT Confusion Attacks
- Cross-service token reuse: Token issued for Service A accepted by Service B due to missing `aud` (audience) check.

### Timing Attacks on HMAC
- Non-constant-time signature comparison allows byte-by-byte secret recovery over high-precision network measurements.

### JWT in URL Parameters
- Tokens passed in query strings leaked via Referer headers, browser history, or server access logs.

## ETC

- JWE (JSON Web Encryption): Encrypts the payload for confidentiality; format has 5 parts (`Header.EncryptedKey.IV.Ciphertext.Tag`).
- JWK / JWKS: JSON Web Key (Set) standard for representing cryptographic keys in JSON format.
- Refresh Tokens: Long-lived tokens used to obtain new short-lived access tokens; must be revoked properly on logout.

## Methodologies

### Tools
- `jwt_tool` — Automated scanning, tampering, and exploit generation.
- `Hashcat` — Mode 16500 for cracking JWT HMAC-SHA256 secrets.
- `Burp Suite` — JSON Web Tokens extension, JWT Editor.

### Manual Testing Steps
1. Capture valid JWT from normal flow.
2. Decode header and payload.
3. Test `none` algorithm: change `"alg": "none"`, remove signature (keep trailing dot).
4. Test signature bypass: change payload claim (e.g. `"admin": true`), keep original signature.
5. Test key confusion: obtain public key (e.g., from `/.well-known/jwks.json`), change `"alg": "HS256"`, sign with public key.
6. Test `kid` parameter: change to a known file path or SQLi payload.
7. Brute-force HMAC secret offline if `HS256` is used.

### Automated Testing with JWT_Tool
```bash
# Analyze token
python3 jwt_tool.py <JWT_STRING>

# Run all automated tests against target endpoint
python3 jwt_tool.py <JWT_STRING> -t https://target.com/api/me -rh "Authorization: Bearer <JWT_STRING>" -M at

# Crack HMAC secret
python3 jwt_tool.py <JWT_STRING> -C -d /path/to/wordlist.txt

# Key confusion exploit (forge RS256 to HS256 with public key)
python3 jwt_tool.py <JWT_STRING> -X k -pk public.pem
```

## Remediation Recommendations
- Always verify signatures: Reject tokens if signature verification fails or algorithm is `none`.
- Enforce expected algorithm: Pin `alg` on server side; do not trust header `alg` blindly.
- Use strong secrets: For HMAC, use >= 256-bit cryptographically random keys; prefer asymmetric RS256/ES256.
- Validate JWKS over pinned TLS; disallow remote `jku`/`x5u` except for trusted domains; cache keys with short TTL and verify `kid` uniqueness.
- Disable `none` and prevent algorithm downgrades; pin `alg` per client and per issuer.
- Bind sessions to device when possible; rotate refresh tokens on every use and revoke the previous (refresh token rotation).
- Prefer `SameSite=Lax/Strict` HttpOnly cookies for web to reduce token exfil; avoid localStorage for access tokens.

## Primary Sources & Provenance
- Provenance source anchor: [[jwt]]

Synthesized and normalized from canonical vault note `[[unprocessed-obsidians/jwt]]`.

## Related Concepts & Entities
- [[jwt-tool]]
- [[jwt-vs-session-cookies]]
- [[jwt-in-oauth2-architecture]]
- [[broken-authentication-and-credential-attacks]]
- [[oauth-attack-vectors]]
