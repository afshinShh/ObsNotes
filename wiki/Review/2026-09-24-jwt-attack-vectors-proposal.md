---
type: llm-wiki-review
status: needs-review
decision: pending
revision: 1
operation: create
target: concepts/jwt-attack-vectors.md
sources:
  - raw/articles/jwt.md
---

# Proposed Wiki change

## What will change
Compiles a dedicated concept page detailing JWT vulnerabilities and offensive exploitation vectors: algorithm manipulation (`none` algorithm, RS256-to-HS256 key confusion), header parameter injection (`jwk`, `jku`, `x5u`, `kid`), HMAC weak key brute-forcing and timing attacks, multi-auth confusion, and mobile/URL token leakage.

## Proposed content

---
title: JWT Vulnerabilities & Exploitation Vectors
created: 2026-09-24
updated: 2026-09-24
type: concept
tags:
  - jwt
  - brute-force
  - payload
  - bug-bounty
sources:
  - unprocessed-obsidians/jwt.md
confidence: high
contested: false
contradictions: []
---

# JWT Vulnerabilities & Exploitation Vectors

## Overview
JSON Web Tokens (JWT) vulnerabilities emerge from implementation flaws in signature verification libraries, insecure server configurations, lack of input sanitization in header parameters, and architectural confusion across authentication mechanisms. Exploitation frequently yields complete authentication bypass, privilege escalation, and account takeover.

## Attack Taxonomy & Exploitation Primitives

### 1. Algorithm Manipulation & Downgrade

#### A. Algorithm "none" Bypass
RFC 7518 specifies the `none` algorithm for unsigned tokens. Vulnerable token parsers that fail to enforce signature verification permit attackers to modify payload claims (e.g. `{"admin": true}`), set `"alg": "none"`, and strip the signature:
```text
base64url({"alg":"none","typ":"JWT"}).base64url({"user":"admin","role":"administrator"}).
```
Defensive parsers often check case-sensitively; testers must evaluate case mutations:
- `none`, `None`, `NONE`, `nOnE`
- Retaining trailing period (`header.payload.`) vs omitting period entirely.

#### B. Algorithm / Key Confusion (RS256 to HS256)
When an application uses asymmetric cryptography (RS256), the server verifies tokens using a public RSA key. If the backend verification library dynamically accepts symmetric HMAC (HS256) based on the token's header `alg`, an attacker can execute Key Confusion:
1. Obtain the server's public RSA verification key (e.g. from `/jwks.json` or certificates).
2. Construct a tampered token and change header algorithm to `"alg": "HS256"`.
3. Sign the token with HMAC-SHA256 using the **raw public key string** (or public key bytes) as the symmetric HMAC secret.
4. The server's validation function passes the public key into `verify(token, key)`; because the algorithm is HS256, the library treats the public key parameter as the shared HMAC secret, successfully validating the forged token.

Automated testing syntax via `[[jwt-tool]]`:
```bash
python3 jwt_tool.py <token> -X a -pk public.key
```

### 2. Header Parameter Injection

#### A. JWK (JSON Web Key) Parameter Injection
The `jwk` header parameter allows embedding a public key directly within the token header. In vulnerable implementations, the server verifies the token signature against the key supplied in the `jwk` parameter itself rather than a server-trusted key:
```json
{
  "alg": "RS256",
  "typ": "JWT",
  "jwk": {
    "kty": "RSA",
    "e": "AQAB",
    "kid": "attacker-key",
    "n": "u1P5y...attacker_public_modulus..."
  }
}
```
The attacker generates a fresh RSA key pair, embeds the public component in `jwk`, and signs the forged payload with the corresponding private key.

#### B. JKU / X5U Injection and SSRF
- **`jku` (JWK Set URL)**: URL pointing to a set of JSON-encoded public keys.
- **`x5u` (X.509 URL)**: URL pointing to an X.509 public key certificate.

If the verification engine does not validate that the URL belongs to a trusted domain, attackers can:
1. Point `jku` to an attacker-controlled server: `"jku": "https://attacker.com/jwks.json"`.
2. Trigger Server-Side Request Forgery (SSRF) against internal metadata endpoints (e.g. `http://169.254.169.254`) or internal services, linking directly to [[blind-ssrf-gopher-redis-rce]].
3. Bypass domain checks via open redirects, CRLF injection, parameter pollution, or DNS rebinding.

#### C. Key ID (`kid`) Manipulation
The `kid` header identifies which key in a database or filesystem should verify the signature:
- **Directory Traversal (Empty Key Injection)**: If `kid` is passed directly to a file read, pointing it to `/dev/null` forces the secret to be an empty string (0 bytes):
  ```json
  {"alg": "HS256", "typ": "JWT", "kid": "../../../../../dev/null"}
  ```
  The token is signed with HMAC-SHA256 using `""` as the secret key.
- **SQL Injection**: When `kid` is queried against a backend key database:
  ```json
  {"alg": "HS256", "typ": "JWT", "kid": "' UNION SELECT 'attacker_secret' --"}
  ```
  Forces the query to return an attacker-controlled secret string.
- **Command Injection**: When `kid` is interpolated into command-line utilities.

#### D. Critical Header (`crit`) Abuse
The `crit` parameter designates headers that MUST be understood and processed. Misconfigured parsers encountering unknown or manipulated `crit` elements may fail open or throw unhandled exceptions revealing memory state.

### 3. Cryptographic Flaws & Brute-Forcing

#### A. Weak HMAC Secret Brute-Forcing
HMAC-signed tokens (`HS256`) relying on short, dictionary-based, or predictable secrets can be cracked offline at high throughput without interacting with the target server:
```bash
# Cracking via jwt_tool
python3 jwt_tool.py <token> -C -d /path/to/wordlist.txt

# High-speed GPU/C cracking via c-jwt-cracker
c-jwt-cracker -t <token> -d /path/to/wordlist.txt
```

#### B. Timing Attacks on Non-Constant-Time HMAC Comparison
When a verification routine compares signatures using standard equality operators (`if (signature == expected)`) instead of constant-time comparisons (`crypto.timingSafeEqual`), the operation terminates on the first mismatched byte. Attackers can measure response latencies using microsecond timing probes to reconstruct the signature byte-by-byte:
```python
import requests, time

def probe_signature(sig_hex):
    start = time.perf_counter()
    requests.get("https://target.com/api", headers={"Authorization": f"Bearer header.payload.{sig_hex}"})
    return time.perf_counter() - start
```

### 4. Multi-Authentication & Token Confusion Attacks
- **OAuth ID Token vs Access Token Confusion**: Clients sending an OIDC ID token (signed JWT containing identity claims) to a resource server expecting an access token. If the resource server validates signature but does not enforce `aud` or `token_type`, access is granted with improper privileges.
- **SAML-JWT Confusion**: Systems accepting multiple authentication artifacts where validation logic falls back to weaker JWT signature rules when an invalid SAML assertion is supplied.
- **Session Cookie-JWT Hybrid Confusion**: Applications checking either a session cookie or a JWT where session invalidation does not invalidate the accompanying JWT, enabling replay.

### 5. Insecure Transport and Storage Exposure
- **GET URL Parameters**: Tokens passed via query strings (`?token=ey...`) leak in proxy logs, CDN caching tiers, server `access.log`, and `Referer` headers to third-party endpoints.
- **Mobile Storage Extraction**:
  - Android: `MODE_WORLD_READABLE` SharedPreferences in `/data/data/<pkg>/shared_prefs/`, or unencrypted backup archiving (`adb backup` with `allowBackup=true`).
  - iOS: Unencrypted iTunes/iCloud backups exposing Keychain data where `kSecAttrAccessibleAlways` is set.

## Hardening and Defensive Remediation
1. **Disable `none` & Enforce Strict Algorithm Whitelisting**: Reject dynamic algorithm selection; pin `alg` explicitly per client.
2. **Prevent Key Confusion**: Never accept symmetric HMAC signatures when verification keys are RSA/EC public keys.
3. **Strict Header Sanitization**: Reject inline `jwk` headers; restrict `jku`/`x5u` to pre-registered domain allowlists over verified TLS; validate `kid` against strict regex whitelist.
4. **Enforce Constant-Time Comparison**: Use cryptographic timing-safe comparisons for all signature checks.
5. **Claims Enforcement**: Mandate and validate `exp`, `nbf`, `iss`, and `aud` on every request.

## Related Pages
- [[jwt]]
- [[jwt-security-mechanisms]]
- [[jwt-tool]]
- [[jwt-vs-session-cookies]]
- [[oauth-attack-vectors]]
- [[blind-ssrf-gopher-redis-rce]]

## Evidence and uncertainty
Synthesized from `unprocessed-obsidians/jwt.md`. All attack mechanics are verified against PortSwigger Web Security Academy research, RFC 7515/7518 specifications, and public CVE disclosures.

## Human feedback
Optionally explain or edit what should change.
