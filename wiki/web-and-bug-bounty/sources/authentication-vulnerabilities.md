---
title: "Source Note - Authentication Vulnerabilities: Credential Attacks, 2FA Bypasses, and OAuth Flaws"
created: 2026-10-01
updated: 2026-10-01
type: source
tags:
  - ato
  - session
  - brute-force
  - oauth
  - payload
  - bug-bounty
sources:
  - Notes/OLD Notes/WEB/vulnerabilities/Authentication vulnerabilities/concepts and defense.md
  - Notes/OLD Notes/WEB/vulnerabilities/Authentication vulnerabilities/METHODOLOGY.md
  - Notes/OLD Notes/WEB/vulnerabilities/Authentication vulnerabilities/payload.md
  - Notes/OLD Notes/WEB/vulnerabilities/Authentication vulnerabilities/resources.md
  - Notes/OLD Notes/WEB/vulnerabilities/Authentication vulnerabilities/OAuth/concepts and defense.md
  - Notes/OLD Notes/WEB/vulnerabilities/Authentication vulnerabilities/OAuth/METHODOLOGY.md
  - Notes/OLD Notes/WEB/vulnerabilities/Authentication vulnerabilities/OAuth/payload.md
extracted_concepts:
  - "[[broken-authentication-and-credential-attacks]]"
  - "[[oauth-attack-vectors]]"
extracted_entities:
  []
extracted_comparisons:
  []
confidence: high
contested: false
contradictions: []
parent: "[[web-and-bug-bounty]]"
cluster: web-and-bug-bounty
---
# Source Note - Authentication Vulnerabilities: Credential Attacks, 2FA Bypasses, and OAuth Flaws

> **Provenance Anchor**: Ingested from canonical vault files under `Notes/OLD Notes/WEB/vulnerabilities/Authentication vulnerabilities/`.
> - `concepts and defense.md` (69 lines, SHA-256: `b6f82d09ad6b38e4a957d197607b19a1a2b16666ba3a32338d1ee717bf40822e`)
> - `METHODOLOGY.md` (117 lines, SHA-256: `6aa414d55f82d81231f82f25492b498f32a76fa968ce61d36bbfa71675a80f08`)
> - `payload.md` (141 lines, SHA-256: `3c5384fdf3dfed9ce37eb7df3859663738f72df91722e03fc11f93f1f31f938d`)
> - `resources.md` (6 lines, SHA-256: `e36a61762d7933d4ff681a95e263d917cb12c40c83226dbf9641e737cbe185b3`)
> - `OAuth/concepts and defense.md` (234 lines, SHA-256: `cff68637e6c708d3e69fe91a5ec409fbe798efcb5bc38c353a25ba9eb2dbad12`)
> - `OAuth/METHODOLOGY.md` (30 lines, SHA-256: `b4fc5b221c1ba242ce0797305988d8b4c207b8ae25b42d1e041db810e74f17a9`)
> - `OAuth/payload.md` (15 lines, SHA-256: `95e3c584c73018c47f7d6a74bca28014feecb438bf228be0bc3bc44efdfad988`)
> **Total Raw Lines**: 612 lines

---

<!-- TOC_START -->
## Table of Contents
- [Compiled Wiki Layers](#compiled-wiki-layers)
  - [Concepts](#concepts)
- [Source Content Topic Breakdown](#source-content-topic-breakdown)
- [Related Pages](#related-pages)
<!-- TOC_END -->

## Compiled Wiki Layers
### Concepts
- [[broken-authentication-and-credential-attacks]] — Deep-dive coverage of username enumeration (status codes, subtle error messages, response timing via password hashing differences), flawed brute-force protections (alternating valid credentials, account lock bypass via credential stuffing), HTTP Basic Auth vulnerabilities, 2FA bypasses (state omission, broken session-binding cookies, verification code brute-forcing), persistent remember-me cookie exploitation (MD5/Base64 pattern cracking, offline Hashcat cracking), password reset logic flaws (token stripping, Host header poisoning), and password change differential error leaks.
- [[oauth-attack-vectors]] — Enriched OAuth 2.0 & OIDC attack vectors incorporating client-side authentication tampering in implicit flows, forced profile linking CSRF, `prompt=none` interaction bypasses, `response_mode=form_post` redirect manipulation (CVE-2023-6291), and OIDC claims/scopes standardization.

## Source Content Topic Breakdown
1. **Password-Based Login Attacks**:
   - Username enumeration through response length, subtle text typos (full stop vs period), and cryptographic timing delays using long passwords.
   - Brute-force evasion by interleaving attacker credentials to reset attempt counters.
   - Account locking limits circumvented via credential stuffing.
2. **Multi-Factor Authentication (2FA) Flaws**:
   - Navigation bypasses to `/my-account` directly after phase 1.
   - Step 2 parameter/cookie swapping (`Cookie: account=victim` or `verify=victim`).
3. **Session Persistence ("Remember Me")**:
   - Weak hashing implementations (`base64(username + ":" + md5(password))`).
   - XSS-assisted cookie harvesting and offline Hashcat dictionary cracking.
4. **Password Reset & Change Flaws**:
   - Stripping `temp-forgot-password-token` parameter leading to immediate reset.
   - `X-Forwarded-Host` password reset poisoning.
   - Error oracle in password change endpoints (`New passwords do not match` vs `Current password is incorrect`).
5. **OAuth & OIDC Architecture**:
   - Complete parameter analysis: `redirect_uri`, `response_type`, `client_id`, `scope`, `state`, `prompt`, `response_mode`.
   - Standard OIDC claims (`sub`, `name`, `email`, `email_verified`) and scopes (`openid`, `profile`, `email`, `phone`).

## Related Pages
- Parent Domain Hub: [[web-and-bug-bounty]]
- Target Concepts: [[broken-authentication-and-credential-attacks]], [[oauth-attack-vectors]], [[account-takeover-and-auth-flaws]]
