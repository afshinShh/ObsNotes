---
title: "Source Note - CSRF: Concepts, Attack Vectors, and Defenses"
created: 2026-10-01
updated: 2026-10-01
type: source
tags:
  - csrf
  - session
  - payload
  - bug-bounty
sources:
  - Notes/OLD Notes/WEB/vulnerabilities/CSRF/concepts and defense.md
  - Notes/OLD Notes/WEB/vulnerabilities/CSRF/attack/Examples.md
  - Notes/OLD Notes/WEB/vulnerabilities/CSRF/links and todos.md
extracted_concepts:
  - "[[csrf-attacks-and-prevention]]"
extracted_entities:
  []
extracted_comparisons:
  - "[[csrf-vs-cors-security]]"
  - "[[clickjacking-vs-csrf]]"
confidence: high
contested: false
contradictions: []
parent: "[[web-and-bug-bounty]]"
cluster: web-and-bug-bounty
---
# Source Note - CSRF: Concepts, Attack Vectors, and Defenses

> **Provenance Anchor**: Ingested from canonical vault files under `Notes/OLD Notes/WEB/vulnerabilities/CSRF/`.
> - `concepts and defense.md` (135 lines, SHA-256: `931e36bc37c6cb399e39f7ba93230c9b1284f54b9f0321257788efb058d1a0ca`)
> - `attack/Examples.md` (184 lines, SHA-256: `b28e9478adb7a9f131200c51d5e0621417492ed319b9e2e8d0b41796ff024843`)
> - `links and todos.md` (18 lines, SHA-256: `5e81eba8369ac91ab96c17ebc524d1db26c4ef61517dab72193e2afafbd23ca6`)
> **Total Raw Lines**: 337 lines

---

<!-- TOC_START -->
## Table of Contents
- [Compiled Wiki Layers](#compiled-wiki-layers)
  - [Concepts](#concepts)
  - [Comparisons](#comparisons)
- [Source Content Topic Breakdown](#source-content-topic-breakdown)
- [Related Pages](#related-pages)
<!-- TOC_END -->

## Compiled Wiki Layers
### Concepts
- [[csrf-attacks-and-prevention]] — Technical conditions for request forgery, token generation criteria (CSPRNG, static secret, user binding), token bypasses (method swapping, token stripping, token pool, non-session cookie binding via CRLF, double-submit weaknesses), SameSite cookie nuances (Strict, Lax, None, Site vs Origin), JSON-CSRF via text/plain, and GraphQL mutation CSRF.

### Comparisons
- [[csrf-vs-cors-security]] — Structural comparison between CSRF (unauthorized state-changing actions) and CORS misconfigurations (unauthorized cross-origin data extraction).
- [[clickjacking-vs-csrf]] — Trade-offs between UI redressing requiring physical user interaction vs invisible background request forgery.

## Source Content Topic Breakdown
1. **Three Core Preconditions**: Relevant state-changing action, cookie-based session tracking, no unpredictable parameters.
2. **Token Bypass Vectors**:
   - Validation depends on HTTP request method (POST to GET conversion).
   - Validation omitted when token parameter is absent.
   - Token not tied to user session (attacker uses their own token from token pool).
   - Token tied to non-session cookie (exploited via HTTP header injection / CRLF cookie tossing).
   - Double-submit cookie implementation failures.
3. **SameSite Cookie Mechanics**: Comparison table of Same-Site vs Same-Origin, top-level navigation Lax exemptions, and Lax-by-default behavior.
4. **Specialized CSRF Exploits**:
   - JSON-CSRF using `enctype="text/plain"`.
   - GraphQL mutation CSRF using URL-encoded parameter transmission.
   - Referer header validation bypasses using `<meta name="referrer" content="no-referrer">`.
   - AJAX / jQuery exploit templates.

## Related Pages
- Parent Domain Hub: [[web-and-bug-bounty]]
- Target Concepts: [[csrf-attacks-and-prevention]], [[account-takeover-and-auth-flaws]], [[clickjacking-attacks-and-ui-redressing]]
