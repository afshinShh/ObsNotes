---
title: "Bug Bounty Live Hunts: Real-World Case Studies & Attack Chains"
created: 2026-09-29
updated: 2026-09-29
type: concept
parent: "[[web-and-bug-bounty]]"
cluster: web-and-bug-bounty
tags:
  - bug-bounty
  - ato
  - payload
  - api
  - xss
sources:
  - Notes/Narroto-Guts Hunt/Live Hunts.md
confidence: high
contested: false
contradictions: []
---
# Bug Bounty Live Hunts: Real-World Case Studies & Attack Chains





<!-- TOC_START -->
## Table of Contents
- [Overview](#overview)
- [1. CapCut: A2W Auth Transfer, Host Header Poisoning & 1-Click ATO](#1-capcut-a2w-auth-transfer-host-header-poisoning-1-click-ato)
  - [Vulnerability Chains:](#vulnerability-chains)
- [2. Superbet.ro: Internal Route Discovery & NoSQL-to-SQLi Pivot](#2-superbetro-internal-route-discovery-nosql-to-sqli-pivot)
  - [Discovery Tradecraft:](#discovery-tradecraft)
- [3. Hiring.Amazon.com: React SPA Route Recovery & Source Map Fuzzing](#3-hiringamazoncom-react-spa-route-recovery-source-map-fuzzing)
  - [Methodological Insights:](#methodological-insights)
- [4. Experian: SessionStorage Redirect XSS & Scheme Confusion](#4-experian-sessionstorage-redirect-xss-scheme-confusion)
  - [Attack Sequence:](#attack-sequence)
- [5. Windsurf: Magic Links, Loopback Bypasses & Extension CSPT](#5-windsurf-magic-links-loopback-bypasses-extension-cspt)
  - [Attack Sequence:](#attack-sequence)
- [6. Romwe: Nested Filter Bypass XSS & Window Opener ATO](#6-romwe-nested-filter-bypass-xss-window-opener-ato)
  - [Attack Sequence:](#attack-sequence)
- [7. TikTok: Stored XSS in File Uploader ($7,500 Bounty)](#7-tiktok-stored-xss-in-file-uploader-7500-bounty)
  - [Attack Mechanics:](#attack-mechanics)
- [8. BytePlus: 2FA State Hijacking via Event Tampering](#8-byteplus-2fa-state-hijacking-via-event-tampering)
  - [Attack Mechanics:](#attack-mechanics)
- [Related Pages](#related-pages)
<!-- TOC_END -->

## Overview
A curated collection of granular bug bounty case studies and vulnerability chains compiled from live application security assessments, highlighting root causes, discovery tradecraft, and weaponization vectors.

---

## 1. CapCut: A2W Auth Transfer, Host Header Poisoning & 1-Click ATO

### Vulnerability Chains:
1. **Host Header & Port Injection on `?next=`**:
   - The application dynamically constructed links using client-supplied headers.
   - Injecting a custom port into the `Host:` header caused verification and notification emails to link to `target.com:1337`, reflecting victim tokens to attacker listeners.
2. **`tokenAuth` Scheme Bypass**:
   - The bridge route converted mobile tokens to web session cookies via client-side JavaScript redirect.
   - The redirect validation blocked `javascript:` schemes, but was bypassed using tab injection: `\tjavascript:alert(origin)`.
3. **State Parameter UUID Misuse (1-Click ATO)**:
   - CapCut reused the OAuth `state` parameter to transmit the user's UUID instead of a cryptographic CSRF token.
   - In cross-platform handoffs (Mac application to web app), swapping the UUID on the generated authorization link logged the victim into the attacker's account or allowed code interception.
4. **Workspace Invitation hDOM CSRF**:
   - Initial invitation links triggered a secondary, fully authenticated HTTP request (`hDOM`) carrying cookies and headers without explicit user confirmation.
   - By tampering with the workspace identifier, attackers forced arbitrary users into attacker workspaces upon link click.

---

## 2. Superbet.ro: Internal Route Discovery & NoSQL-to-SQLi Pivot

### Discovery Tradecraft:
- Identified hidden routes and administrative parameters by inspecting client-side JavaScript bundles and DOM comments rather than relying on active spiders.
- **Vulnerability**: Observed JSON filter parameters: `?filter=[{}:{}]`.
  - Initial probing caused 500 internal errors indicative of NoSQL syntax.
  - Injecting `'1':'1'` provoked database-specific error responses revealing that backend queries transitioned into **MySQL queries**, allowing full SQL injection on select routes.

---

## 3. Hiring.Amazon.com: React SPA Route Recovery & Source Map Fuzzing

### Methodological Insights:
- In React-based SPAs, Burp Suite fails to log routes formatted as hash fragments (`site.com/#/...`).
- **CPU Throttling**: Utilized **4x CPU slowdown** in Chrome DevTools Performance tab to slow down rapid redirects, allowing inspection of ephemeral authentication state in `sessionStorage`.
- **Source Map Fuzzing**: Identified production bundles (`main.prod.js`) and fuzzed unlinked source maps: `main.staging.js.map`, `main.dev.js.map`, recovering full client source trees and dangerous sinks (`window.location.assign`).

---

## 4. Experian: SessionStorage Redirect XSS & Scheme Confusion

### Attack Sequence:
- Observed `successRedirectUrl` stored in `sessionStorage`.
- The application sanitized URL inputs upon initial input, but performed **no sanitization** when retrieving and concatenating the value from `sessionStorage` into a redirect sink.
- **Bypasses**:
  - Injected `%0A` to trigger exceptions and inspect intermediate state.
  - Injected `tel:` schemes to verify sink execution before deploying full XSS payloads.

---

## 5. Windsurf: Magic Links, Loopback Bypasses & Extension CSPT

### Attack Sequence:
- Inspected magic link handlers in DevTools debugger, uncovering a dangerous sink (`location.assign`) guarded by a URL checker function.
- **Checker Bypasses**:
  1. **Loopback Confusion**: The checker allowed URLs starting with `127.0.0.1`. Exploited via userinfo delimiter: `http://127.0.0.1@attacker.com/hack.js`.
  2. **Extension Scheme CSPT**: The handler allowed `chrome-extension://`. Exploited using non-happy path traversal: `chrome-extension://<id>/../../test` to steer requests and leak tokens.
  3. **Credential Extraction**: Extracted authentication tokens from `window.location.hash` using XMLHttpRequest after `fetch()` was blocked by browser credential policies.

---

## 6. Romwe: Nested Filter Bypass XSS & Window Opener ATO

### Attack Sequence:
- **XSS on OAuth Error Parameter**: The application stripped `<script>` tags once without recursion (*change after ruleset flaw*).
  - Bypassed using nested tags and multiline HTML comments:
    ```http
    error=/%3C/script%3Eipt%3E%3Cimg+src=x+oner%3C/script%3Eror=ale%3C/script%3Ert(origin)%3E
    ```
- **ATO via `window.opener`**: Popups lacked `rel="noopener noreferrer"`, allowing the malicious landing page to modify `window.opener.location` and hijack the OAuth callback session.

---

## 7. TikTok: Stored XSS in File Uploader ($7,500 Bounty)

### Attack Mechanics:
- Discovered an input field within the file uploader website section that rendered user input into an anchor tag's `href` attribute.
- Utilized JavaScript analysis to construct a payload that satisfied template engine requirements without breaking client execution:
  ```html
  __template__:test&temp=javascript:alert(document.domain)
  ```

---

## 8. BytePlus: 2FA State Hijacking via Event Tampering

### Attack Mechanics:
- The 2FA verification flow supported multiple delivery channels (Email, Phone/SMS).
- Tampered with the underlying dispatch parameter: changed `"EventName": "SendSecurityEmailCode"` to `"EventName": "SendSecurityTelCode"`.
- Bypassed verification by supplying null and empty code values (`000000`, `null`, empty string), completing authentication without receiving a code.

---

## Related Pages
- [[web-and-bug-bounty]]
- [[account-takeover-and-auth-flaws]]
- [[client-side-path-traversal]]
- [[dom-debugging-and-sink-analysis]]
- [[file-upload-attack-matrix]]
- [[xss-and-waf-evasion-tradecraft]]