---
type: llm-wiki-review
status: needs-review
decision: pending
revision: 1
operation: create
target: web-and-bug-bounty/concepts/client-side-path-traversal.md
sources:
  - Notes/Narroto-Guts Hunt/Live Hunts.md
  - Notes/Narroto-Guts Hunt/Tips and Tricks.md
---

# Proposed Wiki change

## What will change
Compile deep-dive concept note for Client-Side Path Traversal (CSPT).

## Proposed content
```markdown
---
title: "Client-Side Path Traversal (CSPT) & Client Routing Redirection"
created: 2026-09-29
updated: 2026-09-29
type: concept
parent: "[[web-and-bug-bounty]]"
cluster: web-and-bug-bounty
tags:
  - open-redirect
  - api
  - bug-bounty
  - payload
sources:
  - Notes/Narroto-Guts Hunt/Live Hunts.md
  - Notes/Narroto-Guts Hunt/Tips and Tricks.md
confidence: high
contested: false
contradictions: []
---
# Client-Side Path Traversal (CSPT) & Client Routing Redirection

<!-- TOC_START -->
<!-- TOC_END -->

## Overview
Client-Side Path Traversal (CSPT) is a vulnerability class where user-controlled input is incorporated into client-side dynamic request generators (`fetch()`, `XMLHttpRequest`, or dynamic resource loaders) without sufficient path sanitization, allowing an attacker to navigate outside the intended API base directory using directory traversal sequences (`../`).

Unlike classic server-side path traversal (which targets host filesystems such as `/etc/passwd`), CSPT executes in the **victim's browser context**, manipulating client-side routing to steer fully authenticated HTTP requests toward unintended endpoints or external resources.

## Root Cause Mechanics
In Single Page Applications (SPAs) and modern JavaScript frameworks, client-side code frequently builds API queries by concatenating user-controlled parameters into base URLs:

```javascript
// Vulnerable Client-Side Dynamic Fetch
function loadUserProfile(userId) {
  const endpoint = `/api/v1/users/${userId}/details`;
  fetch(endpoint, { credentials: 'include' })
    .then(r => r.json())
    .then(data => renderProfile(data));
}
```

If `userId` is supplied via query parameters or hash fragments without path encoding:
- An attacker supplies: `../../v1/admin/deleteAccount`
- The browser normalizes the URL to: `/api/v1/admin/deleteAccount`
- The browser dispatches a **fully authenticated request (hDOM)** carrying the victim's session cookies and authorization headers.

## Non-Happy Path Weaponization Vectors

> [!warning] Non-Happy Path Traversal
> Target applications often enforce strict validation on the primary target path, but fail to sanitize parent directory climbing in secondary utility schemes or browser extension handlers.

### 1. Browser Extension Scheme CSPT
In desktop applications and IDEs that register custom web handlers or Chromium extensions (e.g. `chrome-extension://<id>/`), URL validation often checks that requests begin with the trusted extension prefix:
```javascript
// Validates prefix only:
if (url.startsWith("chrome-extension://" + EXTENSION_ID)) {
  location.assign(url);
}
```
Attackers supply traversal sequences after the prefix:
```http
chrome-extension://<EXTENSION_ID>/../../attacker.com/exploit.js
```
The browser's URL normalization evaluates the relative path, bypassing the whitelist and loading attacker-controlled assets.

### 2. Host and IP Prefix Confusion
When applications validate loopback or internal endpoints:
```javascript
if (targetUrl.startsWith("http://127.0.0.1")) {
  location.assign(targetUrl);
}
```
Attackers exploit URL parsing ambiguity using userinfo delimiters:
```http
http://127.0.0.1@attacker.com/payload.js
```
The client treats `127.0.0.1` as username credentials and connects to `attacker.com`.

## Exploitation Chains & Attack Scenarios

### 1. Token Leaking via Open Redirect
By steering an asynchronous `fetch()` request via `../` to an endpoint that issues an open redirect or reflects query parameters, sensitive authentication tokens stored in URL fragments (`#token=...`) or headers can be forced into external attacker access logs.

### 2. Unauthorized State-Changing Operations (hDOM Action Hijacking)
When an endpoint triggers state-changing actions (e.g. workspace invitations, subscription transfers, or account binds) based on client-side URL parameters, CSPT enables an attacker to force the browser into executing privileged operations without manual user confirmation.

## Remediation & Defensive Hardening
1. **URL Object Resolution**: Always resolve paths using the standard `URL` constructor and verify that the resulting pathname remains within the expected base prefix:
   ```javascript
   const base = new URL('/api/v1/users/', window.location.origin);
   const resolved = new URL(userInput, base);
   if (!resolved.pathname.startsWith('/api/v1/users/')) {
     throw new Error('CSPT Violation Detected');
   }
   ```
2. **Strict Whitelisting**: Avoid concatenating raw strings into API request sinks; map permitted actions to static dictionaries.
3. **Disallow Traversal Characters**: Reject or encode `%2f`, `%2e`, `.` and `/` in URL parameter validation.

## Related Pages
- [[web-and-bug-bounty]]
- [[cspt-vs-path-traversal]]
- [[open-redirect-attacks]]
- [[app-to-web-auth-transfer]]
- [[dom-debugging-and-sink-analysis]]
```

## Evidence and uncertainty
Documented from canonical notes in Notes/Narroto-Guts Hunt/ (Live Hunts, Structures, Tips and Tricks).

## Human feedback
Optionally explain or edit what should change.
