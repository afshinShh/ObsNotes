---
type: llm-wiki-review
status: needs-review
decision: pending
revision: 1
operation: create
target: web-and-bug-bounty/concepts/account-takeover-and-auth-flaws.md
sources:
  - Notes/Narroto-Guts Hunt/Live Hunts.md
  - Notes/Narroto-Guts Hunt/Tips and Tricks.md
---

# Proposed Wiki change

## What will change
Compile comprehensive checklist note for Account Takeover and modern authentication flaws.

## Proposed content
```markdown
---
title: "Account Takeover (ATO) & Authentication Flow Flaws (Comprehensive Checklist)"
created: 2026-09-29
updated: 2026-09-29
type: concept
parent: "[[web-and-bug-bounty]]"
cluster: web-and-bug-bounty
tags:
  - ato
  - oauth
  - session
  - bug-bounty
  - api
sources:
  - Notes/Narroto-Guts Hunt/Live Hunts.md
  - Notes/Narroto-Guts Hunt/Tips and Tricks.md
confidence: high
contested: false
contradictions: []
---
# Account Takeover (ATO) & Authentication Flow Flaws (Comprehensive Checklist)

<!-- TOC_START -->
<!-- TOC_END -->

## Overview
Authentication and session management mechanisms are primary targets for high-impact vulnerability hunting. Flaws in state transitions, token conversion endpoints, cross-application handoffs, and registration logic frequently lead to direct pre-auth or post-auth Account Takeover (ATO).

## Registration & Onboarding Checklist

- [ ] **Special System Accounts**: Attempt registering with administrative or internal addresses on non-core assets:
  - `noreply@github.com`, `support@company.com`, `admin@target.com`
- [ ] **Email Normalization & OTP Bypasses**:
  - Null-byte and hex character padding: `victim@gmail.com%0a` (values `%00` through `%20`). If the verification email is delivered to `victim@gmail.com` but the internal database indexes the account separately, authentication can be usurped.
  - Sub-addressing permutations: `victim+a@gmail.com` vs `victim@gmail.com` vs `v.i.c.t.i.m@gmail.com`.
    - If the same OTP is generated for all aliases -> bypass rate-limiting and account lockout protections to bruteforce codes.
    - If different OTPs are issued per alias -> execute distributed password spraying while keeping OTP attempts isolated.
- [ ] **Verification Link Tampering**: Inspect confirmation tokens for predictable timestamps, weak hashes, or endpoints that accept `verification_token=null` / `true`.

## Multi-Factor Authentication (2FA) Checklist

- [ ] **State Machine Ordering Analysis**: Map the transition sequence:
  - *Vulnerable Pattern*: `Credentials Verified -> Login Session Cookie Issued -> 2FA Prompt Displayed -> Session Flag Updated`.
    - Probing: Directly issue requests to privileged endpoints using the initial session cookie without completing the 2FA challenge.
  - *Hardened Pattern*: `Credentials Verified -> Temporary Pre-Auth Token Issued -> 2FA Verified -> Session Cookie Issued`.
- [ ] **2FA Parameter Tampering**: In multi-option 2FA flows (SMS, Email, Authenticator App), test tampering with internal event identifiers (e.g. changing `"EventName": "SendSecurityEmailCode"` to `"SendSecurityTelCode"` or supplying empty/null verification codes).
- [ ] **Response Manipulation**: Intercept 2FA verification responses and modify boolean flags (e.g. `{"success": false, "code": "INVALID_OTP"}` -> `{"success": true}`).

## OAuth & Third-Party Integration Checklist

- [ ] **Unknown / Custom Providers**:
  - Test authorization code lifetime (verify codes expire within 30–60 seconds).
  - Multi-app code reuse (test whether a code issued for Client A can be exchanged by Client B).
- [ ] **`redirect_uri` Filter Bypasses**:
  - **Chinese Full-Stop Dot (`。`)**: `%3E%80%82` (`///evil%3E%80%82com`).
  - **Subdomain Prepending**: `evil.com.target.com`.
  - **URL Parameter / Character Confusion**: `target.com%25%2eEvil.com`, `target.com%09Evil.com`, `target.com@evil.com`.
  - **Storage Reflection**: Check whether `redirect_uri` or return state is stored in `localStorage` or `sessionStorage` and can be tampered via DOM injection.
- [ ] **OAuth `state` Parameter Audit**:
  - Is `state` strictly enforced, or can it be omitted without error?
  - **Data in `state`**: Check whether `state` contains serialized JSON, user IDs, or UUIDs instead of a cryptographic CSRF token (*high probability of vulnerability*).
  - **1-Click ATO via State Swap**: An attacker grabs a valid authorization code with their own account, swaps the `state` UUID to the victim's UUID, and lures the victim into opening the link, forcing the victim into account linkage or credential hijacking.
- [ ] **OAuth Race Conditions**:
  - Concurrently exchange authorization code -> `access_token` across parallel threads.
  - Test `refresh_token` reuse across simultaneous token rotation requests.
- [ ] **Permission & Scope Manipulation**: Attempt revoking email permissions in the provider consent dialog or expanding scopes (`scope=read,write,admin`).

## App-to-App & Cross-Environment Transfer Checklist (Non-OAuth)

When authentication state is transferred between mobile/desktop applications and web browsers:

- [ ] **Token Exchange Routes (`tokenAuth`)**: Inspect endpoints that convert native app tokens into browser session cookies:
  ```http
  GET /tokenAuth?token=EXCHANGE_TOKEN&next=https://target.com/dashboard HTTP/1.1
  ```
  - Verify if client-side redirects can be bypassed via tab characters (`	javascript:alert(1)`) or open redirects.
- [ ] **Polling Implementations**: When desktop apps poll a backend API waiting for web browser authentication completion:
  - Is there explicit user consent required on the web page?
  - Is the polling ID predictable or tied to an IP address?
  - If no IP binding exists, sending the authentication link to any victim leads to instant **1-Click ATO** upon victim login.
- [ ] **Top-Level Cookie Sharing**: Check if session cookies are scoped to parent domains (`.domain.com`), exposing sessions to vulnerable subdomains.
- [ ] **Window Opener Redirection (`window.opener`)**: When third-party login flows open popup windows without `rel="noopener noreferrer"`, the child window can execute `window.opener.location = 'https://attacker.com/phish'`.

## Magic Links & QR Code Logins

- [ ] **Cancellation Race & Traffic Inspection**: Cancel magic link requests during redirect transitions to capture unconsumed authorization tokens in network traffic.
- [ ] **Dynamic Host Header Poisoning**: Test whether magic link emails use the client-supplied `Host:`, `X-Forwarded-Host:`, or custom port to construct links.

## Related Pages
- [[web-and-bug-bounty]]
- [[oauth-attack-vectors]]
- [[oauth-grant-types-and-flows]]
- [[app-to-web-auth-transfer]]
- [[client-side-path-traversal]]
- [[bug-bounty-live-hunts-case-studies]]
```

## Evidence and uncertainty
Documented from canonical notes in Notes/Narroto-Guts Hunt/ (Live Hunts, Structures, Tips and Tricks).

## Human feedback
Optionally explain or edit what should change.
