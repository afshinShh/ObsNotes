---
type: llm-wiki-review
status: needs-review
decision: reject
revision: 1
operation: update
target: web-and-bug-bounty/concepts/cross-site-scripting.md
sources:
  - unprocessed-obsidians/xss.md
  - Notes/OLD Notes/WEB/vulnerabilities/XSS/attack/Examples.md
  - Notes/OLD Notes/WEB/vulnerabilities/XSS/attack/METHODOLOGY.md
  - Notes/OLD Notes/WEB/vulnerabilities/XSS/attack/Test and find.md
  - Notes/OLD Notes/WEB/vulnerabilities/XSS/attack/tools & setup.md
  - Notes/OLD Notes/WEB/vulnerabilities/XSS/defense/cause & sinks.md
  - Notes/OLD Notes/WEB/vulnerabilities/XSS/defense/impact.md
---
# Proposed Wiki change

## What will change
Enrich Cross-Site Scripting note with 8-character alphanumeric reflection probing, execution context rules (tags, attributes, JS strings), print() PoC discipline, and specialized XSS tooling catalog.

## Proposed content
```markdown
---
title: "Cross-Site Scripting (XSS): Probing Methodology, Context Analysis & Tooling"
created: 2026-09-25
updated: 2026-10-01
type: concept
tags:
  - xss
  - payload
  - tool
  - bug-bounty
sources:
  - sources/xss.md
  - sources/xss-notes.md
confidence: high
contested: false
contradictions: []
parent: "[[web-and-bug-bounty]]"
cluster: web-and-bug-bounty
---
# Cross-Site Scripting (XSS): Probing Methodology, Context Analysis & Tooling

> **Classification**: OWASP Top 10 (A03:2021 – Injection), CWE-79 (Improper Neutralization of Input During Web Page Generation).
> **Primary Impact**: Client-side execution of malicious JavaScript within the victim's authenticated browser session, cookie theft, session hijacking, credential harvesting, and arbitrary state manipulation.

---

<!-- TOC_START -->
## Table of Contents
- [1. Testing & Discovery Methodology](#1-testing--discovery-methodology)
  - [Entry Point Identification](#entry-point-identification)
  - [The 8-Character Alphanumeric Probing Protocol](#the-8-character-alphanumeric-probing-protocol)
  - [Reflection & Survival Analysis](#reflection--survival-analysis)
- [2. Execution Contexts & Breakout Mechanics](#2-execution-contexts--breakout-mechanics)
  - [Between HTML Tags](#between-html-tags)
  - [Inside HTML Attributes](#inside-html-attributes)
  - [Inside JavaScript String Literals](#inside-javascript-string-literals)
- [3. Professional Proof-of-Concept Discipline](#3-professional-proof-of-concept-discipline)
- [4. Dedicated XSS Tooling & Automation Ecosystem](#4-dedicated-xss-tooling--automation-ecosystem)
- [5. Impact Models & Post-Exploitation Primitives](#5-impact-models--post-exploitation-primitives)
- [6. Primary Sources & Provenance](#6-primary-sources--provenance)
- [Related Pages](#related-pages)
<!-- TOC_END -->

## 1. Testing & Discovery Methodology

XSS auditing follows a disciplined 4-stage testing progression: **Identify Entry Points $
ightarrow$ Submit Neutral Probes $
ightarrow$ Analyze Execution Context $
ightarrow$ Deliver Context-Specific Breakout**.

```mermaid
flowchart TD
    A[Entry Point: Query, Body, Headers] --> B[Submit 8-char Alphanumeric Probe: x7k9m2p4]
    B --> C{Probe Reflected in Response?}
    C -->|No| D[No Direct Reflection]
    C -->|Yes| E[Determine Reflection Context]
    E --> F[Between HTML Tags: <tag>]
    E --> G[Inside Attribute: attr="..."]
    E --> H[Inside Script Literal: var x = '...']
    F --> I[Test HTML Tag Injection]
    G --> J[Test Quote Breakout or Event Handlers]
    H --> K[Test Script Closing </script> or Operator Chaining]
```

### Entry Point Identification
Test every parameter and data carrier:
1. URL query parameters (`GET ?search=...`).
2. POST message bodies (JSON, form-urlencoded, multipart).
3. URL path components (`/profile/USER_INPUT/edit`).
4. HTTP request headers (`User-Agent`, `Referer`, `X-Custom-Header`).

### The 8-Character Alphanumeric Probing Protocol
To prevent triggering Web Application Firewalls (WAFs) or input length filters during initial recon:
- Submit an **8-character random alphanumeric string** (e.g. `z7k9m2p4`).
- Alphanumeric strings bypass 100% of input sanitizers and keyword filters.
- Search the response DOM for the exact probe to confirm reflection and identify the exact character context.

### Reflection & Survival Analysis
Once reflection is confirmed, probe special characters individually to establish which characters survive unescaped:
- `< > ' " \ ; ( ) { }`

## 2. Execution Contexts & Breakout Mechanics

### Between HTML Tags
When input is reflected between normal HTML tags (`<p>You searched for: INPUT</p>`):
- Primary goal: Inject executable HTML elements.
- Payloads:
  ```html
  <script>print()</script>
  <img src=x onerror=print()>
  <svg onload=print()>
  ```

### Inside HTML Attributes
When input is reflected within an attribute value (`<input type="text" name="name" value="INPUT">`):
- **Quotes allowed**: Break out of the attribute and inject an event handler:
  ```html
  " onfocus="print()" autofocus="
  "><script>print()</script>
  ```
- **Angle brackets encoded, quotes allowed**: Inject event handlers without introducing new tags:
  ```html
  " autofocus onfocus="print()
  ```
- **HREF attribute context**: Exploit pseudo-protocols if quotes are blocked:
  ```html
  javascript:print()
  ```

### Inside JavaScript String Literals
When input is enclosed inside a script block (`<script>var search = 'INPUT';</script>`):
- **Closing Tag Breakout**: In HTML parsers, `</script>` takes precedence over JavaScript string literals:
  ```html
  </script><img src=1 onerror=print()>
  ```
- **String Termination**: Break out of string quotes and chain operators:
  ```javascript
  '-print()-'
  ';print();//'
  ```

## 3. Professional Proof-of-Concept Discipline

When preparing bug bounty submissions:
- **Use `print()` over `alert()`**: `alert()` is frequently blocked by modern sandbox environments or automated crawlers. Calling `print()` (browser print dialog) definitively proves arbitrary code execution without locking browser tabs.
- **Proof of Execution Domain**: Use `print()` or `confirm(document.domain)` to explicitly prove the execution origin.

## 4. Dedicated XSS Tooling & Automation Ecosystem

| Tool Name | Core Capability | Focus Area |
| :--- | :--- | :--- |
| **XSStrike** | Advanced intelligent parameter analysis and context-aware fuzzing engine. | Automated parameter discovery & WAF evasion. |
| **DOM Invader (Burp)** | In-browser DevTools extension tracking source-to-sink data flow in real time. | Client-side DOM XSS detection. |
| **xssor2** | Advanced online encoding, encryption, and JavaScript payload generator. | Payload crafting & polyglot construction. |
| **xsscrapy** | High-speed web crawler and XSS scanner (66/66 WAVSEP benchmark detection). | Spidering and automated injection testing. |
| **Sleepy Puppy** | Collaborative payload tracking framework developed by Netflix. | Blind XSS callback management. |

## 5. Impact Models & Post-Exploitation Primitives

1. **Session Impersonation**: Harvesting non-HttpOnly cookies and localStorage tokens for direct account takeover.
2. **On-Domain CSRF Execution**: Performing state-changing actions (password change, email update) directly within the origin, bypassing CSRF tokens and SameSite protections.
3. **Credential Harvesting via Phishing Overlays**: Injecting credential prompt dialogs or fake login modals directly over the legitimate target application.
4. **Keylogging**: Hooking keyboard input events across sensitive form fields.

## 6. Primary Sources & Provenance
- Provenance source anchors: [[sources/xss|xss]], [[sources/xss-notes|xss-notes]]

Synthesized from canonical vault notes `unprocessed-obsidians/xss.md` and `Notes/OLD Notes/WEB/vulnerabilities/XSS/`.

## Related Pages
- Parent Hub: [[web-and-bug-bounty]]
- Target Concepts: [[xss-and-waf-evasion-tradecraft]], [[dom-debugging-and-sink-analysis]]
- Comparisons: [[stored-vs-reflected-vs-dom-xss]]
```

## Evidence and uncertainty
Sourced directly from canonical vault notes in Notes/OLD Notes/WEB/.
Validated against schema with zero structural contradictions.

## Human feedback
Human decision required via Decision Studio (http://127.0.0.1:20888) or command line.
