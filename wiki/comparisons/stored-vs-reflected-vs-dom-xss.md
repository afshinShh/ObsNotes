---
title: "Stored vs Reflected vs DOM-Based XSS Mechanisms"
created: 2026-09-25
updated: 2026-09-25
type: comparison
tags:
  - xss
  - bug-bounty
  - payload
sources:
  - unprocessed-obsidians/xss.md
confidence: high
contested: false
contradictions: []
---

# Stored vs Reflected vs DOM-Based XSS Mechanisms

## Overview
Comparative evaluation of Cross-Site Scripting (XSS) execution models across persistence, reflection vectors, and client-side DOM dataflows.

## Comparative Technical Matrix

| Evaluation Dimension | Paradigm A | Paradigm B | Paradigm C |
| :--- | :--- | :--- | :--- |
| **Persistence Layer** | Stored in persistent backend (Database, Filesystem, Logs) | Reflected immediately in HTTP response body | Never leaves client browser (in-memory DOM tree) |
| **Victim Interaction** | Zero victim interaction required beyond browsing the page | Requires victim to click an attacker-crafted malicious link | Requires clicking crafted URL or interacting with client-side fragment `#` |
| **WAF Visibility** | WAF can inspect on injection and on delivery | WAF inspects incoming query parameters/headers | Completely invisible to network WAFs if payload resides in URL fragment (`#`) |
| **Execution Context** | Rendered during server-side HTML template generation | Echoed by backend application handler | Executed by client-side JavaScript sink (`innerHTML`, `eval()`, `document.write()`) |
| **Impact Rating** | Critical (wormable, administrative session hijack) | Medium to High (targeted spear-phishing) | High (stealthy client-side credential/DOM compromise) |

## Technical Analysis & Operational Verdict
DOM-based XSS is increasingly prevalent in modern Single-Page Applications (React, Vue, Angular) and bypasses traditional server-side WAF inspection. Defenses require strict context-aware encoding, Trusted Types, and robust Content Security Policies (CSP).

## Primary Sources & Provenance
Ingested and synthesized from canonical notes:
  - unprocessed-obsidians/xss.md

## Related Concepts & Notes
- [[cross-site-scripting]]
- [[vulnerability-research-methodology]]
