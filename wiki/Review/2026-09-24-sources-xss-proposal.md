---
type: llm-wiki-review
status: needs-review
decision: pending
revision: 1
operation: create
target: sources/xss.md
sources:
  - raw/articles/xss.md
---

# Proposed Wiki change

## What will change
Establishes the provenance anchor for Cross-Site Scripting (XSS) notes ingested from `unprocessed-obsidians/xss.md`, linking primary source notes to compiled concepts.

## Proposed content

---
title: Source Note - Cross-Site Scripting (XSS)
created: 2026-09-24
updated: 2026-09-24
type: source
tags:
  - xss
  - bug-bounty
sources:
  - unprocessed-obsidians/xss.md
extracted_concepts:
  - "[[cross-site-scripting]]"
---

# Source Note: Cross-Site Scripting (XSS)

> **Provenance Anchor**: Ingested from canonical vault file `[[unprocessed-obsidians/xss]]`.
> **Compiled Wiki Pages**:
> - Concept: [[cross-site-scripting]]

---

## Original Material Overview
The source note covers Cross-Site Scripting classification, hunting methodology, and context-dependent filter evasion:
- **Types of XSS**: Reflected XSS, Stored XSS, DOM-based XSS, and Blind XSS.
- **Hunting Methodology**: Source-to-sink analysis, parameter reflection discovery, context determination (HTML body, attribute, script context, URL context).
- **Filter Evasion Taxonomy**: Tag filtering bypasses, string filter evasion, WAF evasion techniques, parentheses alternatives, alert alternatives, event handler alternatives.
- **Impact and Chaining**: Session hijacking, credential harvesting, CSRF tokens extraction, DOM manipulation, client-side actions impersonation.

## Related Pages
- [[cross-site-scripting]]
- [[server-side-template-injection]]

## Evidence and uncertainty
Directly transcribed and normalized from `unprocessed-obsidians/xss.md`. Standard client-side web application security concepts.

## Human feedback
Optionally explain or edit what should change.
