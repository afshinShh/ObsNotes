---
type: llm-wiki-review
status: needs-review
decision: pending
revision: 1
operation: create
target: sources/open-redirect.md
sources:
  - raw/articles/open-redirect.md
---

# Proposed Wiki change

## What will change
Establishes the provenance anchor for Open Redirect notes ingested from `unprocessed-obsidians/open-redirect.md`, linking primary source notes to compiled concepts.

## Proposed content

---
title: Source Note - Open Redirect Vulnerabilities
created: 2026-09-24
updated: 2026-09-24
type: source
tags:
  - open-redirect
  - bug-bounty
sources:
  - unprocessed-obsidians/open-redirect.md
extracted_concepts:
  - "[[open-redirect-attacks]]"
---

# Source Note: Open Redirect Vulnerabilities

> **Provenance Anchor**: Ingested from canonical vault file `[[unprocessed-obsidians/open-redirect]]`.
> **Compiled Wiki Pages**:
> - Concept: [[open-redirect-attacks]]

---

## Original Material Overview
The source note covers Open Redirect vulnerabilities, detection heuristics, and allowlist bypass patterns:
- **Mechanisms**: Unvalidated client-supplied URLs in HTTP 3xx redirection handlers, post-login return URLs, Referer-based redirections.
- **Bypass Techniques**: Domain spoofing, slash tricks (`//`, `///`), backslash tricks (`/\`), protocol confusion (`javascript:`, `data:`), subdomain flaws, parameter pollution, character encoding (hex, URL, unicode).
- **Chaining & Impact**: Chaining with OAuth flows for authorization code theft (cross-linked to `[[oauth-attack-vectors]]`), phishing link legitimation, SSRF escalation, and CSRF token bypass.

## Related Pages
- [[open-redirect-attacks]]
- [[cross-site-scripting]]

## Evidence and uncertainty
Directly transcribed and normalized from `unprocessed-obsidians/open-redirect.md`. Standard URL parser and redirection validation flaws.

## Human feedback
Optionally explain or edit what should change.
