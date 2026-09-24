---
type: llm-wiki-review
status: needs-review
decision: pending
revision: 1
operation: create
target: sources/parameter-pollution.md
sources:
  - raw/articles/parameter-pollution.md
---

# Proposed Wiki change

## What will change
Establishes the provenance anchor for HTTP Parameter Pollution (HPP) notes ingested from `unprocessed-obsidians/parameter-pollution.md`, linking primary source notes to compiled concepts.

## Proposed content

---
title: Source Note - HTTP Parameter Pollution (HPP)
created: 2026-09-24
updated: 2026-09-24
type: source
tags:
  - api
  - bug-bounty
sources:
  - unprocessed-obsidians/parameter-pollution.md
extracted_concepts:
  - "[[http-parameter-pollution]]"
---

# Source Note: HTTP Parameter Pollution (HPP)

> **Provenance Anchor**: Ingested from canonical vault file `[[unprocessed-obsidians/parameter-pollution]]`.
> **Compiled Wiki Pages**:
> - Concept: [[http-parameter-pollution]]

---

## Original Material Overview
The source note covers HTTP Parameter Pollution (HPP) mechanics across diverse application and web server technologies:
- **Server Parameter Precedence**: Matrix of technology behaviors when encountering duplicate parameters (First occurrence, Last occurrence, Array concatenation, Comma-delimited merging).
- **Attack Classifications**: Client-side HPP (injecting query strings into generated links) vs Server-side HPP (manipulating backend internal API requests).
- **Impact Scenarios**: Bypassing WAF rules by splitting SQLi/XSS keywords across parameters, overriding backend default query parameters, privilege escalation in payment and checkout workflows.
- **Real-World Case Studies & CVEs**: Account takeover and authorization bypasses in social platforms, bank transfers, and OAuth redirection flows.

## Related Pages
- [[http-parameter-pollution]]
- [[sql-injection-testing]]

## Evidence and uncertainty
Directly transcribed and normalized from `unprocessed-obsidians/parameter-pollution.md`. Standard web technology parameter parsing behavior.

## Human feedback
Optionally explain or edit what should change.
