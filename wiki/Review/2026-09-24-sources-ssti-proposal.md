---
type: llm-wiki-review
status: needs-review
decision: pending
revision: 1
operation: create
target: sources/ssti.md
sources:
  - raw/articles/ssti.md
---

# Proposed Wiki change

## What will change
Establishes the provenance anchor for Server-Side Template Injection (SSTI) notes ingested from `unprocessed-obsidians/ssti.md`, linking primary source notes to compiled concepts.

## Proposed content

---
title: Source Note - Server-Side Template Injection (SSTI)
created: 2026-09-24
updated: 2026-09-24
type: source
tags:
  - ssti
  - bug-bounty
sources:
  - unprocessed-obsidians/ssti.md
extracted_concepts:
  - "[[server-side-template-injection]]"
---

# Source Note: Server-Side Template Injection (SSTI)

> **Provenance Anchor**: Ingested from canonical vault file `[[unprocessed-obsidians/ssti]]`.
> **Compiled Wiki Pages**:
> - Concept: [[server-side-template-injection]]

---

## Original Material Overview
The source note covers Server-Side Template Injection mechanics, template engine fingerprinting, and Remote Code Execution (RCE) chains:
- **Vulnerable vs Secure Implementations**: Jinja2 / Flask pattern analysis (concatenating user input into template string vs passing variables to `render_template`).
- **Detection & Identification Polyglots**: Math expression probes (`${7*7}`, `{{7*7}}`, `<%= 7*7 %>`, `#{7*7}`) separating server-side template evaluation from client-side reflection.
- **Engine Fingerprinting Decision Tree**: Jinja2 vs Twig, Smarty, Freemarker, Velocity, ERB, Pebble.
- **Filter Bypass Techniques**: Character blacklists (escaping quotes, underscores), keyword filtering bypasses, Python MRO (`__mro__`, `__subclasses__`) traversal, and .NET reflection string-less exploitation.

## Related Pages
- [[server-side-template-injection]]
- [[cross-site-scripting]]

## Evidence and uncertainty
Directly transcribed and normalized from `unprocessed-obsidians/ssti.md`. Standard server-side template execution mechanics across Python, Java, Ruby, PHP, and .NET.

## Human feedback
Optionally explain or edit what should change.
