---
type: llm-wiki-review
status: needs-review
decision: approve
revision: 1
operation: create
target: web-and-bug-bounty/sources/source-code-review.md
sources:
  - Notes/OLD Notes/WEB/Source Code Review.md
---
# Proposed Wiki change

## What will change
Create provenance source anchor for Source Code Review note in Notes/OLD Notes/WEB/Source Code Review.md.

## Proposed content
```markdown
---
title: "Source Note - Source Code Review & Client-Side HTML Inspection"
created: 2026-10-01
updated: 2026-10-01
type: source
tags:
  - osint
  - mapping
  - secret-leak
  - bug-bounty
sources:
  - Notes/OLD Notes/WEB/Source Code Review.md
extracted_concepts:
  - "[[source-code-review-and-client-side-analysis]]"
extracted_entities:
  []
extracted_comparisons:
  []
confidence: high
contested: false
contradictions: []
parent: "[[web-and-bug-bounty]]"
cluster: web-and-bug-bounty
---
# Source Note - Source Code Review & Client-Side HTML Inspection

> **Provenance Anchor**: Ingested from canonical vault file `Notes/OLD Notes/WEB/Source Code Review.md`.
> - `Source Code Review.md` (39 lines, SHA-256: `24e320840157dc16d47b7782163b2853eaeeff37bca609ff0dc92c9b4e72462e`)
> **Total Raw Lines**: 39 lines

---

<!-- TOC_START -->
## Table of Contents
- [Compiled Wiki Layers](#compiled-wiki-layers)
  - [Concepts](#concepts)
- [Source Content Topic Breakdown](#source-content-topic-breakdown)
- [Related Pages](#related-pages)
<!-- TOC_END -->

## Compiled Wiki Layers
### Concepts
- [[source-code-review-and-client-side-analysis]] — Client-side HTML/DOM reconnaissance tradecraft, source code comment mining, email address extraction and OSINT pivoting, tracking identifier attribution (Google Publisher IDs, Analytics UAs), hidden directory discovery via asset paths, and regex pattern hunting.

## Source Content Topic Breakdown
1. **HTML Source Inspection Primitives**: Quick Ctrl+U source auditing for leaked metadata.
2. **Core Search Terms**:
   - Comments (`<!--`): Developer notes, hidden credentials, deprecated endpoints, debug flags.
   - Email Addresses (`@`): Internal staff emails, IT support contacts, corporate username structures.
   - Google Publisher IDs (`ca-pub`): Adsense IDs for infrastructure clustering and corporate attribution.
   - Google Analytics IDs (`ua-` / `G-`): Shared tracking IDs connecting seemingly unrelated corporate web properties.
   - Media & Asset Paths (`.jpg`, `.png`, `/static/`): Discovering backend directory structures and hidden endpoints.
3. **Regex Pattern Hunting**: Scanning client-side scripts for API keys, bearer tokens, and internal endpoints.

## Related Pages
- Parent Domain Hub: [[web-and-bug-bounty]]
- Target Concepts: [[source-code-review-and-client-side-analysis]], [[bug-bounty-recon-and-threat-modeling]], [[dom-debugging-and-sink-analysis]]
```

## Evidence and uncertainty
Sourced directly from canonical vault notes in Notes/OLD Notes/WEB/.
Validated against schema with zero structural contradictions.

## Human feedback
Human decision required via Decision Studio (http://127.0.0.1:20888) or command line.
