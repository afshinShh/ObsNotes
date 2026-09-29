---
type: llm-wiki-review
status: needs-review
decision: pending
revision: 1
operation: create
target: web-and-bug-bounty/sources/narroto-guts-hunt-tips-and-tricks.md
sources:
  - Notes/Narroto-Guts Hunt/Tips and Tricks.md
---

# Proposed Wiki change

## What will change
Compile provenance source anchor for Practical Tips & Client-Side Exploitation note.

## Proposed content
```markdown
---
title: "Source Note - Narroto-Guts Hunt: Practical Tips & Client-Side Exploitation"
created: 2026-09-29
updated: 2026-09-29
type: source
tags:
  - xss
  - bug-bounty
  - payload
  - tool
sources:
  - Notes/Narroto-Guts Hunt/Tips and Tricks.md
extracted_concepts:
  - "[[dom-debugging-and-sink-analysis]]"
  - "[[client-side-path-traversal]]"
extracted_entities:
  - "[[recollapse]]"
extracted_comparisons:
  []
confidence: high
contested: false
contradictions: []
parent: "[[web-and-bug-bounty]]"
cluster: web-and-bug-bounty
---
# Source Note - Narroto-Guts Hunt: Practical Tips & Client-Side Exploitation

> **Provenance Anchor**: Ingested from canonical vault file `[[Notes/Narroto-Guts Hunt/Tips and Tricks]]`.
> **Total Raw Lines**: 659 lines
> **SHA-256 Digest**: `ef34a55779ad73ed72d377340542c72cb37f182d8e9bd716b257f611a42c80fa`

---

## Compiled Wiki Layers
### Concepts
- [[dom-debugging-and-sink-analysis]] — Advanced DevTools debugging, hook-based fuzzing, and postMessage security analysis.
- [[client-side-path-traversal]] — Browser-side path traversal and API route redirection.

### Entities
- [[recollapse]] — Normalization and regex bypass fuzzing engine by 0xacb.

---

## Source Content Topic Breakdown
- **Client-Side Debugging**: "80% in Debugger" rule, event handler enumeration via `Object.keys(window).filter()`, conditional breakpoints.
- **DOM & Sinks**: Identifying dangerous sinks (`document.write`, `window.location.assign`), parameter flow analysis, and source map fuzzing.
- **postMessage Exploitation**: Regex origin validation bypasses (missing `$`, unescaped `.`), iframe restrictions, and DOM Invader interception.
- **Filter & WAF Bypasses**: HTML tag fuzzing, attribute encoding confusion, string concatenation, and parentheses-less execution.
- **Targeted Fuzzing**: Following the least change principle, avoiding blind fuzzing on static SPAs, and utilizing `recollapse`.

## Related Pages
- [[web-and-bug-bounty]]
- [[dom-debugging-and-sink-analysis]]
- [[client-side-path-traversal]]
- [[recollapse]]
```

## Evidence and uncertainty
Documented from canonical notes in Notes/Narroto-Guts Hunt/ (Live Hunts, Structures, Tips and Tricks).

## Human feedback
Optionally explain or edit what should change.
