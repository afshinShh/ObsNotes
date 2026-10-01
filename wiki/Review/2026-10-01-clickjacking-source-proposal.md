---
type: llm-wiki-review
status: needs-review
decision: approve
revision: 1
operation: create
target: web-and-bug-bounty/sources/clickjacking.md
sources:
  - Notes/OLD Notes/WEB/vulnerabilities/Clickjacking/concepts and defense.md
  - Notes/OLD Notes/WEB/vulnerabilities/Clickjacking/attack/payload.md
  - Notes/OLD Notes/WEB/vulnerabilities/Clickjacking/attack/METHODOLOGY.md
  - Notes/OLD Notes/WEB/vulnerabilities/Clickjacking/attack/tools & setup.md
---
# Proposed Wiki change

## What will change
Create provenance source anchor for Clickjacking notes in Notes/OLD Notes/WEB/vulnerabilities/Clickjacking/.

## Proposed content
```markdown
---
title: "Source Note - Clickjacking: UI Redressing, Payloads, and Mitigation"
created: 2026-10-01
updated: 2026-10-01
type: source
tags:
  - web-security
  - payload
  - tool
  - bug-bounty
sources:
  - Notes/OLD Notes/WEB/vulnerabilities/Clickjacking/concepts and defense.md
  - Notes/OLD Notes/WEB/vulnerabilities/Clickjacking/attack/payload.md
  - Notes/OLD Notes/WEB/vulnerabilities/Clickjacking/attack/METHODOLOGY.md
  - Notes/OLD Notes/WEB/vulnerabilities/Clickjacking/attack/tools & setup.md
extracted_concepts:
  - "[[clickjacking-attacks-and-ui-redressing]]"
extracted_entities:
  []
extracted_comparisons:
  - "[[clickjacking-vs-csrf]]"
confidence: high
contested: false
contradictions: []
parent: "[[web-and-bug-bounty]]"
cluster: web-and-bug-bounty
---
# Source Note - Clickjacking: UI Redressing, Payloads, and Mitigation

> **Provenance Anchor**: Ingested from canonical vault files under `Notes/OLD Notes/WEB/vulnerabilities/Clickjacking/`.
> - `concepts and defense.md` (39 lines, SHA-256: `92d4664d5680b6210a8dcfd921bfc973dd188fa8e8a2db0f6e7c209bf202d765`)
> - `attack/payload.md` (64 lines, SHA-256: `b9eafe919ec8ee4c42f58372a05d2fa632204957278243e64e75f882bdfeae74`)
> - `attack/METHODOLOGY.md` (24 lines, SHA-256: `b526a316acdc2448a4bc5c08e342912444f152a2678f2f463f8fbd9bd4569149`)
> - `attack/tools & setup.md` (5 lines, SHA-256: `c99b90f1dd89ec063a94e830058f9b452232b5caf4d88aaf9f6cc02d3b9c4935`)
> **Total Raw Lines**: 132 lines

---

<!-- TOC_START -->
## Table of Contents
- [Compiled Wiki Layers](#compiled-wiki-layers)
  - [Concepts](#concepts)
  - [Comparisons](#comparisons)
- [Source Content Topic Breakdown](#source-content-topic-breakdown)
- [Related Pages](#related-pages)
<!-- TOC_END -->

## Compiled Wiki Layers
### Concepts
- [[clickjacking-attacks-and-ui-redressing]] — Mechanics of interface-based attacks, CSS iframe layer manipulation (opacity, coordinates, z-index), prefilled form exploitation via GET parameters, frame-busting script bypasses using HTML5 sandbox attributes, multi-step clickjacking, DOM XSS chaining, Burp Clickbandit tooling, and defensive CSP/XFO controls.

### Comparisons
- [[clickjacking-vs-csrf]] — Technical trade-off analysis between UI redressing requiring physical user interaction vs invisible background request forgery.

## Source Content Topic Breakdown
1. **Definition & Core Mechanics**: Decoy website layering, transparent iframes, and CSS stacking contexts.
2. **Comparison with CSRF**: Why anti-CSRF tokens fail against Clickjacking (requests originate on-domain).
3. **Advanced Attack Primitives**:
   - Prefilled forms using GET query parameters.
   - Frame busting bypass using iframe `sandbox="allow-scripts allow-forms"` without `allow-top-navigation`.
   - Multi-step clickjacking coordination for shopping baskets and account deletion confirmations.
   - Chaining Clickjacking with DOM XSS.
4. **Tooling & Defenses**: Burp Clickbandit interactive generator, `X-Frame-Options: DENY/SAMEORIGIN`, and CSP `frame-ancestors`.

## Related Pages
- Parent Domain Hub: [[web-and-bug-bounty]]
- Target Concepts: [[clickjacking-attacks-and-ui-redressing]], [[csrf-attacks-and-prevention]], [[cross-site-scripting]]
```

## Evidence and uncertainty
Sourced directly from canonical vault notes in Notes/OLD Notes/WEB/vulnerabilities/.
Validated against schema with zero structural contradictions.

## Human feedback
Human decision required via Decision Studio (http://127.0.0.1:20888) or command line.
