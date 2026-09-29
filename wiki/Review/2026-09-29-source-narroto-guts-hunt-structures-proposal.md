---
type: llm-wiki-review
status: needs-review
decision: pending
revision: 1
operation: create
target: web-and-bug-bounty/sources/narroto-guts-hunt-structures.md
sources:
  - Notes/Narroto-Guts Hunt/Structures.md
---

# Proposed Wiki change

## What will change
Compile provenance source anchor for Hunting Structures & Threat Modeling note.

## Proposed content
```markdown
---
title: "Source Note - Narroto-Guts Hunt: Hunting Structures & Threat Modeling"
created: 2026-09-29
updated: 2026-09-29
type: source
tags:
  - bug-bounty
  - mapping
  - asm
  - triage
  - report
sources:
  - Notes/Narroto-Guts Hunt/Structures.md
extracted_concepts:
  - "[[bug-bounty-recon-and-threat-modeling]]"
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
# Source Note - Narroto-Guts Hunt: Hunting Structures & Threat Modeling

> **Provenance Anchor**: Ingested from canonical vault file `[[Notes/Narroto-Guts Hunt/Structures]]`.
> **Total Raw Lines**: 151 lines
> **SHA-256 Digest**: `4d284057160e5dfbe285e52320d48b58a8ad63b6e0cfcf3ed63e4fdcc2405c31`

---

## Compiled Wiki Layers
### Concepts
- [[bug-bounty-recon-and-threat-modeling]] — Core threat modeling principles, wide vs narrow recon, and triage reporting discipline.

---

## Source Content Topic Breakdown
- **Hunting Mindset**: Target offers the vulnerability; least change principle; hook-based fuzzing; exploring like a normal user.
- **Wide Reconnaissance**: TLD search (`tldx`), certificate transparency (`crt.sh`, Censys), reverse WHOIS, DNS resolution (`dnsx`).
- **Narrow Reconnaissance**: Search engine dorking (Google, Bing, DuckDuckGo), Wayback CDX API snapshot digests, and DOM sink exploration.
- **Threat Modeling Matrix**: Functional UI behavior mapping to vulnerability primitives (reflection -> XSS, URL input -> SSRF, file upload -> RCE).
- **Professional Reporting**: Direct attack scenarios, eliminating speculative prose ("attacker can"), reproducible Burp packets, and short PoC videos (<= 2 minutes).

## Related Pages
- [[web-and-bug-bounty]]
- [[bug-bounty-recon-and-threat-modeling]]
```

## Evidence and uncertainty
Documented from canonical notes in Notes/Narroto-Guts Hunt/ (Live Hunts, Structures, Tips and Tricks).

## Human feedback
Optionally explain or edit what should change.
