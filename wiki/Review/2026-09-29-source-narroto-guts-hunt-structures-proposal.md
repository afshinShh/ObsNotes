---
type: llm-wiki-review
status: needs-review
decision: pending
revision: 2
operation: create
target: web-and-bug-bounty/sources/narroto-guts-hunt-structures.md
sources:
  - Notes/Narroto-Guts Hunt/Structures.md
---

# Proposed Wiki change

## What will change
Comprehensively enrich Structures source anchor to document all extracted reconnaissance, threat modeling, and reporting tradecraft.

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
- **Hunting Mindset**: Target offers the vulnerability; least change principle; hook-based fuzzing; exploring like a normal user; paid features as golden areas.
- **Wide Reconnaissance**: Domain discovery via legal footers and favicons; TLD search oneliner (`curl ...`) and `tldx`; certificate transparency (`crt.sh`, Censys, Shodan); reverse WHOIS (`website.informer.com`, `viewdns.info`); DNS resolution (`dnsx`); avoiding third-party SaaS traps.
- **Narrow Reconnaissance**: Search engine dorking (Google AND Bing with `&filter=0`); Wayback CDX Server API digest collapsing (`fl=timestamp,original&collapse=digest`); `robofinder` for robots.txt; Katana DOM limitations; passive vs active crawling; `ext:html` for DOM XSS; `ext:aspx,php,asp,jsp` for backend endpoints.
- **Architectural Threat Modeling**: Five diagnostic questions (threat model, application purpose, data passing mechanisms, user and authentication handling); functional mapping matrix (reflection -> XSS/SSTI, URL input -> SSRF/CSPT, uploader -> RCE, database -> SQLi); BackSlash Powered Scanner; Unicode and HTML attribute decoding rules.
- **Professional Reporting Discipline**: Direct attack scenarios without speculative prose; clear Burp Suite request packets; video PoCs under 2 minutes (30s ideal); scope boundary discipline before escalating.

## Related Pages
- [[web-and-bug-bounty]]
- [[bug-bounty-recon-and-threat-modeling]]
```

## Evidence and uncertainty
Documented from canonical notes in Notes/Narroto-Guts Hunt/ (Live Hunts, Structures, Tips and Tricks).

## Human feedback
Optionally explain or edit what should change.
