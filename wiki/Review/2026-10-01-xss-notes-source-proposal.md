---
type: llm-wiki-review
status: needs-review
decision: approve
revision: 1
operation: create
target: web-and-bug-bounty/sources/xss-notes.md
sources:
  - Notes/OLD Notes/WEB/vulnerabilities/XSS/attack/Examples.md
  - Notes/OLD Notes/WEB/vulnerabilities/XSS/attack/METHODOLOGY.md
  - Notes/OLD Notes/WEB/vulnerabilities/XSS/attack/Test and find.md
  - Notes/OLD Notes/WEB/vulnerabilities/XSS/attack/tools & setup.md
  - Notes/OLD Notes/WEB/vulnerabilities/XSS/defense/cause & sinks.md
  - Notes/OLD Notes/WEB/vulnerabilities/XSS/defense/impact.md
  - Notes/OLD Notes/WEB/vulnerabilities/XSS/defense/protection.md
  - Notes/OLD Notes/WEB/vulnerabilities/XSS/links and todos.md
---
# Proposed Wiki change

## What will change
Create provenance source anchor for XSS notes in Notes/OLD Notes/WEB/vulnerabilities/XSS/.

## Proposed content
```markdown
---
title: "Source Note - Cross-Site Scripting (XSS): Probing, Context Analysis, and Tooling"
created: 2026-10-01
updated: 2026-10-01
type: source
tags:
  - xss
  - payload
  - tool
  - bug-bounty
sources:
  - Notes/OLD Notes/WEB/vulnerabilities/XSS/attack/Examples.md
  - Notes/OLD Notes/WEB/vulnerabilities/XSS/attack/METHODOLOGY.md
  - Notes/OLD Notes/WEB/vulnerabilities/XSS/attack/Test and find.md
  - Notes/OLD Notes/WEB/vulnerabilities/XSS/attack/tools & setup.md
  - Notes/OLD Notes/WEB/vulnerabilities/XSS/defense/cause & sinks.md
  - Notes/OLD Notes/WEB/vulnerabilities/XSS/defense/impact.md
  - Notes/OLD Notes/WEB/vulnerabilities/XSS/defense/protection.md
  - Notes/OLD Notes/WEB/vulnerabilities/XSS/links and todos.md
extracted_concepts:
  - "[[cross-site-scripting]]"
extracted_entities:
  []
extracted_comparisons:
  - "[[stored-vs-reflected-vs-dom-xss]]"
confidence: high
contested: false
contradictions: []
parent: "[[web-and-bug-bounty]]"
cluster: web-and-bug-bounty
---
# Source Note - Cross-Site Scripting (XSS): Probing, Context Analysis, and Tooling

> **Provenance Anchor**: Ingested from canonical vault files under `Notes/OLD Notes/WEB/vulnerabilities/XSS/`.
> - `attack/Examples.md` (87 lines, SHA-256: `91ca6fc82a875a5960010901e74f88e6a2542a17f694e9f36b6df11174a7b3db`)
> - `attack/METHODOLOGY.md` (110 lines, SHA-256: `c8d887a0da7b33aa3bbaaa102213d80336214878a1352ae7ddcf68e5cc69910d`)
> - `attack/Test and find.md` (21 lines, SHA-256: `ec555a6d36ef55fa8993c17cc39efd1e9f193eb77839352cf5298a0c2134cb74`)
> - `attack/tools & setup.md` (36 lines, SHA-256: `08b5e40632612716ef5a8a1ea22b378fe87932c10a4e3fa33f9ca0a6042a981c`)
> - `defense/cause & sinks.md` (50 lines, SHA-256: `98762ecdbd873dd19ad778fe873616a8fa37299cb2934cf5e2ea859345719ae5`)
> - `defense/impact.md` (19 lines, SHA-256: `0079dcbf018be29d702319207e2c9efca1b777a83fa30c9d784fa7408f62f392`)
> - `defense/protection.md` (0 lines, SHA-256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`)
> - `links and todos.md` (37 lines, SHA-256: `41b7fe009d17d6928e469e3a63ec5018698ca1187dff9ec31165c7198bb602c3`)
> **Total Raw Lines**: 360 lines

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
- [[cross-site-scripting]] — Comprehensive XSS testing methodology incorporating 8-character random alphanumeric probing, context identification (HTML tag body, attribute context, JavaScript string context), WAF evasion tradecraft, non-intrusive `print()` PoC discipline, XSS scanning tooling ecosystem (XSStrike, xssor2, xsscrapy, Sleepy Puppy, DOM Invader), and impact modeling.

### Comparisons
- [[stored-vs-reflected-vs-dom-xss]] — Comparative trade-offs across persistence models, delivery mechanisms, and execution sinks.

## Source Content Topic Breakdown
1. **Testing & Discovery Methodology**:
   - Comprehensive entry point identification: URL parameters, request body, URL path, headers (`User-Agent`, `Referer`).
   - 8-character random alphanumeric probing to track reflection without triggering WAF blocks.
2. **Execution Contexts**:
   - Between HTML tags: Tag injection (`<script>`, `<img>`, `<svg>`).
   - Inside HTML attributes: Event handlers (`onload=`, `onerror=`, `onfocus=autofocus`), quote escaping.
   - Inside JavaScript variables/strings: Quoted context escape (`'-alert(1)-'`, `</script>` tag closing).
3. **PoC Standards**: Ethical verification using `print()` or `alert(document.domain)` instead of destructive hooks.
4. **Tooling Ecosystem**: XSStrike, xssor2, xsscrapy, Netflix Sleepy Puppy, and PortSwigger DOM Invader.
5. **Impact Classifications**: Session impersonation, arbitrary action execution, credential harvesting, and DOM defacement.

## Related Pages
- Parent Domain Hub: [[web-and-bug-bounty]]
- Target Concepts: [[cross-site-scripting]], [[xss-and-waf-evasion-tradecraft]], [[dom-debugging-and-sink-analysis]]
- Comparisons: [[stored-vs-reflected-vs-dom-xss]]
```

## Evidence and uncertainty
Sourced directly from canonical vault notes in Notes/OLD Notes/WEB/.
Validated against schema with zero structural contradictions.

## Human feedback
Human decision required via Decision Studio (http://127.0.0.1:20888) or command line.
