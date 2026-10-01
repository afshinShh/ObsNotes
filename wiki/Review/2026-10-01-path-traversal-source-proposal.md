---
type: llm-wiki-review
status: needs-review
decision: approve
revision: 1
operation: create
target: web-and-bug-bounty/sources/path-traversal.md
sources:
  - Notes/OLD Notes/WEB/vulnerabilities/Path Traversal/concepts.md
  - Notes/OLD Notes/WEB/vulnerabilities/Path Traversal/METHODOLOGY(Attack).md
  - Notes/OLD Notes/WEB/vulnerabilities/Path Traversal/defense.md
  - Notes/OLD Notes/WEB/vulnerabilities/Path Traversal/Examples.md
---
# Proposed Wiki change

## What will change
Create provenance source anchor for Path Traversal notes in Notes/OLD Notes/WEB/vulnerabilities/Path Traversal/.

## Proposed content
```markdown
---
title: "Source Note - Path Traversal: Mechanics, Obstacle Bypasses, and Defenses"
created: 2026-10-01
updated: 2026-10-01
type: source
tags:
  - web-security
  - payload
  - bug-bounty
sources:
  - Notes/OLD Notes/WEB/vulnerabilities/Path Traversal/concepts.md
  - Notes/OLD Notes/WEB/vulnerabilities/Path Traversal/METHODOLOGY(Attack).md
  - Notes/OLD Notes/WEB/vulnerabilities/Path Traversal/defense.md
  - Notes/OLD Notes/WEB/vulnerabilities/Path Traversal/Examples.md
extracted_concepts:
  - "[[path-traversal-and-directory-traversal]]"
extracted_entities:
  []
extracted_comparisons:
  - "[[cspt-vs-path-traversal]]"
confidence: high
contested: false
contradictions: []
parent: "[[web-and-bug-bounty]]"
cluster: web-and-bug-bounty
---
# Source Note - Path Traversal: Mechanics, Obstacle Bypasses, and Defenses

> **Provenance Anchor**: Ingested from canonical vault files under `Notes/OLD Notes/WEB/vulnerabilities/Path Traversal/`.
> - `concepts.md` (22 lines, SHA-256: `18f8e0255476a666dcae3c631a049d5c317ad91e1d0f507b514cce316d3f2ec2`)
> - `METHODOLOGY(Attack).md` (10 lines, SHA-256: `78e24fa5d078b549646b96e54c8651811802d33454b5dfd175249fbf791f24d7`)
> - `defense.md` (17 lines, SHA-256: `09cba115f532b2aebfe46e3bebf0f2b2b1bc277c050a41764ce5f992a25567b4`)
> - `Examples.md` (36 lines, SHA-256: `89fce3b8fc7f3f1f7d5c589073c4cf7e7db6b63ca0c14b317420422c53a6bce4`)
> **Total Raw Lines**: 85 lines

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
- [[path-traversal-and-directory-traversal]] — Core arbitrary file read/write mechanics, filesystem API path concatenation, Windows vs Unix directory separator handling, obstacle bypass matrix (absolute paths, nested sequences, standard/double URL encoding, non-standard multibyte encodings, base folder matching, null-byte extension bypass), and defensive path canonicalization.

### Comparisons
- [[cspt-vs-path-traversal]] — Comparative trade-offs between Client-Side Path Traversal (browser client-side routing and DOM sink manipulation) and Server-Side Directory Traversal (arbitrary local filesystem access).

## Source Content Topic Breakdown
1. **Root Cause**: Unsanitized user inputs appended directly to server base directories (`/var/www/images/ + filename`).
2. **Platform Path Separators**: Unix (`../`) vs Windows (`..\` and `../`).
3. **Common Obstacle Bypasses**:
   - Stripping sequences: Nested traversal sequences (`....//`, `....\/`).
   - Absolute path injection (`/etc/passwd`, `C:\windows\win.ini`).
   - URL encoding (`%2e%2e%2f`) and double URL encoding (`%252e%252e%252f`).
   - Non-standard multibyte Unicode encodings (`..%c0%af`, `..%ef%bc%8f`).
   - Base folder prefix enforcement (`/var/www/images/../../../etc/passwd`).
   - Extension suffix enforcement (Null byte `%00` truncation).
4. **Defensive Architecture**: Two-layer defense with input whitelisting and platform canonicalization (`File.getCanonicalPath().startsWith(BASE_DIR)`).

## Related Pages
- Parent Domain Hub: [[web-and-bug-bounty]]
- Target Concepts: [[path-traversal-and-directory-traversal]], [[client-side-path-traversal]], [[file-upload-attack-matrix]]
```

## Evidence and uncertainty
Sourced directly from canonical vault notes in Notes/OLD Notes/WEB/.
Validated against schema with zero structural contradictions.

## Human feedback
Human decision required via Decision Studio (http://127.0.0.1:20888) or command line.
