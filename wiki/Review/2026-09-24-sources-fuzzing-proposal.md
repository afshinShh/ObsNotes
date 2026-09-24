---
type: llm-wiki-review
status: needs-review
decision: pending
revision: 1
operation: create
target: sources/fuzzing.md
sources:
  - raw/articles/fuzzing.md
---

# Proposed Wiki change

## What will change
Establishes the provenance anchor for Fuzzing notes ingested from `unprocessed-obsidians/fuzzing.md`, linking primary source notes to compiled concepts.

## Proposed content

---
title: Source Note - Fuzzing Methodologies & Architectures
created: 2026-09-24
updated: 2026-09-24
type: source
tags:
  - tool
  - bug-bounty
sources:
  - unprocessed-obsidians/fuzzing.md
extracted_concepts:
  - "[[fuzzing-techniques]]"
---

# Source Note: Fuzzing Methodologies & Architectures

> **Provenance Anchor**: Ingested from canonical vault file `[[unprocessed-obsidians/fuzzing]]`.
> **Compiled Wiki Pages**:
> - Concept: [[fuzzing-techniques]]

---

## Original Material Overview
The source note provides an extensive technical taxonomy of automated fuzzing engines, architectures, and instrumentation techniques:
- **Fuzzing Taxonomies**: BlackBox, GreyBox (coverage-guided), WhiteBox (symbolic/concolic), Snapshot fuzzing (Nyx, Snapchange, wtf), Ensemble fuzzing.
- **Engine Components**: Power schedulers, mutation engines, directed fuzzing (AFLGo, UAFuzz), feedback loops (edge coverage, sanitizers ASAN/UBSAN), and crash triage oracles.
- **Tool Catalog**: General (AFL++, Honggfuzz, Boofuzz, WinAFL), Kernel (Syzkaller, kAFL, wtf), Grammar-based (Tlspuffin, AFLSmart), Frameworks (LibAFL).
- **Snapshot Fuzzing Recipes**: User-mode AFL++ Nyx recipes, persistent mode harnesses, and LLM-assisted hybrid fuzzing (ChatAFL).

## Related Pages
- [[fuzzing-techniques]]
- [[vulnerability-research-methodology]]

## Evidence and uncertainty
Directly transcribed and normalized from `unprocessed-obsidians/fuzzing.md`. Extensive reference catalog covering academic and industry fuzzing tools.

## Human feedback
Optionally explain or edit what should change.
