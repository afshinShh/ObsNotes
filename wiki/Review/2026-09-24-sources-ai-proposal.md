---
type: llm-wiki-review
status: needs-review
decision: pending
revision: 1
operation: create
target: sources/ai.md
sources:
  - raw/articles/ai.md
---

# Proposed Wiki change

## What will change
Establishes the provenance anchor for AI / LLM Penetration Testing notes ingested from `unprocessed-obsidians/ai.md`, linking primary source notes to compiled concepts.

## Proposed content

---
title: Source Note - AI & LLM Security Testing
created: 2026-09-24
updated: 2026-09-24
type: source
tags:
  - api
  - bug-bounty
sources:
  - unprocessed-obsidians/ai.md
extracted_concepts:
  - "[[ai-security-testing]]"
---

# Source Note: AI & LLM Security Testing

> **Provenance Anchor**: Ingested from canonical vault file `[[unprocessed-obsidians/ai]]`.
> **Compiled Wiki Pages**:
> - Concept: [[ai-security-testing]]

---

## Original Material Overview
The source note synthesizes offensive testing methodologies, vulnerability classes, and jailbreak tradecraft for Artificial Intelligence and Large Language Model (LLM) applications:
- **Core Vulnerability Mechanisms**: Instruction following ambiguity, training data extraction, black-box agency and tool chaining risks, insecure downstream output handling.
- **Prompt Injection Primitives**: Direct jailbreaks, instruction override, indirect prompt injection via ingested third-party documents/RAG pipelines, tokenization exploits (Unicode, zero-width spaces).
- **MLOps & Agent Security**: Excessive agency in multi-agent frameworks, tool permission escalation, agent memory poisoning (AutoGPT, LangChain), model extraction via embedding probing.
- **Testing Tooling**: `garak`, `LLMFuzzer`, automated jailbreak benches, compliance auditing (EU AI Act, ISO/IEC 42001).

## Related Pages
- [[ai-security-testing]]
- [[cross-site-scripting]]

## Evidence and uncertainty
Directly transcribed and normalized from `unprocessed-obsidians/ai.md`. Covers OWASP Top 10 for LLM applications and modern prompt injection techniques.

## Human feedback
Optionally explain or edit what should change.
