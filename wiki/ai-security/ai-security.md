---
title: "AI & LLM Application Security"
created: 2026-09-25
updated: 2026-09-25
type: hub
tags:
  - payload
  - api
  - business-logic
  - bug-bounty
cluster: ai-security
sources:
  - sources/ai.md
---

# AI & LLM Application Security

> **Domain Hub & Map of Content**
> Systematic methodology for testing Large Language Model (LLM) applications, prompt injection attacks, multi-turn jailbreaks, agentic agency escalation, and RAG poisoning.

## Architecture & Hierarchy

- **Parent Directory**: `wiki/ai-security/`
- **Root Index**: [[index|Wiki Master Index]]
- **Domain Cluster**: `ai-security`

---

## Core Concepts & Attack Classes
- [[ai-security-testing]] — Direct prompt injection, indirect context injection via RAG databases or untrusted document uploads, multi-turn persona jailbreaking, system prompt extraction, agent tool invocation hijacking, and LLM-driven SSRF/RCE pivoting.

---

## Primary Sources & Ingestion Provenance
- [[ai]] — Raw notes on LLM application penetration testing, prompt injection vectors, jailbreak syntax, and defensive guardrail evaluations.

---

## Cross-Domain Attack Chains & Related Domains
- [[web-and-bug-bounty]] — Integrating LLM prompt injections with traditional web flaws: exploiting LLM agent tool calls for [[server-side-request-forgery]] or [[cross-site-scripting]].
- [[defense-and-evasion]] — Evasion of AI-based defensive classifiers and content filtering mechanisms.
