---
title: Source Note - Insecure Deserialization
created: 2026-09-24
updated: 2026-09-24
type: source
tags:
  - deserialization
  - bug-bounty
sources:
  - unprocessed-obsidians/insecure-deserialization.md
extracted_concepts:
  - "[[deserialization-attacks]]"
---

# Source Note: Insecure Deserialization

> **Provenance Anchor**: Ingested from canonical vault file `[[unprocessed-obsidians/insecure-deserialization]]`.
> **Compiled Wiki Pages**:
> - Concept: [[deserialization-attacks]]

---

## Original Material Overview
The source note covers Insecure Deserialization mechanics, language-specific signatures, gadget chains, and modern attack vectors:
- **Signatures by Technology**: PHP (`O:4:"User":...`, PHAR metadata), Java (`ac ed 00 05` / `rO0` Base64), .NET (`BinaryFormatter` / `AAEAAAD...`), Python (`pickle` opcodes, PyYAML unsafe load), Ruby (`Marshal.load`), Node.js (`node-serialize` IIFE `_$$ND_FUNC$$_`).
- **Bypass Techniques**: Alternate gadget chains, type confusion, indirect persistence via message queues and session stores, format-specific wrappers.
- **Modern Vectors**: Container and Kubernetes orchestrators, message brokers (RabbitMQ, Kafka), serverless function event payloads, CI/CD pipelines.

## Related Pages
- [[deserialization-attacks]]
- [[server-side-template-injection]]
