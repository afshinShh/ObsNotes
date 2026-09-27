---
title: "Ekko Sleep Obfuscation"
created: 2026-09-25
updated: 2026-09-25
type: entity
tags:
  - tool
  - evasion
  - red-team
  - payload
sources:
  - unprocessed-obsidians/edr.md
confidence: high
contested: false
contradictions: []
parent: "[[defense-and-evasion]]"
cluster: defense-and-evasion
---
# Ekko Sleep Obfuscation

## Overview
Ekko is an advanced in-memory evasion technique and tool authored by Cracked5pider. It utilizes Win32 asynchronous timer queues to encrypt the beaconing agent's private memory allocations and protect stack contexts while sleeping, thwarting periodic EDR memory scanners.

- **Repository**: [https://github.com/Cracked5pider/Ekko](https://github.com/Cracked5pider/Ekko)
- **Documentation**: [https://github.com/y11en/FOLIAGE](https://github.com/y11en/FOLIAGE)

## Core Capabilities & Operational Modules
- **Timer Queue Chaining**: Queues multiple ROP-style calls (`RtlCaptureContext`, `NtProtectVirtualMemory`, `SystemFunction032`, `WaitForSingleObject`) on a background timer queue.
- **RC4 Sleep Encryption**: Encrypts payload memory blocks using `SystemFunction032` (advapi32 unexported RC4) while idle.
- **Page Permission Flipping**: Flips memory permissions from `PAGE_EXECUTE_READ` / `PAGE_EXECUTE_READWRITE` to benign `PAGE_READWRITE` or `PAGE_NOACCESS` during sleep cycles.
- **FOLIAGE Alternative**: Complements FOLIAGE (Foliage/Amsi) by avoiding APC queuing and exploiting thread pool wait objects.

## CLI Execution & Syntax Examples
```c
// Invocation pattern for Ekko sleep obfuscation
Ekko(5000); // Encrypts heap/code segments and sleeps for 5000ms
```

## Integration in Offensive Workflows
This entity serves as a core automation and execution primitive within modern red-team and bug-bounty pipelines. It bridges the gap between theoretical attack patterns and operational verification.

## Primary Sources & Provenance
Ingested and structured from canonical notes:
  - unprocessed-obsidians/edr.md

## Related Notes & Concepts
- [[edr-evasion-techniques]]
- [[edr-detection-methods]]
- [[shellcode-development]]

## Related Pages
- [[defense-and-evasion]]
