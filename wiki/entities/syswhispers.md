---
title: "SysWhispers (Direct & Indirect Syscall Generator)"
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
---

# SysWhispers (Direct & Indirect Syscall Generator)

## Overview
SysWhispers (developed by Jackson T. and KlezVirus) is a tool for generating position-independent C/ASM stubs that execute direct and indirect Windows system calls, completely evading user-mode API hooks installed by Endpoint Detection and Response (EDR) solutions.

- **Repository**: [https://github.com/jthuraisamy/SysWhispers2](https://github.com/jthuraisamy/SysWhispers2)
- **Documentation**: [https://github.com/klezVirus/SysWhispers3](https://github.com/klezVirus/SysWhispers3)

## Core Capabilities & Operational Modules
- **Dynamic Syscall Resolution**: Walks the Export Address Table (EAT) of `ntdll.dll` in memory and resolves syscall numbers dynamically by sorting function addresses.
- **Indirect Syscalls Execution**: Executes the `syscall` instruction within legitimate `ntdll.dll` memory space, ensuring RIP pointers and return addresses conform to valid kernel stack frames.
- **Hook Bypass**: Evades inline JMP patches installed in `ntdll` functions (`NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx`).
- **SysWhispers3 Enhancements**: Supports egg hunters, Halo's Gate / Tartarus' Gate neighbor heuristics, and MinGW / MSVC cross-compilation.

## CLI Execution & Syntax Examples
```bash
# Generate indirect syscall stubs for memory injection functions
python3 syswhispers.py -f NtAllocateVirtualMemory,NtWriteVirtualMemory,NtCreateThreadEx,NtProtectVirtualMemory -m indirect -o syscalls_stubs
```

## Integration in Offensive Workflows
This entity serves as a core automation and execution primitive within modern red-team and bug-bounty pipelines. It bridges the gap between theoretical attack patterns and operational verification.

## Primary Sources & Provenance
Ingested and structured from canonical notes:
  - unprocessed-obsidians/edr.md

## Related Notes & Concepts
- [[edr-evasion-techniques]]
- [[direct-vs-indirect-syscalls]]
- [[edr-detection-methods]]
