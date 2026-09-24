---
title: "Donut Position-Independent Shellcode Generator"
created: 2026-09-25
updated: 2026-09-25
type: entity
tags:
  - tool
  - payload
  - evasion
  - red-team
sources:
  - unprocessed-obsidians/initial-access.md
  - unprocessed-obsidians/shellcode.md
confidence: high
contested: false
contradictions: []
---

# Donut Position-Independent Shellcode Generator

## Overview
Donut is a position-independent code (PIC) generator authored by TheWover. It converts .NET assemblies, native x86/x64 PE executables, and DLLs into self-contained, in-memory PIC shellcode capable of execution via arbitrary process injection techniques.

- **Repository**: [https://github.com/TheWover/donut](https://github.com/TheWover/donut)
- **Documentation**: [https://thewover.github.io/Donut/](https://thewover.github.io/Donut/)

## Core Capabilities & Operational Modules
- **In-Memory CLR Bootstrapping**: Injects and executes .NET assemblies in unmanaged processes by bootstrapping the Common Language Runtime (CLR) via COM interfaces.
- **Antimalware & AMSI Bypass**: Automatically patches AMSI (Antimalware Scan Interface) and WLDP (Windows Lockdown Policy) in memory prior to payload loading.
- **Symmetric Payload Encryption**: Encrypts payload assemblies with Chaskey or RC4 ciphers using unique dynamic runtime keys.
- **Process Argument Decoupling**: Passes execution arguments directly to entrypoints without touching host command-line structures.

## CLI Execution & Syntax Examples
```bash
# Convert .NET assembly to PIC shellcode
donut -i Seatbelt.exe -a 2 -o seatbelt.bin

# Convert native DLL with exported function and parameters
donut -i payload.dll -m RunWork -p "arg1 arg2" -a 2 -o payload_x64.bin
```

## Integration in Offensive Workflows
This entity serves as a core automation and execution primitive within modern red-team and bug-bounty pipelines. It bridges the gap between theoretical attack patterns and operational verification.

## Primary Sources & Provenance
Ingested and structured from canonical notes:
  - unprocessed-obsidians/initial-access.md
  - unprocessed-obsidians/shellcode.md

## Related Notes & Concepts
- [[shellcode-development]]
- [[initial-access-vectors]]
- [[edr-evasion-techniques]]
