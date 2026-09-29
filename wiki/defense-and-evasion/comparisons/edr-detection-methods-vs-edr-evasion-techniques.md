---
title: "EDR Telemetry Architectures & Detection Mechanisms vs EDR Evasion Engineering & In-Memory Bypass Tradecraft"
created: 2026-09-25
updated: 2026-09-25
type: comparison
parent: "[[defense-and-evasion]]"
cluster: defense-and-evasion
tags:
  - evasion
  - payload
  - red-team
  - edr
sources:
  - defense-and-evasion/concepts/edr-detection-methods.md
  - defense-and-evasion/concepts/edr-evasion-techniques.md
confidence: high
contested: false
contradictions: []
---

# EDR Telemetry Architectures & Detection Mechanisms vs EDR Evasion Engineering & In-Memory Bypass Tradecraft

## Comparative Analysis
Technical trade-off evaluation comparing [[edr-detection-methods|EDR Telemetry Architectures & Detection Mechanisms]] with [[edr-evasion-techniques|EDR Evasion Engineering & In-Memory Bypass Tradecraft]] across sensor collection and telemetry evasion vectors.

EDR detection systems monitor process memory, inspect thread call stacks for unbacked executable regions, and hook user-mode system service stubs. In response, modern evasion engineering utilizes direct/indirect syscall generation (`SysWhispers`), synthetic call-stack frame crafting, module unhooking, and asynchronous timer-based sleep encryption (`Ekko`) to achieve undetectable in-memory execution.

## Technical Comparison Matrix

| EDR Telemetry & Detection Sensor | Target Artifact | Offensive Evasion Countermeasure | Countermeasure Trade-offs |
| :--- | :--- | :--- | :--- |
| **Inline User-Mode API Hooking** | JMP instructions in `ntdll.dll` / `kernel32.dll` | Module unhooking (Perun's Fart, disk reload) or Indirect Syscalls | Memory allocation signatures; requiring clean `syscall; ret` gadget extraction |
| **Kernel Callbacks & Object Filtering** | Process creation, thread injection (`OpenProcess`) | Bring-Your-Own-Vulnerable-Driver (BYOVD) or kernel callback zeroing | Elevate privilege requirement; risk of system instability |
| **Thread Call-Stack Inspection** | RIP pointing to floating/unbacked executable memory | Synthetic call-stack spoofing, frame chaining, `jmp [rbx]` return emulation | Complex assembly thunk maintenance across Windows build revisions |
| **Periodic Memory Scanners** | RWX memory pages, plaintext beacon sleep signatures | Timer queue sleep encryption (`Ekko`, `Foliage`, `Zloader` sleep methods) | ROP gadget dependencies; timer callback thread integrity requirements |

## Interlinked Concepts
- [[edr-detection-methods]] — EDR telemetry pipelines, ETW-Ti collection, and sensor architecture.
- [[edr-evasion-techniques]] — Bypass engineering, indirect syscalls, and in-memory stealth.
- [[defense-and-evasion]] — Parent Topic Hub for defense evasion and security controls.

## Related Pages
- [[defense-and-evasion]]
- [[edr-detection-methods]]
- [[edr-evasion-techniques]]
