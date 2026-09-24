---
type: llm-wiki-review
status: needs-review
decision: pending
revision: 1
operation: create
target: concepts/edr-evasion-techniques.md
sources:
  - unprocessed-obsidians/initial-access.md
  - unprocessed-obsidians/edr.md
confidence: high
contested: false
contradictions: []
---

# Proposed Wiki change

## What will change
Compiles a dedicated concept page detailing endpoint evasion engineering: DLL unhooking, Direct and Indirect System Calls, AMSI/ETW patching, sleep memory encryption, and call stack spoofing.

## Proposed content

---
title: EDR Evasion Engineering & In-Memory Bypass Tradecraft
created: 2026-09-24
updated: 2026-09-24
type: concept
tags:
  - evasion
  - red-team
  - payload
sources:
  - unprocessed-obsidians/initial-access.md
  - unprocessed-obsidians/edr.md
confidence: high
contested: false
contradictions: []
---

# EDR Evasion Engineering & In-Memory Bypass Tradecraft

## Overview
As documented in [[edr-detection-methods]], Endpoint Detection and Response (EDR) agents intercept process execution by placing inline user-mode hooks on system DLLs and monitoring kernel events. EDR Evasion encompasses the low-level tradecraft and architectural techniques developed to neutralize or bypass these monitoring mechanisms without triggering behavioral or memory-scanning detection rules.

## Core Evasion Primitives & Methodologies

```
+---------------------------------------------------------------+
|                    EDR Evasion Primitives                     |
+---------------------------------------------------------------+
        |                       |                       |
        v                       v                       v
[ User-Mode Unhooking ]     [ Syscall Tradecraft ]   [ Memory & Stack Evasion ]
- Read fresh ntdll on disk  - Direct Syscalls        - Call Stack Spoofing
- Map \KnownDlls
tdll      - Indirect Syscalls      - Sleep Obfuscation (Ekko)
- Perun's Fart (suspended)  - Tartarus / Halo Gate   - Module Stomping / Overload
```

### 1. User-Mode DLL Unhooking
EDR hooks only exist in process memory; the DLL files stored on disk remain unhooked. An application can restore original code:
- **Disk Mapping**: Opening `\System32
tdll.dll` from disk, reading the clean `.text` section, and overwriting the hooked `.text` section in memory using `VirtualProtect`.
- **KnownDlls Exploitation**: Mapping a pristine copy of `ntdll.dll` directly from the `\KnownDlls\` object directory without opening standard disk handles.
- **Perun's Fart Technique**: Spawning a benign suspended process, mapping its unhooked `ntdll.dll` before EDR DLL injection completes, and copying clean bytes into the active process.

### 2. Syscall Tradecraft: Direct vs Indirect System Calls
To execute operating system requests without passing through hooked `ntdll.dll` stubs:
- **Direct System Calls (Hell's Gate / SysWhispers)**: Extracting the System Service Number (SSN) dynamically from memory or disk, assembling raw syscall instructions into the payload, and executing `syscall` directly.
  - *Limitation*: EDRs monitoring thread call stacks identify that the `syscall` instruction was executed from outside `ntdll.dll` address space (e.g. from an unbacked heap or private memory region), generating high-confidence detection.
- **Indirect System Calls (Halo's Gate / Tartarus' Gate)**: Resolving the SSN dynamically, setting up registers (`r10`, `eax`), but executing a `jmp [syscall_address_in_ntdll]` to jump to a legitimate `syscall` instruction within official `ntdll.dll` memory.
  - *Advantage*: The RIP at kernel entry points into legitimate `ntdll.dll` code, satisfying call stack inspection rules.

### 3. In-Memory AMSI & ETW Neutralization
- **AMSI (Antimalware Scan Interface) Patching**: Patching `AmsiScanBuffer` in `amsi.dll` to write instructions that immediately return `AMSI_RESULT_CLEAN` (`0x80070057` / `E_INVALIDARG` or `ret`).
- **ETW Patching**: Overwriting `EtwEventWrite` in `ntdll.dll` with an immediate `ret` (`0xC3`) instruction, suppressing all subsequent user-mode ETW event generation.

### 4. Sleep Obfuscation & Memory Encryption (Ekko / Foliage)
C2 beacons spend the vast majority of runtime sleeping between check-in intervals:
- During sleep, shellcode memory is fully readable by periodic EDR memory scanners (e.g. Moneta, Pe-sieve).
- **Sleep Obfuscation**:
  1. Queues asynchronous timers via Windows Timer Queues.
  2. Uses ROP to call `VirtualProtect` modifying payload memory to `PAGE_READWRITE` (`RW`).
  3. Encrypts payload memory in-place using RC4 or SystemFunction032.
  4. Enters sleep state.
  5. Upon timer expiration, decrypts memory in-place and restores `PAGE_EXECUTE_READ` (`RX`) permissions before resuming beacon execution.

### 5. Call Stack Spoofing & Module Stomping
- **Call Stack Spoofing**: Synthesizing fake call stack frames using ROP or hardware breakpoints to simulate legitimate execution origins (e.g. making thread execution appear to originate from `kernel32!BaseThreadInitThunk`).
- **Module Stomping**: Loading a legitimate, signed third-party DLL into process memory and overwriting its executable `.text` section with shellcode, masking unbacked private memory detections.

## Related Pages
- [[initial-access-vectors]]
- [[edr-detection-methods]]
- [[shellcode-development]]
- [[av-vs-edr]]

## Evidence and uncertainty
Synthesized from `unprocessed-obsidians/initial-access.md` and `unprocessed-obsidians/edr.md`. Covers unhooking, direct/indirect system calls, AMSI neutralization, and memory encryption.

## Human feedback
Optionally explain or edit what should change.
