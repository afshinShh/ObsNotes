---
title: Shellcode Engineering & Position-Independent Code (PIC)
created: 2026-09-24
updated: 2026-09-24
type: concept
tags:
  - payload
  - rce
  - red-team
sources:
  - unprocessed-obsidians/shellcode.md
confidence: high
contested: false
contradictions: []
---

# Shellcode Engineering & Position-Independent Code (PIC)

## Overview
Shellcode consists of raw, architecture-specific machine code instructions designed to execute independently of standard binary loaders and OS linking phases. In modern offensive operations and exploit development, shellcode must be completely **Position-Independent (PIC)**, capable of executing at arbitrary memory addresses without relying on fixed absolute pointers, while dynamically resolving system APIs at runtime through environment data structures.

## Position-Independent Code (PIC) Techniques

Because shellcode cannot predict where in memory it will be loaded, it must determine its own runtime instruction pointer (EIP/RIP) to calculate offsets to embedded strings or data tables:

```
+-------------------------------------------------------------+
|                Position-Independent Addressing               |
+-------------------------------------------------------------+
        |                                             |
[ x86 (32-bit) ]                              [ x64 (64-bit) ]
- Call / Pop Method                           - RIP-Relative Addressing
- FPU State Method (fnstenv)                    (e.g. lea rsi, [rip + data])
- SEH Frame Query
```

### 1. 32-bit Call/Pop Method
```nasm
call get_eip
get_eip:
pop eax          ; EAX now holds the runtime address of get_eip
```

### 2. 64-bit RIP-Relative Addressing
In x86_64, instructions can address data relative to the current instruction pointer directly, eliminating the need for call/pop primitives:
```nasm
lea rdx, [rip + string_offset]
```

## Windows Dynamic API Resolution via PEB Walk
Shellcode cannot rely on static import tables. In Windows, it dynamically resolves `kernel32.dll` and necessary function pointers through the Process Environment Block (PEB):

```
GS Register (x64) / FS Register (x86)
        |
        v
PEB (Process Environment Block)
        |
        v
PEB_LDR_DATA (Ldr)
        |
        v
InMemoryOrderModuleList (Doubly-linked list of loaded DLLs)
        |
        v
Locate kernel32.dll Base Address
        |
        v
Parse PE Header -> Export Directory (EAT)
        |
        v
Compare API Hashes -> Resolve GetProcAddress / LoadLibraryA
```

### API Hashing
To avoid embedding conspicuous ASCII API names (e.g. `"VirtualAlloc"`, `"CreateProcessA"`) which trigger static string detection, shellcode uses cryptographic or bitwise hashes:
- Function names in the Export Address Table are hashed (e.g. ROR-13 or CRC32).
- The shellcode compares the calculated hash against precomputed target constants, resolving pointers stealthily.

## Memory Allocation & Injection Trade-offs
Directly allocating memory with `PAGE_EXECUTE_READWRITE` (`RWX`) is heavily monitored and flagged by modern Endpoint Detection and Response (EDR) memory scanners:
- **Insecure / High Signal**: `VirtualAlloc(..., PAGE_EXECUTE_READWRITE)` -> Write shellcode -> `CreateThread()`.
- **Evasion-Focused Pattern**:
  1. Allocate memory with `PAGE_READWRITE` (`RW`).
  2. Copy shellcode bytes into the buffer.
  3. Modify permissions to `PAGE_EXECUTE_READ` (`RX`) using `VirtualProtect`.
  4. Execute payload via thread execution hijacking or Callback functions (e.g. `EnumSystemLocalesA`, `CreateThreadPoolWork`).

## Modern Cross-Platform Primitives
- **Windows on ARM64 (WoA)**: Requires flushing instruction caches via `FlushInstructionCache` after modifying memory pages to ensure CPU pipeline coherency.
- **Linux Modern Primitives**: Kernel 6.9+ introduces eBPF tokens and eBPF memory arenas, providing alternative unprivileged execution pipelines.

## Related Pages
- [[shellcode]]
- [[exploit-development]]
- [[initial-access-vectors]]
- [[edr-evasion-techniques]]
- [[exploit-mitigations]]
