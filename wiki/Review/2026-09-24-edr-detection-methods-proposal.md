---
type: llm-wiki-review
status: needs-review
decision: pending
revision: 1
operation: create
target: concepts/edr-detection-methods.md
sources:
  - raw/articles/edr.md
---

# Proposed Wiki change

## What will change
Compiles a dedicated concept page detailing EDR telemetry sources, usermode API hooking, kernel callbacks, Event Tracing for Windows Threat Intelligence (ETW-Ti), and memory inspection heuristics.

## Proposed content

---
title: EDR Telemetry Architectures & Detection Mechanisms
created: 2026-09-24
updated: 2026-09-24
type: concept
tags:
  - evasion
  - red-team
sources:
  - unprocessed-obsidians/edr.md
confidence: high
contested: false
contradictions: []
---

# EDR Telemetry Architectures & Detection Mechanisms

## Overview
Endpoint Detection and Response (EDR) systems provide continuous, host-level behavioral monitoring, threat detection, and telemetry collection. Unlike traditional signature-based antivirus solutions that primarily inspect files at rest, EDR focuses on runtime execution telemetry, correlating events across process creation, memory allocation, inter-process communication, file system operations, and network connections.

## Windows Execution Flow & EDR Interception Points

```
[ Application (e.g. evil.exe) ]
              |
              v
[ Subsystem DLL (kernel32.dll) ]
              |
              v
[ Low-Level Runtime (ntdll.dll) ] <----- [ EDR User-Mode Hook (JMP to edr.dll) ]
              | (Syscall instruction)
              v
[ Windows Kernel (ntoskrnl.exe) ] <----- [ Kernel Callbacks (PsSetCreateProcessNotify) ]
                                  <----- [ Filesystem Minifilter Drivers ]
                                  <----- [ ETW-Ti (Threat Intelligence Sensor) ]
```

### 1. User-Mode API Hooking
To inspect parameters before execution reaches the kernel, EDR agents inject a monitoring DLL into newly spawned processes. The DLL overwrites the prologue of sensitive NT API functions in `ntdll.dll` (e.g. `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx`):
- **Prologue Patching**: Replacing the initial 5 bytes (`mov r10, rcx; mov eax, ...`) with an unconditional jump (`jmp [EDR_Hook_Function]`).
- **Trampoline Execution**: The hook inspects function arguments, call stacks, and buffer pointers. If deemed benign, execution branches to a trampoline executing the original stolen bytes, then returns to the syscall stub.

### 2. Kernel Callbacks & Object Filtering
Operating systems provide supported callback routines for registered kernel drivers:
- **`PsSetCreateProcessNotifyRoutineEx`**: Intercepts process creation, inspecting parent PID, command lines, and image paths before thread execution begins.
- **`PsSetCreateThreadNotifyRoutine`**: Monitors thread injection across foreign process boundaries.
- **`ObRegisterCallbacks`**: Restricts process handle permissions (stripping `PROCESS_ALL_ACCESS` or `PROCESS_VM_WRITE` requested by non-privileged callers against protected targets).

### 3. Event Tracing for Windows Threat Intelligence (ETW-Ti)
ETW-Ti is a dedicated, kernel-level telemetry provider (`Microsoft-Windows-Threat-Intelligence`) designed specifically for security vendors:
- Operates directly inside `ntoskrnl.exe`, rendering it immune to user-mode unhooking.
- Generates events for virtual memory allocations (`ALLOCVM_LOCAL/REMOTE`), memory protection modifications (`PROTECTVM`), and thread context modifications (`SETTHREADCONTEXT`).

## Detection Analytics & Heuristics
- **Call Stack Spoofing Detection**: Validating return addresses during API calls to ensure execution originated from legitimate calling frames rather than raw shellcode memory allocations.
- **Parent-Child Process Anomalies**: Spawning `cmd.exe` or `powershell.exe` from Office applications (`winword.exe`), web servers (`w3wp.exe`), or SQL servers (`sqlserver.exe`).
- **Memory Scanning & Beacon Detection**: Periodic scans of `PAGE_EXECUTE_READWRITE` (`RWX`) memory regions, thread stack state inspection, and sleep jitter pattern recognition.

## Related Pages
- [[edr]]
- [[edr-evasion-techniques]]
- [[av-vs-edr]]
- [[exploit-mitigations]]

## Evidence and uncertainty
Synthesized from `unprocessed-obsidians/edr.md`. Covers Windows subsystem call hierarchies, user-mode inline hooks, kernel callbacks, and ETW-Ti telemetry collection.

## Human feedback
Optionally explain or edit what should change.
