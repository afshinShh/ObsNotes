---
title: "EDR Telemetry Architectures & Detection Mechanisms"
created: 2026-09-25
updated: 2026-09-25
type: concept
tags:
  - evasion
  - red-team
  - triage
sources:
  - unprocessed-obsidians/edr.md
confidence: high
contested: false
contradictions: []
---

# EDR Telemetry Architectures & Detection Mechanisms

## Overview
Endpoint Detection and Response (EDR) platforms provide continuous monitoring and behavioral threat detection across modern operating system endpoints. This note synthesizes EDR internal components, kernel-level sensors, event tracing mechanisms, memory scanners, and heuristic correlation pipelines.

## Architectural Fundamentals & Detection Engines

## Fundamentals

### AV vs EDR

**Antivirus (preventive approach)**:

- Static Analysis: Matching known signatures in files
- Dynamic Analysis: Limited behavioral monitoring/sandboxing
- Effective against known threats, weaker against advanced attacks

**EDR (proactive & investigative approach)**:

- Continuous endpoint monitoring
- Behavioral analysis at kernel level
- Anomaly detection and post-compromise visibility
- Prioritizes incident response and investigation

### Windows Execution Flow

Windows program execution follows a hierarchical flow:

1. **Applications** - User programs like firefox.exe
2. **DLLs** - Libraries providing Windows functionality without direct low-level access
3. **Kernel32.dll** - Core DLL for memory management, process/thread creation
4. **Ntdll.dll** - Lowest user-mode DLL that exposes the NT API interface to the kernel
5. **Kernel** - Core OS component with unrestricted hardware access

Example operation flow (creating a file):

1. Application invokes `CreateFile` function
2. CreateFile forwards to `NtCreateFile`
3. Ntdll.dll triggers `NtCreateFile` syscall
4. Kernel creates the file and returns a handle

## EDR Visibility

### EDR Architecture & Components

EDR solutions consist of multiple components creating a complex attack surface:

**Client-Side Components:**

- **User-space Applications** - Main agent processes and UI components
- **Kernel-space Drivers** - Filter drivers, network drivers, software drivers
- **Communication Interfaces** - IOCTLs, FilterConnectionPorts, ALPC, Named Pipes

**Component Communication Methods:**

- **Kernel-to-Kernel**: Exported functions, IOCTLs
- **User-to-Kernel**: IOCTLs, FilterConnectionPorts (minifilter-specific), ALPC
- **User-to-User**: ALPC, Named Pipes, Files, Registry

**Server-Side Components:**

- Cloud services and management consoles
- On-premise servers (some vendors)
- Custom protocols for agent-to-cloud communication

### EDR Visibility Methods

EDR solutions require extended visibility into system activities:

- Filesystem monitoring via mini-filter drivers
- Process/module loading via image load kernel callbacks
- Process/.NET modules/Registry/kernel object events via ETW Ti
- Network monitoring via NDIS and network filtering drivers

### Static Analysis

- Extract information from binary
  - Known malicious strings
  - Threat actor IP or domains
  - Malware binary hashes

### Dynamic Analysis

- Execute binary in a sandbox environment and observe it
  - Network connections
  - Registry changes
  - Memory access
  - File creation/deletion
- AntiMalware Scan Interface

### Behavioral Analysis

- Observe the binary as its executing, Hook into functions/syscalls
  - User actions
  - System calls
  - Kernel callbacks
  - Commands executed in the command line
  - Which process is executing the code
  - Event Tracing for Windows

## Detection Methods

### AV Signature Scanning

- Scans files using known signatures (YARA rules)
- Typically targets loaders and droppers
- Primarily static analysis of files on disk

### AV Emulation

- Runs suspicious programs in a simulated environment
- Triggers on behaviors without executing real code
- Used to detect obfuscated malware

### Usermode Hooks

- EDR hooks critical API calls in userspace (ntdll.dll)
- Monitors process creation, memory allocations, and network operations
- Allows for inspection before execution continues

### Kernel Telemetry

- Monitors events directly from the kernel
- Captures file, registry, process, and network operations
- Difficult to bypass as it operates at a lower level

### Memory Scanning

- Scans process memory for known signatures
- Triggers based on suspicious behavior
- Looks for shellcode, encryption, malicious strings
- **Modern Context:**
  - Attackers also scan process memory for sensitive artifacts like authentication tokens. Co‑pilot/IDE integrations, chat assistants, and browser extensions frequently cache Bearer/JWT tokens in memory.
  - Practical triage: search for `"Authorization: Bearer"`, `"eyJ"` (base64 JWT prefix), or provider‑specific headers; dump minimal pages to avoid tripping anti‑exfil rules.

## OpSec Quickstart (lab)

- Pre‑run
  - Network: block or sinkhole vendor EDR/XDR endpoints; disable cloud sample submission; tag lab hosts.
  - Mitigations snapshot: `Get-ProcessMitigation -System`; `Get-CimInstance Win32_DeviceGuard` (VBS/HVCI/KDP); `Get-MpPreference` (ASR/Cloud).
  - Events baseline: enable and tail `Microsoft-Windows-CodeIntegrity/Operational`, `Security (4688/4689)`, `Microsoft-Windows-Sense/Operational`, Sysmon (if present).
- Injection hygiene
  - Favor `MEM_IMAGE` mappings (ghosting/herpaderping/overwriting) over `MEM_PRIVATE` RWX to avoid 24H2 hotpatch loader checks.
  - Satisfy XFG/CET: jump via import thunks; ensure IBT `ENDBR64` at indirect targets; maintain plausible stacks for syscalls (replicate `ntdll` frames).
  - Avoid noisy APIs: split `alloc/write/exec` over time; prefer APC+`NtContinue` pivots; keep thread contexts consistent.
- Telemetry minimization
  - Jitter long‑lived channels; prefer named‑pipe/HTTP3 over noisy HTTP1; throttle upload intervals.
  - Use COM/runspace over PowerShell console to reduce script‑block logs; avoid AMSI‑flagged prologues.
- Cleanup
  - Remove services, tasks, drivers; restore SDDL; revert registry policy flips (WDAC/CI/Defender) and re‑enable protections.
  - Purge user caches (Recent Files, Jump Lists) and ETW providers enabled during tests.

### Memory Regions

- Monitors suspicious memory allocation patterns
- Flags RWX (read-write-execute) regions
- Tracks regions that change from RW to RX

### Callstack Analysis

- Examines the call stack of suspicious functions
- Verifies legitimate origin of critical operations
- Detects unusual function call chains

### Hook Implementation

EDRs can't directly hook kernel memory due to PatchGuard, so they:

1. Inject their DLL into newly spawned processes
2. Position before malware can block/unmap it
3. Adjust `_PEB`, hook process's module `IAT`/Imports, and loaded libraries `EAT`/Exports
4. Implement trampolines, hooks, and detours

### ETW Monitoring

- EDR maintains ring-buffer with per-process activities produced by ETW Ti:
  - Processes, command lines, parent-child relationships
  - File/Registry/Process open/write operations
  - Created threads, their call stacks, starting addresses
  - Native functions called
  - Created .NET AppDomains, loaded .NET assemblies, static class names, methods

#### Event Correlation

- High fidelity alert (such as LSASS open) triggers correlation of collected activities
- High memory/resources cost limits preservation of events to a time window
- ML/AI may compute risk scores and isolate TTP (Tactics, Techniques, and Procedures)

#### Shellcode Loaders

Shellcode loaders typically follow this pattern:

```c
char *shellcode = "\xAA\xBB...";
char *dest = VirtualAlloc(NULL, 0x1234, 0x3000, PAGE_READWRITE);
memcpy(dest, shellcode, 0x1234)
VirtualProtect(dest, 0x1234, PAGE_EXECUTE_READ, &result)
(*(void(*)())(dest))();  // jump to dest: execute shellcode
```

## Key Technical Primitives
- **Kernel Callbacks**: Registered via `PsSetCreateProcessNotifyRoutineEx`, `PsSetCreateThreadNotifyRoutine`, and `ObRegisterCallbacks` to monitor process creations and handle duplication attempts.
- **Event Tracing for Windows (ETW / ETW-Ti)**: Kernel-level telemetry logging memory allocations (`NtAllocateVirtualMemory`), thread executions, and API invocations.
- **User-Mode API Hooking**: Inline JMP instructions placed inside critical DLLs (`ntdll.dll`, `kernel32.dll`) intercepting suspicious API calls.
- **Continuous Memory Scanners**: Periodic inspection of executable memory pages targeting unbacked code, RWX permissions, and known C2 beacon signatures.

## Primary Sources & Provenance
- Provenance source anchor: [[edr]]

Synthesized and normalized from canonical vault note `[[unprocessed-obsidians/edr]]`.

## Related Concepts & Entities
- [[edr-evasion-techniques]]
- [[av-vs-edr]]
- [[direct-vs-indirect-syscalls]]
- [[syswhispers]]
- [[ekko-sleep-obfuscation]]
