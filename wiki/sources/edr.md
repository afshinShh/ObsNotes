---
title: Source Note - Endpoint Detection and Response (EDR)
created: 2026-09-24
updated: 2026-09-24
type: source
tags:
  - evasion
  - red-team
sources:
  - unprocessed-obsidians/edr.md
extracted_concepts:
  - "[[edr-detection-methods]]"
  - "[[edr-evasion-techniques]]"
extracted_comparisons:
  - "[[av-vs-edr]]"
---

# Source Note: Endpoint Detection and Response (EDR)

> **Provenance Anchor**: Ingested from canonical vault file `[[unprocessed-obsidians/edr]]`.
> **Compiled Wiki Pages**:
> - Concept: [[edr-detection-methods]]
> - Concept: [[edr-evasion-techniques]]
> - Comparison: [[av-vs-edr]]

---

## Original Material Overview
The source note synthesizes Endpoint Detection and Response (EDR) architectural components, visibility mechanisms, and telemetry collection pipelines:
- **Architecture & Execution Flow**: Windows execution hierarchy (Application -> Subsystem DLLs -> Kernel32 -> Ntdll -> Syscall -> Kernel), minifilter drivers, ALPC communication, and user-space agent coordination.
- **Detection Mechanisms**: Usermode API hooking (inline function patching, trampolines), kernel callbacks (`PsSetCreateProcessNotifyRoutine`, `ObRegisterCallbacks`), Event Tracing for Windows (ETW / ETW-Ti).
- **Telemetry Analysis**: Memory scanning heuristics, call stack unwinding, parent-process spoofing detection, and behavioral anomaly correlation.

## Related Pages
- [[edr-detection-methods]]
- [[edr-evasion-techniques]]
- [[av-vs-edr]]
