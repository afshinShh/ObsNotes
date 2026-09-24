---
type: llm-wiki-review
status: needs-review
decision: pending
revision: 1
operation: create
target: sources/edr.md
sources:
  - raw/articles/edr.md
---

# Proposed Wiki change

## What will change
Establishes the provenance anchor for Endpoint Detection and Response (EDR) notes ingested from `unprocessed-obsidians/edr.md`, linking primary source notes to compiled concepts and comparative analyses.

## Proposed content

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

## Evidence and uncertainty
Directly transcribed and normalized from `unprocessed-obsidians/edr.md`. Grounded in Windows internal subsystem telemetry and security driver architectures.

## Human feedback
Optionally explain or edit what should change.
