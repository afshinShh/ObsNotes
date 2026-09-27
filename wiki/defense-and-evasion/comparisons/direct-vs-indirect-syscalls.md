---
title: "Direct Syscalls vs Indirect Syscalls Evasion Architecture"
created: 2026-09-25
updated: 2026-09-25
type: comparison
tags:
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
# Direct Syscalls vs Indirect Syscalls Evasion Architecture

## Overview
Architectural comparison of user-mode EDR hook evasion via Direct System Calls (raw inline syscall assembly) versus Indirect System Calls (jumping to legitimate ntdll syscall stubs).

## Comparative Technical Matrix

| Evaluation Dimension | Variant / Paradigm A | Variant / Paradigm B |
| :--- | :--- | :--- |
| **Execution Location** | Malware private/RX memory block | Legitimate `ntdll.dll` code segment (`PAGE_EXECUTE_READ`) |
| **Callstack Verification** | Flagged by EDR (Return address points to unbacked/private memory) | Clean (RIP points directly to legitimate ntdll instruction) |
| **Kernel Return Path** | Returns directly to malware code segment | Returns through ntdll stub stack frame |
| **Implementation Complexity** | Low (simple inline assembly or SysWhispers1) | Moderate to High (SysWhispers3, Halo's Gate, Tartarus' Gate) |
| **Detection Vectors** | Kernel ETW-Ti telemetry, thread callstack inspection, memory scanning | Instrumentation callback tracing, hardware breakpoints, kernel-level behavioral heuristics |
| **Tool Reference** | Hell's Gate, raw ASM stubs | SysWhispers2/3, RecycledGate, Tartarus' Gate |

## Technical Analysis & Operational Verdict
Direct syscalls are easily caught by modern tier-1 EDRs (CrowdStrike, SentinelOne, Defender for Endpoint) using kernel callstack telemetry (ETW-Ti). Indirect syscalls combined with callstack spoofing (synthetic frames) are mandatory for resilient evasion on Windows 11.

## Primary Sources & Provenance
Ingested and synthesized from canonical notes:
  - unprocessed-obsidians/edr.md

## Related Concepts & Notes
- [[edr-evasion-techniques]]
- [[edr-detection-methods]]
- [[syswhispers]]
- [[shellcode-development]]
