---
title: "Antivirus (AV) vs Endpoint Detection and Response (EDR)"
created: 2026-09-24
updated: 2026-09-24
type: comparison
tags:
  - evasion
  - red-team
sources:
  - unprocessed-obsidians/edr.md
confidence: high
contested: false
contradictions: []
parent: "[[defense-and-evasion]]"
cluster: defense-and-evasion
---
# Antivirus (AV) vs Endpoint Detection and Response (EDR)

## Overview
Endpoint security architectures have transitioned from static, signature-driven **Antivirus (AV)** software to dynamic, behavioral **Endpoint Detection and Response (EDR)** platforms. Understanding the technical divergence between preventive signature matching and continuous kernel-level event correlation is critical for both security operations and red-team evasion engineering.

## Side-by-Side Comparison Matrix

| Evaluation Dimension | Traditional Antivirus (AV) | Endpoint Detection and Response (EDR) | Security & Evasion Implications |
| :--- | :--- | :--- | :--- |
| **Primary Philosophy** | Preventive & Pre-Execution. Blocks known threats before execution. | Investigative & Continuous. Assumes breach; monitors runtime behaviors. | AV focuses on file persistence; EDR monitors volatile in-memory operations and inter-process interactions. |
| **Visibility Surface** | File systems, disk I/O, static file hashes, basic network perimeter traffic. | Deep kernel telemetry, usermode API hooks, thread stacks, memory allocations, ETW-Ti. | Obfuscated payloads bypass AV static scanning easily; EDR observes the decrypted payload at point-of-execution. |
| **Detection Mechanism** | Byte signatures (YARA), heuristic matching, basic sandboxing emulators. | Behavioral correlation, anomaly detection, machine learning graphs, MITRE ATT&CK mapping. | AV can be bypassed by polymorphic packing; EDR detects anomalous behavioral sequences regardless of binary hash. |
| **Interception Depth** | File filter drivers, web browser extensions. | Kernel callbacks (`PsSetCreateProcessNotifyRoutine`), object filters (`ObRegisterCallbacks`), injected usermode hooks. | EDR intercepts system calls and API parameters directly in memory. |
| **Evasion Difficulty** | Low. Modifying variable names, compiling with different flags, or encrypting payload defeats signatures. | High. Requires unhooking `ntdll`, using direct/indirect syscalls, spoofing call stacks, and obfuscating sleeping memory. | EDR demands sophisticated in-memory evasion tradecraft. |
| **Response Actions** | Automated quarantine or deletion of malicious binary. | Process isolation, host network isolation, live forensic memory dumping, centralized alert triaging. | EDR alerts human SOC analysts even if execution is not immediately blocked, triggering incident response. |

## Technical Evolution & Convergence
While early EDR products lacked standalone blocking capabilities and relied on companion AV engines, modern enterprise platforms (e.g. CrowdStrike Falcon, Microsoft Defender for Endpoint, SentinelOne) unify Next-Generation Antivirus (NGAV) file scanning with EDR behavioral graphing in a single kernel-driver architecture.

## Related Pages
- [[defense-and-evasion]]
- [[edr]]
- [[edr-detection-methods]]
- [[edr-evasion-techniques]]
