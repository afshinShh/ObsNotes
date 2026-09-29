---
title: "Endpoint Defense & Evasion"
created: 2026-09-25
updated: 2026-09-25
type: hub
tags:
  - evasion
  - red-team
  - payload
  - tool
cluster: defense-and-evasion
sources:
  - sources/edr.md
  - sources/initial-access.md
  - sources/mitigations.md
---

# Endpoint Defense & Evasion

> **Domain Hub & Map of Content**
> Comprehensive catalog of Endpoint Detection and Response (EDR) internals, telemetry interception mechanisms, user-mode and kernel-mode evasion, and operating system exploit mitigations.

## Architecture & Hierarchy

- **Parent Directory**: `wiki/defense-and-evasion/`
- **Root Index**: [[index|Wiki Master Index]]
- **Domain Cluster**: `defense-and-evasion`

---

## Core Concepts & Attack Vectors
- [[edr-detection-methods]] — EDR architecture, user-mode API hooking (`ntdll.dll`), kernel callbacks (`PsSetCreateProcessNotifyRoutineEx`), Event Tracing for Windows Threat Intelligence (ETW-Ti), and memory inspection heuristics.
- [[edr-evasion-techniques]] — Unhooking techniques (perun's fart, disk reload), Direct and Indirect Syscalls, AMSI/ETW user-mode patching, thread call-stack spoofing, and Ekko timer-based sleep obfuscation.
- [[initial-access-vectors]] — Delivery trade-offs, HTML smuggling, container-based Mark-of-the-Web (MOTW) bypasses (ISO/VHD), Adversary-in-the-Middle (AiTM) MFA proxying, and perimeter VPN exploitation.
- [[exploit-mitigations]] — Modern OS and hardware exploit mitigations including KASLR, Kernel Page Table Isolation (KPTI), SMAP/SMEP, Hardware-enforced Stack Protection, Memory Tagging Extensions (MTE), and Hypervisor-protected Code Integrity (HVCI).

---

## Comparative Trade-off Analyses
- [[edr-detection-methods-vs-edr-evasion-techniques]]
- [[edr-detection-methods-vs-exploit-mitigations]]
- [[av-vs-edr]] — Static pre-execution file inspection and signature heuristics vs continuous runtime kernel behavioral telemetry and process graph telemetry.
- [[direct-vs-indirect-syscalls]] — Execution path trade-offs, `rip` address indicators, Call-Stack Telemetry (ETW-Ti), and RIP-validation bypasses.
- [[kaslr-vs-kpti-mitigations]] — Memory randomization vs address-space page isolation against Meltdown and kernel memory side-channel leakages.

---

## Entities & Tooling Catalog
- [[syswhispers]] — Automated tool for generating direct and indirect syscall stubs with dynamic SSN (System Service Number) resolution.
- [[ekko-sleep-obfuscation]] — In-memory payload sleep encryption framework utilizing `CreateTimerQueueTimer` to bypass continuous memory scanners.
- [[mythic-c2]] — Multi-platform, modular post-exploitation command and control framework designed for custom agent development and stealth operations.

---

## Primary Sources & Ingestion Provenance
- [[edr]] — Raw notes analyzing EDR sensor architectures, hooking mechanisms, and telemetry collection pipelines.
- [[initial-access]] — Raw notes detailing payload delivery formats, container smuggling, and perimeter intrusion tactics.
- [[mitigations]] — Raw notes covering hardware and operating system exploit prevention mechanisms.

---

## Cross-Domain Attack Chains & Related Domains
- [[binary-exploitation]] — Weaponizing memory corruption primitives while bypassing hardware mitigations ([[exploit-development]], [[shellcode-development]]).
- [[web-and-bug-bounty]] — Gaining initial access through web vulnerabilities to drop or stage C2 implants ([[initial-access-vectors]]).
