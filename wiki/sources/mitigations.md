---
title: Source Note - Modern Kernel Exploit Mitigations
created: 2026-09-24
updated: 2026-09-24
type: source
tags:
  - evasion
  - red-team
sources:
  - unprocessed-obsidians/mitigations.md
extracted_concepts:
  - "[[exploit-mitigations]]"
---

# Source Note: Modern Kernel Exploit Mitigations

> **Provenance Anchor**: Ingested from canonical vault file `[[unprocessed-obsidians/mitigations]]`.
> **Compiled Wiki Pages**:
> - Concept: [[exploit-mitigations]]

---

## Original Material Overview
The source note provides an extensive technical catalog of kernel and hardware-assisted exploit mitigations across Linux and Windows:
- **Memory Safety & Layout Randomization**: KASLR (prefetch cache timing side-channels, info leaks), Kernel Page Table Isolation (KPTI / Meltdown mitigation), Linear Address Masking (LAM).
- **Execution & Access Controls**: SMAP (Supervisor Mode Access Prevention, `stac`/`clac` gadgets), SMEP (Supervisor Mode Execution Protection, CR4 bit 20), Privileged Access Never (PAN).
- **Kernel Integrity & Hardware Defenses**: Kernel Data Protection (KDP), Memory Integrity (HVCI / VBS), RODATA hardening, Hardened Usercopy, Memory Tagging Extension (MTE / ARMv8.5+), Memory Sealing, Kernel DMA Protection.

## Related Pages
- [[exploit-mitigations]]
- [[exploit-development]]
