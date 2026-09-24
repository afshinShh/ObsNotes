---
title: Source Note - Modern Initial Access & Defensive Evasion
created: 2026-09-24
updated: 2026-09-24
type: source
tags:
  - red-team
  - evasion
sources:
  - unprocessed-obsidians/initial-access.md
extracted_concepts:
  - "[[initial-access-vectors]]"
  - "[[edr-evasion-techniques]]"
---

# Source Note: Modern Initial Access & Defensive Evasion

> **Provenance Anchor**: Ingested from canonical vault file `[[unprocessed-obsidians/initial-access]]`.
> **Compiled Wiki Pages**:
> - Concept: [[initial-access-vectors]]
> - Concept: [[edr-evasion-techniques]]

---

## Original Material Overview
The source note covers modern external initial access vectors, weaponization pipelines, and defensive evasion techniques:
- **Initial Access Vectors**: Email HTML smuggling, Mark-of-the-Web (MOTW) container bypasses (ISO, VHD), OAuth consent phishing, AiTM proxy kits (EvilProxy, Tycoon), developer ecosystem supply chain compromise, and edge appliance zero-days (Ivanti, Citrix).
- **Endpoint Defense Evasion**: Ntdll unhooking (from disk, KnownDlls, clean process), Direct & Indirect System Calls (Hell's Gate, Halo's Gate, SysWhispers), AMSI / ETW patching, memory allocation evasion.
- **Sleep & Memory Obfuscation**: Ekko, Foliage, Timer Queue sleep encryption to defeat periodic EDR memory scanners, Call Stack Spoofing.

## Related Pages
- [[initial-access-vectors]]
- [[edr-evasion-techniques]]
