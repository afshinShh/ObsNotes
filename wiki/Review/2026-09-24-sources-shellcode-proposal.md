---
type: llm-wiki-review
status: needs-review
decision: approve
revision: 1
operation: create
target: sources/shellcode.md
sources:
  - raw/articles/shellcode.md
---

# Proposed Wiki change

## What will change
Establishes the provenance anchor for Shellcode Engineering notes ingested from `unprocessed-obsidians/shellcode.md`, linking primary source notes to compiled concepts.

## Proposed content

---
title: Source Note - Shellcode Architecture & Development
created: 2026-09-24
updated: 2026-09-24
type: source
tags:
  - payload
  - red-team
sources:
  - unprocessed-obsidians/shellcode.md
extracted_concepts:
  - "[[shellcode-development]]"
---

# Source Note: Shellcode Architecture & Development

> **Provenance Anchor**: Ingested from canonical vault file `[[unprocessed-obsidians/shellcode]]`.
> **Compiled Wiki Pages**:
> - Concept: [[shellcode-development]]

---

## Original Material Overview
The source note covers machine code payload engineering, Position-Independent Code (PIC), Windows execution flows, and shellcode loaders:
- **Core Concepts**: Allocate-Write-Execute pattern, avoiding flagged `PAGE_EXECUTE_READWRITE` allocations, relative addressing, RIP-relative addressing in x64.
- **Position-Independent Code (PIC)**: Address resolution techniques (Call/Pop delta, FPU state `fnstenv`, SEH method, Global Offset Table).
- **Windows API Resolution**: Traversing the Process Environment Block (PEB), finding `InMemoryOrderModuleList`, walking PE Export Address Tables (EAT), API hashing (ROR13 / Murmur).
- **Shellcode Loaders & Execution**: Early bird APC injection, process hollowing, thread pool execution, DLL to shellcode conversion (Donut), cross-platform modern primitives (Linux eBPF tokens, Windows on ARM64).

## Related Pages
- [[shellcode-development]]
- [[initial-access-vectors]]

## Evidence and uncertainty
Directly transcribed and normalized from `unprocessed-obsidians/shellcode.md`. Standard binary payload and position-independent execution techniques.

## Human feedback
Optionally explain or edit what should change.
