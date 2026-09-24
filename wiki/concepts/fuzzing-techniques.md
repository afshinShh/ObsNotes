---
title: Fuzzing Techniques, Feedback Loops & Engine Architectures
created: 2026-09-24
updated: 2026-09-24
type: concept
tags:
  - tool
  - triage
  - bug-bounty
sources:
  - unprocessed-obsidians/fuzzing.md
confidence: high
contested: false
contradictions: []
---

# Fuzzing Techniques, Feedback Loops & Engine Architectures

## Overview
Fuzzing is an automated dynamic testing technique that generates and feeds malformed, pseudo-random, or model-structured inputs into a target binary or system to detect software vulnerabilities, assertion violations, memory corruption, and unhandled exception states. Modern fuzzing has evolved from naive random generation into high-performance, coverage-guided, and snapshot-accelerated feedback loops.

## Fuzzing Architecture Taxonomy

| Category | Program Visibility | Feedback Mechanism | Execution Speed | Primary Strengths & Limitations |
| :--- | :--- | :--- | :--- | :--- |
| **BlackBox** | None (Zero knowledge) | Crash / Hang status only | Extremely High | Scalable and simple; poor coverage on deep, nested logic branches. |
| **GreyBox** | Lightweight Instrumentation | Edge/Block Coverage Bitmaps | High | Excellent balance of execution throughput and branch exploration (e.g. AFL++, Honggfuzz). |
| **Snapshot** | Target VM / Process Memory | Restores memory/CPU snapshots | High (bypasses init) | Avoids slow multi-process initialization; ideal for complex or closed-source targets (Nyx, wtf). |
| **WhiteBox** | Full Source / IR Analysis | Symbolic / Concolic Execution | Low | High path coverage by solving branch constraints (QSYM, SymSan); computationally expensive. |
| **Directed** | Distance Metrics to Target | Focuses on specific functions | Medium | Steers execution toward newly committed code or suspected CVE sinks (AFLGo, UAFuzz). |

## Core Engine Components

```
+---------------------------------------------------------------+
|                       Fuzzing Pipeline                        |
+---------------------------------------------------------------+
        |
        v
[ Seed Corpus ] ---> [ Mutation Engine / Power Scheduler ]
                            |
                            v
                     [ Target Executor ] (Forkserver / Snapshot)
                            |
                            v
                     [ Feedback Loop ] (Coverage Bitmap, Sanitizers)
                            |
                            +--> New Path Discovered? -> Add to Corpus
                            +--> Crash Detected?      -> Triage Oracle
```

### 1. Power Scheduler & Seed Selection
Determines how much computational budget (fuzzing cycles) to assign to individual seeds in the queue based on execution speed, code depth, and previously observed edge transitions.

### 2. Mutation Strategies
- **Deterministic**: Bit flips, byte overwrites, inserting boundary arithmetic integers (`0`, `0x7FFF`, `0xFFFFFFFF`).
- **Havoc / Random**: Stacking random splicing, deletion, and chunk shuffling.
- **Structure-Aware / Grammar**: Parsing input formats (JSON, Protobuf, SQL, TLS) to mutate valid structures without failing initial syntax checks.

### 3. Execution Engines
- **Standard Forkserver**: Clones the process using `fork()` after binary initialization, bypassing `execve()` overhead.
- **Persistent Mode**: In-process fuzzing where a loop repeatedly calls the target API function in memory without terminating the process (achieving 10,000+ execs/second).
- **Snapshot Fuzzing**: Utilizing hypervisor hardware virtualization (Intel VT-x / Intel-PT) to reset memory and CPU register state to an exact snapshot location within microseconds.

## Sanitizers & Oracle Verification
Fuzzing targets are compiled with compiler-based instrumentation to catch memory corruption before an actual OS segmentation fault occurs:
- **AddressSanitizer (ASAN)**: Flags out-of-bounds heap/stack accesses and Use-After-Free via shadow memory checks.
- **UndefinedBehaviorSanitizer (UBSAN)**: Detects integer overflows, null-pointer dereferences, and alignment violations.
- **ThreadSanitizer (TSAN)**: Identifies data races in multithreaded applications.

## Related Pages
- [[fuzzing]]
- [[vulnerability-research-methodology]]
- [[exploit-development]]
- [[course]]
