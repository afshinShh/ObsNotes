---
type: llm-wiki-review
status: needs-review
decision: approve
revision: 1
operation: create
target: entities/afl-plus-plus.md
sources:
  - unprocessed-obsidians/course.md
  - unprocessed-obsidians/fuzzing.md
---

# Proposed Wiki change

## What will change
Compiles dedicated entity profile for `AFL++ (American Fuzzy Lop Plus Plus)`, documenting operational commands, repository links, capabilities, and cross-links to related vulnerability concepts.

## Proposed content

---
title: "AFL++ (American Fuzzy Lop Plus Plus)"
created: 2026-09-25
updated: 2026-09-25
type: entity
tags:
  - tool
  - fuzzing
  - payload
  - triage
sources:
  - unprocessed-obsidians/course.md
  - unprocessed-obsidians/fuzzing.md
confidence: high
contested: false
contradictions: []
---

# AFL++ (American Fuzzy Lop Plus Plus)

## Overview
AFL++ is the community-driven, cutting-edge fork of American Fuzzy Lop (AFL). It incorporates modern coverage-guided fuzzing innovations including LLVM instrumentation (PCGUARD, LTO), custom mutators, persistent mode execution, QEMU and Frida binary-only instrumentation, and collision-free coverage maps.

- **Repository**: [https://github.com/AFLplusplus/AFLplusplus](https://github.com/AFLplusplus/AFLplusplus)
- **Documentation**: [https://aflplus.plus/docs/](https://aflplus.plus/docs/)

## Core Capabilities & Operational Modules
- **LLVM Instrumentation**: `afl-clang-fast` / `afl-clang-lto` provides collision-free edge coverage via LLVM PCGUARD and link-time optimization (LTO).
- **Persistent Mode**: Re-executes in-process target functions thousands of times per second without `fork()` overhead via `__AFL_LOOP()`.
- **Custom Mutators**: Supports Python and C-based custom grammar mutators (Custom Mutator API) for structured protocol and file fuzzing.
- **Multi-Core Scaling**: Synchronizes queue findings across master (`-M main`) and secondary (`-S slaveN`) worker threads.

## CLI Execution & Syntax Examples
```bash
# Compilation with LTO instrumentation
export CC=afl-clang-lto
export CXX=afl-clang-lto++
./configure && make -j$(nproc)

# Multi-core fuzzing run
# Master node
afl-fuzz -i seed_corpus/ -o findings/ -M master_01 -- ./target @@

# Slave node with dictionary and memory limit
afl-fuzz -i seed_corpus/ -o findings/ -S slave_02 -x dict/formats.dict -m none -- ./target @@
```

## Integration in Offensive Workflows
This entity serves as a core automation and execution primitive within modern red-team and bug-bounty pipelines. It bridges the gap between theoretical attack patterns and operational verification.

## Primary Sources & Provenance
Ingested and structured from canonical notes:
  - unprocessed-obsidians/course.md
  - unprocessed-obsidians/fuzzing.md

## Related Notes & Concepts
- [[fuzzing-techniques]]
- [[honggfuzz]]
- [[boofuzz]]
- [[blackbox-vs-greybox-vs-whitebox-fuzzing]]


## Evidence and uncertainty
Extracted directly from technical tool usage sections and referenced links in the unprocessed vault notes.

## Human feedback
Optionally explain or edit what should change.
