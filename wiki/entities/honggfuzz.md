---
title: "Honggfuzz"
created: 2026-09-25
updated: 2026-09-25
type: entity
tags:
  - tool
  - fuzzing
  - payload
  - triage
sources:
  - unprocessed-obsidians/fuzzing.md
  - unprocessed-obsidians/course.md
confidence: high
contested: false
contradictions: []
---

# Honggfuzz

## Overview
Honggfuzz is a high-performance, multi-threaded, coverage-guided fuzzer developed by Google. It uniquely leverages Linux hardware performance counters (Intel BTS, Intel PT) and ptrace/POSIX signals to achieve high throughput on both source-instrumented and closed-source binary targets.

- **Repository**: [https://github.com/google/honggfuzz](https://github.com/google/honggfuzz)
- **Documentation**: [https://github.com/google/honggfuzz/blob/master/docs/USAGE.md](https://github.com/google/honggfuzz/blob/master/docs/USAGE.md)

## Core Capabilities & Operational Modules
- **Hardware-Assisted Tracing**: Uses Intel Processor Trace (PT) and Branch Trace Store (BTS) for binary-only branch coverage without binary rewriting.
- **Multi-Threaded Engine**: Runs multiple fuzzing threads inside a single parent process, sharing a single persistent seed corpus without filesystem disk I/O bottlenecks.
- **Feedback Modes**: Supports sanitizer coverage (ASan, MSan, UBSan), compile-time coverage (`hfuzz-clang`), and socket/TCP server fuzzing.
- **Crash Minimization**: Automatically minimizes crash-inducing inputs and generates deduplicated crash callstacks.

## CLI Execution & Syntax Examples
```bash
# In-process instrumented fuzzing
hfuzz-clang target.c -o target
honggfuzz -i corpus/ -o crashes/ -P -- ./target ___FILE___

# Fuzzing network socket services
honggfuzz -i corpus/ -t 2 --listen 127.0.0.1:8080 -P -- ./server
```

## Integration in Offensive Workflows
This entity serves as a core automation and execution primitive within modern red-team and bug-bounty pipelines. It bridges the gap between theoretical attack patterns and operational verification.

## Primary Sources & Provenance
Ingested and structured from canonical notes:
  - unprocessed-obsidians/fuzzing.md
  - unprocessed-obsidians/course.md

## Related Notes & Concepts
- [[fuzzing-techniques]]
- [[afl-plus-plus]]
- [[boofuzz]]
- [[blackbox-vs-greybox-vs-whitebox-fuzzing]]
