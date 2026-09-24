---
title: Source Note - Practical Fuzzing & Exploit Development Lab Workflows
created: 2026-09-24
updated: 2026-09-24
type: source
tags:
  - tool
  - triage
sources:
  - unprocessed-obsidians/course.md
extracted_concepts:
  - "[[fuzzing-techniques]]"
---

# Source Note: Practical Fuzzing & Exploit Development Lab Workflows

> **Provenance Anchor**: Ingested from canonical vault file `[[unprocessed-obsidians/course]]`.
> **Compiled Wiki Pages**:
> - Concept: [[fuzzing-techniques]]

---

## Original Material Overview
The source note provides concrete setup scripts, compilation commands, and practical tooling harnesses for fuzzing:
- **AFL++ Setup & Execution**: Building AFL++ from source with LLVM 19, `afl-clang-fast` / `afl-clang-lto` compiler wrappers, seed generation via `/dev/urandom`, and parallel Master/Slave multi-core fuzzing.
- **Sanitizers & Crash Collection**: Configuring `AFL_USE_ASAN=1` and `AFL_USE_UBSAN=1`, defining `ASAN_OPTIONS` parameters, building real-world file parsers (Dlib `imglab`), and automated crash deduplication via `afl-collect` with GDB and GEF integration.
- **Google FuzzTest Integration**: In-process fuzzing harnesses, CMake configuration (`fuzztest_setup_fuzzing_flags`), property-based testing macros (`FUZZ_TEST`), and Clang build pipelines.
- **Advanced Engines**: Setup and target execution workflows for HonggFuzz, Syzkaller kernel fuzzing, and binary crash analysis.

## Related Pages
- [[fuzzing-techniques]]
- [[fuzzing]]
