---
type: llm-wiki-review
status: needs-review
decision: approve
revision: 1
operation: create
target: comparisons/blackbox-vs-greybox-vs-whitebox-fuzzing.md
sources:
  - unprocessed-obsidians/fuzzing.md
---

# Proposed Wiki change

## What will change
Compiles dedicated comparative architecture analysis for `Black-Box vs Grey-Box vs White-Box Fuzzing Architectures`, providing side-by-side technical trade-offs and offensive implications.

## Proposed content

---
title: "Black-Box vs Grey-Box vs White-Box Fuzzing Architectures"
created: 2026-09-25
updated: 2026-09-25
type: comparison
tags:
  - fuzzing
  - red-team
  - tool
sources:
  - unprocessed-obsidians/fuzzing.md
confidence: high
contested: false
contradictions: []
---

# Black-Box vs Grey-Box vs White-Box Fuzzing Architectures

## Overview
Technical trade-off analysis comparing Black-Box (input-agnostic, protocol-driven), Grey-Box (coverage-guided, instrumentation-based), and White-Box (symbolic execution, constraint-solving) fuzzing paradigms.

## Comparative Technical Matrix

| Evaluation Dimension | Paradigm A | Paradigm B | Paradigm C |
| :--- | :--- | :--- | :--- |
| **Target Visibility** | Zero internal visibility (closed source / protocol) | Partial visibility (edge/branch coverage counters via LLVM or hardware) | Full program semantics (source AST, symbolic equations, constraints) |
| **Instrumentation Overhead** | Near-zero overhead (native execution) | Moderate (15-30% overhead for edge coverage feedback) | Extreme (100x - 1000x overhead due to constraint solving) |
| **Bug Coverage & Depth** | Shallow parser bugs, network protocol crashes | Deep state-machine bugs, logic flaws, memory corruptions | Deep mathematical/algorithmic edge cases and complex branch predicates |
| **Speed & Throughput** | High (thousands of execs/sec) | Very High in persistent mode (10,000+ execs/sec) | Very Low (tens to hundreds of inputs/hour) |
| **Tool Archetypes** | BooFuzz, Peach, Spike | AFL++, Honggfuzz, libFuzzer | Angr, KLEE, SAGE, Triton |

## Technical Analysis & Operational Verdict
Grey-box fuzzing represents the optimal balance for modern binary and application testing. When encountering complex branch conditions (e.g. CRC checksums, magic values), hybrid fuzzing combining grey-box engines with concolic white-box solvers (e.g. QSYM + AFL++) yields maximal coverage.

## Primary Sources & Provenance
Ingested and synthesized from canonical notes:
  - unprocessed-obsidians/fuzzing.md

## Related Concepts & Notes
- [[fuzzing-techniques]]
- [[afl-plus-plus]]
- [[honggfuzz]]
- [[boofuzz]]


## Evidence and uncertainty
Synthesized directly from operational trade-offs, defensive mitigations, and attack models documented across vault notes.

## Human feedback
Optionally explain or edit what should change.
