---
type: llm-wiki-review
status: needs-review
decision: approve
revision: 1
operation: create
target: entities/boofuzz.md
sources:
  - unprocessed-obsidians/fuzzing.md
---

# Proposed Wiki change

## What will change
Compiles dedicated entity profile for `BooFuzz Network Protocol Fuzzer`, documenting operational commands, repository links, capabilities, and cross-links to related vulnerability concepts.

## Proposed content

---
title: "BooFuzz Network Protocol Fuzzer"
created: 2026-09-25
updated: 2026-09-25
type: entity
tags:
  - tool
  - fuzzing
  - payload
  - api
sources:
  - unprocessed-obsidians/fuzzing.md
confidence: high
contested: false
contradictions: []
---

# BooFuzz Network Protocol Fuzzer

## Overview
BooFuzz is the active Python-based fork and successor of Sulley. It is designed for black-box and grey-box network protocol and state-machine fuzzing, featuring robust target process monitoring, automated test-case serialization, and crash-reproduction instrumentation.

- **Repository**: [https://github.com/jtpereyda/boofuzz](https://github.com/jtpereyda/boofuzz)
- **Documentation**: [https://boofuzz.readthedocs.io/](https://boofuzz.readthedocs.io/)

## Core Capabilities & Operational Modules
- **Protocol Definition DSL**: Allows rapid definition of hierarchical protocols using primitives (`s_string()`, `s_delim()`, `s_word()`, `s_block()`).
- **Process & Network Monitors**: Interfaces with target servers via serial, SSH, or local ptrace monitors to automatically restart hung or crashed services.
- **Web Interface**: Provides a built-in web dashboard visualizing session graphs, test execution progress, and recorded failure packets.
- **Stateful Transitions**: Models complex multi-step protocol handshakes (e.g. Auth -> Connect -> Transfer -> Terminate).

## CLI Execution & Syntax Examples
```python
from boofuzz import *

session = Session(target=Target(SocketConnection("192.168.1.100", 21, proto='tcp')))

s_initialize("ftp_user")
s_string("USER")
s_delim(" ")
s_string("anonymous")
s_static("\r\n")

session.connect(s_get("ftp_user"))
session.fuzz()
```

## Integration in Offensive Workflows
This entity serves as a core automation and execution primitive within modern red-team and bug-bounty pipelines. It bridges the gap between theoretical attack patterns and operational verification.

## Primary Sources & Provenance
Ingested and structured from canonical notes:
  - unprocessed-obsidians/fuzzing.md

## Related Notes & Concepts
- [[fuzzing-techniques]]
- [[afl-plus-plus]]
- [[blackbox-vs-greybox-vs-whitebox-fuzzing]]


## Evidence and uncertainty
Extracted directly from technical tool usage sections and referenced links in the unprocessed vault notes.

## Human feedback
Optionally explain or edit what should change.
