---
type: llm-wiki-review
status: needs-review
decision: approve
revision: 1
operation: create
target: entities/tplmap.md
sources:
  - unprocessed-obsidians/ssti.md
---

# Proposed Wiki change

## What will change
Compiles dedicated entity profile for `Tplmap (Server-Side Template Injection Exploitation)`, documenting operational commands, repository links, capabilities, and cross-links to related vulnerability concepts.

## Proposed content

---
title: "Tplmap (Server-Side Template Injection Exploitation)"
created: 2026-09-25
updated: 2026-09-25
type: entity
tags:
  - tool
  - ssti
  - payload
  - bug-bounty
sources:
  - unprocessed-obsidians/ssti.md
confidence: high
contested: false
contradictions: []
---

# Tplmap (Server-Side Template Injection Exploitation)

## Overview
Tplmap (developed by epinna) is the standard automated vulnerability scanner and exploitation engine for Server-Side Template Injection (SSTI). It fingerprints over 15 template engines and automates the transition from reflection to arbitrary remote code execution (RCE).

- **Repository**: [https://github.com/epinna/tplmap](https://github.com/epinna/tplmap)
- **Documentation**: [https://github.com/epinna/tplmap/blob/master/README.md](https://github.com/epinna/tplmap/blob/master/README.md)

## Core Capabilities & Operational Modules
- **Automated Engine Fingerprinting**: Tests polyglot payload evaluation trees across Jinja2, Mako, Twig, Smarty, Freemarker, Velocity, and ERB.
- **Interactive Shell Execution**: Spawns pseudo-interactive bash/sh shells directly through exploited template evaluation contexts.
- **File Upload & Download**: Uploads native exploitation binaries or exfiltrates remote configuration files through template gadgets.
- **Reverse Shell Generation**: Injects inline network socket payloads for automated reverse shell callbacks.

## CLI Execution & Syntax Examples
```bash
# Automated SSTI vulnerability scan on URL parameter
python2.7 tplmap.py -u "http://target.com/profile?name=john"

# Interactive OS command execution shell on Jinja2 target
python2.7 tplmap.py -u "http://target.com/page?msg=test" --os-shell
```

## Integration in Offensive Workflows
This entity serves as a core automation and execution primitive within modern red-team and bug-bounty pipelines. It bridges the gap between theoretical attack patterns and operational verification.

## Primary Sources & Provenance
Ingested and structured from canonical notes:
  - unprocessed-obsidians/ssti.md

## Related Notes & Concepts
- [[server-side-template-injection]]
- [[vulnerability-research-methodology]]


## Evidence and uncertainty
Extracted directly from technical tool usage sections and referenced links in the unprocessed vault notes.

## Human feedback
Optionally explain or edit what should change.
