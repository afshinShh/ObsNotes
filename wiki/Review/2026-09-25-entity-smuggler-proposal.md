---
type: llm-wiki-review
status: needs-review
decision: approve
revision: 1
operation: create
target: entities/smuggler.md
sources:
  - unprocessed-obsidians/req-smuggle.md
---

# Proposed Wiki change

## What will change
Compiles dedicated entity profile for `Smuggler (HTTP Request Smuggling Scanner)`, documenting operational commands, repository links, capabilities, and cross-links to related vulnerability concepts.

## Proposed content

---
title: "Smuggler (HTTP Request Smuggling Scanner)"
created: 2026-09-25
updated: 2026-09-25
type: entity
tags:
  - tool
  - request-smuggling
  - bug-bounty
  - api
sources:
  - unprocessed-obsidians/req-smuggle.md
confidence: high
contested: false
contradictions: []
---

# Smuggler (HTTP Request Smuggling Scanner)

## Overview
Smuggler (developed by defparam) is a fast Python-based CLI scanner designed to identify HTTP Request Smuggling (HRS) desynchronization vulnerabilities. It tests edge-case header mutations across CL.TE, TE.CL, and TE.TE permutations.

- **Repository**: [https://github.com/defparam/smuggler](https://github.com/defparam/smuggler)
- **Documentation**: [https://github.com/defparam/smuggler/blob/master/README.md](https://github.com/defparam/smuggler/blob/master/README.md)

## Core Capabilities & Operational Modules
- **Mutation Engine**: Generates dozens of Transfer-Encoding obfuscations (e.g. `Transfer-Encoding: chunked`, `Transfer-encoding: cow`, `Transfer-Encoding: [tab]chunked`).
- **Timeout & Differential Analysis**: Measures response delay differentials on backend sockets to detect desync conditions without causing denial of service.
- **HTTP/2 Support**: Interoperates with modern HTTP/2 protocol downgrade configurations.
- **Batch Domain Scanning**: Accepts piped domain lists from Subfinder/Amass for attack surface discovery.

## CLI Execution & Syntax Examples
```bash
# Single host desynchronization test
python3 smuggler.py -u https://target.com/

# Batch list testing with custom configuration
python3 smuggler.py -u https://target.com/ -m POST -q
```

## Integration in Offensive Workflows
This entity serves as a core automation and execution primitive within modern red-team and bug-bounty pipelines. It bridges the gap between theoretical attack patterns and operational verification.

## Primary Sources & Provenance
Ingested and structured from canonical notes:
  - unprocessed-obsidians/req-smuggle.md

## Related Notes & Concepts
- [[http-request-smuggling]]
- [[cl-te-vs-te-cl]]
- [[turbo-intruder]]


## Evidence and uncertainty
Extracted directly from technical tool usage sections and referenced links in the unprocessed vault notes.

## Human feedback
Optionally explain or edit what should change.
