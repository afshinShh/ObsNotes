---
title: "Mythic C2 Framework"
created: 2026-09-25
updated: 2026-09-25
type: entity
tags:
  - tool
  - red-team
  - evasion
  - payload
sources:
  - unprocessed-obsidians/initial-access.md
confidence: high
contested: false
contradictions: []
---

# Mythic C2 Framework

## Overview
Mythic is a modern, collaborative, multi-agent Command and Control (C2) framework developed by @its-a-feature. Built with a microservice Docker backend, GraphQL API, and asynchronous WebSocket architecture, it powers red-team operations across cross-platform environments.

- **Repository**: [https://github.com/its-a-feature/Mythic](https://github.com/its-a-feature/Mythic)
- **Documentation**: [https://docs.mythic-c2.net/](https://docs.mythic-c2.net/)

## Core Capabilities & Operational Modules
- **Multi-Agent Architecture**: Supports diverse agents including Poseidon (macOS/Linux in Go), Merlin (Go), Athena (.NET), and Apollo (C#).
- **Modular C2 Profiles**: Implements flexible egress communication profiles (HTTP, WebSockets, SMB named pipes, DNS, Slack, GitHub).
- **On-the-Fly Payload Building**: Automates obfuscation, crypters, and shellcode transforms directly via Dockerized payload build pipelines.
- **Role-Based Access & Operation Auditing**: Full event logging, operator attribution, and synchronized timeline reconstruction.

## CLI Execution & Syntax Examples
```bash
# Deploy Mythic backend
git clone https://github.com/its-a-feature/Mythic.git
cd Mythic && sudo ./install_docker_kali.sh
sudo ./mythic-cli start

# Install agent and C2 profile
sudo ./mythic-cli install github https://github.com/MythicAgents/poseidon
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```

## Integration in Offensive Workflows
This entity serves as a core automation and execution primitive within modern red-team and bug-bounty pipelines. It bridges the gap between theoretical attack patterns and operational verification.

## Primary Sources & Provenance
Ingested and structured from canonical notes:
  - unprocessed-obsidians/initial-access.md

## Related Notes & Concepts
- [[initial-access-vectors]]
- [[edr-evasion-techniques]]
- [[shellcode-development]]
