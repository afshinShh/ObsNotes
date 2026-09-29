---
title: "Turbo Intruder"
created: 2026-09-25
updated: 2026-09-25
type: entity
tags:
  - tool
  - race-condition
  - request-smuggling
  - bug-bounty
sources:
  - unprocessed-obsidians/race-condition.md
  - unprocessed-obsidians/req-smuggle.md
confidence: high
contested: false
contradictions: []
parent: "[[web-and-bug-bounty]]"
cluster: web-and-bug-bounty
---
# Turbo Intruder

## Overview
Turbo Intruder is a high-speed Burp Suite extension authored by James Kettle. Built on a custom HTTP stack written from scratch in C, it enables precision timing attacks, single-packet race conditions, and massive-scale fuzzing at tens of thousands of requests per second.

- **Repository**: [https://github.com/PortSwigger/turbo-intruder](https://github.com/PortSwigger/turbo-intruder)
- **Documentation**: [https://portswigger.net/research/turbo-intruder-embracing-the-billion-request-attack](https://portswigger.net/research/turbo-intruder-embracing-the-billion-request-attack)

## Core Capabilities & Operational Modules
- **Single-Packet Attack**: Queues multiple HTTP requests across TCP connections and synchronizes their arrival using HTTP/2 multiplexing or HTTP/1.1 TCP packet fragmentation.
- **Custom Python Scripting**: Exposes full programmatic request building, connection pooling, and response filtering callbacks via Jython.
- **High-Performance C Engine**: Circumvents JVM network stack bottlenecks to achieve sustained speeds of 30,000+ requests per second.
- **Smuggling Validation**: Used to deliver desynchronized prefix payloads and verify connection state desynchronization.

## CLI Execution & Syntax Examples
```python
# Race condition single-packet attack script in Turbo Intruder
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=1, engine=Engine.BURP2)
    for i in range(30):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

## Integration in Offensive Workflows
This entity serves as a core automation and execution primitive within modern red-team and bug-bounty pipelines. It bridges the gap between theoretical attack patterns and operational verification.

## Primary Sources & Provenance
Ingested and structured from canonical notes:
  - unprocessed-obsidians/race-condition.md
  - unprocessed-obsidians/req-smuggle.md

## Related Notes & Concepts
- [[race-condition-attacks]]
- [[http-request-smuggling]]

## Related Pages
- [[web-and-bug-bounty]]


## Exploitation Chains & Pivot Vectors
- **Pivot to [[http-request-smuggling-defense-and-remediation|HTTP Request Smuggling Defense, Hardening & Protocol Remediation]]:** Weaponize vulnerability surface in Turbo Intruder to trigger [[http-request-smuggling-defense-and-remediation]].
- **Pivot to [[http-request-smuggling-advanced-desync|Advanced HTTP Request Smuggling: H2/H3 Desync, Tunneling & Client-Side Attacks]]:** Weaponize vulnerability surface in Turbo Intruder to trigger [[http-request-smuggling-advanced-desync]].
