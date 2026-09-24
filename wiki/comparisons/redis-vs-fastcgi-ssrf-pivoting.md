---
title: Redis RESP vs FastCGI Binary Protocol SSRF Pivoting
created: 2026-09-25
updated: 2026-09-25
type: comparison
tags:
  - ssrf
  - rce
  - payload
  - bug-bounty
sources:
  - concepts/blind-ssrf-gopher-redis-rce.md
  - concepts/fastcgi-ssrf-exploitation.md
---

# Redis RESP vs FastCGI Binary Protocol SSRF Pivoting

## Comparative Matrix

| Vector Attribute | Redis SSRF Pivoting | FastCGI SSRF Pivoting |
| :--- | :--- | :--- |
| **Primary Reference** | [[blind-ssrf-gopher-redis-rce]] | [[fastcgi-ssrf-exploitation]] |
| **Default Port** | TCP 6379 | TCP 9000 |
| **Protocol Format** | Text-based RESP (Redis Serialization Protocol) | Binary packet records (Record Header + Body) |
| **Payload Framing** | Gopher URL-encoded plain text commands with CRLF (`%0D%0A`) | Gopher URL-encoded binary FastCGI frames (FCGI_BEGIN_REQUEST, FCGI_PARAMS) |
| **Execution Sink** | Webroot overwrite (`CONFIG SET dir/dbfilename` + `SAVE`) or Lua sandbox (`EVAL`) | Arbitrary PHP execution via `auto_prepend_file=php://input` |
| **Target Daemon** | Standalone Redis server process | PHP-FPM worker pool |
| **Privilege Scope** | User running Redis daemon (often `redis` or `root` in containers) | User running PHP-FPM (`www-data`) |

## Lateral Movement Trade-offs
1. **Redis:** More resilient against line-break corruption; fails open when authentication is disabled.
2. **FastCGI:** Requires valid `SCRIPT_FILENAME` pointing to an existing on-disk PHP file (e.g. `/usr/share/php/PEAR.php` or `/var/www/html/index.php`).

## Related Notes
- [[blind-ssrf-gopher-redis-rce]]
- [[fastcgi-ssrf-exploitation]]
- [[wordpress-performance-monitor]]
