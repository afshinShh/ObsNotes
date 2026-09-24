---
title: Source Note - Performance Monitor Blind SSRF
created: 2026-09-24
updated: 2026-09-24
type: source
source_file: "BUG-Notes/performance monitor.md"
tags:
  - wordpress
  - ssrf
  - bug-bounty
extracted_entities:
  - "[[wordpress-performance-monitor]]"
extracted_concepts:
  - "[[blind-ssrf-gopher-redis-rce]]"
  - "[[fastcgi-ssrf-exploitation]]"
---

# Source Note: Performance Monitor

> **Provenance Anchor**: Ingested from `[[BUG-Notes/performance monitor]]`.
> **Compiled Wiki Pages**:
> - Entity: [[wordpress-performance-monitor]]
> - Concept: [[blind-ssrf-gopher-redis-rce]]
> - Concept: [[fastcgi-ssrf-exploitation]]

---

## Original Content

```php
public static function ensure_absolute_url( $url, $original_url ) {

$parsed_url = wp_parse_url( $url );

if ( ! isset( $parsed_url['scheme'] ) ) {

$parsed_original_url = wp_parse_url( $original_url );

$scheme = isset( $parsed_original_url['scheme'] ) ? $parsed_original_url['scheme'] : 'http';

$url = $scheme . '://' . ltrim( $url, '/' );

}
return $url;
}
```
- performance-monitor/includes/class-rest-callback.php : get_curl_data (uses -> )
	- performance-monitor/admin/class-curl.php -> ==get_analysed_page_data (no checks)==
		- only injection point is on get_curl_data function

### WordPress and Requirements
- Enable `wp-json` via permalinks (e.g. *Post name*).
- Vulnerable endpoint: `/wp-json/performance-monitor/v1/curl_data?url=<target>`

### Target Services & Exploitation Matrix
- **Redis ≤ 6.x:** `CONFIG SET dir/dbfilename` webshell write via Gopher RESP.
- **Redis 7.0+ to 8.2.x:** Lua `EVAL` RCE (`os.execute`) / CVE-2025-49844 Lua Use-After-Free.
- **Redis 8.2.0–8.2.2:** Memory corruption via `XACKDEL` overflow (CVE-2025-62507).
- **PHP-FPM (FastCGI):** Port 9000 binary injection via Gopher overriding `PHP_VALUE auto_prepend_file=php://input`.
