---
title: WordPress Performance Monitor Plugin
created: 2026-09-24
updated: 2026-09-24
type: entity
tags:
  - wordpress
  - ssrf
  - bug-bounty
sources:
  - BUG-Notes/performance monitor.md
confidence: high
contested: false
contradictions: []
---

# WordPress Performance Monitor Plugin

## Overview
Performance Monitor is a WordPress plugin designed to measure site response times and server metrics. In vulnerable versions, an unauthenticated cURL wrapper endpoint permits full unauthenticated blind SSRF, enabling arbitrary scheme injection (including `gopher://`).

## Vulnerability Profile
- **Vulnerability Class:** Unauthenticated Blind SSRF
- **Endpoint:** `/wp-json/performance-monitor/v1/curl_data?url=<target-url>`
- **Prerequisites:** WordPress site must have permalinks enabled (non-plain permalink setting required to expose `/wp-json/`).

## Root Cause Analysis
The endpoint accepts a `url` parameter and passes it through an incomplete normalization function:
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
In `class-curl.php`, `get_analysed_page_data()` passes the resulting URL directly to `curl_exec()` without verifying:
1. Allowed URL schemes (allowing `gopher://`, `dict://`, `file://`).
2. Target IP addresses (allowing RFC 1918 private ranges, localhost, and Docker container hosts).
3. Whitelisted hosts.

## Exploitation Chains
By chaining the blind SSRF via `gopher://`, internal services can be exploited for RCE:
- **Source Note:** [[performance monitor]]
- **Redis RCE:** [[blind-ssrf-gopher-redis-rce]]
- **FastCGI / PHP-FPM Injection:** [[fastcgi-ssrf-exploitation]]

## Remediation
1. Enforce strict scheme validation to permit only `http` and `https`.
2. Block internal IP addresses and loopback ranges (`127.0.0.1`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
3. Require authentication for diagnostic endpoints.


## Exploitation Chains & Pivot Vectors
- **Pivot to [[cross-site-scripting|Cross-Site Scripting (XSS) Execution Contexts & Filter Evasion]]:** Weaponize vulnerability surface in WordPress Performance Monitor Plugin to trigger [[cross-site-scripting]].
- **Pivot to [[ai-security-testing|AI & LLM Application Security Testing & Jailbreak Vectors]]:** Weaponize vulnerability surface in WordPress Performance Monitor Plugin to trigger [[ai-security-testing]].
