# Wiki Index

> Content catalog for the Offensive Security & Bug Bounty LLM Wiki.
> Last updated: 2026-09-24 | Total pages: 6

## Entities
- [[wordpress-performance-monitor]] — Performance Monitor is a WordPress plugin designed to measure site response times and server metrics. In vulnerable versions, an unauthenticated cURL wrapper endpoint permits full unauthenticated blind SSRF, enabling arbitrary scheme injection (including `gopher://`).

## Concepts
- [[blind-ssrf-gopher-redis-rce]] — Server-Side Request Forgery (SSRF) vulnerabilities supporting the `gopher://` URL scheme allow attackers to send arbitrary raw TCP data packets to internal network services. When internal Redis instances (default port 6379) are exposed without authentication or protected mode, Gopher payloads can achieve unauthenticated Remote Code Execution (RCE).
- [[fastcgi-ssrf-exploitation]] — When PHP-FPM listens on an accessible network socket (e.g. TCP port 9000) or an internal container bridge without authentication, an SSRF supporting arbitrary binary/raw byte transmission (such as `gopher://`) can emulate FastCGI protocol frames. By injecting FastCGI parameters (`PHP_VALUE` and `PHP_ADMIN_VALUE`), an attacker can override runtime PHP directives to achieve arbitrary code execution.

## Sources
- [[jwt]] — # Source Note: JSON Web Tokens (JWT) Security
- [[performance monitor]] — # Source Note: Performance Monitor

## Comparisons
- [[authorization-code-vs-implicit-flow]] — OAuth 2.0 ([RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)) originally defined the Implicit Flow for single-page applications (SPAs) and client-side web apps that could not securely maintain a client secret. Subsequent security analyses revealed fundamental vulnerabilities in transmitting access tokens via front-channel browser redirects. Consequently, the OAuth Working Group deprecated the Implicit Flow in OAuth 2.1 in favor of the Authorization Code Flow with Proof Key for Code Exchange (PKCE / RFC 7636).

## Queries
<!-- Alphabetical within section -->
