# Wiki Index

> Content catalog for the Offensive Security & Bug Bounty LLM Wiki.
> Last updated: 2026-09-25 | Total pages: 17

## Entities
- [[jwt-tool]] — **JWT Tool** (`jwt_tool`) is a Python-based security auditing and exploitation utility authored by [ticarpi](https://github.com/ticarpi/jwt_tool). It is the standard specialized CLI tool used by red teams and bug bounty researchers to analyze, tamper with, crack, and forge JSON Web Tokens across web applications and API endpoints.
- [[wordpress-performance-monitor]] — Performance Monitor is a WordPress plugin designed to measure site response times and server metrics. In vulnerable versions, an unauthenticated cURL wrapper endpoint permits full unauthenticated blind SSRF, enabling arbitrary scheme injection (including `gopher://`).

## Concepts
- [[ai-security-testing]] — Large Language Model (LLM) applications combine non-deterministic neural network inference with traditional software infrastructure (APIs, databases, vector stores, and external tool plugins). Security boundaries in LLMs are inherently porous because instructions (system prompts) and untrusted user data share the identical text input channel. Vulnerabilities emerge when malicious inputs override system rules, trigger unauthorized tool executions, or manipulate downstream application runtimes.
- [[blind-ssrf-gopher-redis-rce]] — Server-Side Request Forgery (SSRF) vulnerabilities supporting the `gopher://` URL scheme allow attackers to send arbitrary raw TCP data packets to internal network services. When internal Redis instances (default port 6379) are exposed without authentication or protected mode, Gopher payloads can achieve unauthenticated Remote Code Execution (RCE).
- [[fastcgi-ssrf-exploitation]] — When PHP-FPM listens on an accessible network socket (e.g. TCP port 9000) or an internal container bridge without authentication, an SSRF supporting arbitrary binary/raw byte transmission (such as `gopher://`) can emulate FastCGI protocol frames. By injecting FastCGI parameters (`PHP_VALUE` and `PHP_ADMIN_VALUE`), an attacker can override runtime PHP directives to achieve arbitrary code execution.
- [[jwt-attack-vectors]] — JSON Web Tokens (JWT) vulnerabilities emerge from implementation flaws in signature verification libraries, insecure server configurations, lack of input sanitization in header parameters, and architectural confusion across authentication mechanisms. Exploitation frequently yields complete authentication bypass, privilege escalation, and account takeover.
- [[jwt-security-mechanisms]] — JSON Web Tokens (JWT) are an open standard defined in [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) for transmitting information between parties as a compact, URL-safe JSON object. JWTs are predominantly used for stateless authentication and fine-grained authorization. A fundamental tenet of JWT architecture is that standard tokens provide **integrity** (via cryptographic signatures), not **confidentiality**; any party possessing the token can decode and inspect the unencrypted payload claims unless paired with JSON Web Encryption (JWE / RFC 7516).
- [[oauth-attack-vectors]] — OAuth 2.0 and OpenID Connect (OIDC) implementations frequently suffer from integration logic flaws, inadequate input validation on redirection endpoints, misconfigured state bindings, and weak token verification. Flaws in OAuth implementations represent critical vulnerabilities often leading to complete Account Takeover (ATO), private data exfiltration, and lateral privilege escalation.
- [[oauth-grant-types-and-flows]] — OAuth 2.0 ([RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)) is an authorization framework that enables third-party applications to obtain limited access to an HTTP service on behalf of a resource owner. OpenID Connect (OIDC) builds on OAuth 2.0 to provide identity authentication via standardized JSON Web Tokens (`id_token`).

## Sources
- [[jwt]] — # Source Note: JSON Web Tokens (JWT) Security
- [[oauth]] — # Source Note: OAuth Security Testing
- [[performance monitor]] — # Source Note: Performance Monitor
- [[shellcode]] — # Source Note: Shellcode Architecture & Development

## Comparisons
- [[authorization-code-vs-implicit-flow]] — OAuth 2.0 ([RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)) originally defined the Implicit Flow for single-page applications (SPAs) and client-side web apps that could not securely maintain a client secret. Subsequent security analyses revealed fundamental vulnerabilities in transmitting access tokens via front-channel browser redirects. Consequently, the OAuth Working Group deprecated the Implicit Flow in OAuth 2.1 in favor of the Authorization Code Flow with Proof Key for Code Exchange (PKCE / RFC 7636).
- [[jwt-in-oauth2-architecture]] — # JWT Bearer Tokens in OAuth 2.0 & OIDC Architecture
- [[jwt-vs-session-cookies]] — A critical architectural decision in web application engineering is choosing between client-stored, cryptographically signed tokens (JSON Web Tokens) and server-managed session identifiers (stateful cookies). Both approaches offer distinct advantages and operational failure modes regarding scalability, revocation latency, and vulnerability exposure.
- [[redis-vs-fastcgi-ssrf-pivoting]] — # Redis RESP vs FastCGI Binary Protocol SSRF Pivoting

## Queries
<!-- Alphabetical within section -->
