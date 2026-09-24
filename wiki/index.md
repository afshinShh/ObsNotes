# Wiki Index

> Content catalog for the Offensive Security & Bug Bounty LLM Wiki.
> Last updated: 2026-09-25 | Total pages: 86

## Entities
- [[afl-plus-plus]] — AFL++ is the community-driven, cutting-edge fork of American Fuzzy Lop (AFL). It incorporates modern coverage-guided fuzzing innovations including LLVM instrumentation (PCGUARD, LTO), custom mutators, persistent mode execution, QEMU and Frida binary-only instrumentation, and collision-free coverage maps.
- [[boofuzz]] — BooFuzz is the active Python-based fork and successor of Sulley. It is designed for black-box and grey-box network protocol and state-machine fuzzing, featuring robust target process monitoring, automated test-case serialization, and crash-reproduction instrumentation.
- [[donut-loader]] — Donut is a position-independent code (PIC) generator authored by TheWover. It converts .NET assemblies, native x86/x64 PE executables, and DLLs into self-contained, in-memory PIC shellcode capable of execution via arbitrary process injection techniques.
- [[ekko-sleep-obfuscation]] — Ekko is an advanced in-memory evasion technique and tool authored by Cracked5pider. It utilizes Win32 asynchronous timer queues to encrypt the beaconing agent's private memory allocations and protect stack contexts while sleeping, thwarting periodic EDR memory scanners.
- [[ghidriff]] — Ghidriff is an open-source binary patch diffing engine powered by the NSA's Ghidra decompiler. It compares unpatched and patched program executables to rapidly pinpoint security fixes, vulnerability root causes, and zero-day attack surfaces.
- [[honggfuzz]] — Honggfuzz is a high-performance, multi-threaded, coverage-guided fuzzer developed by Google. It uniquely leverages Linux hardware performance counters (Intel BTS, Intel PT) and ptrace/POSIX signals to achieve high throughput on both source-instrumented and closed-source binary targets.
- [[jwt-tool]] — **JWT Tool** (`jwt_tool`) is a Python-based security auditing and exploitation utility authored by [ticarpi](https://github.com/ticarpi/jwt_tool). It is the standard specialized CLI tool used by red teams and bug bounty researchers to analyze, tamper with, crack, and forge JSON Web Tokens across web applications and API endpoints.
- [[mythic-c2]] — Mythic is a modern, collaborative, multi-agent Command and Control (C2) framework developed by @its-a-feature. Built with a microservice Docker backend, GraphQL API, and asynchronous WebSocket architecture, it powers red-team operations across cross-platform environments.
- [[ropper]] — Ropper is a Python-based gadget discovery and return-oriented programming (ROP) chain construction engine. It analyzes x86, x86_64, ARM, ARM64, and MIPS binaries (ELF, PE, Mach-O) to find valid execution sequences that bypass Data Execution Prevention (DEP/NX).
- [[smuggler]] — Smuggler (developed by defparam) is a fast Python-based CLI scanner designed to identify HTTP Request Smuggling (HRS) desynchronization vulnerabilities. It tests edge-case header mutations across CL.TE, TE.CL, and TE.TE permutations.
- [[sqlmap]] — Sqlmap is an open-source penetration testing tool that automates the process of detecting and exploiting SQL injection flaws and taking over database servers. It supports fingerprinting, data dumping, file system access, and out-of-band OS command execution.
- [[syswhispers]] — SysWhispers (developed by Jackson T. and KlezVirus) is a tool for generating position-independent C/ASM stubs that execute direct and indirect Windows system calls, completely evading user-mode API hooks installed by Endpoint Detection and Response (EDR) solutions.
- [[tplmap]] — Tplmap (developed by epinna) is the standard automated vulnerability scanner and exploitation engine for Server-Side Template Injection (SSTI). It fingerprints over 15 template engines and automates the transition from reflection to arbitrary remote code execution (RCE).
- [[turbo-intruder]] — Turbo Intruder is a high-speed Burp Suite extension authored by James Kettle. Built on a custom HTTP stack written from scratch in C, it enables precision timing attacks, single-packet race conditions, and massive-scale fuzzing at tens of thousands of requests per second.
- [[wordpress-performance-monitor]] — Performance Monitor is a WordPress plugin designed to measure site response times and server metrics. In vulnerable versions, an unauthenticated cURL wrapper endpoint permits full unauthenticated blind SSRF, enabling arbitrary scheme injection (including `gopher://`).
- [[ysoserial]] — ysoserial (authored by frohoff) is the pioneering proof-of-concept tool for generating Java deserialization gadget chains. It exploits common Java libraries in classpaths to achieve arbitrary command execution when untrusted `ObjectInputStream.readObject()` calls are invoked.

## Concepts
- [[ai-security-testing]] — Offensive testing methodologies for Artificial Intelligence and Large Language Model applications. Covers direct and indirect prompt injection, jailbreaking tradecraft, training data extraction, tool use / function calling exploitation, and RAG poisoning.
- [[blind-ssrf-gopher-redis-rce]] — Server-Side Request Forgery (SSRF) vulnerabilities supporting the `gopher://` URL scheme allow attackers to send arbitrary raw TCP data packets to internal network services. When internal Redis instances (default port 6379) are exposed without authentication or protected mode, Gopher payloads can achieve unauthenticated Remote Code Execution (RCE).
- [[cross-site-scripting]] — Cross-Site Scripting (XSS) allows attackers to execute arbitrary JavaScript in the context of an end user's browser. This note covers stored, reflected, and DOM-based vectors, context-specific breakouts, Content Security Policy (CSP) bypasses, script gadgets, and mutation XSS (mXSS).
- [[deserialization-attacks]] — Insecure Deserialization occurs when untrusted serialized byte streams are instantiated by applications. This note details language-specific magic bytes, gadget chain generation, and remote code execution across Java, PHP, .NET, Python, and Node.js.
- [[edr-detection-methods]] — Endpoint Detection and Response (EDR) platforms provide continuous monitoring and behavioral threat detection across modern operating system endpoints. This note synthesizes EDR internal components, kernel-level sensors, event tracing mechanisms, memory scanners, and heuristic correlation pipelines.
- [[edr-evasion-techniques]] — EDR evasion encompasses the low-level tradecraft, kernel driver manipulation, memory obfuscation, and callstack manipulation techniques used to execute payloads without alerting endpoint detection engines.
- [[exploit-development]] — Exploit development is the engineering discipline of transforming software vulnerabilities into reliable execution primitives. This note covers root cause analysis, stack overflows, SEH overwrite techniques, egg hunting, heap corruption (Use-After-Free), ROP chain synthesis, and weaponization.
- [[exploit-mitigations]] — Modern operating system kernels and user-space runtimes implement multi-layered hardware-assisted and software-enforced mitigations designed to neutralize memory corruption vulnerabilities (buffer overflows, use-after-free, type confusion) and break weaponization chains.
- [[fastcgi-ssrf-exploitation]] — When PHP-FPM listens on an accessible network socket (e.g. TCP port 9000) or an internal container bridge without authentication, an SSRF supporting arbitrary binary/raw byte transmission (such as `gopher://`) can emulate FastCGI protocol frames. By injecting FastCGI parameters (`PHP_VALUE` and `PHP_ADMIN_VALUE`), an attacker can override runtime PHP directives to achieve arbitrary code execution.
- [[fuzzing-techniques]] — Fuzzing is the automated testing methodology that generates malformed or unexpected inputs to trigger unhandled exceptions, memory corruptions, and security violations. This comprehensive reference integrates fuzzing engine taxonomies, compiler sanitizers, snapshot fuzzing, and practical multi-core lab execution workflows.
- [[graphql-security]] — GraphQL introduces distinct attack surfaces including schema introspection, field suggestion leakage, recursive query denial of service, batching attacks, and broken authorization in resolvers.
- [[http-parameter-pollution]] — HTTP Parameter Pollution (HPP) manipulates application logic by supplying repeated parameters across HTTP requests. This note provides the complete precedence matrix across web server technologies, WAF evasion techniques, and client-side parameter injection.
- [[http-request-smuggling]] — HTTP Request Smuggling exploits discrepancies between frontend proxies and backend servers in parsing ambiguous message boundaries. This reference synthesizes CL.TE, TE.CL, TE.TE obfuscations, HTTP/2 request splitting, and cache poisoning desynchronizations.
- [[initial-access-vectors]] — Initial Access encompasses the delivery techniques, payload formats, execution chains, and evasion mechanics employed by offensive operators to establish an initial foothold within corporate environments while bypassing modern email gateways and endpoint defenses.
- [[insecure-direct-object-reference]] — Insecure Direct Object References (IDOR / BOLA) occur when applications accept client-supplied object identifiers without validating authorization policies. This note details discovery heuristics, UUID/GUID manipulation, multi-step flow bypasses, and authorization-as-code pitfalls.
- [[jwt-attack-vectors]] — JWT attack vectors target implementation flaws, algorithm verification confusion, header injection vulnerabilities, and weak cryptographic secrets. This note provides practical payloads and execution commands utilizing [[jwt-tool]].
- [[jwt-security-mechanisms]] — JSON Web Tokens (JWT) defined in RFC 7519 provide compact, URL-safe means of representing claims between two parties. This reference documents token structure, header parameters, payload claims, signature verification semantics, and cryptographic algorithm choices.
- [[oauth-attack-vectors]] — OAuth 2.0 and OIDC implementations frequently suffer from redirection uri validation flaws, state parameter omission, authorization code leakage, and token handling discrepancies leading to complete Account Takeover (ATO).
- [[oauth-grant-types-and-flows]] — OAuth 2.0 (RFC 6749) and OpenID Connect (OIDC) govern delegated authorization and identity assertion across web, mobile, and API ecosystems. This note covers grant types, PKCE enhancements, OAuth 2.1 deprecations, and Financial-grade API (FAPI) security profiles.
- [[open-redirect-attacks]] — Open Redirects allow attackers to manipulate application redirection logic to forward users to arbitrary external domains. This reference documents URL parser differentials, browser quirks, regex bypasses, and attack chaining with OAuth and SSRF.
- [[osint-investigation-techniques]] — Rigorous open-source intelligence operations require operational security (OpSec) discipline to prevent target counter-surveillance, combined with analytical methods for cryptocurrency ledger tracing, multi-spectrum visual forensics, chronolocation, and threat actor infrastructure attribution.
- [[osint-reconnaissance]] — Open-Source Intelligence (OSINT) encompasses the systematic identification, collection, and correlation of publicly accessible data to map external attack surfaces, profile target entities, unmask threat actor infrastructure, and analyze decentralized ledgers. This knowledge base synthesizes over 320 specialized tools, databases, APIs, and search engines into operational categories.
- [[race-condition-attacks]] — Race conditions occur when concurrent threads or processes access shared resources without adequate synchronization. This guide details Time-of-Check to Time-of-Use (TOCTOU), limit-overrun attacks, database transaction isolation anomalies, and single-packet attack synchronization.
- [[server-side-request-forgery]] — Server-Side Request Forgery (SSRF) enables attackers to force backend servers into initiating arbitrary network requests. This comprehensive guide covers cloud metadata services (AWS IMDSv1/v2, GCP, Azure), DNS rebinding, URL parser differentials, and protocol smuggling.
- [[server-side-template-injection]] — Server-Side Template Injection (SSTI) occurs when untrusted input is embedded directly into server-side template engines. This reference provides the engine fingerprinting decision tree, Jinja2, Twig, FreeMarker, and Velocity RCE gadget chains, and sandbox escapes.
- [[shellcode-development]] — Shellcode engineering requires writing self-contained machine code capable of executing from arbitrary memory locations without relying on dynamic linkers. This reference covers position-independent code (PIC) design, PEB traversal, API hashing, memory allocation patterns, and stealth execution alternatives.
- [[sql-injection-testing]] — SQL Injection (SQLi) occurs when untrusted user input is directly concatenated into database query structures. This note synthesizes in-band, error-based, blind boolean/time-based, and out-of-band (OOB) techniques across all major SQL dialects.
- [[vulnerability-research-methodology]] — Vulnerability research is the systematic exploration of complex software systems to discover unknown security flaws. This reference documents end-to-end audit pipelines spanning attack surface mapping, static source and binary analysis, patch diffing, dynamic binary instrumentation, taint analysis, and symbolic execution.
- [[xml-external-entity-injection]] — XML External Entity (XXE) vulnerabilities arise when improperly configured XML parsers process user-controlled DTD declarations. This reference documents classic in-band reflection, blind out-of-band parameter entities, error-based exfiltration, SOAP attacks, and local DTD repurposing.

## Sources
- [[ai]] — # Source Note - AI & LLM Security Testing
- [[bug-identification]] — # Source Note - Vulnerability Research & Bug Identification
- [[course]] — # Source Note - Practical Fuzzing & Exploit Development Lab Workflows
- [[development]] — # Source Note - Exploit Development
- [[edr]] — # Source Note - Endpoint Detection and Response (EDR)
- [[fuzzing]] — # Source Note - Fuzzing Methodologies & Architectures
- [[graphql]] — # Source Note - GraphQL Security Testing
- [[idor]] — # Source Note - Insecure Direct Object References (IDOR)
- [[initial-access]] — # Source Note - Modern Initial Access & Defensive Evasion
- [[insecure-deserialization]] — # Source Note - Insecure Deserialization
- [[jwt]] — # Source Note - JSON Web Tokens (JWT) Security
- [[mitigations]] — # Source Note - Modern Kernel Exploit Mitigations
- [[oauth]] — # Source Note - OAuth Security Testing
- [[open-redirect]] — # Source Note - Open Redirect Vulnerabilities
- [[osint-method]] — # Source Note - OSINT Investigation Methodologies
- [[osint]] — # Source Note - OSINT Tools & Data Sources
- [[parameter-pollution]] — # Source Note - HTTP Parameter Pollution (HPP)
- [[performance monitor]] — # Source Note: Performance Monitor
- [[race-condition]] — # Source Note - Race Conditions
- [[req-smuggle]] — # Source Note - HTTP Request Smuggling
- [[shellcode]] — # Source Note - Shellcode Architecture & Development
- [[sql-injection]] — # Source Note - SQL Injection
- [[ssrf]] — # Source Note - Server-Side Request Forgery (SSRF)
- [[ssti]] — # Source Note - Server-Side Template Injection (SSTI)
- [[xss]] — # Source Note - Cross-Site Scripting (XSS)
- [[xxe]] — # Source Note - XML External Entity (XXE) Injection

## Comparisons
- [[authorization-code-vs-implicit-flow]] — OAuth 2.0 ([RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)) originally defined the Implicit Flow for single-page applications (SPAs) and client-side web apps that could not securely maintain a client secret. Subsequent security analyses revealed fundamental vulnerabilities in transmitting access tokens via front-channel browser redirects. Consequently, the OAuth Working Group deprecated the Implicit Flow in OAuth 2.1 in favor of the Authorization Code Flow with Proof Key for Code Exchange (PKCE / RFC 7636).
- [[av-vs-edr]] — Endpoint security architectures have transitioned from static, signature-driven **Antivirus (AV)** software to dynamic, behavioral **Endpoint Detection and Response (EDR)** platforms. Understanding the technical divergence between preventive signature matching and continuous kernel-level event correlation is critical for both security operations and red-team evasion engineering.
- [[blackbox-vs-greybox-vs-whitebox-fuzzing]] — Technical trade-off analysis comparing Black-Box (input-agnostic, protocol-driven), Grey-Box (coverage-guided, instrumentation-based), and White-Box (symbolic execution, constraint-solving) fuzzing paradigms.
- [[cl-te-vs-te-cl]] — HTTP request smuggling stems from parsing ambiguities between front-end reverse proxies and backend application servers. The two primary classic variants—**CL.TE** and **TE.CL**—depend on which server in the proxy pipeline prioritizes the `Content-Length` header versus the `Transfer-Encoding` header.
- [[classic-vs-blind-xxe]] — Comparison of XML External Entity injection paradigms: Direct response entity reflection versus Blind Out-of-Band parameter entity exfiltration via external DTD hosting.
- [[direct-vs-indirect-syscalls]] — Architectural comparison of user-mode EDR hook evasion via Direct System Calls (raw inline syscall assembly) versus Indirect System Calls (jumping to legitimate ntdll syscall stubs).
- [[imdsv1-vs-imdsv2-ssrf]] — Architectural and exploitation comparison of AWS Instance Metadata Service version 1 (request-response) versus version 2 (session-oriented token authorization).
- [[in-band-vs-blind-sqli]] — Technical trade-off analysis comparing direct In-Band (Union-based, Error-based) SQLi with Inferential/Blind (Boolean, Time-based, Out-of-Band) SQLi methodologies.
- [[jwt-in-oauth2-architecture]] — # JWT Bearer Tokens in OAuth 2.0 & OIDC Architecture
- [[jwt-vs-session-cookies]] — A critical architectural decision in web application engineering is choosing between client-stored, cryptographically signed tokens (JSON Web Tokens) and server-managed session identifiers (stateful cookies). Both approaches offer distinct advantages and operational failure modes regarding scalability, revocation latency, and vulnerability exposure.
- [[kaslr-vs-kpti-mitigations]] — Technical deep dive comparing Kernel Address Space Layout Randomization (KASLR) and Kernel Page Table Isolation (KPTI) in operating system kernel defense.
- [[open-redirect-in-oauth-flows]] — # Open Redirect in OAuth Flows
- [[redis-vs-fastcgi-ssrf-pivoting]] — # Redis RESP vs FastCGI Binary Protocol SSRF Pivoting
- [[stack-vs-heap-exploitation]] — Technical analysis of memory corruption primitives comparing Stack Buffer Overflows (direct control-flow hijacking) with Heap Exploitation (allocator manipulation, use-after-free, chunk consolidation).
- [[stored-vs-reflected-vs-dom-xss]] — Comparative evaluation of Cross-Site Scripting (XSS) execution models across persistence, reflection vectors, and client-side DOM dataflows.

## Queries
<!-- Alphabetical within section -->
