# Wiki Index

> Content catalog for the Offensive Security & Bug Bounty LLM Wiki.
> Last updated: 2026-09-30 | Total pages: 115

## Domain Clusters Overview
The knowledge vault is structured into 6 domain clusters with parent-child hierarchy:
- ⚙️ **[[binary-exploitation]]** (16 pages) — Memory corruption, PIC shellcode, fuzzing engines, ROP weaponization.
- 🌐 **[[web-and-bug-bounty]]** (51 pages) — Web injection, request smuggling, GraphQL, logic flaws, OAuth/JWT, SSRF.
- 🛡️ **[[defense-and-evasion]]** (14 pages) — EDR internals, unhooking, syscalls, sleep obfuscation, kernel mitigations.
- 📡 **[[recon-and-osint]]** (5 pages) — Cross-platform intelligence, persona OpSec, blockchain tracing, geolocation.
- 🤖 **[[ai-security]]** (3 pages) — LLM red teaming, prompt injection, agent tool hijacking, jailbreak syntax.
- 🔬 **[[vulnerability-research]]** (3 pages) — Code auditing, patch diffing, dynamic binary instrumentation, taint tracking.

## 🌐 Web Application Security & Bug Bounty
**Parent Topic Hub**: [[web-and-bug-bounty]]

### Concepts
- [[account-takeover-and-auth-flaws]] — <!-- TOC_START -->
- [[app-to-web-auth-transfer]] — Application-to-Web (A2W) and Web-to-Application (W2A) authentication transfer refers to the architectural handoff mec...
- [[blind-ssrf-gopher-redis-rce]] — Server-Side Request Forgery (SSRF) vulnerabilities supporting the `gopher://` URL scheme allow attackers to send arbi...
- [[bug-bounty-live-hunts-case-studies]] — <!-- TOC_START -->
- [[bug-bounty-recon-and-threat-modeling]] — <!-- TOC_START -->
- [[client-side-path-traversal]] — <!-- TOC_START -->
- [[cross-site-scripting]] — Cross-Site Scripting (XSS) allows attackers to execute arbitrary JavaScript in the context of an end user's browser
- [[deserialization-attacks]] — Insecure Deserialization occurs when untrusted serialized byte streams are instantiated by applications
- [[dom-debugging-and-sink-analysis]] — <!-- TOC_START -->
- [[fastcgi-ssrf-exploitation]] — When PHP-FPM listens on an accessible network socket (e.g
- [[file-upload-attack-matrix]] — <!-- TOC_START -->
- [[graphql-security]] — GraphQL introduces distinct attack surfaces including schema introspection, field suggestion leakage, recursive query...
- [[http-parameter-pollution]] — HTTP Parameter Pollution (HPP) manipulates application logic by supplying repeated parameters across HTTP requests
- [[http-request-smuggling]] — <!-- TOC_START -->
- [[http-request-smuggling-advanced-desync]] — ```mermaid
- [[http-request-smuggling-defense-and-remediation]] — 1
- [[http-request-smuggling-detection-methodology]] — <!-- TOC_START -->
- [[insecure-direct-object-reference]] — Insecure Direct Object References (IDOR / BOLA) occur when applications accept client-supplied object identifiers wit...
- [[jwt-attack-vectors]] — JWT attack vectors target implementation flaws, algorithm verification confusion, header injection vulnerabilities, a...
- [[jwt-security-mechanisms]] — <!-- TOC_START -->
- [[oauth-attack-vectors]] — OAuth 2.0 and OIDC implementations frequently suffer from redirection uri validation flaws, state parameter omission,...
- [[oauth-grant-types-and-flows]] — OAuth 2.0 (RFC 6749) and OpenID Connect (OIDC) govern delegated authorization and identity assertion across web, mobi...
- [[open-redirect-attacks]] — Open Redirects allow attackers to manipulate application redirection logic to forward users to arbitrary external dom...
- [[race-condition-attacks]] — Race conditions occur when concurrent threads or processes access shared resources without adequate synchronization
- [[server-side-request-forgery]] — Server-Side Request Forgery (SSRF) enables attackers to force backend servers into initiating arbitrary network requests
- [[server-side-template-injection]] — Server-Side Template Injection (SSTI) occurs when untrusted input is embedded directly into server-side template engines
- [[sql-injection-testing]] — <!-- TOC_START -->
- [[sql-injection-testing-defense-and-remediation]] — <!-- TOC_START -->
- [[sql-injection-testing-detection-methodology]] — <!-- TOC_START -->
- [[sql-injection-testing-exploitation-and-attack-vectors]] — <!-- TOC_START -->
- [[sql-injection-testing-methodologies]] — <!-- TOC_START -->
- [[xml-external-entity-injection]] — XML External Entity (XXE) vulnerabilities arise when improperly configured XML parsers process user-controlled DTD de...
- [[xss-and-waf-evasion-tradecraft]] — <!-- TOC_START -->

### Comparisons
- [[authorization-code-vs-implicit-flow]] — OAuth 2.0 ([RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)) originally defined the Implicit Flow for single...
- [[blind-ssrf-gopher-redis-rce-vs-fastcgi-ssrf-exploitation]] — Technical trade-off evaluation comparing Blind SSRF to Redis RCE via Gopher and FastCGI Protocol Injection via SSRF w...
- [[cl-te-vs-te-cl]] — HTTP request smuggling stems from parsing ambiguities between front-end reverse proxies and backend application servers
- [[classic-vs-blind-xxe]] — Comparison of XML External Entity injection paradigms: Direct response entity reflection versus Blind Out-of-Band par...
- [[cspt-vs-path-traversal]] — <!-- TOC_START -->
- [[imdsv1-vs-imdsv2-ssrf]] — Architectural and exploitation comparison of AWS Instance Metadata Service version 1 (request-response) versus versio...
- [[in-band-vs-blind-sqli]] — Technical trade-off analysis comparing direct In-Band (Union-based, Error-based) SQLi with Inferential/Blind (Boolean...
- [[jwt-in-oauth2-architecture]] — In modern identity systems, JSON Web Tokens (jwt-security-mechanisms) provide the self-contained token format powerin...
- [[jwt-vs-session-cookies]] — A critical architectural decision in web application engineering is choosing between client-stored, cryptographically...
- [[open-redirect-in-oauth-flows]] — Cross-linking open-redirect-attacks with oauth-attack-vectors.
- [[redis-vs-fastcgi-ssrf-pivoting]] — | Vector Attribute | Redis SSRF Pivoting | FastCGI SSRF Pivoting |
- [[stored-vs-reflected-vs-dom-xss]] — Comparative evaluation of Cross-Site Scripting (XSS) execution models across persistence, reflection vectors, and cli...

### Entities & Tools
- [[jwt-tool]] — **JWT Tool** (`jwt_tool`) is a Python-based security auditing and exploitation utility authored by [ticarpi](https://...
- [[recollapse]] — <!-- TOC_START -->
- [[smuggler]] — Smuggler (developed by defparam) is a fast Python-based CLI scanner designed to identify HTTP Request Smuggling (HRS)...
- [[sqlmap]] — Sqlmap is an open-source penetration testing tool that automates the process of detecting and exploiting SQL injectio...
- [[tplmap]] — Tplmap (developed by epinna) is the standard automated vulnerability scanner and exploitation engine for Server-Side...
- [[turbo-intruder]] — Turbo Intruder is a high-speed Burp Suite extension authored by James Kettle
- [[wordpress-performance-monitor]] — Performance Monitor is a WordPress plugin designed to measure site response times and server metrics
- [[ysoserial]] — ysoserial (authored by frohoff) is the pioneering proof-of-concept tool for generating Java deserialization gadget ch...

### Sources
- [[graphql]] — > **Provenance Anchor**: Ingested from canonical vault file `unprocessed-obsidians/graphql`.
- [[idor]] — > **Provenance Anchor**: Ingested from canonical vault file `unprocessed-obsidians/idor`.
- [[insecure-deserialization]] — > **Provenance Anchor**: Ingested from canonical vault file `unprocessed-obsidians/insecure-deserialization`.
- [[jwt]] — > **Provenance Anchor**: Ingested from canonical vault file `unprocessed-obsidians/jwt`.
- [[narroto-guts-hunt-live-hunts]] — > **Provenance Anchor**: Ingested from canonical vault file `Notes/Narroto-Guts Hunt/Live Hunts`.
- [[narroto-guts-hunt-structures]] — > **Provenance Anchor**: Ingested from canonical vault file `Notes/Narroto-Guts Hunt/Structures`.
- [[narroto-guts-hunt-tips-and-tricks]] — > **Provenance Anchor**: Ingested from canonical vault file `Notes/Narroto-Guts Hunt/Tips and Tricks`.
- [[oauth]] — > **Provenance Anchor**: Ingested from canonical vault file `unprocessed-obsidians/oauth`.
- [[open-redirect]] — > **Provenance Anchor**: Ingested from canonical vault file `unprocessed-obsidians/open-redirect`.
- [[parameter-pollution]] — > **Provenance Anchor**: Ingested from canonical vault file `unprocessed-obsidians/parameter-pollution`.
- [[performance monitor]] — > **Provenance Anchor**: Ingested from `BUG-Notes/performance monitor`.
- [[race-condition]] — > **Provenance Anchor**: Ingested from canonical vault file `unprocessed-obsidians/race-condition`.
- [[req-smuggle]] — > **Provenance Anchor**: Ingested from canonical vault file `unprocessed-obsidians/req-smuggle`.
- [[sql-injection]] — > **Provenance Anchor**: Ingested from canonical vault file `unprocessed-obsidians/sql-injection`.
- [[ssrf]] — > **Provenance Anchor**: Ingested from canonical vault file `unprocessed-obsidians/ssrf`.
- [[ssti]] — > **Provenance Anchor**: Ingested from canonical vault file `unprocessed-obsidians/ssti`.
- [[xss]] — > **Provenance Anchor**: Ingested from canonical vault file `unprocessed-obsidians/xss`.
- [[xxe]] — > **Provenance Anchor**: Ingested from canonical vault file `unprocessed-obsidians/xxe`.

## ⚙️ Binary Exploitation & Memory Corruption
**Parent Topic Hub**: [[binary-exploitation]]

### Concepts
- [[exploit-development]] — Exploit development is the engineering discipline of transforming software vulnerabilities into reliable execution pr...
- [[fuzzing-techniques]] — Fuzzing is the automated testing methodology that generates malformed or unexpected inputs to trigger unhandled excep...
- [[shellcode-development]] — Shellcode engineering requires writing self-contained machine code capable of executing from arbitrary memory locatio...

### Comparisons
- [[blackbox-vs-greybox-vs-whitebox-fuzzing]] — Technical trade-off analysis comparing Black-Box (input-agnostic, protocol-driven), Grey-Box (coverage-guided, instru...
- [[stack-vs-heap-exploitation]] — Technical analysis of memory corruption primitives comparing Stack Buffer Overflows (direct control-flow hijacking) w...

### Entities & Tools
- [[afl-plus-plus]] — AFL++ is the community-driven, cutting-edge fork of American Fuzzy Lop (AFL)
- [[boofuzz]] — BooFuzz is the active Python-based fork and successor of Sulley
- [[donut-loader]] — Donut is a position-independent code (PIC) generator authored by TheWover
- [[ghidriff]] — Ghidriff is an open-source binary patch diffing engine powered by the NSA's Ghidra decompiler
- [[honggfuzz]] — Honggfuzz is a high-performance, multi-threaded, coverage-guided fuzzer developed by Google
- [[ropper]] — Ropper is a Python-based gadget discovery and return-oriented programming (ROP) chain construction engine

### Sources
- [[course]] — > **Provenance Anchor**: Ingested from canonical vault file `unprocessed-obsidians/course`.
- [[development]] — > **Provenance Anchor**: Ingested from canonical vault file `unprocessed-obsidians/development`.
- [[fuzzing]] — > **Provenance Anchor**: Ingested from canonical vault file `unprocessed-obsidians/fuzzing`.
- [[shellcode]] — > **Provenance Anchor**: Ingested from canonical vault file `unprocessed-obsidians/shellcode`.

## 🛡️ Endpoint Defense & Evasion
**Parent Topic Hub**: [[defense-and-evasion]]

### Concepts
- [[edr-detection-methods]] — Endpoint Detection and Response (EDR) platforms provide continuous monitoring and behavioral threat detection across...
- [[edr-evasion-techniques]] — EDR evasion encompasses the low-level tradecraft, kernel driver manipulation, memory obfuscation, and callstack manip...
- [[exploit-mitigations]] — Modern operating system kernels and user-space runtimes implement multi-layered hardware-assisted and software-enforc...
- [[initial-access-vectors]] — Initial Access encompasses the delivery techniques, payload formats, execution chains, and evasion mechanics employed...

### Comparisons
- [[av-vs-edr]] — Endpoint security architectures have transitioned from static, signature-driven **Antivirus (AV)** software to dynami...
- [[direct-vs-indirect-syscalls]] — Architectural comparison of user-mode EDR hook evasion via Direct System Calls (raw inline syscall assembly) versus I...
- [[edr-detection-methods-vs-edr-evasion-techniques]] — Technical trade-off evaluation comparing EDR Telemetry Architectures & Detection Mechanisms with EDR Evasion Engineer...
- [[edr-detection-methods-vs-exploit-mitigations]] — Technical trade-off evaluation comparing EDR Telemetry Architectures & Detection Mechanisms and Modern Operating Syst...
- [[kaslr-vs-kpti-mitigations]] — Technical deep dive comparing Kernel Address Space Layout Randomization (KASLR) and Kernel Page Table Isolation (KPTI...

### Entities & Tools
- [[ekko-sleep-obfuscation]] — Ekko is an advanced in-memory evasion technique and tool authored by Cracked5pider
- [[mythic-c2]] — Mythic is a modern, collaborative, multi-agent Command and Control (C2) framework developed by @its-a-feature
- [[syswhispers]] — SysWhispers (developed by Jackson T

### Sources
- [[edr]] — > **Provenance Anchor**: Ingested from canonical vault file `unprocessed-obsidians/edr`.
- [[initial-access]] — > **Provenance Anchor**: Ingested from canonical vault file `unprocessed-obsidians/initial-access`.
- [[mitigations]] — > **Provenance Anchor**: Ingested from canonical vault file `unprocessed-obsidians/mitigations`.

## 📡 Reconnaissance & OSINT
**Parent Topic Hub**: [[recon-and-osint]]

### Concepts
- [[osint-investigation-techniques]] — Rigorous open-source intelligence operations require operational security (OpSec) discipline to prevent target counte...
- [[osint-reconnaissance]] — Open-Source Intelligence (OSINT) encompasses the systematic identification, collection, and correlation of publicly a...

### Sources
- [[osint]] — > **Provenance Anchor**: Ingested from canonical vault file `unprocessed-obsidians/osint`.
- [[osint-method]] — > **Provenance Anchor**: Ingested from canonical vault file `unprocessed-obsidians/osint-method`.

## 🤖 AI & LLM Application Security
**Parent Topic Hub**: [[ai-security]]

### Concepts
- [[ai-security-testing]] — Offensive testing methodologies for Artificial Intelligence and Large Language Model applications

### Sources
- [[ai]] — > **Provenance Anchor**: Ingested from canonical vault file `unprocessed-obsidians/ai`.

## 🔬 Vulnerability Research & Discovery
**Parent Topic Hub**: [[vulnerability-research]]

### Concepts
- [[vulnerability-research-methodology]] — Vulnerability research is the systematic exploration of complex software systems to discover unknown security flaws

### Sources
- [[bug-identification]] — > **Provenance Anchor**: Ingested from canonical vault file `unprocessed-obsidians/bug-identification`.
