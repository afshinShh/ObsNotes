# Wiki Index

> Content catalog for the Offensive Security & Bug Bounty LLM Wiki.
> Last updated: 2026-09-29 | Total pages: 92

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
- [[blind-ssrf-gopher-redis-rce]] — Server-Side Request Forgery (SSRF) vulnerabilities supporting the `gopher://` URL scheme allow attackers to send arbitra
- [[cross-site-scripting]] — Cross-Site Scripting (XSS) allows attackers to execute arbitrary JavaScript in the context of an end user's browser
- [[deserialization-attacks]] — Insecure Deserialization occurs when untrusted serialized byte streams are instantiated by applications
- [[fastcgi-ssrf-exploitation]] — When PHP-FPM listens on an accessible network socket (e.g
- [[graphql-security]] — GraphQL introduces distinct attack surfaces including schema introspection, field suggestion leakage, recursive query de
- [[http-parameter-pollution]] — HTTP Parameter Pollution (HPP) manipulates application logic by supplying repeated parameters across HTTP requests
- [[http-request-smuggling]] — HTTP Request Smuggling exploits discrepancies between frontend proxies and backend servers in parsing ambiguous message 
- [[insecure-direct-object-reference]] — Insecure Direct Object References (IDOR / BOLA) occur when applications accept client-supplied object identifiers withou
- [[jwt-attack-vectors]] — JWT attack vectors target implementation flaws, algorithm verification confusion, header injection vulnerabilities, and 
- [[jwt-security-mechanisms]] — JSON Web Tokens (JWT) defined in RFC 7519 provide compact, URL-safe means of representing claims between two parties
- [[oauth-attack-vectors]] — OAuth 2.0 and OIDC implementations frequently suffer from redirection uri validation flaws, state parameter omission, au
- [[oauth-grant-types-and-flows]] — OAuth 2.0 (RFC 6749) and OpenID Connect (OIDC) govern delegated authorization and identity assertion across web, mobile,
- [[open-redirect-attacks]] — Open Redirects allow attackers to manipulate application redirection logic to forward users to arbitrary external domain
- [[race-condition-attacks]] — Race conditions occur when concurrent threads or processes access shared resources without adequate synchronization
- [[server-side-request-forgery]] — Server-Side Request Forgery (SSRF) enables attackers to force backend servers into initiating arbitrary network requests
- [[server-side-template-injection]] — Server-Side Template Injection (SSTI) occurs when untrusted input is embedded directly into server-side template engines
- [[sql-injection-testing]] — SQL Injection (SQLi) occurs when untrusted user input is directly concatenated into database query structures
- [[xml-external-entity-injection]] — XML External Entity (XXE) vulnerabilities arise when improperly configured XML parsers process user-controlled DTD decla

### Comparisons
- [[authorization-code-vs-implicit-flow]] — OAuth 2.0 ([RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)) originally defined the Implicit Flow for single-pa
- [[cl-te-vs-te-cl]] — HTTP request smuggling stems from parsing ambiguities between front-end reverse proxies and backend application servers
- [[classic-vs-blind-xxe]] — Comparison of XML External Entity injection paradigms: Direct response entity reflection versus Blind Out-of-Band parame
- [[imdsv1-vs-imdsv2-ssrf]] — Architectural and exploitation comparison of AWS Instance Metadata Service version 1 (request-response) versus version 2
- [[in-band-vs-blind-sqli]] — Technical trade-off analysis comparing direct In-Band (Union-based, Error-based) SQLi with Inferential/Blind (Boolean, T
- [[jwt-in-oauth2-architecture]] — In modern identity systems, JSON Web Tokens ([[jwt-security-mechanisms]]) provide the self-contained token format poweri
- [[jwt-vs-session-cookies]] — A critical architectural decision in web application engineering is choosing between client-stored, cryptographically si
- [[open-redirect-in-oauth-flows]] — Cross-linking [[open-redirect-attacks]] with [[oauth-attack-vectors]].
- [[redis-vs-fastcgi-ssrf-pivoting]] — | Vector Attribute | Redis SSRF Pivoting | FastCGI SSRF Pivoting |
- [[stored-vs-reflected-vs-dom-xss]] — Comparative evaluation of Cross-Site Scripting (XSS) execution models across persistence, reflection vectors, and client

### Entities & Tools
- [[jwt-tool]] — **JWT Tool** (`jwt_tool`) is a Python-based security auditing and exploitation utility authored by [ticarpi](https://git
- [[smuggler]] — Smuggler (developed by defparam) is a fast Python-based CLI scanner designed to identify HTTP Request Smuggling (HRS) de
- [[sqlmap]] — Sqlmap is an open-source penetration testing tool that automates the process of detecting and exploiting SQL injection f
- [[tplmap]] — Tplmap (developed by epinna) is the standard automated vulnerability scanner and exploitation engine for Server-Side Tem
- [[turbo-intruder]] — Turbo Intruder is a high-speed Burp Suite extension authored by James Kettle
- [[wordpress-performance-monitor]] — Performance Monitor is a WordPress plugin designed to measure site response times and server metrics
- [[ysoserial]] — ysoserial (authored by frohoff) is the pioneering proof-of-concept tool for generating Java deserialization gadget chain

### Sources
- [[graphql]] — > **Provenance Anchor**: Ingested from canonical vault file `[[unprocessed-obsidians/graphql]]`.
- [[idor]] — > **Provenance Anchor**: Ingested from canonical vault file `[[unprocessed-obsidians/idor]]`.
- [[insecure-deserialization]] — > **Provenance Anchor**: Ingested from canonical vault file `[[unprocessed-obsidians/insecure-deserialization]]`.
- [[jwt]] — > **Provenance Anchor**: Ingested from canonical vault file `[[unprocessed-obsidians/jwt]]`.
- [[oauth]] — > **Provenance Anchor**: Ingested from canonical vault file `[[unprocessed-obsidians/oauth]]`.
- [[open-redirect]] — > **Provenance Anchor**: Ingested from canonical vault file `[[unprocessed-obsidians/open-redirect]]`.
- [[parameter-pollution]] — > **Provenance Anchor**: Ingested from canonical vault file `[[unprocessed-obsidians/parameter-pollution]]`.
- [[performance monitor]] — > **Provenance Anchor**: Ingested from `[[BUG-Notes/performance monitor]]`.
- [[race-condition]] — > **Provenance Anchor**: Ingested from canonical vault file `[[unprocessed-obsidians/race-condition]]`.
- [[req-smuggle]] — > **Provenance Anchor**: Ingested from canonical vault file `[[unprocessed-obsidians/req-smuggle]]`.
- [[sql-injection]] — > **Provenance Anchor**: Ingested from canonical vault file `[[unprocessed-obsidians/sql-injection]]`.
- [[ssrf]] — > **Provenance Anchor**: Ingested from canonical vault file `[[unprocessed-obsidians/ssrf]]`.
- [[ssti]] — > **Provenance Anchor**: Ingested from canonical vault file `[[unprocessed-obsidians/ssti]]`.
- [[xss]] — > **Provenance Anchor**: Ingested from canonical vault file `[[unprocessed-obsidians/xss]]`.
- [[xxe]] — > **Provenance Anchor**: Ingested from canonical vault file `[[unprocessed-obsidians/xxe]]`.

## ⚙️ Binary Exploitation & Memory Corruption
**Parent Topic Hub**: [[binary-exploitation]]

### Concepts
- [[exploit-development]] — Exploit development is the engineering discipline of transforming software vulnerabilities into reliable execution primi
- [[fuzzing-techniques]] — Fuzzing is the automated testing methodology that generates malformed or unexpected inputs to trigger unhandled exceptio
- [[shellcode-development]] — Shellcode engineering requires writing self-contained machine code capable of executing from arbitrary memory locations 

### Comparisons
- [[blackbox-vs-greybox-vs-whitebox-fuzzing]] — Technical trade-off analysis comparing Black-Box (input-agnostic, protocol-driven), Grey-Box (coverage-guided, instrumen
- [[stack-vs-heap-exploitation]] — Technical analysis of memory corruption primitives comparing Stack Buffer Overflows (direct control-flow hijacking) with

### Entities & Tools
- [[afl-plus-plus]] — AFL++ is the community-driven, cutting-edge fork of American Fuzzy Lop (AFL)
- [[boofuzz]] — BooFuzz is the active Python-based fork and successor of Sulley
- [[donut-loader]] — Donut is a position-independent code (PIC) generator authored by TheWover
- [[ghidriff]] — Ghidriff is an open-source binary patch diffing engine powered by the NSA's Ghidra decompiler
- [[honggfuzz]] — Honggfuzz is a high-performance, multi-threaded, coverage-guided fuzzer developed by Google
- [[ropper]] — Ropper is a Python-based gadget discovery and return-oriented programming (ROP) chain construction engine

### Sources
- [[course]] — > **Provenance Anchor**: Ingested from canonical vault file `[[unprocessed-obsidians/course]]`.
- [[development]] — > **Provenance Anchor**: Ingested from canonical vault file `[[unprocessed-obsidians/development]]`.
- [[fuzzing]] — > **Provenance Anchor**: Ingested from canonical vault file `[[unprocessed-obsidians/fuzzing]]`.
- [[shellcode]] — > **Provenance Anchor**: Ingested from canonical vault file `[[unprocessed-obsidians/shellcode]]`.

## 🛡️ Endpoint Defense & Evasion
**Parent Topic Hub**: [[defense-and-evasion]]

### Concepts
- [[edr-detection-methods]] — Endpoint Detection and Response (EDR) platforms provide continuous monitoring and behavioral threat detection across mod
- [[edr-evasion-techniques]] — EDR evasion encompasses the low-level tradecraft, kernel driver manipulation, memory obfuscation, and callstack manipula
- [[exploit-mitigations]] — Modern operating system kernels and user-space runtimes implement multi-layered hardware-assisted and software-enforced 
- [[initial-access-vectors]] — Initial Access encompasses the delivery techniques, payload formats, execution chains, and evasion mechanics employed by

### Comparisons
- [[av-vs-edr]] — Endpoint security architectures have transitioned from static, signature-driven **Antivirus (AV)** software to dynamic, 
- [[direct-vs-indirect-syscalls]] — Architectural comparison of user-mode EDR hook evasion via Direct System Calls (raw inline syscall assembly) versus Indi
- [[kaslr-vs-kpti-mitigations]] — Technical deep dive comparing Kernel Address Space Layout Randomization (KASLR) and Kernel Page Table Isolation (KPTI) i

### Entities & Tools
- [[ekko-sleep-obfuscation]] — Ekko is an advanced in-memory evasion technique and tool authored by Cracked5pider
- [[mythic-c2]] — Mythic is a modern, collaborative, multi-agent Command and Control (C2) framework developed by @its-a-feature
- [[syswhispers]] — SysWhispers (developed by Jackson T

### Sources
- [[edr]] — > **Provenance Anchor**: Ingested from canonical vault file `[[unprocessed-obsidians/edr]]`.
- [[initial-access]] — > **Provenance Anchor**: Ingested from canonical vault file `[[unprocessed-obsidians/initial-access]]`.
- [[mitigations]] — > **Provenance Anchor**: Ingested from canonical vault file `[[unprocessed-obsidians/mitigations]]`.

## 📡 Reconnaissance & OSINT
**Parent Topic Hub**: [[recon-and-osint]]

### Concepts
- [[osint-investigation-techniques]] — Rigorous open-source intelligence operations require operational security (OpSec) discipline to prevent target counter-s
- [[osint-reconnaissance]] — Open-Source Intelligence (OSINT) encompasses the systematic identification, collection, and correlation of publicly acce

### Sources
- [[osint]] — > **Provenance Anchor**: Ingested from canonical vault file `[[unprocessed-obsidians/osint]]`.
- [[osint-method]] — > **Provenance Anchor**: Ingested from canonical vault file `[[unprocessed-obsidians/osint-method]]`.

## 🤖 AI & LLM Application Security
**Parent Topic Hub**: [[ai-security]]

### Concepts
- [[ai-security-testing]] — Offensive testing methodologies for Artificial Intelligence and Large Language Model applications

### Sources
- [[ai]] — > **Provenance Anchor**: Ingested from canonical vault file `[[unprocessed-obsidians/ai]]`.

## 🔬 Vulnerability Research & Discovery
**Parent Topic Hub**: [[vulnerability-research]]

### Concepts
- [[vulnerability-research-methodology]] — Vulnerability research is the systematic exploration of complex software systems to discover unknown security flaws

### Sources
- [[bug-identification]] — > **Provenance Anchor**: Ingested from canonical vault file `[[unprocessed-obsidians/bug-identification]]`.
