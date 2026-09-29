---
title: "Client-Side Path Traversal (CSPT) vs Server-Side Path Traversal"
created: 2026-09-29
updated: 2026-09-29
type: comparison
parent: "[[web-and-bug-bounty]]"
cluster: web-and-bug-bounty
tags:
  - open-redirect
  - lfi
  - bug-bounty
  - api
sources:
  - Notes/Narroto-Guts Hunt/Live Hunts.md
  - Notes/Narroto-Guts Hunt/Tips and Tricks.md
confidence: high
contested: false
contradictions: []
---
# Client-Side Path Traversal (CSPT) vs Server-Side Path Traversal



<!-- TOC_START -->
## Table of Contents
- [Comparative Analysis](#comparative-analysis)
- [Technical Comparison Matrix](#technical-comparison-matrix)
- [Interlinked Concepts](#interlinked-concepts)
- [Related Pages](#related-pages)
<!-- TOC_END -->

## Comparative Analysis
Technical trade-off evaluation comparing [[client-side-path-traversal|Client-Side Path Traversal (CSPT)]] and classic Server-Side Path Traversal / Local File Inclusion within web application security assessments and bug bounty hunting.

While classic Path Traversal manipulates filesystem path resolution on the web server to access unauthorized files (`/etc/passwd`, configuration files, source code), Client-Side Path Traversal manipulates dynamic URL resolution within the user's browser, steering client-side asynchronous API requests (`fetch`, `xhr`) toward unauthorized endpoints while carrying the victim's authenticated session credentials.

## Technical Comparison Matrix

| Dimension | [[client-side-path-traversal|Client-Side Path Traversal (CSPT)]] | Server-Side Path Traversal (LFI / Path Traversal) |
| :--- | :--- | :--- |
| **Execution Environment** | Victim's Web Browser / Client Runtime | Web Server / Operating System Backend |
| **Vulnerable Component** | Dynamic JavaScript path concatenation (`fetch`, `xhr`, `location.assign`) | Filesystem APIs (`file_get_contents`, `open()`, `FileInputStream`) |
| **Target Artifact** | Authenticated API routes, token endpoints, extension schemes | Operating system files, credentials, local source files |
| **Authentication Context** | Dispatches requests carrying victim's session cookies & headers | Accesses files under the web server's OS process privileges |
| **Traversal Delimiters** | URL path segments (`/../`, `%2f..%2f`) | File path separators (`/`, `\`, `..\`, `../`) |
| **Primary Weaponization** | Token leakage, 1-click CSRF/hDOM actions, Open Redirect | Arbitrary File Read, Source Code Disclosure, RCE via log poisoning |

## Interlinked Concepts
- [[client-side-path-traversal]] — Core mechanics of client-side path manipulation and API route redirection.
- [[open-redirect-attacks]] — URL parameter redirection and open redirect chaining.
- [[web-and-bug-bounty]] — Parent Topic Hub for web application security.

## Related Pages
- [[web-and-bug-bounty]]
- [[client-side-path-traversal]]
- [[open-redirect-attacks]]