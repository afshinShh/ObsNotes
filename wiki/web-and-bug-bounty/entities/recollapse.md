---
title: "Recollapse (Normalization & Regex Bypass Fuzzing Tool)"
created: 2026-09-29
updated: 2026-09-29
type: entity
parent: "[[web-and-bug-bounty]]"
cluster: web-and-bug-bounty
tags:
  - tool
  - payload
  - bug-bounty
sources:
  - Notes/Narroto-Guts Hunt/Tips and Tricks.md
confidence: high
contested: false
contradictions: []
---
# Recollapse (Normalization & Regex Bypass Fuzzing Tool)



<!-- TOC_START -->
## Table of Contents
- [Overview](#overview)
- [Core Capabilities & Operational Modules](#core-capabilities-operational-modules)
- [CLI Execution & Syntax Examples](#cli-execution-syntax-examples)
- [Integration in Offensive Workflows](#integration-in-offensive-workflows)
- [Primary Sources & Provenance](#primary-sources-provenance)
- [Related Pages](#related-pages)
<!-- TOC_END -->

## Overview
**Recollapse** is an advanced input permutation and normalization fuzzing utility authored by security researcher 0xacb. It is designed to generate targeted bypass wordlists for Web Application Firewalls (WAFs), input validation filters, and weak regular expressions.

By systematically applying normalization permutations, character substitutions, and encoding variations, Recollapse identifies edge cases where security filters interpret an input differently than the backend application processor.

## Core Capabilities & Operational Modules
- **Regex & Whitelist Permutation**: Generates variations designed to bypass regex boundary checks, unescaped dot validations, and substring matching.
- **Normalization Discrepancy Fuzzing**: Exploits character normalization routines (Unicode normalization, NFKC, URL decoding differences) between intermediate reverse proxies and backend servers.
- **Integration with Fuzzers**: Pipes generated wordlists directly into active scanners such as FFUF, Burp Suite Intruder, or custom Python scripts.

## CLI Execution & Syntax Examples

```bash
# Generate normalization permutations for a target keyword
recollapse -s "admin" -o wordlist.txt

# Pipe permutations directly into ffuf for parameter fuzzing
recollapse -s "redirect" | ffuf -u "https://target.com/callback?url=FUZZ" -w - -mc 200,302
```

## Integration in Offensive Workflows
- **CSPT & Open Redirect Testing**: Generating URL permutations (`http://target.com@attacker.com`, `http://target.com.attacker.com`) to bypass URL validation filters.
- **WAF Filter Evasion**: Finding valid whitespace and attribute injection sequences (`<img/src`, `<img\x0asrc`) that survive WAF inspection.

## Primary Sources & Provenance
- Repository: [https://github.com/0xacb/recollapse](https://github.com/0xacb/recollapse)
- Documented in: [[Notes/Narroto-Guts Hunt/Tips and Tricks]]

## Related Pages
- [[web-and-bug-bounty]]
- [[bug-bounty-recon-and-threat-modeling]]
- [[dom-debugging-and-sink-analysis]]
- [[client-side-path-traversal]]
- [[xss-and-waf-evasion-tradecraft]]