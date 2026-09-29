---
title: "Bug Bounty Threat Modeling & Narrow Reconnaissance Methodology"
created: 2026-09-29
updated: 2026-09-29
type: concept
parent: "[[web-and-bug-bounty]]"
cluster: web-and-bug-bounty
tags:
  - bug-bounty
  - mapping
  - asm
  - osint
  - triage
  - report
sources:
  - Notes/Narroto-Guts Hunt/Structures.md
confidence: high
contested: false
contradictions: []
---
# Bug Bounty Threat Modeling & Narrow Reconnaissance Methodology

<!-- TOC_START -->
<!-- TOC_END -->

## Overview
Disciplined bug bounty hunting requires a deliberate reconnaissance and threat modeling methodology rather than aimless scanning. Understanding an application's business logic, architectural boundaries, and data flows must always precede active vulnerability probing.

## Core Operational Axioms (The Hunter's Mindset)

1. **The Target Offers You the Vulnerability**: Never force a predetermined exploit onto an incompatible architecture. Observe what the target exposes and follow its natural attack surface.
2. **The Least Change Principle**: When testing parameters, modify the absolute minimum number of characters, values, or headers necessary to measure state change.
3. **Hook-Based Fuzzing**: Always establish a reliable baseline hook before launching fuzzers to avoid being misled by false positives.
4. **Modern SPAs Cannot Be Crawled Automatically**: Automated tools (such as Katana) fail on complex DOMs. Passive traffic logging during real user interaction is mandatory; active crawling should only be reserved for automated pipelines.
5. **Explore Like a Normal User (Phase 0)**: Before launching intercepting proxies or scanners, navigate the application as an end user, building a mental model of business features.
6. **Paid & Authenticated Features Are Golden Areas**: High-privilege, paid, enterprise, or subscription-tier features receive less scrutiny from casual hunters and exhibit higher vulnerability density.
7. **Replacement After Ruleset Is a Killer**: Vulnerabilities frequently emerge when backend processors normalize or modify input *after* the WAF or sanitizer checker function has already evaluated the request.

---

## Two-Tier Reconnaissance Architecture
