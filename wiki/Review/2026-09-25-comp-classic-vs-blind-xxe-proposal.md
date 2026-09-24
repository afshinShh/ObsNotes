---
type: llm-wiki-review
status: needs-review
decision: pending
revision: 1
operation: create
target: comparisons/classic-vs-blind-xxe.md
sources:
  - unprocessed-obsidians/xxe.md
---

# Proposed Wiki change

## What will change
Compiles dedicated comparative architecture analysis for `Classic In-Band vs Blind Out-of-Band (OOB) XXE Architecture`, providing side-by-side technical trade-offs and offensive implications.

## Proposed content

---
title: "Classic In-Band vs Blind Out-of-Band (OOB) XXE Architecture"
created: 2026-09-25
updated: 2026-09-25
type: comparison
tags:
  - xxe
  - bug-bounty
  - payload
sources:
  - unprocessed-obsidians/xxe.md
confidence: high
contested: false
contradictions: []
---

# Classic In-Band vs Blind Out-of-Band (OOB) XXE Architecture

## Overview
Comparison of XML External Entity injection paradigms: Direct response entity reflection versus Blind Out-of-Band parameter entity exfiltration via external DTD hosting.

## Comparative Technical Matrix

| Evaluation Dimension | Variant / Paradigm A | Variant / Paradigm B |
| :--- | :--- | :--- |
| **Data Reflection** | Reflected directly in XML parsing response | Zero server response reflection; requires external DNS/HTTP listener |
| **Payload Type** | General entity (`&file;`) defined in inline DOCTYPE | Parameter entity (`%file;`, `%dtd;`) defined across external hosted DTD |
| **Parser Constraints** | Blocked if parser suppresses output or runs asynchronously | Succeeds on blind/batch parsers provided outbound network egress is allowed |
| **Exfiltration Mechanism** | Inline text output in HTTP body | Appended to URL query parameters on attacker HTTP server (`http://attacker.com/?d=...`) |
| **Error-Based Alternative** | Detailed XML parsing error messages | Triggered via invalid local system entity paths to leak data inside error messages |

## Technical Analysis & Operational Verdict
Blind OOB XXE with external DTD hosting is the primary vector against modern enterprise document and SOAP parsers. If outbound network traffic is completely egress-firewalled, researchers must pivot to local DTD repurposing (e.g. `docbook.dtd`, `yelp.dtd`) to trigger error-based exfiltration.

## Primary Sources & Provenance
Ingested and synthesized from canonical notes:
  - unprocessed-obsidians/xxe.md

## Related Concepts & Notes
- [[xml-external-entity-injection]]
- [[server-side-request-forgery]]


## Evidence and uncertainty
Synthesized directly from operational trade-offs, defensive mitigations, and attack models documented across vault notes.

## Human feedback
Optionally explain or edit what should change.
