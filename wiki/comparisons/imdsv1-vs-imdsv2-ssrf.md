---
title: "AWS IMDSv1 vs IMDSv2 SSRF Exploitation Constraints"
created: 2026-09-25
updated: 2026-09-25
type: comparison
tags:
  - ssrf
  - cloud-iam
  - bug-bounty
sources:
  - unprocessed-obsidians/ssrf.md
confidence: high
contested: false
contradictions: []
---

# AWS IMDSv1 vs IMDSv2 SSRF Exploitation Constraints

## Overview
Architectural and exploitation comparison of AWS Instance Metadata Service version 1 (request-response) versus version 2 (session-oriented token authorization).

## Comparative Technical Matrix

| Evaluation Dimension | Variant / Paradigm A | Variant / Paradigm B |
| :--- | :--- | :--- |
| **Authentication Primitive** | Zero authentication required (direct GET request) | Session token required via `X-aws-ec2-metadata-token` header |
| **Token Acquisition** | N/A | Requires `PUT` request to `/latest/api/token` with `X-aws-ec2-metadata-token-ttl-seconds` |
| **SSRF Exploitation Scope** | Exploitable via simple GET SSRF, Open Redirect, or XXE | Requires ability to set custom HTTP headers and methods (PUT) |
| **Network Hop Limit** | Default TTL allows multi-hop routing | Default token response TTL = 1 (drops if routed through proxy/WAF container) |
| **Impact** | Instant IAM role credential compromise (`security-credentials/`) | Blocks 95%+ of standard web SSRF vectors lacking header injection |

## Technical Analysis & Operational Verdict
IMDSv2 successfully mitigates classic URL-reflection SSRF. However, if the SSRF vulnerability exists in a client library supporting arbitrary HTTP methods and headers (or CRLF header injection), an attacker can acquire a token and query metadata identical to IMDSv1.

## Primary Sources & Provenance
Ingested and synthesized from canonical notes:
  - unprocessed-obsidians/ssrf.md

## Related Concepts & Notes
- [[server-side-request-forgery]]
- [[http-parameter-pollution]]
