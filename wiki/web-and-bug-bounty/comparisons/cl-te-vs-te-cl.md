---
title: "CL.TE vs TE.CL: Request Smuggling Desynchronization Comparison"
created: 2026-09-24
updated: 2026-09-24
type: comparison
tags:
  - request-smuggling
  - bug-bounty
sources:
  - unprocessed-obsidians/req-smuggle.md
confidence: high
contested: false
contradictions: []
parent: "[[web-and-bug-bounty]]"
cluster: web-and-bug-bounty
---
# CL.TE vs TE.CL: Request Smuggling Desynchronization Comparison

## Overview
HTTP request smuggling stems from parsing ambiguities between front-end reverse proxies and backend application servers. The two primary classic variants—**CL.TE** and **TE.CL**—depend on which server in the proxy pipeline prioritizes the `Content-Length` header versus the `Transfer-Encoding` header.

## Side-by-Side Comparison Matrix

| Technical Dimension | CL.TE Variant | TE.CL Variant | Attack Considerations |
| :--- | :--- | :--- | :--- |
| **Front-End Interpretation** | Uses `Content-Length` | Uses `Transfer-Encoding: chunked` | In CL.TE, front-end forwards full payload based on declared byte length; in TE.CL, front-end terminates at `0

`. |
| **Back-End Interpretation** | Uses `Transfer-Encoding: chunked` | Uses `Content-Length` | In CL.TE, backend halts processing at chunk 0; in TE.CL, backend reads partial byte count from Content-Length. |
| **Smuggled Payload Position** | Appended after terminating `0

` chunk. | Embedded inside the chunked body before terminating `0

`. | Packet crafting differs: TE.CL requires calculating chunk size headers covering the smuggled request. |
| **Detection Signal (Timing)** | Sending `POST` where chunk length exceeds body causes backend to hang waiting for remaining chunk bytes. | Sending `POST` with small chunk and oversized `Content-Length` causes backend to wait for missing body bytes. | Precision differential timing probes distinguish between CL.TE and TE.CL targets. |
| **Smuggling Exploitation Flow** | Smuggled request is treated as independent HTTP message following the chunk boundary. | Backend reads first N bytes, leaving the remainder of the chunk as the start of the next request. | TE.CL often requires a dummy trailing header (e.g. `X-Ignore: X`) to absorb the next request's method line. |
| **Typical Target Technologies** | Front-ends: Older Nginx, CloudFront; Back-ends: Apache, Gunicorn. | Front-ends: HAProxy, ATS; Back-ends: IIS, WebLogic, Node.js. | Depends heavily on server configurations and HTTP specification adherence. |

## Detection Probe Differential

### CL.TE Diagnostic Probe
```http
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 4

1
Z
Q
```
- Front-end forwards 4 bytes (`1
Z
`).
- Backend expects chunk size `1`, reads `Z`, then expects chunk terminator; encountering `Q` causes an immediate protocol error or timeout waiting for chunk termination.

### TE.CL Diagnostic Probe
```http
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 6

0

X
```
- Front-end reads up to `0

` and forwards the request.
- Backend reads `Content-Length: 6`, but only 5 bytes are delivered (`0


`); backend hangs waiting for the 6th byte, resulting in a measurable timeout.

## Verdict & Architectural Remediation
- Both vulnerabilities arise from dual header presence.
- **Remediation**: Configure front-end servers to normalize incoming requests, rejecting ambiguous `Transfer-Encoding` / `Content-Length` pairs or disabling HTTP connection reuse on backend connections.

## Related Pages
- [[web-and-bug-bounty]]
- [[req-smuggle]]
- [[http-request-smuggling]]
