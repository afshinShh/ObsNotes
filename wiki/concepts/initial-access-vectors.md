---
title: Modern Initial Access Vectors & Payload Delivery
created: 2026-09-24
updated: 2026-09-24
type: concept
tags:
  - red-team
  - payload
  - evasion
sources:
  - unprocessed-obsidians/initial-access.md
confidence: high
contested: false
contradictions: []
---

# Modern Initial Access Vectors & Payload Delivery

## Overview
Initial Access encompasses the techniques and delivery vectors adversaries employ to establish an initial foothold within a target corporate network or cloud environment. With modern operating systems enforcing Mark-of-the-Web (MOTW) protections and blocking internet macros by default, initial access tradecraft has shifted toward HTML smuggling, container encapsulation, identity federation phishing, and edge appliance perimeter exploitation.

## Delivery Vectors & Tradecraft Matrix

| Attack Vector | Delivery Mechanism | Defensive Barrier Bypassed | Tradecraft Specifics |
| :--- | :--- | :--- | :--- |
| **HTML Smuggling** | JavaScript creates payload blob in memory via `URL.createObjectURL(blob)` on user download. | Email gateway attachment filters, perimeter content inspection. | Payloads are generated client-side from encrypted strings; no malicious executable traverses the email gateway directly. |
| **Container Encapsulation** | Packaging payloads inside disk images (`.iso`, `.vhd`, `.vhdx`) or archives (`.7z`). | Legacy Mark-of-the-Web (MOTW) propagation. | Windows historically did not propagate MOTW flags to files extracted from mounted virtual disk images. |
| **OAuth Consent Phishing** | Registering rogue Azure AD / Google Workspace applications requesting overbroad scopes. | Multi-Factor Authentication (MFA), password rotation policies. | Tricking users into granting OAuth tokens; bypasses credential rotation and maintains persistent API access. |
| **Adversary-in-the-Middle (AiTM)** | Reverse-proxy frameworks (EvilProxy, Tycoon, Muraena) proxying live login portals. | Standard SMS / Push notification MFA. | Steals authenticated session cookies and SAML/OAuth bearer tokens immediately after victim completes legitimate MFA. |
| **Edge Appliance Exploitation** | Exploiting unauthenticated RCE on internet-facing VPNs, firewalls, and gateways (Ivanti, Citrix). | Complete perimeter defense and endpoint EDR visibility. | Edge appliances often run stripped Linux kernels without EDR telemetry, providing stealthy enterprise footholds. |
| **Supply Chain & Developer Targets** | Poisoned package registries (NPM, PyPI), malicious GitHub Actions, fake developer tools. | Corporate firewalls and standard workstation baselines. | Targets high-privilege software engineers with access to source code, cloud credentials, and internal production systems. |

## Payload Hosting & Perimeter OpSec
- **Domain Categorization & Age**: Ensuring delivery domains possess clean historical reputation, established age (>30 days), and valid SSL/TLS certificates.
- **Traffic Redirection & Bot Filtering**: Deploying defensive reverse-proxy redirectors (Apache/Nginx mod_rewrite) that verify User-Agent, geolocation, and IP reputation, redirecting automated security sandbox scanners to benign decoy websites.
- **Sender Infrastructure Warming**: Utilizing reputable relay infrastructure (e.g. AWS SES, SendGrid, Google Workspace relays) to avoid immediate SPF/DKIM spam scoring penalties.

## Related Pages
- [[initial-access]]
- [[edr-evasion-techniques]]
- [[shellcode-development]]
