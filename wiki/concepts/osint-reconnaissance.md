---
title: OSINT Reconnaissance Frameworks & Data Sources
created: 2026-09-24
updated: 2026-09-24
type: concept
tags:
  - osint
  - mapping
  - secret-leak
sources:
  - unprocessed-obsidians/osint.md
confidence: high
contested: false
contradictions: []
---

# OSINT Reconnaissance Frameworks & Data Sources

## Overview
Open-Source Intelligence (OSINT) encompasses the systematic identification, collection, and correlation of publicly accessible data to map attack surfaces, enumerate organizational infrastructure, unmask threat actor identities, or profile target individuals. Modern OSINT integrates specialized search engines, social media scraping pipelines, identity correlation databases, and public blockchain ledgers.

## OSINT Data Source Taxonomy & Tool Directory

| Investigation Domain | Objectives & Techniques | Key Tools & Platforms |
| :--- | :--- | :--- |
| **Search Engines** | Metasearch aggregation, document parsing, cluster indexing. | `Carrot2`, `etools.ch`, `PDF Search`, `Kagi`, `Brave Search`, `Google Dorks`. |
| **Username & Handle Hunting** | Enumerating profile registrations across hundreds of social networks simultaneously. | `WhatsMyName`, `Maigret`, `Sherlock`, `Namechk`, `NameCheckup`. |
| **Email Verification & Reputation** | Validating inbox existence, discovering connected platforms, domain pattern extraction. | `Holehe`, `EmailRep.io`, `Hunter.io`, `Epieos`, `ContactOut`, `Emailable`. |
| **People Search & Face Matching** | Reverse image searching faces across social profiles and public databases. | `FaceCheck.id`, `Search4Faces`, `FaceSeek`, `TruePeopleSearch`, `Spokeo`, `Pipl`. |
| **Social Media Scraping** | Extracting public tweets, threads, and channel messages without API credentials. | `snscrape` (CLI scraper for X/Twitter, Reddit, Telegram), `Picuki` (Instagram). |
| **Data Leaks & Public Records** | Monitoring leaked archives, credential dumps, and regulatory corporate registries. | `DDoSecrets`, `IntelTechniques`, `Bellingcat Toolkit`. |
| **Cryptocurrency OSINT** | Multi-chain transaction tracing, bridge monitoring, whale tracking. | `Arkham Intelligence`, `Cielo`, `TRM Labs`, `MetaSleuth`, `Socketscan`. |

## Identity Correlation & Pivot Methodology
1. **Target Handle / Email Discovery**: Initiate search from known corporate domain or target email. Use `Hunter.io` or `ContactOut` to establish naming conventions (`firstname.lastname@company.com`).
2. **Platform Registration Probing**: Run `Holehe` against target email to identify registered services (e.g. GitHub, Twitter, Spotify, Adobe) without alerting the target.
3. **Handle Consistency Mapping**: Execute `Maigret` on identified usernames to uncover personal accounts, forums, or developer profiles.
4. **Facial Verification**: Isolate high-resolution profile images and query `FaceCheck.id` to detect unlinked accounts containing identical facial embeddings.

## Defensive Countermeasures & Digital Privacy
- Regular audits of personal data broker aggregators (`DeleteMe`, manual opt-outs on Spokeo/WhitePages).
- Utilizing pseudonymous forwarding addresses (`SimpleLogin`, `Firefox Relay`) and hardware security keys.

## Related Pages
- [[osint]]
- [[osint-investigation-techniques]]
