---
title: OSINT Investigation Methodologies, OpSec & Media Forensics
created: 2026-09-24
updated: 2026-09-24
type: concept
tags:
  - osint
  - mapping
sources:
  - unprocessed-obsidians/osint-method.md
confidence: high
contested: false
contradictions: []
---

# OSINT Investigation Methodologies, OpSec & Media Forensics

## Overview
Rigorous open-source investigations demand strict Operational Security (OpSec) to prevent target attribution, coupled with analytical methodologies for tracing decentralized transactions, verifying media provenance, and geolocating visual evidence.

## Investigative Operational Security (OpSec) & Persona Creation

```
+---------------------------------------------------------------+
|                    Investigator Workstation                   |
+---------------------------------------------------------------+
        |
        +--> Separate Browser Profiles (Firefox Containers)
        +--> Dedicated Disposable VoIP / SMS Numbers (Silent Link, Burner)
        +--> AI-Synthesized Avatar (ThisPersonDoesNotExist)
        +--> Realistic Persona Backstory & Established Post History
        +--> Dedicated VPN / Residential Proxy per Target Workspace
```

- **Persona Isolation**: Never link sock puppet accounts to personal phone numbers, recovery emails, or home IP addresses.
- **Browser Compartmentalization**: Utilize isolated container tabs or dedicated virtual machines to eliminate cross-session cookie tracking.
- **Chain of Custody**: Record cryptographic hashes (SHA-256) of collected media artifacts, log exact UTC timestamps, and document tool versions used during extraction.

## Cryptocurrency & Blockchain Forensic Analysis

### 1. Layer-1 vs Layer-2 Rollup Tracking
- **L1 Anchors**: Rollups batch hundreds of L2 transactions and submit compressed proofs to Ethereum Layer-1. Investigators start by analyzing L1 bridge deposit/withdrawal contracts to link L2 wallets to funded L1 addresses.
- **Optimistic Rollups (Arbitrum, Optimism)**: Transactions are batched into calldata on L1. Detailed state is reconstructed via dedicated explorers (`Arbiscan`, `Optimistic Etherscan`).
- **ZK-Rollups (zkSync Era, Polygon zkEVM)**: Zero-knowledge proofs validate state transitions; individual internal transactions are private on L1 and must be queried on L2 block explorers.

### 2. De-Anonymizing Privacy Protocols & Cross-Chain Bridges
- **Bridge Mixers (Hop, Across, Stargate)**: Synthetic liquidity pools break direct transaction graph links. De-anonymization relies on:
  - **Temporal Correlation**: Matching deposit timestamps on Chain A with withdrawal timestamps on Chain B within narrow time windows.
  - **Amount Clustering**: Tracking uncommon deposit values minus standard relayer gas fees.
- **Shielded Pools (Railgun, Tornado Cash)**: Focus on deposit/withdrawal addresses, relayer wallet interactions, and off-chain transaction memos.

## Visual Forensics & Geolocation Techniques
- **Image Metadata Extraction**: Checking EXIF headers for GPS coordinates, camera model, lens parameters, and timestamps.
- **Chronolocation (Shadow Analysis)**: Calculating sun altitude and azimuth angle using tools like `SunCalc` to determine the exact time of day a photo was taken based on object shadow length.
- **Terrain & Ridgeline Matching**: Comparing background mountain horizons against elevation map databases using `PeakVisor` to pinpoint photographer coordinates.

## Related Pages
- [[osint-method]]
- [[osint-reconnaissance]]
