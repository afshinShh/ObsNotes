---
type: llm-wiki-review
status: needs-review
decision: pending
revision: 1
operation: create
target: web-and-bug-bounty/sources/narroto-guts-hunt-live-hunts.md
sources:
  - Notes/Narroto-Guts Hunt/Live Hunts.md
---

# Proposed Wiki change

## What will change
Compile comprehensive provenance source anchor for Live Hunts case studies note from Notes/Narroto-Guts Hunt/.

## Proposed content
```markdown
---
title: "Source Note - Narroto-Guts Hunt: Live Hunts Case Studies"
created: 2026-09-29
updated: 2026-09-29
type: source
tags:
  - bug-bounty
  - payload
  - api
  - ato
sources:
  - Notes/Narroto-Guts Hunt/Live Hunts.md
extracted_concepts:
  - "[[bug-bounty-live-hunts-case-studies]]"
  - "[[client-side-path-traversal]]"
  - "[[account-takeover-and-auth-flaws]]"
extracted_entities:
  []
extracted_comparisons:
  - "[[cspt-vs-path-traversal]]"
confidence: high
contested: false
contradictions: []
parent: "[[web-and-bug-bounty]]"
cluster: web-and-bug-bounty
---
# Source Note - Narroto-Guts Hunt: Live Hunts Case Studies

> **Provenance Anchor**: Ingested from canonical vault file `[[Notes/Narroto-Guts Hunt/Live Hunts]]`.
> **Total Raw Lines**: 176 lines
> **SHA-256 Digest**: `f2fdfa81e3f6ae84f4f53241c0248e6f0a39c3be919a260484dcc52e14a2e1db`

---

## Compiled Wiki Layers
### Concepts
- [[bug-bounty-live-hunts-case-studies]] — Detailed operational case studies covering CapCut, Superbet, Amazon Hiring, Experian, Windsurf, Romwe, TikTok, and BytePlus.
- [[client-side-path-traversal]] — Client-side path manipulation, non-happy path URL attacks, and token exfiltration.
- [[account-takeover-and-auth-flaws]] — Application-to-web (A2W) authentication flow hijacking, deep links, and OAuth state misuse.

### Comparisons
- [[cspt-vs-path-traversal]] — Client-Side Path Traversal vs Server-Side Path Traversal mechanics and impact.

---

## Source Content Topic Breakdown
- **CapCut**: Deep link authentication transfer, `?next=` host header poisoning, collaborator blind SSRF, state UUID parameter misuse for 1-click ATO, workspace invitation hDOM CSRF.
- **Superbet.ro**: Internal routing clues in DOM, NoSQL injection transitioning to MySQL injection (`1:1` syntax).
- **Hiring.amazon.com**: React SPA route recovery, 4x CPU slowdown for DOM inspection, source map fuzzing (`.map`), and postMessage prioritization.
- **Experian**: SessionStorage redirect XSS, `%0A` error injection, and `tel:` scheme manipulation.
- **Windsurf**: Magic links, `location.assign` checker function bypass via `127.0.0.1@attacker.com`, CSPT on chrome-extension (`chrome-extension/../test`), and XHR token exfiltration.
- **Romwe**: OAuth callback error XSS (nested script tag filter bypass), ATO via user phone number manipulation, and `window.opener` redirection.
- **TikTok**: Stored XSS in file uploader website field via template tag and `href` attributes ($7,500 bounty).
- **BytePlus**: 2FA flow state hijacking via `EventName` parameter tampering and null-code bypass.

## Related Pages
- [[web-and-bug-bounty]]
- [[bug-bounty-live-hunts-case-studies]]
- [[client-side-path-traversal]]
- [[account-takeover-and-auth-flaws]]
```

## Evidence and uncertainty
Documented from canonical notes in Notes/Narroto-Guts Hunt/ (Live Hunts, Structures, Tips and Tricks).

## Human feedback
Optionally explain or edit what should change.
