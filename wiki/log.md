# Wiki Log

> Chronological record of all wiki actions. Append-only.
> Format: `## [YYYY-MM-DD] action | subject`
> Actions: ingest, update, query, lint, create, archive, delete

## [2026-09-24] create | Wiki initialized
- Domain: Offensive Security, Bug Bounty, Red Teaming, Web Security
- Structure created with SCHEMA.md, index.md, log.md, Review/, raw/ and compiled folders.
- Review companion gate activated via llm-wiki-review.

## [2026-09-24] ingest | WordPress Performance Monitor SSRF
- Source: raw/articles/performance-monitor-ssrf.md (from BUG-Notes/performance monitor.md)
- Approved proposals applied:
  - concepts/blind-ssrf-gopher-redis-rce.md (created)
  - concepts/fastcgi-ssrf-exploitation.md (created)
  - entities/wordpress-performance-monitor.md (created)
- Review proposals marked applied:
  - Review/2026-09-24-blind-ssrf-gopher-redis-rce-proposal.md
  - Review/2026-09-24-fastcgi-ssrf-exploitation-proposal.md
  - Review/2026-09-24-wordpress-performance-monitor-proposal.md
- Index updated: 3 total pages.

## [2026-09-24] deduplicate | Purged raw duplicates and review proposals
- Deleted Review/ proposals (applied).
- Removed redundant raw copy raw/articles/performance-monitor-ssrf.md; compiled pages now cite canonical vault source `BUG-Notes/performance monitor.md`.
- Added provenance anchor: sources/performance monitor.md.

## [2026-09-24] apply-single | Applied proposal: comparisons/authorization-code-vs-implicit-flow.md
- Target: comparisons/authorization-code-vs-implicit-flow.md
- Proposal: 2026-09-24-authorization-code-vs-implicit-flow-proposal.md

## [2026-09-24] apply-single | Applied proposal: sources/jwt.md
- Target: sources/jwt.md
- Proposal: 2026-09-24-sources-jwt-proposal.md

## [2026-09-24] apply | Applied 6 approved proposals
- Applied compiled page: concepts/jwt-security-mechanisms.md
- Applied compiled page: concepts/jwt-attack-vectors.md
- Applied compiled page: concepts/oauth-grant-types-and-flows.md
- Applied compiled page: concepts/oauth-attack-vectors.md
- Applied compiled page: comparisons/jwt-vs-session-cookies.md
- Applied compiled page: entities/jwt-tool.md

## [2026-09-24] apply-single | Applied proposal: sources/oauth.md
- Target: sources/oauth.md
- Proposal: 2026-09-24-sources-oauth-proposal.md

## [2026-09-24] ingest | JWT & OAuth 2.0/OIDC authentication notes
- Sources (canonical vault notes): unprocessed-obsidians/jwt.md, unprocessed-obsidians/oauth.md
- Raw capture body-hash receipts (sha256, verified pre/post ingest):
  - jwt.md: b5c7a479d88658e70c82ae20c9118c9d4a216f097546bc5e474e57d52309a743
  - oauth.md: 709da89069dd5e58f03f53e97a0776f7670bce0d323787a7f317a19074be7dc9
- Approved proposals applied (9/9, revision 1, via Decision Studio):
  - sources/jwt.md (created), sources/oauth.md (created)
  - concepts/jwt-security-mechanisms.md, concepts/jwt-attack-vectors.md (created)
  - concepts/oauth-grant-types-and-flows.md, concepts/oauth-attack-vectors.md (created)
  - comparisons/jwt-vs-session-cookies.md, comparisons/authorization-code-vs-implicit-flow.md (created)
  - entities/jwt-tool.md (created)
- Approval receipts: 8/9 review records carried `decision: approve` at apply time.
  - AUDIT NOTE: sources/jwt.md was applied while its record still read `decision: pending`
    (studio apply preceded the frontmatter flip). Approval basis: user proceed command
    ("Please proceed with the approved revision") + Decision Studio apply. Applied content
    proven byte-identical to reviewed revision 1 via git-blob comparison (EXACT-EXTRACT).
- Post-apply deduplication: Review/ purged (9 applied proposals), wiki/raw/article copies purged;
  frontmatter `sources:` bound directly to canonical notes.
- Post-apply verification: 13 pages, 0 broken wikilinks, 0 orphans, schema/tags valid, index rebuilt.

## [2026-09-24] lint | Post-apply graph verification
- 13 pages scanned. Broken links: 0. Orphans: 0. Verdict: PERFECT (All green).

## [2026-09-25] apply | Applied 2 approved proposals
- Applied compiled page: sources/shellcode.md
- Applied compiled page: concepts/ai-security-testing.md
