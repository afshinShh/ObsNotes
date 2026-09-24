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
