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

## [2026-09-25] ingest | Full Vault Backlog Compilation & Graph Synthesis
- Ingestion of remaining 23 unprocessed notes from `unprocessed-obsidians/`:
  - 52 review proposals approved and applied into compiled gold layer.
  - Raw duplicates purged from `wiki/raw/articles/`; provenance bound to canonical notes.
  - Syntheses and comparisons added: `redis-vs-fastcgi-ssrf-pivoting`, `jwt-in-oauth2`, `open-redirect-vs-oauth-attacks`.
  - Cross-linked orphan `redis-vs-fastcgi-ssrf-pivoting` bidirectionally with `blind-ssrf-gopher-redis-rce` and `fastcgi-ssrf-exploitation`.
- Index updated: 64 total pages cataloged.

## [2026-09-25] lint | Post-Apply Full Graph Verification
- Total Scanned Pages: 64
- Broken Links: 0
- Orphan Pages: 0
- Health Verdict: PERFECT (All green)

## [2026-09-25] apply | Applied 74 approved proposals
- Applied compiled page: entities/afl-plus-plus.md
- Applied compiled page: entities/honggfuzz.md
- Applied compiled page: entities/boofuzz.md
- Applied compiled page: entities/mythic-c2.md
- Applied compiled page: entities/donut-loader.md
- Applied compiled page: entities/syswhispers.md
- Applied compiled page: entities/ekko-sleep-obfuscation.md
- Applied compiled page: entities/tplmap.md
- Applied compiled page: entities/sqlmap.md
- Applied compiled page: entities/turbo-intruder.md
- Applied compiled page: entities/ropper.md
- Applied compiled page: entities/ghidriff.md
- Applied compiled page: entities/ysoserial.md
- Applied compiled page: entities/smuggler.md
- Applied compiled page: comparisons/blackbox-vs-greybox-vs-whitebox-fuzzing.md
- Applied compiled page: comparisons/direct-vs-indirect-syscalls.md
- Applied compiled page: comparisons/stack-vs-heap-exploitation.md
- Applied compiled page: comparisons/stored-vs-reflected-vs-dom-xss.md
- Applied compiled page: comparisons/in-band-vs-blind-sqli.md
- Applied compiled page: comparisons/classic-vs-blind-xxe.md
- Applied compiled page: comparisons/kaslr-vs-kpti-mitigations.md
- Applied compiled page: comparisons/imdsv1-vs-imdsv2-ssrf.md
- Applied compiled page: concepts/osint-reconnaissance.md
- Applied compiled page: concepts/osint-investigation-techniques.md
- Applied compiled page: concepts/edr-detection-methods.md
- Applied compiled page: concepts/edr-evasion-techniques.md
- Applied compiled page: concepts/exploit-mitigations.md
- Applied compiled page: concepts/exploit-development.md
- Applied compiled page: concepts/fuzzing-techniques.md
- Applied compiled page: concepts/initial-access-vectors.md
- Applied compiled page: concepts/shellcode-development.md
- Applied compiled page: concepts/vulnerability-research-methodology.md
- Applied compiled page: concepts/sql-injection-testing.md
- Applied compiled page: concepts/server-side-request-forgery.md
- Applied compiled page: concepts/xml-external-entity-injection.md
- Applied compiled page: concepts/cross-site-scripting.md
- Applied compiled page: concepts/http-request-smuggling.md
- Applied compiled page: concepts/race-condition-attacks.md
- Applied compiled page: concepts/http-parameter-pollution.md
- Applied compiled page: concepts/insecure-direct-object-reference.md
- Applied compiled page: concepts/server-side-template-injection.md
- Applied compiled page: concepts/graphql-security.md
- Applied compiled page: concepts/deserialization-attacks.md
- Applied compiled page: concepts/open-redirect-attacks.md
- Applied compiled page: concepts/ai-security-testing.md
- Applied compiled page: concepts/jwt-security-mechanisms.md
- Applied compiled page: concepts/jwt-attack-vectors.md
- Applied compiled page: concepts/oauth-grant-types-and-flows.md
- Applied compiled page: concepts/oauth-attack-vectors.md
- Applied compiled page: sources/ai.md
- Applied compiled page: sources/bug-identification.md
- Applied compiled page: sources/course.md
- Applied compiled page: sources/development.md
- Applied compiled page: sources/edr.md
- Applied compiled page: sources/fuzzing.md
- Applied compiled page: sources/graphql.md
- Applied compiled page: sources/idor.md
- Applied compiled page: sources/initial-access.md
- Applied compiled page: sources/insecure-deserialization.md
- Applied compiled page: sources/jwt.md
- Applied compiled page: sources/mitigations.md
- Applied compiled page: sources/oauth.md
- Applied compiled page: sources/open-redirect.md
- Applied compiled page: sources/osint-method.md
- Applied compiled page: sources/osint.md
- Applied compiled page: sources/parameter-pollution.md
- Applied compiled page: sources/race-condition.md
- Applied compiled page: sources/req-smuggle.md
- Applied compiled page: sources/shellcode.md
- Applied compiled page: sources/sql-injection.md
- Applied compiled page: sources/ssrf.md
- Applied compiled page: sources/ssti.md
- Applied compiled page: sources/xss.md
- Applied compiled page: sources/xxe.md

## [2026-09-25] refactor | Domain Partitioning & Parent-Child Clustering Architecture
- Partitioned the entire compiled LLM Wiki (86 notes) into 6 distinct domain directory hierarchies:
  1. `wiki/binary-exploitation/` (16 pages: 3 concepts, 2 comparisons, 6 entities, 4 sources + parent hub)
  2. `wiki/web-and-bug-bounty/` (51 pages: 18 concepts, 10 comparisons, 7 entities, 15 sources + parent hub)
  3. `wiki/defense-and-evasion/` (14 pages: 4 concepts, 3 comparisons, 3 entities, 3 sources + parent hub)
  4. `wiki/recon-and-osint/` (5 pages: 2 concepts, 2 sources + parent hub)
  5. `wiki/ai-security/` (3 pages: 1 concept, 1 source + parent hub)
  6. `wiki/vulnerability-research/` (3 pages: 1 concept, 1 source + parent hub)
- Created 6 comprehensive Parent Topic Hubs / Maps of Content (MOC):
  - `wiki/binary-exploitation/binary-exploitation.md` (`type: hub`)
  - `wiki/web-and-bug-bounty/web-and-bug-bounty.md` (`type: hub`)
  - `wiki/defense-and-evasion/defense-and-evasion.md` (`type: hub`)
  - `wiki/recon-and-osint/recon-and-osint.md` (`type: hub`)
  - `wiki/ai-security/ai-security.md` (`type: hub`)
  - `wiki/vulnerability-research/vulnerability-research.md` (`type: hub`)
- Standardized Parent-Child schema:
  - Injected `parent: "[[<domain-hub>]]"` and `cluster: <domain-slug>` into all child note frontmatter.
  - Injected reciprocal `- [[<domain-hub>]]` backlink in `## Related Pages` for all child notes.
  - Linked all child concepts, comparisons, entities, and sources from their respective Parent Topic Hubs.
- Upgraded `wiki/scripts/librarian_tool.py`:
  - Recursive note discovery engine `get_all_wiki_notes()` supporting domain directory hierarchies.
  - Preflight checks validating domain clusters and core files.
  - Domain-clustered master catalog generator (`librarian index`).
  - Full graph linting resolving cross-domain wikilinks (`librarian lint`).
  - Multi-cluster graph serialization for Decision Studio API (`/api/graph`, `/api/toc`, `/api/note`, `/api/stats`).
- Upgraded `wiki/scripts/studio.html`:
  - Cluster-centered force simulation: local focal gravity anchors each domain cluster in 2D space.
  - Strong inter-cluster repulsion (1200px cutoff) physically guarantees complete cluster separation between Binary Exploitation, Web Hacking, Defense & Evasion, and other domains.
  - Ambient glowing halos and uppercase floating header banners for each domain cluster.
  - Domain Cluster Selector Bar (`cluster-pill`) with smooth camera pan and zoom focus.
  - Color mode toggle: Domain Cluster Palette vs Layer Type Palette.
  - Table of Contents dual-mode view: Domain Clusters (with expandable Parent Hubs) vs Layer Types.
- Verification & Graph Health Receipts:
  - Total Scanned Pages: 92
  - Total Verified Links: 484
  - Broken Links: 0
  - Orphan Pages: 0
  - Health Verdict: PERFECT (All green)

## [2026-09-25] feat | Dynamic Convex Hulls & Implementation of Approved Recommendations
- Upgraded Decision Studio Cluster Architecture (`studio.html`):
  - Completely replaced static circular boundaries with **Dynamic Organic Convex Hulls (Minkowski Sum Fillets)**.
  - Hulls are computed dynamically on every animation frame from the actual live positions of member nodes using Graham Scan + 45px rounded margin expansion.
  - Mathematically guarantees **100% of cluster nodes are enclosed** with zero exceptions or leaky nodes.
  - Dynamic centroid & apex tracking: floating domain banners (`⚙️ BINARY EXPLOITATION`, `🌐 WEB HACKING & BB`, etc.) automatically float above the uppermost node of each cluster.
  - Added multi-mode boundary controls in graph HUD: `🛡️ Boundary: Dynamic Hulls` -> `☁️ Boundary: Soft Clouds` -> `🌿 Boundary: Off (Native Obsidian)`.
- Implemented 5 Human-Approved Architecture Recommendations:
  1. `rec_chain_wordpress-performance-monitor_deserialization-attacks`: Cross-linked `[[deserialization-attacks]]` into `web-and-bug-bounty/entities/wordpress-performance-monitor.md` with reciprocal backlink.
  2. `rec_chain_jwt-tool_cross-site-scripting`: Cross-linked `[[cross-site-scripting]]` into `web-and-bug-bounty/entities/jwt-tool.md` with reciprocal backlink.
  3. `rec_comp_edr-detection-methods_exploit-mitigations`: Synthesized and compiled `defense-and-evasion/comparisons/edr-detection-methods-vs-exploit-mitigations.md` with bidirectional links to `edr-detection-methods.md`, `exploit-mitigations.md`, and parent hub `defense-and-evasion.md`.
  4. `rec_comp_edr-detection-methods_edr-evasion-techniques`: Synthesized and compiled `defense-and-evasion/comparisons/edr-detection-methods-vs-edr-evasion-techniques.md` with bidirectional links to `edr-detection-methods.md`, `edr-evasion-techniques.md`, and parent hub `defense-and-evasion.md`.
  5. `rec_comp_blind-ssrf-gopher-redis-rce_fastcgi-ssrf-exploitation`: Synthesized and compiled `web-and-bug-bounty/comparisons/blind-ssrf-gopher-redis-rce-vs-fastcgi-ssrf-exploitation.md` with bidirectional links to `blind-ssrf-gopher-redis-rce.md`, `fastcgi-ssrf-exploitation.md`, and parent hub `web-and-bug-bounty.md`.
- Updated `wiki/recommendations.json` marking all 5 items as `implemented`.
- Rebuilt Master Catalog `wiki/index.md` (now 95 compiled pages).
- Verification Diagnostics (`librarian lint`):
  - Total Scanned Pages: 95
  - Total Verified Links: 509
  - Broken Links: 0
  - Orphan Pages: 0
  - Health Verdict: PERFECT (All green)

## [2026-09-25] fix | Code Fence Boundary Repair & Excerpt Sanitization
- Audited all markdown notes in `wiki/` for code fence mismatches, unclosed blocks, and prose-in-code swallow errors.
- Cleanly repaired `wiki/web-and-bug-bounty/concepts/http-request-smuggling.md`:
  - Removed 5 duplicate adjacent closing backtick fences (`   ```\n``` `) at detection test samples that had caused a markdown parser state inversion, swallowing subsequent prose text into code blocks.
  - Tagged all bare code blocks with explicit syntax indicators (`http`, `bash`, `python`).
  - Isolated code blocks and prose with clean vertical blank lines.
- Patched `wiki/scripts/librarian_tool.py`:
  - Sanitized `cmd_index` excerpt extraction to strip wikilink wrappers before length truncation, preventing trailing broken `[[...` fragments in `wiki/index.md`.
  - Added interpreter failover for `yaml` import.
- Rebuilt `wiki/index.md` (95 compiled pages).
- Verification Diagnostics (`librarian lint`):
  - Total Scanned Pages: 95
  - Total Verified Links: 509
  - Broken Links: 0
  - Orphan Pages: 0
  - Health Verdict: PERFECT (All green)

## [2026-09-25] feat | Dynamic Markdown Table of Contents Engine
- Implemented an idempotent, self-updating dynamic Table of Contents (TOC) engine matching Obsidian community extensions (`obsidian-dynamic-toc` / `markdown-toc`):
  - Bounded by standard Markdown comment tags: `<!-- TOC_START -->` and `<!-- TOC_END -->`.
  - Automatically parses all H2-H4 headings outside code fences and builds a hierarchical, indented list of anchor links (`#slug`).
  - Idempotent regeneration: clicking generate/update automatically scans the note, strips any existing previous `<!-- TOC_START -->` block, and regenerates a fresh TOC reflecting updated headings.
  - Safe removal: clean one-click deletion of the TOC block.
- Backend Engine (`librarian_tool.py`):
  - Functions `generate_markdown_toc()`, `remove_markdown_toc()`, and `handle_note_toc()`.
  - API endpoint `POST /api/note/toc` (`{"path": ..., "action": "generate"|"remove"}`).
  - CLI commands: `librarian toc <note-path>`, `librarian toc --all`, `librarian toc --remove <note-path>`.
  - Enhanced `get_note_detail` with `has_toc` detection.
- Frontend Experience (`studio.html`):
  - Custom `renderer.heading` in `marked.js` assigning slug `id` attributes to all `h1-h6` elements.
  - Interactive top toolbar buttons in reader: `📑 Generate Table of Contents` (if none exists) or `🔄 Update TOC` and `🗑️ Remove TOC` (if active).
  - High-contrast, dark-mode `note-toc-card` with `📑 TABLE OF CONTENTS [DYNAMIC]` badge, inline `🔄 Update` and `🗑️ Remove` controls.
  - Smooth anchor jumping with purple spotlight flash highlight (`heading-jump-highlight`) on heading target.
  - Floating status toast notifications (`showToast`).
- Graph Diagnostics (`librarian lint`):
  - Total Scanned Pages: 95
  - Total Verified Links: 509
  - Broken Links: 0
  - Orphan Pages: 0
  - Health Verdict: PERFECT (All green)

## [2026-09-25] feat | Obsidian Callouts, Link Beautification & Context-Aware Recommendation Engine
- Implemented full Obsidian Callout / Admonition parser (`[!note]`, `[!warning]`, `[!danger]`, `[!tip]`, `[!bug]`, `[!info]`, `[!success]`, `[!example]`, `[!quote]`):
  - Custom `renderer.blockquote` in `marked.js` detects callout syntax and renders native Obsidian-themed containers with colored left accent borders, custom icons (⚠️, 💡, 🚨, ℹ️, 🪲, 📌, ✅), and styled title headers.
- Beautified all markdown hyperlinks:
  - Eliminated legacy default browser blue underlined hyperlinks.
  - Formatted external links (`[text](url)`) as modern, dark-slate cyan pill chips (`#38bdf8`) with external link indicator arrows (`↗`).
  - Formatted internal wikilinks (`[[slug]]`) as elegant purple pill badges with document icons (`📄`).
  - Preserved clean, unboxed typography for Table of Contents anchor links.
- Overhauled Recommendation Engine (`librarian_tool.py`):
  - Root Cause Diagnosis: Naive tag matching matched generic catch-all tags (`payload`, `red-team`, `rce`, `tool`) across unrelated domains, proposing absurd attack chains (e.g., Java web deserializer `ysoserial` to kernel/binary `exploit-development`).
  - Enforced strict domain cluster affinity: entities and concepts must belong to the same offensive domain cluster.
  - Filtered out all generic tags (`payload`, `red-team`, `rce`, `tool`, `evasion`, `triage`, `report`, `web-security`, `development`, `api`).
  - Primitive-specific matching: only links genuine vulnerability primitives (`sqli`, `ssti`, `ssrf`, `deserialization`, `fuzzing`, `shellcode`, `rop`, `edr`, `jwt`, `oauth`).
  - Purged 20 legacy absurd recommendations from `recommendations.json`.
- Implemented Recommendation Dismissal & Rejection Workflow:
  - Added `✕ Dismiss` button to every active recommendation card in Decision Studio.
  - Added backend endpoints: `POST /api/recommendations/dismiss` and `POST /api/recommendations/restore`.
  - Saved `status: "dismissed"` in `recommendations.json` so rejected proposals are permanently remembered and never re-proposed.
  - Added collapsible Dismissed Recommendations drawer in Studio UI with `↺ Restore` capability.
- Verification Diagnostics (`librarian lint`):
  - Total Scanned Pages: 95
  - Total Verified Links: 509
  - Broken Links: 0
  - Orphan Pages: 0
  - Health Verdict: PERFECT (All green)

## [2026-09-29] apply-single | Applied proposal: web-and-bug-bounty/concepts/app-to-web-auth-transfer.md
- Target: web-and-bug-bounty/concepts/app-to-web-auth-transfer.md
- Proposal: 2026-09-29-app-to-web-auth-transfer-proposal.md

## [2026-09-30] apply-single | Applied proposal: web-and-bug-bounty/concepts/bug-bounty-recon-and-threat-modeling.md
- Target: web-and-bug-bounty/concepts/bug-bounty-recon-and-threat-modeling.md
- Proposal: 2026-09-29-bug-bounty-recon-and-threat-modeling-proposal.md

## [2026-09-30] apply | Narroto-Guts Hunt Full Knowledge Base Integration
- Applied Approved Proposals:
  - `web-and-bug-bounty/concepts/client-side-path-traversal.md` (189 lines, 17 TOC entries) — Full CSPT tradecraft, WAF depth vs app depth formulas, 8-framework parameter decoding matrix, XSS escalation sinks, safe sources, server-side SSRF sinks, and exploitation chains.
  - `web-and-bug-bounty/concepts/dom-debugging-and-sink-analysis.md` (169 lines, 17 TOC entries) — DevTools 80% rule, global handler enumeration, conditional breakpoints, DOM redirect freezing with Escape, PostMessage regex bypasses, and chunked parameter fuzzing.
  - `web-and-bug-bounty/concepts/bug-bounty-recon-and-threat-modeling.md` (180 lines, 14 TOC entries) — Full restoration of hunter mindset axioms, TLD expansion oneliners, Wayback CDX digest collapsing, architectural threat modeling matrix, and reporting discipline.
  - `web-and-bug-bounty/entities/recollapse.md` (65 lines, 6 TOC entries) — Tool profile for 0xacb's normalization & regex bypass fuzzing engine.
  - `web-and-bug-bounty/sources/narroto-guts-hunt-live-hunts.md` (70 lines, 5 TOC entries) — Provenance anchor for Live Hunts case studies.
  - `web-and-bug-bounty/sources/narroto-guts-hunt-structures.md` (58 lines, 4 TOC entries) — Provenance anchor for Structures note.
  - `web-and-bug-bounty/sources/narroto-guts-hunt-tips-and-tricks.md` (66 lines, 4 TOC entries) — Provenance anchor for Tips and Tricks note.
- Parser Defect Diagnosis & Remediation (`librarian_tool.py`):
  - Fixed non-greedy regex `re.search(r"## Proposed content\s*```(?:markdown)?
([\s\S]*?)
```", body)` that truncated proposals containing nested code fences (such as ```mermaid, ```bash, ```javascript).
  - Implemented `extract_proposed_content(text)` across validation, application, TOC cataloging, note detail, and Studio API endpoints.
  - Synced fix to `damndummydumdum/Rokki` in commit `18c9e73`.
- Rebuilt master index (`wiki/index.md`): 115 total pages indexed.
- Health Check (`librarian lint`):
  - Total Scanned Pages: 115
  - Broken Links: 0
  - Orphan Pages: 0
  - Health Verdict: PERFECT (All green)
