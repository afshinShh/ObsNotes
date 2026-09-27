# Wiki Schema

## Domain
Offensive Security, Bug Bounty, Red Teaming, Web Application Security, Exploitation Techniques, and Reconnaissance.

## Conventions
- **File names:** lowercase, hyphens, no spaces (e.g., `http-request-smuggling.md`, `oauth-flaws.md`)
- **Frontmatter:** Every wiki page must begin with YAML frontmatter conforming to the schema below.
- **Wikilinks:** Use `[[wikilinks]]` to interlink concepts, entities, and comparisons (minimum 2 outbound links per page).
- **Updates:** When updating a page, always bump the `updated` date.
- **Index:** Every new or updated page must be cataloged in `index.md` under its corresponding section.
- **Audit Log:** Every action must be appended to `log.md`.
- **Review Gate:** All new pages or material changes to compiled pages must be approved via the `Review/` proposal staging workflow (`llm-wiki-review`).
- **Provenance markers:** On pages that synthesize 3+ sources, append `^[raw/<type>/<source-file>.md]` at the end of paragraphs whose claims come from a specific source.

## Frontmatter
```yaml
---
title: Page Title
created: YYYY-MM-DD
updated: YYYY-MM-DD
type: hub | entity | concept | comparison | query | summary
tags: [from taxonomy below]
parent: "[[parent-domain-slug]]"         # Parent Topic Hub wikilink
cluster: domain-cluster-slug            # Domain cluster (e.g., binary-exploitation, web-and-bug-bounty)
sources: [sources/<source-name>.md]
confidence: high | medium | low        # claim strength / corroboration
contested: false                       # set true when unresolved contradictions exist
contradictions: []                     # list of conflicting wiki page slugs
---
```

## raw/ Frontmatter
Raw sources stored in `raw/` are immutable and must carry:
```yaml
---
source_url: https://...               # original URL or file origin
ingested: YYYY-MM-DD
sha256: <hex-digest-of-body-only>     # SHA-256 computed on content below frontmatter
---
```

## Tag Taxonomy
All tags must be chosen from the following categories:
- **Vulnerabilities:** sqli, xss, ssrf, xxe, idor, rce, lfi, race-condition, deserialization, request-smuggling, csrf, open-redirect, prototype-pollution, ssti
- **Auth & Identity:** oauth, oidc, saml, jwt, session, mfa, sso, brute-force, ato
- **Recon & Discovery:** osint, subdomains, vhost, port-scan, asm, mapping, secret-leak
- **Architecture & Logic:** business-logic, api, graphql, grpc, microservices, cloud-iam, k8s, serverless
- **Binary Exploitation:** binary-exploitation, exploit-dev, shellcode, fuzzing, rop
- **Defense & Evasion:** edr, evasion, mitigations, initial-access
- **AI & Emerging:** ai, prompt-injection, jailbreak
- **Vulnerability Research:** vulnerability-research, patch-diffing, code-audit
- **Target Stacks:** wordpress, springboot, laravel, nextjs, django, aspnet, nodejs, entra-id
- **Operations:** bug-bounty, red-team, payload, triage, report, tool, web-security

## Domain-Clustered Architecture & Parent-Child Hierarchy
The wiki organizes compiled offensive security knowledge into 6 primary domain clusters:
1. `binary-exploitation/` — Memory corruption, shellcode development, fuzzing engines, ROP weaponization.
2. `web-and-bug-bounty/` — Web application security, injection, smuggling, GraphQL, logic flaws, OAuth/JWT, SSRF.
3. `defense-and-evasion/` — EDR internals, unhooking, direct/indirect syscalls, sleep obfuscation, mitigations.
4. `recon-and-osint/` — OSINT methodology, reconnaissance frameworks, attack surface mapping.
5. `ai-security/` — AI/LLM security testing, prompt injection, model jailbreaks.
6. `vulnerability-research/` — Vulnerability discovery workflows, patch diffing, code audit methodology.

### Directory Structure per Domain:
```
wiki/<domain-cluster>/
├── <domain-cluster>.md       # Parent Topic Hub / Map of Content (type: hub)
├── concepts/                  # Deep-dive technical concept notes
├── comparisons/               # Comparative trade-off analyses
├── entities/                  # Tools, platforms, and frameworks
└── sources/                   # Primary source provenance anchors
```

### Parent-Child Linking Conventions:
- **Parent Hub Note (`type: hub`)**: Centrally catalogs and bidirectionally links all child concepts, comparisons, entities, and sources within its domain.
- **Child Notes**: Must declare `parent: "[[<domain-cluster>]]"` and `cluster: <domain-cluster>` in frontmatter, and maintain an explicit backlink to their parent hub under `## Related Pages`.
- **Bidirectional Links**: Every compiled page must have at least 2 bidirectional wikilinks (`[[slug]]`). No orphan pages are permitted.

## Page Thresholds
- **Create a page:** When an entity or technique appears in 2+ sources OR is central to one source.
- **Add to existing page:** When a source mentions a technique, attack chain, or defense already covered.
- **Skip page creation:** For passing mentions, minor one-off payloads, or irrelevant noise.
- **Split a page:** When it exceeds ~200 lines — split into focused deep dives and maintain cross-links.
- **Archive a page:** Move obsolete notes to `_archive/` and update inbound links with `(archived)`.

## Entity Pages (`entities/`)
Profiles of tools, platforms, targets, research groups, or threat actors. Includes:
- Overview and role
- Core capabilities and attack surface
- Wikilinks to related concepts and tools
- Primary source references

## Concept Pages (`concepts/`)
Technical attack primitives, vulnerability classes, defensive controls, and methodologies. Includes:
- Technical definition and root cause mechanics
- Attack vectors and detection/exploitation methodology
- Mitigation / hardening steps
- Related concepts and entity wikilinks

## Comparison Pages (`comparisons/`)
Side-by-side technical trade-off analyses (e.g. `CL.TE vs TE.CL`, `JWT vs Session Cookies`). Includes:
- Comparison dimensions (table format)
- Contextual verdicts and attack considerations
- Sources

## Update & Contradiction Policy
When incoming source claims contradict existing wiki pages:
1. Do not overwrite or erase the existing claim.
2. Formulate a proposal marking both claims and context.
3. Mark frontmatter with `contested: true` and specify conflicting page slugs in `contradictions: [...]`.
4. Surface the contradiction to the user for explicit decision (`Keep both`, `Not a contradiction`, or `Decide later`).
