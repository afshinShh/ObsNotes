# LLM Wiki Review Policy

For compiled Wiki changes, always load `llm-wiki-review`, consult `llm-wiki`, create proposals under `wiki/Review/`, and stop before writing compiled pages.

Never mutate compiled pages (`wiki/concepts/`, `wiki/entities/`, `wiki/comparisons/`, `wiki/queries/`, `wiki/index.md`) directly without an explicit human review and approval.

## Environment Paths
- **Obsidian Vault Root:** `/home/omp/Desktop/RED/Knowledge/ObsNotes_clean`
- **Wiki Root:** `/home/omp/Desktop/RED/Knowledge/ObsNotes_clean/wiki`
- **Staging / Proposals:** `/home/omp/Desktop/RED/Knowledge/ObsNotes_clean/wiki/Review/`
- **Raw Immutable Sources:** `/home/omp/Desktop/RED/Knowledge/ObsNotes_clean/wiki/raw/`

## Ingestion Workflow
1. Move or copy source material into `wiki/raw/<category>/` (or reference notes in `unprocessed-obsidians/`).
2. Run `/llm-wiki-review` to extract entities, concepts, and relationships.
3. Generate structured proposal files in `wiki/Review/` and halt execution.
4. Wait for explicit human confirmation: `"Please proceed with the approved revision."`
5. On approval, commit approved pages to `wiki/` and update `wiki/index.md` and `wiki/log.md`.
6. **Post-Application Deduplication:** Remove temporary proposals from `wiki/Review/` and delete duplicate raw copies from `wiki/raw/` to keep the vault clean and link canonical vault sources directly.
