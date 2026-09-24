# LLM Wiki Review Policy

For compiled Wiki changes, always load `llm-wiki-review`, consult `llm-wiki`, create proposals under `Review/`, and stop before writing compiled pages.

Never mutate compiled pages (`concepts/`, `entities/`, `comparisons/`, `queries/`, `index.md`) directly without an explicit human review and approval.

## Environment Paths
- **Obsidian Vault Root:** `/home/omp/Desktop/RED/Knowledge/ObsNotes_clean`
- **Wiki Root:** `/home/omp/Desktop/RED/Knowledge/ObsNotes_clean/wiki`
- **Staging / Proposals:** `/home/omp/Desktop/RED/Knowledge/ObsNotes_clean/wiki/Review/`
- **Raw Immutable Sources:** `/home/omp/Desktop/RED/Knowledge/ObsNotes_clean/wiki/raw/`

## Ingestion Workflow
1. Store source material under `raw/<category>/`.
2. Extract concepts, entities, and diffs.
3. Write proposals into `Review/` with frontmatter `status: needs-review`, `decision: pending`.
4. Halt and report proposed changes for human review.
5. Apply only when the user explicitly requests: `"Please proceed with the approved revision."`
6. **Post-Application Deduplication:** Immediately after applying approved changes to compiled pages, remove the temporary proposal files from `Review/` and purge duplicate raw copies from `raw/`, ensuring `sources:` frontmatter cites the canonical note directly (e.g. `BUG-Notes/` or `unprocessed-obsidians/`).
