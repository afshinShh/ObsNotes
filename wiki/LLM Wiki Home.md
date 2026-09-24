---
title: LLM Wiki Home & Dashboard
type: dashboard
created: 2026-09-24
updated: 2026-09-24
tags:
  - wiki
  - dashboard
  - meta
---

# 🧠 LLM Wiki Home & Decision Center

> Welcome to your curated **Offensive Security & Red Teaming Knowledge Vault**.
> Managed by the **Obsidian Librarian** with source-grounded provenance and human-in-the-loop review gating.

---

## ⚡ Quick Actions & Tools

> [!tip] Operating Controls
> - **Decision Studio (Review UI):** Run `librarian studio` in terminal, or open [http://127.0.0.1:20888](http://127.0.0.1:20888) when running.
> - **Pre-Flight Diagnostics:** `librarian preflight`
> - **Health & Link Lint:** `librarian lint`
> - **Compile Approved Proposals:** `librarian apply`
> - **Agent Profile:** `obsidian-librarian chat`

---

## 📥 Silver Layer: Pending Review Proposals

The staging ground where new proposals wait for human approval before entering the compiled wiki.

```dataview
TABLE 
  target as "Target Path",
  decision as "Decision",
  revision as "Rev",
  sources as "Provenance"
FROM "wiki/Review"
SORT file.name ASC
```

*(If this table is empty, all proposed updates have been reviewed, applied, and deduplicated!)*

---

## 🏛️ Gold Layer: Curated Knowledge Base

### 💡 Core Vulnerability Concepts
```dataview
TABLE
  type as "Type",
  tags as "Tags",
  confidence as "Confidence",
  updated as "Last Updated"
FROM "wiki/concepts"
SORT file.name ASC
```

### 🎯 Entities & Target Stacks
```dataview
TABLE
  type as "Type",
  tags as "Tags",
  updated as "Last Updated"
FROM "wiki/entities"
SORT file.name ASC
```

### 📜 Provenance Sources
```dataview
TABLE
  source_file as "Original Vault Note",
  tags as "Tags",
  updated as "Ingested"
FROM "wiki/sources"
SORT file.name ASC
```

---

## ⚠️ Unresolved Contradictions & Contested Claims

Pages where conflicting technical claims or divergent version behaviors have been identified and preserved for review.

```dataview
TABLE
  contradictions as "Conflicting Pages",
  tags as "Tags",
  updated as "Date"
FROM "wiki/concepts" OR "wiki/entities"
WHERE contested = true
```

---

## 🕒 Recently Updated Notes

```dataview
TABLE
  file.folder as "Category",
  file.mtime as "Modified"
FROM "wiki"
WHERE file.name != "LLM Wiki Home" AND file.name != "index" AND file.name != "log" AND file.name != "SCHEMA"
SORT file.mtime DESC
LIMIT 8
```

---

## 🗺️ Navigation Map of Content (MOC)
- **Central Index:** [[wiki/index|Complete Wiki Content Catalog]]
- **Audit & Action Log:** [[wiki/log|Changelog & Ingestion History]]
- **Domain Conventions:** [[wiki/SCHEMA|Wiki Schema & Tag Taxonomy]]
- **Review Policy:** [[wiki/HERMES|Agent Ingestion & Review Policy]]
