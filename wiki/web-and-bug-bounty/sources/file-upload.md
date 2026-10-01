---
title: "Source Note - File Upload: Vulnerabilities, Web Shells, and Configuration Overrides"
created: 2026-10-01
updated: 2026-10-01
type: source
tags:
  - rce
  - payload
  - web-security
  - bug-bounty
sources:
  - Notes/OLD Notes/WEB/vulnerabilities/File Upload/concept and defense.md
  - Notes/OLD Notes/WEB/vulnerabilities/File Upload/METHODOLOGY.md
  - Notes/OLD Notes/WEB/vulnerabilities/File Upload/Examples.md
extracted_concepts:
  - "[[file-upload-attack-matrix]]"
extracted_entities:
  []
extracted_comparisons:
  []
confidence: high
contested: false
contradictions: []
parent: "[[web-and-bug-bounty]]"
cluster: web-and-bug-bounty
---
# Source Note - File Upload: Vulnerabilities, Web Shells, and Configuration Overrides

> **Provenance Anchor**: Ingested from canonical vault files under `Notes/OLD Notes/WEB/vulnerabilities/File Upload/`.
> - `concept and defense.md` (79 lines, SHA-256: `6e6fc138eb1c3053d26a27e7d6981cf0ec726c59b66231362e105db0890df661`)
> - `METHODOLOGY.md` (80 lines, SHA-256: `c56a1b24bf42ff6c6a461b1793540e1f76e3381fa558004fcf13c9eec1e07b5a`)
> - `Examples.md` (55 lines, SHA-256: `c830ddaf283592da3b35583b63204207f2df2ea42861c8bb4fef947be73a3aa5`)
> **Total Raw Lines**: 214 lines

---

<!-- TOC_START -->
## Table of Contents
- [Compiled Wiki Layers](#compiled-wiki-layers)
  - [Concepts](#concepts)
- [Source Content Topic Breakdown](#source-content-topic-breakdown)
- [Related Pages](#related-pages)
<!-- TOC_END -->

## Compiled Wiki Layers
### Concepts
- [[file-upload-attack-matrix]] — Enriched attack matrix incorporating multipart form structures, Content-Disposition, MIME spoofing, filename path traversal into non-executable directories, web server configuration overrides (`.htaccess`, `.user.ini`, `web.config`), extension obfuscation techniques (multiple extensions, trailing dots, semicolons, null bytes), polyglot JPEG construction via `exiftool`, HTTP PUT uploads, and complete defense standards.

## Source Content Topic Breakdown
1. **Root Causes**: Insufficient validation of file name, type, content, or size allowing arbitrary code execution or filesystem tampering.
2. **Web Server Static File Handlers**: Preconfigured mappings between extensions and execution handlers (`mod_php`, FastCGI, IIS ISAPI).
3. **Flawed Validation Exploitation**:
   - MIME type spoofing (`image/jpeg` header on PHP payload).
   - Filename path traversal (`filename="../exploit.php"` or `..%2fexploit.php`).
   - Server configuration file overrides (`.htaccess` with `AddType application/x-httpd-php .l33t`, `web.config` with custom MIME mappings).
   - Extension obfuscation: multiple extensions (`.php.jpg`), trailing dots/spaces (`.php.`), semicolons (`.asp;.jpg`), null-byte truncation (`.php%00.jpg`), and non-recursive stripping (`.p.phphp`).
   - Content validation & polyglots: embedding PHP web shells inside valid JPEG EXIF comment headers.
4. **Client-Side Attacks via File Upload**: HTML/SVG upload for Stored XSS, and XML-based document parsing for XXE injection.
5. **Defensive Standards**: Extension whitelisting, file renaming with random UUIDs, storing outside document root, and disabling execution permissions.

## Related Pages
- Parent Domain Hub: [[web-and-bug-bounty]]
- Target Concepts: [[file-upload-attack-matrix]], [[path-traversal-and-directory-traversal]], [[cross-site-scripting]]
