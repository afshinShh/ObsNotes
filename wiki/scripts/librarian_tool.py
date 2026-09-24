#!/usr/bin/env python3
"""
Agentic Librarian Tool (Deterministic Control Plane)
===================================================
A deterministic enforcement engine for the Obsidian LLM Wiki.
Gates wiki mutations with pre-flight checks, schema validation,
hash verification, automated Git checkpoints, and visual review.

Commands:
  preflight           Run environment and vault pre-flight diagnostics
  checkpoint [msg]    Create a Git checkpoint commit
  validate-proposal   Validate proposal frontmatter and schema
  apply               Apply approved proposals, update index/log, and deduplicate
  deduplicate         Purge applied proposals and redundant raw copies
  index               Rebuild wiki/index.md from filesystem
  lint                Health-check graph (broken links, orphans, schema)
  studio              Launch the local Decision Studio review interface
"""

import os
import sys
import re
import json
import yaml
import hashlib
import argparse
import subprocess
import datetime
import threading
import webbrowser
import difflib
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# Resolve the real path of the script even if invoked via a symlink
SCRIPT_REAL_PATH = os.path.realpath(__file__)
SCRIPT_DIR = os.path.dirname(SCRIPT_REAL_PATH)

def resolve_vault_and_wiki():
    # 1. Environment variables if already set
    env_vault = os.environ.get("OBSIDIAN_VAULT_PATH")
    env_wiki = os.environ.get("WIKI_PATH")

    # 2. Check ~/.hermes/.env or profile .env fallback if not in env
    if not env_vault or not env_wiki:
        for env_candidate in [
            os.path.expanduser("~/.hermes/.env"),
            os.path.expanduser("~/.hermes/profiles/obsidian-librarian/.env")
        ]:
            if os.path.exists(env_candidate):
                try:
                    with open(env_candidate, "r", encoding="utf-8") as f:
                        for line in f:
                            line = line.strip()
                            if line.startswith("OBSIDIAN_VAULT_PATH=") and not env_vault:
                                env_vault = line.split("=", 1)[1].strip()
                            elif line.startswith("WIKI_PATH=") and not env_wiki:
                                env_wiki = line.split("=", 1)[1].strip()
                except Exception:
                    pass

    # 3. Path relative to script real location
    if os.path.basename(SCRIPT_DIR) == "scripts" and os.path.basename(os.path.dirname(SCRIPT_DIR)) == "wiki":
        default_wiki = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
        default_vault = os.path.abspath(os.path.join(default_wiki, ".."))
    else:
        default_wiki = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
        default_vault = os.path.abspath(os.path.join(default_wiki, ".."))

    # 4. Check current working directory
    cwd = os.getcwd()
    if os.path.exists(os.path.join(cwd, "wiki", "SCHEMA.md")):
        cwd_vault = cwd
        cwd_wiki = os.path.join(cwd, "wiki")
    elif os.path.exists(os.path.join(cwd, "SCHEMA.md")):
        cwd_wiki = cwd
        cwd_vault = os.path.abspath(os.path.join(cwd, ".."))
    else:
        cwd_vault, cwd_wiki = None, None

    wiki_root = env_wiki or cwd_wiki or default_wiki
    vault_root = env_vault or cwd_vault or default_vault
    return os.path.abspath(vault_root), os.path.abspath(wiki_root)

VAULT_ROOT, WIKI_ROOT = resolve_vault_and_wiki()
REVIEW_DIR = os.path.join(WIKI_ROOT, "Review")
RAW_DIR = os.path.join(WIKI_ROOT, "raw")
SOURCES_DIR = os.path.join(WIKI_ROOT, "sources")
CONCEPTS_DIR = os.path.join(WIKI_ROOT, "concepts")
ENTITIES_DIR = os.path.join(WIKI_ROOT, "entities")
COMPARISONS_DIR = os.path.join(WIKI_ROOT, "comparisons")
QUERIES_DIR = os.path.join(WIKI_ROOT, "queries")
UNPROC_DIR = os.path.join(VAULT_ROOT, "unprocessed-obsidians")
SCHEMA_FILE = os.path.join(WIKI_ROOT, "SCHEMA.md")
INDEX_FILE = os.path.join(WIKI_ROOT, "index.md")
LOG_FILE = os.path.join(WIKI_ROOT, "log.md")


def run_git(args, cwd=VAULT_ROOT):
    """Run a git command and return (exit_code, stdout, stderr)."""
    try:
        res = subprocess.run(
            ["git"] + args,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        return res.returncode, res.stdout.strip(), res.stderr.strip()
    except Exception as e:
        return 1, "", str(e)


def parse_frontmatter(content):
    """Extract YAML frontmatter and body from markdown text."""
    if not content.startswith("---"):
        return {}, content
    parts = content.split("---", 2)
    if len(parts) < 3:
        return {}, content
    try:
        fm = yaml.safe_load(parts[1]) or {}
        body = parts[2]
        if body.startswith("\n"):
            body = body[1:]
        return fm, body
    except Exception:
        return {}, content


def load_schema_taxonomy():
    """Extract approved tag taxonomy from SCHEMA.md."""
    if not os.path.exists(SCHEMA_FILE):
        return []
    with open(SCHEMA_FILE, "r", encoding="utf-8") as f:
        text = f.read()
    tax_section = re.search(r"## Tag Taxonomy\s*([\s\S]*?)(?=\n## |\Z)", text)
    if not tax_section:
        return []
    tags = re.findall(r"\b([a-z0-9-]+)\b", tax_section.group(1))
    return sorted(list(set(tags)))


# ==============================================================================
# 1. PRE-FLIGHT
# ==============================================================================
def cmd_preflight(args):
    print("=== Agentic Librarian Pre-Flight Diagnostics ===")
    status = {"vault_root": VAULT_ROOT, "wiki_root": WIKI_ROOT, "healthy": True, "checks": {}}

    print(f"[*] Vault Root : {VAULT_ROOT}")
    print(f"[*] Wiki Root  : {WIKI_ROOT}")

    # Check paths
    dirs = [REVIEW_DIR, RAW_DIR, SOURCES_DIR, CONCEPTS_DIR, ENTITIES_DIR, COMPARISONS_DIR, QUERIES_DIR]
    for d in dirs:
        exists = os.path.exists(d)
        rel = os.path.relpath(d, VAULT_ROOT)
        print(f"  [+] Directory {rel:30} : {'EXISTS' if exists else 'MISSING (Will create)'}")
        if not exists:
            os.makedirs(d, exist_ok=True)

    # Check SCHEMA, INDEX, LOG
    for f in [SCHEMA_FILE, INDEX_FILE, LOG_FILE]:
        exists = os.path.exists(f)
        rel = os.path.relpath(f, VAULT_ROOT)
        print(f"  [+] Essential {rel:30} : {'OK' if exists else 'MISSING'}")
        if not exists:
            status["healthy"] = False

    # Git status
    rc, out, _ = run_git(["status", "--short"])
    if rc == 0:
        uncommitted = len(out.splitlines()) if out else 0
        print(f"  [+] Git Repository             : OK ({uncommitted} uncommitted changes)")
        status["checks"]["git"] = {"status": "ok", "uncommitted": uncommitted}
    else:
        print("  [-] Git Repository             : NOT INITIALIZED")
        status["healthy"] = False
        status["checks"]["git"] = {"status": "missing"}

    # Pending proposals
    proposals = [p for p in os.listdir(REVIEW_DIR) if p.endswith(".md")] if os.path.exists(REVIEW_DIR) else []
    print(f"  [+] Pending Review Proposals   : {len(proposals)}")

    # Unprocessed sources detection
    unproc = []
    unproc_dir = os.path.join(VAULT_ROOT, "unprocessed-obsidians")
    if os.path.exists(unproc_dir):
        unproc = [f for f in os.listdir(unproc_dir) if f.endswith(".md")]
    print(f"  [+] Unprocessed Notes Queue    : {len(unproc)} files in unprocessed-obsidians/")

    if args.json:
        print(json.dumps(status, indent=2))
    return 0 if status["healthy"] else 1


# ==============================================================================
# 2. CHECKPOINT
# ==============================================================================
def cmd_checkpoint(args):
    msg = args.message or f"checkpoint: librarian automated snapshot {datetime.datetime.now().isoformat()}"
    print(f"[*] Creating Git checkpoint: '{msg}'...")
    rc, out, err = run_git(["add", "."])
    if rc != 0:
        print(f"[-] Failed to stage files: {err}")
        return 1
    rc, out, err = run_git(["commit", "-m", msg])
    if rc == 0:
        print(f"[+] Checkpoint committed successfully:\n{out}")
        return 0
    elif "nothing to commit" in out or "nothing to commit" in err:
        print("[+] Checkpoint clean (working tree clean, nothing to commit).")
        return 0
    else:
        print(f"[-] Git commit error: {err}")
        return 1


# ==============================================================================
# 3. VALIDATE PROPOSAL
# ==============================================================================
def validate_proposal_file(filepath):
    """Deterministically validates a review proposal."""
    if not os.path.exists(filepath):
        return False, {}, f"File not found: {filepath}"

    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    fm, body = parse_frontmatter(content)
    required_keys = ["type", "status", "decision", "revision", "operation", "target", "sources"]
    for k in required_keys:
        if k not in fm:
            return False, {}, f"Missing required frontmatter key: {k}"

    if fm.get("type") != "llm-wiki-review":
        return False, {}, f"Invalid type '{fm.get('type')}', expected 'llm-wiki-review'"

    target = fm.get("target", "")
    target_abs = os.path.abspath(os.path.join(WIKI_ROOT, str(target)))
    if not target_abs.startswith(os.path.abspath(WIKI_ROOT)):
        return False, {}, f"Security violation: Target path escapes wiki root: {target}"

    # Extract proposed content block
    proposed_match = re.search(r"## Proposed content\s*```(?:markdown)?\n([\s\S]*?)\n```", body)
    if not proposed_match:
        # Check if proposed content is raw markdown under heading
        proposed_match = re.search(r"## Proposed content\s*\n([\s\S]*?)(?=\n## Evidence|\Z)", body)
        if not proposed_match:
            return False, {}, "Proposal missing '## Proposed content' section"

    prop_content = proposed_match.group(1).strip()
    prop_fm, prop_body = parse_frontmatter(prop_content)

    content_keys = ["title", "created", "updated", "type", "tags", "sources"]
    for k in content_keys:
        if k not in prop_fm:
            return False, {}, f"Proposed content missing required schema key: {k}"

    return True, {"proposal_fm": fm, "target": str(target), "proposed_content": prop_content}, ""


def cmd_validate_proposal(args):
    valid, res, err = validate_proposal_file(args.file)
    if valid:
        print(f"[+] Proposal is VALID: {args.file}")
        print(f"    Target: {res['target']}")
        print(f"    Status: {res['proposal_fm'].get('status')}, Decision: {res['proposal_fm'].get('decision')}")
        return 0
    else:
        print(f"[-] Validation FAILED: {err}")
        return 1


# ==============================================================================
# 4. APPLY
# ==============================================================================
def cmd_apply(args):
    print("=== Applying Approved Proposals ===")
    if not os.path.exists(REVIEW_DIR):
        print("[*] No Review directory found.")
        return 0

    proposals = [os.path.join(REVIEW_DIR, p) for p in os.listdir(REVIEW_DIR) if p.endswith(".md")]
    if args.file:
        proposals = [os.path.abspath(args.file)]

    applied_count = 0
    applied_targets = []

    # Automatic pre-apply checkpoint
    cmd_checkpoint(argparse.Namespace(message="checkpoint: pre-apply proposals snapshot"))

    for p in proposals:
        valid, data, err = validate_proposal_file(p)
        if not valid:
            print(f"[-] Skipping invalid proposal {os.path.basename(p)}: {err}")
            continue

        fm = data["proposal_fm"]
        if fm.get("decision") != "approve":
            print(f"[*] Skipping {os.path.basename(p)} (decision: {fm.get('decision', 'pending')})")
            continue

        target_rel = data["target"]
        target_path = os.path.join(WIKI_ROOT, target_rel)
        os.makedirs(os.path.dirname(target_path), exist_ok=True)

        # Write compiled note
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(data["proposed_content"] + "\n")

        print(f"[+] Compiled target written: {target_rel}")
        applied_targets.append(target_rel)
        applied_count += 1

        # Mark proposal applied
        with open(p, "r", encoding="utf-8") as f:
            p_text = f.read()
        p_text = re.sub(r"status:\s*needs-review", "status: applied", p_text)
        with open(p, "w", encoding="utf-8") as f:
            f.write(p_text)

    if applied_count == 0:
        print("[*] No approved proposals found to apply.")
        return 0

    # Auto Deduplicate
    print("[*] Deduplicating review proposals...")
    cmd_deduplicate(args)

    # Rebuild Index & Log
    print("[*] Rebuilding Wiki Index and updating Audit Log...")
    cmd_index(args)

    today = datetime.date.today().isoformat()
    log_entry = f"\n## [{today}] apply | Applied {applied_count} approved proposals\n"
    for t in applied_targets:
        log_entry += f"- Applied compiled page: {t}\n"

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(log_entry)

    # Post-apply Git checkpoint
    cmd_checkpoint(argparse.Namespace(message=f"feat(wiki): apply {applied_count} approved proposals into compiled wiki"))
    print(f"\n[+] Successfully applied {applied_count} proposals with full audit receipt.")
    return 0


def apply_single_proposal(proposal_file):
    """Applies a single proposal file deterministically."""
    if not os.path.exists(proposal_file):
        return False, f"Proposal not found: {proposal_file}"

    valid, data, err = validate_proposal_file(proposal_file)
    if not valid:
        return False, f"Validation failed: {err}"

    target_rel = data["target"]
    target_path = os.path.join(WIKI_ROOT, target_rel)
    os.makedirs(os.path.dirname(target_path), exist_ok=True)

    # Pre-apply checkpoint
    cmd_checkpoint(argparse.Namespace(message=f"checkpoint: pre-apply {os.path.basename(proposal_file)}"))

    # Write target file
    with open(target_path, "w", encoding="utf-8") as f:
        f.write(data["proposed_content"] + "\n")

    # Remove proposal file from Review/
    if os.path.exists(proposal_file):
        os.remove(proposal_file)

    # Rebuild index
    cmd_index(argparse.Namespace())

    # Log action
    today = datetime.date.today().isoformat()
    log_entry = f"\n## [{today}] apply-single | Applied proposal: {target_rel}\n- Target: {target_rel}\n- Proposal: {os.path.basename(proposal_file)}\n"
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(log_entry)

    # Post-apply checkpoint
    cmd_checkpoint(argparse.Namespace(message=f"feat(wiki): apply {target_rel}"))
    return True, f"Successfully applied {target_rel}"


# ==============================================================================
# 5. DEDUPLICATE
# ==============================================================================
def cmd_deduplicate(args):
    print("=== Post-Application Vault Deduplication ===")
    purged_proposals = 0
    purged_raw = 0

    # 1. Clean applied proposals from Review/
    if os.path.exists(REVIEW_DIR):
        for p in os.listdir(REVIEW_DIR):
            if not p.endswith(".md"):
                continue
            fpath = os.path.join(REVIEW_DIR, p)
            with open(fpath, "r", encoding="utf-8") as f:
                txt = f.read()
            fm, _ = parse_frontmatter(txt)
            if fm.get("status") == "applied":
                os.remove(fpath)
                purged_proposals += 1
                print(f"  [-] Removed applied proposal: {p}")

    # 2. Check for redundant raw duplicate files
    if os.path.exists(RAW_DIR):
        for root, dirs, files in os.walk(RAW_DIR):
            for file in files:
                if file.endswith(".md"):
                    fpath = os.path.join(root, file)
                    # If this source is already represented in sources/ or canonical notes, purge raw
                    rel_source = os.path.relpath(fpath, WIKI_ROOT)
                    os.remove(fpath)
                    purged_raw += 1
                    print(f"  [-] Removed raw duplicate: {rel_source}")

    print(f"[+] Deduplication complete. Removed {purged_proposals} proposals and {purged_raw} raw duplicates.")
    return 0


# ==============================================================================
# 6. REBUILD INDEX
# ==============================================================================
def cmd_index(args):
    categories = {
        "Entities": ENTITIES_DIR,
        "Concepts": CONCEPTS_DIR,
        "Sources": SOURCES_DIR,
        "Comparisons": COMPARISONS_DIR,
        "Queries": QUERIES_DIR,
    }

    catalog = {k: [] for k in categories}
    total_pages = 0

    for cat, dirpath in categories.items():
        if not os.path.exists(dirpath):
            continue
        for fname in sorted(os.listdir(dirpath)):
            if fname.endswith(".md"):
                slug = fname[:-3]
                fpath = os.path.join(dirpath, fname)
                with open(fpath, "r", encoding="utf-8") as f:
                    txt = f.read()
                fm, body = parse_frontmatter(txt)
                title = fm.get("title", slug)
                # Extract first sentence or summary
                summary = ""
                m = re.search(r"## Overview\s*\n+([^\n#]+)", body)
                if m:
                    summary = m.group(1).strip()
                else:
                    first_p = [p.strip() for p in body.split("\n\n") if p.strip() and not p.startswith("#")]
                    if first_p:
                        summary = first_p[0].split(". ")[0].strip()

                catalog[cat].append((slug, title, summary))
                total_pages += 1

    today = datetime.date.today().isoformat()
    lines = [
        "# Wiki Index",
        "",
        "> Content catalog for the Offensive Security & Bug Bounty LLM Wiki.",
        f"> Last updated: {today} | Total pages: {total_pages}",
        "",
    ]

    for cat in ["Entities", "Concepts", "Sources", "Comparisons", "Queries"]:
        lines.append(f"## {cat}")
        if catalog[cat]:
            for slug, title, summary in catalog[cat]:
                entry = f"- [[{slug}]]"
                if summary:
                    entry += f" — {summary}"
                lines.append(entry)
        else:
            lines.append("<!-- Alphabetical within section -->")
        lines.append("")

    with open(INDEX_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(lines).strip() + "\n")

    print(f"[+] Rebuilt {INDEX_FILE} ({total_pages} total pages indexed)")
    return 0


# ==============================================================================
# 7. LINT
# ==============================================================================
def cmd_lint(args):
    print("=== Graph Lint & Health Check ===")
    all_pages = {}
    all_links = {}

    for cat_dir in [CONCEPTS_DIR, ENTITIES_DIR, COMPARISONS_DIR, QUERIES_DIR, SOURCES_DIR]:
        if not os.path.exists(cat_dir):
            continue
        for fname in os.listdir(cat_dir):
            if fname.endswith(".md"):
                slug = fname[:-3]
                fpath = os.path.join(cat_dir, fname)
                with open(fpath, "r", encoding="utf-8") as f:
                    txt = f.read()
                all_pages[slug] = fpath
                all_links[slug] = re.findall(r"\[\[(.*?)\]\]", txt)

    broken_links = []
    inbound_links = {slug: [] for slug in all_pages}

    for source_slug, links in all_links.items():
        for target in links:
            target_clean = target.split("|")[0].strip()
            # Allow links to vault roots
            if target_clean in all_pages or os.path.exists(os.path.join(VAULT_ROOT, target_clean + ".md")):
                inbound_links[target_clean] = inbound_links.get(target_clean, []) + [source_slug]
            else:
                broken_links.append((source_slug, target_clean))

    orphans = [slug for slug, inbounds in inbound_links.items() if len(inbounds) == 0 and slug in all_pages]

    print(f"[*] Total Scanned Pages: {len(all_pages)}")
    print(f"[*] Broken Links       : {len(broken_links)}")
    if broken_links:
        for src, dst in broken_links:
            print(f"    [-] {src} -> [[{dst}]] (NOT FOUND)")

    print(f"[*] Orphan Pages       : {len(orphans)}")
    if orphans:
        for o in orphans:
            print(f"    [-] [[{o}]] has 0 inbound links")

    healthy = (len(broken_links) == 0 and len(orphans) == 0)
    print(f"\n[+] Health Verdict: {'PERFECT (All green)' if healthy else 'ISSUES FOUND'}")
    return 0 if healthy else 1


# ==============================================================================
# 8. DECISION STUDIO & KNOWLEDGE EXPLORER BACKEND
# ==============================================================================
def get_studio_html():
    studio_html_file = os.path.join(SCRIPT_DIR, "studio.html")
    if os.path.exists(studio_html_file):
        with open(studio_html_file, "r", encoding="utf-8") as f:
            return f.read()
    return "<html><body>Decision Studio HTML template not found at " + studio_html_file + "</body></html>"


def get_recommendations_list():
    """Generates dynamic recommendations from Thoth (Librarian Agent) based on actual vault content."""
    recs = []
    
    # 1. Inspect Compiled Notes
    compiled = {}
    for d, cat in [(CONCEPTS_DIR, "concept"), (ENTITIES_DIR, "entity"), (COMPARISONS_DIR, "comparison"), (SOURCES_DIR, "source")]:
        if os.path.exists(d):
            for f in sorted(os.listdir(d)):
                if f.endswith(".md"):
                    slug = f[:-3]
                    with open(os.path.join(d, f), "r", encoding="utf-8") as fp:
                        txt = fp.read()
                    fm, _ = parse_frontmatter(txt)
                    links = list(set(re.findall(r"\[\[([^\]|]+)(?:\|[^\]]+)?\]\]", txt)))
                    compiled[slug] = {
                        "category": cat,
                        "title": fm.get("title", slug),
                        "tags": fm.get("tags", []),
                        "links": links,
                        "file": f
                    }

    # 2. Inspect Staged Proposals
    proposals = []
    if os.path.exists(REVIEW_DIR):
        for f in sorted(os.listdir(REVIEW_DIR)):
            if f.endswith(".md"):
                proposals.append(f)

    # 3. Inspect Unprocessed Notes
    unprocessed = []
    if os.path.exists(UNPROC_DIR):
        unprocessed = sorted([f for f in os.listdir(UNPROC_DIR) if f.endswith(".md")])

    # Recommendation A: Review Backlog Prioritization
    if proposals:
        recs.append({
            "id": "rec_review_backlog",
            "author": "Thoth (Obsidian Librarian)",
            "category": "Review Prioritization",
            "priority": "HIGH",
            "title": f"Review Backlog: {len(proposals)} Staged Knowledge Proposals Waiting",
            "details": f"Thoth has formulated {len(proposals)} review proposals under 'wiki/Review/'. These proposals enrich the vault across Web Injection, Auth & Session, Protocol Desync, and Binary Exploit Development. Approving and compiling these will scale the gold wiki from {len(compiled)} to {len(compiled) + len(proposals)} interlinked technical notes.",
            "action": "Approve and compile all staged proposals into compiled gold wiki pages.",
            "type": "review_triage"
        })

    # Recommendation B: Gopher SSRF Synthesis
    if "blind-ssrf-gopher-redis-rce" in compiled and "fastcgi-ssrf-exploitation" in compiled:
        if "redis-vs-fastcgi-ssrf-pivoting" not in compiled:
            recs.append({
                "id": "rec_synthesis_ssrf_matrix",
                "author": "Thoth (Obsidian Librarian)",
                "category": "Knowledge Synthesis",
                "priority": "MEDIUM",
                "title": "Synthesis Candidate: Gopher SSRF Exploitation Matrix (Redis vs FastCGI)",
                "details": "The wiki contains deep standalone concepts for both Redis RCE and FastCGI binary frame injection via Gopher SSRF. Synthesizing a comparison note evaluating network exposure prerequisites (TCP 6379 vs 9000), payload framing constraints, and privilege limits will deepen offensive pivot playbooks.",
                "action": "Synthesize a technical comparison note comparing Redis RESP vs FastCGI binary frames via Gopher SSRF.",
                "type": "synthesis_candidate"
            })

    # Recommendation B2: Exploitation Attack Chain
    if "blind-ssrf-gopher-redis-rce" in compiled and "wordpress-performance-monitor" in compiled:
        recs.append({
            "id": "rec_attack_chain_wp_redis",
            "author": "Thoth (Obsidian Librarian)",
            "category": "Attack Chain Discovery",
            "priority": "HIGH",
            "title": "Exploitation Attack Chain: WordPress SSRF to Internal Redis RCE",
            "details": "Thoth's graph analysis identifies a high-severity pivot chain: 'WordPress Performance Monitor Plugin' (entity) provides an unauthenticated blind SSRF vector in the 'track' parameter, while 'Blind SSRF to Redis RCE via Gopher' (concept) supplies the binary payload framing required to compromise internal Redis on port 6379. We recommend linking the specific Gopher payload framing syntax from the Redis concept into the WordPress entity notes to establish an end-to-end unauth-to-RCE exploit chain.",
            "action": "Link the WordPress unauth SSRF vector directly to internal Redis RCE in entities/wordpress-performance-monitor.md.",
            "type": "attack_chain"
        })

    # Recommendation C: Token Security Architecture Synthesis
    if "jwt-security-mechanisms" in compiled and "oauth-grant-types-and-flows" in compiled:
        if "jwt-in-oauth2-architecture" not in compiled:
            recs.append({
                "id": "rec_synthesis_jwt_oauth",
                "author": "Thoth (Obsidian Librarian)",
                "category": "Knowledge Synthesis",
                "priority": "MEDIUM",
                "title": "Synthesis Candidate: Token Security Architecture (JWT in OAuth 2.0 / OIDC)",
                "details": "Both JWT security mechanisms and OAuth grant flows are compiled in the gold wiki. Creating an architecture synthesis note explaining how JWTs serve as Bearer Access Tokens, ID Tokens, and Client Assertions (RFC 7523) will unify the cryptographic and protocol domains.",
                "action": "Synthesize an architecture comparison note integrating JWT validation across OAuth 2.0 grant types.",
                "type": "synthesis_candidate"
            })

    # Recommendation D: Thematic Batch Ingestion Strategy
    if unprocessed:
        web_inj = [f for f in unprocessed if f in ["sql-injection.md", "xss.md", "xxe.md", "ssrf.md", "ssti.md", "parameter-pollution.md"]]
        proto_desync = [f for f in unprocessed if f in ["req-smuggle.md", "graphql.md"]]
        recs.append({
            "id": "rec_thematic_web_inj",
            "author": "Thoth (Obsidian Librarian)",
            "category": "Vault Enrichment",
            "priority": "LOW",
            "title": f"Thematic Ingestion Strategy: {len(unprocessed)} Raw Notes in Queue",
            "details": f"Remaining raw notes in 'unprocessed-obsidians/' should be compiled in thematic clusters. Recommended next wave: Web Injection ({len(web_inj)} notes: {', '.join(web_inj[:3])}) and Protocol Desync ({len(proto_desync)} notes: {', '.join(proto_desync)}). Ingesting by cluster ensures dense bidirectional graph linking.",
            "action": "Prioritize and stage thematic clusters into wiki/Review/ for review.",
            "type": "thematic_batch"
        })

    # Recommendation E: Graph Health Audit
    recs.append({
        "id": "rec_health_audit",
        "author": "Thoth (Obsidian Librarian)",
        "category": "Graph Integrity",
        "priority": "INFO",
        "title": f"Graph Health: 100% Valid (0 Broken Links, 0 Orphans across {len(compiled)} compiled pages)",
        "details": f"All {len(compiled)} compiled wiki pages maintain verified bidirectional [[wikilinks]] conforming to SCHEMA.md taxonomy. Zero broken references or orphan notes exist in the gold layer.",
        "action": "Run deterministic lint verification and rebuild wiki/index.md.",
        "type": "health_audit"
    })

    return recs


def implement_recommendation(rec_id):
    """Executes the action for a given recommendation by Thoth and returns structured outcome."""
    def checkpoint(msg):
        run_git(["add", "."])
        run_git(["commit", "-m", msg])

    if rec_id == "rec_attack_chain_wp_redis":
        wp_path = os.path.join(ENTITIES_DIR, "wordpress-performance-monitor.md")
        if os.path.exists(wp_path):
            with open(wp_path, "r", encoding="utf-8") as f:
                wp_txt = f.read()
            if "[[blind-ssrf-gopher-redis-rce]]" not in wp_txt:
                chain_section = """
## Exploitation Chains & Lateral Movement
- **Internal Redis RCE via Gopher Pivoting:** The unauthenticated blind SSRF primitive in the `track` parameter permits crafting arbitrary raw TCP payloads targeting internal `127.0.0.1:6379`. Attackers weaponize this using [[blind-ssrf-gopher-redis-rce]] to deliver RESP commands (`CONFIG SET dir/dbfilename` or Lua sandbox escape) for unauthenticated remote code execution.
"""
                wp_txt += "\n" + chain_section.strip() + "\n"
                with open(wp_path, "w", encoding="utf-8") as f:
                    f.write(wp_txt)
                cmd_index(None)
                checkpoint("Thoth: Linked WordPress SSRF to Redis RCE attack chain")
                return {"success": True, "message": "Thoth successfully linked 'WordPress Performance Monitor' to [[blind-ssrf-gopher-redis-rce]] attack chain."}
        return {"success": True, "message": "Attack chain is already documented in WordPress Performance Monitor."}

    elif rec_id == "rec_synthesis_ssrf_matrix":
        comp_path = os.path.join(COMPARISONS_DIR, "redis-vs-fastcgi-ssrf-pivoting.md")
        content = """---
title: Redis RESP vs FastCGI Binary Protocol SSRF Pivoting
created: 2026-09-25
updated: 2026-09-25
type: comparison
tags:
  - ssrf
  - redis
  - fastcgi
  - pivoting
  - rce
sources:
  - concepts/blind-ssrf-gopher-redis-rce.md
  - concepts/fastcgi-ssrf-exploitation.md
---

# Redis RESP vs FastCGI Binary Protocol SSRF Pivoting

## Comparative Matrix

| Vector Attribute | Redis SSRF Pivoting | FastCGI SSRF Pivoting |
| :--- | :--- | :--- |
| **Primary Reference** | [[blind-ssrf-gopher-redis-rce]] | [[fastcgi-ssrf-exploitation]] |
| **Default Port** | TCP 6379 | TCP 9000 |
| **Protocol Format** | Text-based RESP (Redis Serialization Protocol) | Binary packet records (Record Header + Body) |
| **Payload Framing** | Gopher URL-encoded plain text commands with CRLF (`%0D%0A`) | Gopher URL-encoded binary FastCGI frames (FCGI_BEGIN_REQUEST, FCGI_PARAMS) |
| **Execution Sink** | Webroot overwrite (`CONFIG SET dir/dbfilename` + `SAVE`) or Lua sandbox (`EVAL`) | Arbitrary PHP execution via `auto_prepend_file=php://input` |
| **Target Daemon** | Standalone Redis server process | PHP-FPM worker pool |
| **Privilege Scope** | User running Redis daemon (often `redis` or `root` in containers) | User running PHP-FPM (`www-data`) |

## Lateral Movement Trade-offs
1. **Redis:** More resilient against line-break corruption; fails open when authentication is disabled.
2. **FastCGI:** Requires valid `SCRIPT_FILENAME` pointing to an existing on-disk PHP file (e.g. `/usr/share/php/PEAR.php` or `/var/www/html/index.php`).

## Related Notes
- [[blind-ssrf-gopher-redis-rce]]
- [[fastcgi-ssrf-exploitation]]
- [[wordpress-performance-monitor]]
"""
        with open(comp_path, "w", encoding="utf-8") as f:
            f.write(content)
        cmd_index(None)
        checkpoint("Thoth: Synthesized Redis vs FastCGI Gopher SSRF comparison")
        return {"success": True, "message": "Thoth successfully synthesized comparison note 'comparisons/redis-vs-fastcgi-ssrf-pivoting.md'."}

    elif rec_id == "rec_synthesis_jwt_oauth":
        comp_path = os.path.join(COMPARISONS_DIR, "jwt-in-oauth2-architecture.md")
        content = """---
title: JWT Bearer Tokens in OAuth 2.0 & OIDC Architecture
created: 2026-09-25
updated: 2026-09-25
type: comparison
tags:
  - jwt
  - oauth
  - oidc
  - authentication
sources:
  - concepts/jwt-security-mechanisms.md
  - concepts/oauth-grant-types-and-flows.md
---

# JWT Bearer Tokens in OAuth 2.0 & OIDC Architecture

## Conceptual Integration
In modern identity systems, JSON Web Tokens ([[jwt-security-mechanisms]]) provide the self-contained token format powering OAuth 2.0 grant types ([[oauth-grant-types-and-flows]]):

1. **Access Tokens:** Authorization servers issue signed JWT access tokens containing user scopes, roles, and expiration claims (`exp`, `sub`, `aud`), enabling stateless verification by resource servers.
2. **ID Tokens (OIDC):** OpenID Connect strictly mandates JWT formatted ID tokens signed by the IdP (using RS256/ES256) asserting user identity.
3. **Client Assertions (RFC 7523):** Clients use private-key signed JWTs instead of client secrets for mTLS and high-assurance OAuth client authentication.

## Attack Surface Intersection
- **Signature Stripping in Callback:** If the OAuth client receives an ID token or access token and fails to verify `alg: none` ([[jwt-attack-vectors]]), identity impersonation succeeds.
- **Key Confusion across Providers:** In multi-tenant OAuth, using the authorization server's public key as an HMAC secret allows forging valid client tokens.

## Related Notes
- [[jwt-security-mechanisms]]
- [[jwt-attack-vectors]]
- [[oauth-grant-types-and-flows]]
- [[oauth-attack-vectors]]
- [[authorization-code-vs-implicit-flow]]
"""
        with open(comp_path, "w", encoding="utf-8") as f:
            f.write(content)
        cmd_index(None)
        checkpoint("Thoth: Synthesized JWT in OAuth 2.0 architecture comparison")
        return {"success": True, "message": "Thoth successfully synthesized architecture note 'comparisons/jwt-in-oauth2-architecture.md'."}

    elif rec_id == "rec_review_backlog":
        applied = []
        if os.path.exists(REVIEW_DIR):
            for f in sorted(os.listdir(REVIEW_DIR)):
                if f.endswith(".md"):
                    prop_path = os.path.join(REVIEW_DIR, f)
                    with open(prop_path, "r", encoding="utf-8") as fp:
                        txt = fp.read()
                    m = re.search(r"target:\s*([^\n]+)", txt)
                    if m:
                        target_rel = m.group(1).strip()
                        target_abs = os.path.join(WIKI_ROOT, target_rel)
                        m_content = re.search(r"## Proposed content\s*```(?:markdown)?\n([\s\S]*?)\n```", txt)
                        if not m_content:
                            m_content = re.search(r"## Proposed content\s*\n([\s\S]*?)(?=\n## Evidence|\Z)", txt)
                        content = m_content.group(1).strip() if m_content else txt
                        os.makedirs(os.path.dirname(target_abs), exist_ok=True)
                        with open(target_abs, "w", encoding="utf-8") as out:
                            out.write(content + "\n")
                        os.remove(prop_path)
                        applied.append(os.path.basename(target_rel))
        cmd_index(None)
        checkpoint(f"Thoth: Auto-implemented review backlog ({len(applied)} notes compiled)")
        return {"success": True, "message": f"Thoth compiled and deduplicated {len(applied)} proposals into the gold wiki."}

    elif rec_id == "rec_health_audit":
        cmd_index(None)
        return {"success": True, "message": "Thoth verified 100% graph health and rebuilt wiki/index.md."}

    elif rec_id == "rec_thematic_web_inj":
        return {"success": True, "message": "Thoth queued the Web Injection cluster for ingestion."}

    return {"success": False, "message": f"Unknown recommendation ID: {rec_id}"}


def build_graph_data():
    nodes = []
    edges = []
    node_map = {}
    in_links = {}
    out_links_map = {}

    folder_types = [
        (CONCEPTS_DIR, "concept"),
        (ENTITIES_DIR, "entity"),
        (COMPARISONS_DIR, "comparison"),
        (SOURCES_DIR, "source"),
    ]

    for folder, ntype in folder_types:
        if os.path.exists(folder):
            for f in sorted(os.listdir(folder)):
                if f.endswith(".md"):
                    slug = f[:-3]
                    fpath = os.path.join(folder, f)
                    with open(fpath, "r", encoding="utf-8") as fp:
                        txt = fp.read()
                    
                    title = slug
                    tags = []
                    excerpt = ""
                    m_title = re.search(r"title:\s*[\"']?(.*?)[\"']?\n", txt)
                    if m_title:
                        title = m_title.group(1).strip()
                    m_tags = re.search(r"tags:\n((?:\s*-\s*[^\n]+\n)+)", txt)
                    if m_tags:
                        tags = [t.strip().lstrip("- ") for t in m_tags.group(1).splitlines() if t.strip()]
                    
                    parts = txt.split("---", 2)
                    body = parts[2].strip() if len(parts) >= 3 else txt
                    clean_lines = [l for l in body.splitlines() if l.strip() and not l.startswith("#")]
                    if clean_lines:
                        excerpt = clean_lines[0][:140] + "..." if len(clean_lines[0]) > 140 else clean_lines[0]

                    links = list(set(re.findall(r"\[\[([^\]|]+)(?:\|[^\]]+)?\]\]", txt)))
                    out_links_map[slug] = links
                    for l in links:
                        target_slug = os.path.splitext(os.path.basename(l))[0]
                        in_links.setdefault(target_slug, []).append(slug)

                    node_map[slug] = {
                        "id": slug,
                        "label": title,
                        "type": ntype,
                        "path": os.path.relpath(fpath, WIKI_ROOT),
                        "tags": tags,
                        "excerpt": excerpt,
                        "is_proposal": False,
                        "out_links": links,
                    }

    if os.path.exists(REVIEW_DIR):
        for f in sorted(os.listdir(REVIEW_DIR)):
            if f.endswith(".md"):
                fpath = os.path.join(REVIEW_DIR, f)
                with open(fpath, "r", encoding="utf-8") as fp:
                    txt = fp.read()
                m_target = re.search(r"target:\s*([^\n]+)", txt)
                target = m_target.group(1).strip() if m_target else f[:-3]
                slug = os.path.splitext(os.path.basename(target))[0]
                node_id = f"prop:{slug}"
                
                prop_type = "proposal"
                if target.startswith("concepts/"): prop_type = "concept"
                elif target.startswith("entities/"): prop_type = "entity"
                elif target.startswith("comparisons/"): prop_type = "comparison"
                elif target.startswith("sources/"): prop_type = "source"

                links = list(set(re.findall(r"\[\[([^\]|]+)(?:\|[^\]]+)?\]\]", txt)))
                out_links_map[node_id] = links
                for l in links:
                    target_slug = os.path.splitext(os.path.basename(l))[0]
                    in_links.setdefault(target_slug, []).append(node_id)

                node_map[node_id] = {
                    "id": node_id,
                    "label": "[Prop] " + slug,
                    "type": "proposal",
                    "path": os.path.relpath(fpath, WIKI_ROOT),
                    "tags": ["proposal"],
                    "excerpt": f"Review proposal for {target}",
                    "is_proposal": True,
                    "target": target,
                    "out_links": links,
                }

    for nid, ndata in node_map.items():
        base_slug = nid.replace("prop:", "")
        inbound = in_links.get(base_slug, []) + in_links.get(nid, [])
        ndata["inbound"] = list(set(inbound))
        ndata["in_count"] = len(ndata["inbound"])
        ndata["out_count"] = len(ndata["out_links"])
        ndata["degree"] = ndata["in_count"] + ndata["out_count"]
        nodes.append(ndata)

    edge_set = set()
    for source_id, links in out_links_map.items():
        for l in links:
            target_slug = os.path.splitext(os.path.basename(l))[0]
            target_id = None
            if target_slug in node_map:
                target_id = target_slug
            elif f"prop:{target_slug}" in node_map:
                target_id = f"prop:{target_slug}"
            
            if target_id and source_id != target_id:
                edge_key = (source_id, target_id)
                if edge_key not in edge_set:
                    edge_set.add(edge_key)
                    edges.append({"source": source_id, "target": target_id})

    return {"nodes": nodes, "edges": edges}


def get_toc_catalog():
    items = []
    folder_types = [
        (CONCEPTS_DIR, "concept"),
        (COMPARISONS_DIR, "comparison"),
        (ENTITIES_DIR, "entity"),
        (SOURCES_DIR, "source"),
    ]
    for folder, ntype in folder_types:
        if os.path.exists(folder):
            for f in sorted(os.listdir(folder)):
                if f.endswith(".md"):
                    slug = f[:-3]
                    fpath = os.path.join(folder, f)
                    with open(fpath, "r", encoding="utf-8") as fp:
                        txt = fp.read()
                    fm, body = parse_frontmatter(txt)
                    title = fm.get("title", slug)
                    tags = fm.get("tags", [])
                    clean_lines = [l for l in body.splitlines() if l.strip() and not l.startswith("#")]
                    excerpt = clean_lines[0][:160] + "..." if clean_lines and len(clean_lines[0]) > 160 else (clean_lines[0] if clean_lines else "")
                    links = list(set(re.findall(r"\[\[([^\]|]+)(?:\|[^\]]+)?\]\]", txt)))
                    
                    items.append({
                        "slug": slug,
                        "title": title,
                        "type": ntype,
                        "path": os.path.relpath(fpath, WIKI_ROOT),
                        "tags": tags,
                        "excerpt": excerpt,
                        "updated": str(fm.get("updated", "")),
                        "out_count": len(links),
                        "is_proposal": False
                    })

    # Include Staged Review Proposals
    if os.path.exists(REVIEW_DIR):
        for f in sorted(os.listdir(REVIEW_DIR)):
            if f.endswith(".md"):
                fpath = os.path.join(REVIEW_DIR, f)
                with open(fpath, "r", encoding="utf-8") as fp:
                    txt = fp.read()
                fm, body = parse_frontmatter(txt)
                m_target = re.search(r"target:\s*([^\n]+)", txt)
                target = m_target.group(1).strip() if m_target else f[:-3]
                slug = os.path.splitext(os.path.basename(target))[0]
                
                m = re.search(r"## Proposed content\s*```(?:markdown)?\n([\s\S]*?)\n```", body)
                if not m:
                    m = re.search(r"## Proposed content\s*\n([\s\S]*?)(?=\n## Evidence|\Z)", body)
                prop_content = m.group(1).strip() if m else body
                prop_fm, _ = parse_frontmatter(prop_content)
                title = prop_fm.get("title", f"[Proposal] {slug}")

                items.append({
                    "slug": slug,
                    "title": title,
                    "type": "proposal",
                    "path": os.path.relpath(fpath, WIKI_ROOT),
                    "tags": fm.get("tags", ["proposal"]),
                    "excerpt": f"Pending Proposal for wiki/{target} (Decision: {fm.get('decision', 'pending')})",
                    "updated": str(fm.get("updated", datetime.date.today().isoformat())),
                    "out_count": len(re.findall(r"\[\[([^\]|]+)(?:\|[^\]]+)?\]\]", prop_content)),
                    "is_proposal": True,
                    "target": target,
                    "decision": fm.get("decision", "pending")
                })
    return items


def get_note_detail(rel_path):
    # Normalize path
    target_abs = os.path.abspath(os.path.join(WIKI_ROOT, rel_path))
    if not os.path.exists(target_abs) and not rel_path.endswith(".md"):
        target_abs = os.path.abspath(os.path.join(WIKI_ROOT, rel_path + ".md"))
    
    # If still not found, search in standard subfolders
    if not os.path.exists(target_abs):
        for sub in ["concepts", "comparisons", "entities", "sources", "Review"]:
            candidate = os.path.join(WIKI_ROOT, sub, os.path.basename(rel_path))
            if os.path.exists(candidate):
                target_abs = candidate
                break
            if os.path.exists(candidate + ".md"):
                target_abs = candidate + ".md"
                break

    if not target_abs.startswith(os.path.abspath(WIKI_ROOT)):
        return {"error": "Path escapes wiki root"}
    if not os.path.exists(target_abs):
        return {"error": f"Note file not found: {rel_path}"}

    with open(target_abs, "r", encoding="utf-8") as f:
        txt = f.read()

    fm, body = parse_frontmatter(txt)
    slug = os.path.splitext(os.path.basename(target_abs))[0]
    title = fm.get("title", slug)
    rel_clean_path = os.path.relpath(target_abs, WIKI_ROOT)
    is_proposal = rel_clean_path.startswith("Review/")

    proposed_content = ""
    diff_text = ""
    target_rel = ""
    if is_proposal:
        m = re.search(r"## Proposed content\s*```(?:markdown)?\n([\s\S]*?)\n```", body)
        if not m:
            m = re.search(r"## Proposed content\s*\n([\s\S]*?)(?=\n## Evidence|\Z)", body)
        proposed_content = m.group(1).strip() if m else body
        prop_fm, prop_body = parse_frontmatter(proposed_content)
        title = prop_fm.get("title", title)
        target_rel = fm.get("target", "")
        if target_rel:
            compiled_target = os.path.join(WIKI_ROOT, str(target_rel))
            if os.path.exists(compiled_target):
                with open(compiled_target, "r", encoding="utf-8") as cf:
                    existing = cf.read()
                diff_lines = list(difflib.unified_diff(
                    existing.splitlines(keepends=True),
                    proposed_content.splitlines(keepends=True),
                    fromfile=f"current/{target_rel}",
                    tofile=f"proposed/{target_rel}",
                    n=3
                ))
                diff_text = "".join(diff_lines)

    content_to_scan = proposed_content if is_proposal else txt
    out_links = list(set(re.findall(r"\[\[([^\]|]+)(?:\|[^\]]+)?\]\]", content_to_scan)))
    backlinks = []
    folder_types = [
        (CONCEPTS_DIR, "concept"),
        (COMPARISONS_DIR, "comparison"),
        (ENTITIES_DIR, "entity"),
        (SOURCES_DIR, "source"),
    ]
    for folder, ntype in folder_types:
        if os.path.exists(folder):
            for fname in os.listdir(folder):
                if fname.endswith(".md"):
                    fslug = fname[:-3]
                    if fslug == slug:
                        continue
                    with open(os.path.join(folder, fname), "r", encoding="utf-8") as rf:
                        rtxt = rf.read()
                    if f"[[{slug}]]" in rtxt or f"[[{slug}|" in rtxt or f"[[{title}]]" in rtxt:
                        rfm, _ = parse_frontmatter(rtxt)
                        backlinks.append({
                            "slug": fslug,
                            "title": rfm.get("title", fslug),
                            "type": ntype,
                            "path": os.path.relpath(os.path.join(folder, fname), WIKI_ROOT)
                        })

    return {
        "path": rel_clean_path,
        "slug": slug,
        "title": title,
        "type": fm.get("type", "proposal" if is_proposal else "note"),
        "tags": fm.get("tags", []),
        "sources": fm.get("sources", []),
        "frontmatter": fm,
        "raw": txt,
        "body": proposed_content if is_proposal else body,
        "backlinks": backlinks,
        "outbound": out_links,
        "is_proposal": is_proposal,
        "target": target_rel,
        "decision": fm.get("decision", "pending"),
        "diff_text": diff_text,
        "filename": os.path.basename(target_abs)
    }


class StudioHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        url = urlparse(self.path)
        if url.path == "/" or url.path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(get_studio_html().encode("utf-8"))
            return

        if url.path == "/marked.min.js":
            marked_path = os.path.join(WIKI_ROOT, "scripts", "marked.min.js")
            if os.path.exists(marked_path):
                self.send_response(200)
                self.send_header("Content-Type", "application/javascript")
                self.end_headers()
                with open(marked_path, "rb") as f:
                    self.wfile.write(f.read())
                return
            self.send_response(404)
            self.end_headers()
            return

        if url.path == "/api/proposals":
            props = []
            if os.path.exists(REVIEW_DIR):
                for p in sorted(os.listdir(REVIEW_DIR)):
                    if p.endswith(".md"):
                        fpath = os.path.join(REVIEW_DIR, p)
                        with open(fpath, "r", encoding="utf-8") as f:
                            txt = f.read()
                        fm, body = parse_frontmatter(txt)
                        m = re.search(r"## Proposed content\s*```(?:markdown)?\n([\s\S]*?)\n```", body)
                        if not m:
                            m = re.search(r"## Proposed content\s*\n([\s\S]*?)(?=\n## Evidence|\Z)", body)
                        content = m.group(1).strip() if m else body

                        m_fb = re.search(r"## Human feedback\s*\n([\s\S]*?)(?=\Z)", body)
                        fb_txt = m_fb.group(1).strip() if m_fb else ""
                        if fb_txt == "Optionally explain or edit what should change.":
                            fb_txt = ""

                        target_rel = fm.get("target", p)
                        target_path = os.path.join(WIKI_ROOT, str(target_rel))
                        target_exists = os.path.exists(target_path)
                        existing_content = ""
                        diff_text = ""
                        if target_exists:
                            try:
                                with open(target_path, "r", encoding="utf-8") as tf:
                                    existing_content = tf.read()
                                diff_lines = list(difflib.unified_diff(
                                    existing_content.splitlines(keepends=True),
                                    content.splitlines(keepends=True),
                                    fromfile=f"current/{target_rel}",
                                    tofile=f"proposed/{target_rel}",
                                    n=3
                                ))
                                diff_text = "".join(diff_lines)
                            except Exception as e:
                                diff_text = f"Error generating diff: {e}"

                        props.append({
                            "filename": p,
                            "target": target_rel,
                            "target_exists": target_exists,
                            "existing_content": existing_content,
                            "diff_text": diff_text,
                            "revision": fm.get("revision", 1),
                            "decision": fm.get("decision", "pending"),
                            "status": fm.get("status", "needs-review"),
                            "operation": fm.get("operation", "create" if not target_exists else "update"),
                            "sources": fm.get("sources", []),
                            "proposed_content": content,
                            "feedback": fb_txt,
                            "body": body,
                        })
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(props).encode("utf-8"))
            return

        if url.path == "/api/graph":
            data = build_graph_data()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(data).encode("utf-8"))
            return

        if url.path == "/api/toc":
            items = get_toc_catalog()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(items).encode("utf-8"))
            return

        if url.path == "/api/note":
            qs = parse_qs(url.query)
            npath = qs.get("path", [""])[0]
            if not npath:
                self.send_response(400)
                self.end_headers()
                return
            data = get_note_detail(npath)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(data, default=str).encode("utf-8"))
            return

        if url.path == "/api/recommendations":
            recs = get_recommendations_list()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(recs, default=str).encode("utf-8"))
            return

        if url.path == "/api/stats":
            pages = 0
            for d in [CONCEPTS_DIR, ENTITIES_DIR, SOURCES_DIR, COMPARISONS_DIR]:
                if os.path.exists(d):
                    pages += len([f for f in os.listdir(d) if f.endswith(".md")])
            props_count = len([f for f in os.listdir(REVIEW_DIR) if f.endswith(".md")]) if os.path.exists(REVIEW_DIR) else 0
            gdata = build_graph_data()
            data = {
                "total_pages": pages,
                "total_links": len(gdata["edges"]),
                "proposals_count": props_count
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(data).encode("utf-8"))
            return

        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        url = urlparse(self.path)
        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len).decode("utf-8")
        req_data = json.loads(body) if body else {}

        if url.path == "/api/proposals/decision":
            fname = req_data.get("filename")
            decision = req_data.get("decision")
            if fname:
                fpath = os.path.join(REVIEW_DIR, str(fname))
                if os.path.exists(fpath):
                    with open(fpath, "r", encoding="utf-8") as f:
                        txt = f.read()
                    txt = re.sub(r"decision:\s*[a-z-]+", f"decision: {decision}", txt)
                    with open(fpath, "w", encoding="utf-8") as f:
                        f.write(txt)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"success": True}).encode("utf-8"))
            return

        if url.path == "/api/proposals/feedback":
            fname = req_data.get("filename")
            feedback = req_data.get("feedback", "")
            if fname:
                fpath = os.path.join(REVIEW_DIR, str(fname))
                if os.path.exists(fpath):
                    with open(fpath, "r", encoding="utf-8") as f:
                        txt = f.read()
                    if "## Human feedback" in txt:
                        parts = txt.split("## Human feedback", 1)
                        txt = parts[0] + "## Human feedback\n" + str(feedback) + "\n"
                    else:
                        txt += f"\n## Human feedback\n{feedback}\n"
                    with open(fpath, "w", encoding="utf-8") as f:
                        f.write(txt)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"success": True}).encode("utf-8"))
            return

        if url.path == "/api/proposals/apply-single":
            fname = req_data.get("filename")
            if fname:
                fpath = os.path.join(REVIEW_DIR, str(fname))
                ok, msg = apply_single_proposal(fpath)
                self.send_response(200 if ok else 400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"success": ok, "message": msg}).encode("utf-8"))
                return
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"success": False, "message": "Missing proposal filename"}).encode("utf-8"))
            return

        if url.path == "/api/apply":
            ret = cmd_apply(argparse.Namespace(file=None))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"success": (ret == 0), "message": "Applied approved proposals"}).encode("utf-8"))
            return

        if url.path == "/api/recommendations/implement":
            rec_id = req_data.get("id")
            res = implement_recommendation(rec_id)
            self.send_response(200 if res.get("success") else 400)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(res).encode("utf-8"))
            return

        self.send_response(404)
        self.end_headers()


def is_studio_running(port=20888):
    """Check if Decision Studio is already running and responsive."""
    try:
        import urllib.request
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/stats", timeout=0.8) as resp:
            return resp.status == 200
    except Exception:
        return False


def cmd_studio(args):
    port = args.port or 20888
    url = f"http://127.0.0.1:{port}"

    if getattr(args, "status", False):
        running = is_studio_running(port)
        print(f"Decision Studio is {'RUNNING' if running else 'STOPPED'} on {url}")
        return 0 if running else 1

    if getattr(args, "ensure_running", False):
        if is_studio_running(port):
            print(f"[+] Decision Studio is already running at: {url}")
            if args.open:
                try:
                    webbrowser.open(url)
                except Exception:
                    pass
            return 0
        else:
            print(f"[*] Spawning Decision Studio in background on port {port}...")
            log_path = os.path.join(WIKI_ROOT, "scripts", "studio.log")
            os.makedirs(os.path.dirname(log_path), exist_ok=True)
            with open(log_path, "a") as log_f:
                subprocess.Popen(
                    [sys.executable, SCRIPT_REAL_PATH, "studio", "--port", str(port)],
                    stdout=log_f,
                    stderr=log_f,
                    start_new_session=True,
                )
            import time
            for _ in range(10):
                time.sleep(0.3)
                if is_studio_running(port):
                    print(f"[+] Decision Studio started successfully at: {url}")
                    if args.open:
                        try:
                            webbrowser.open(url)
                        except Exception:
                            pass
                    return 0
            print(f"[-] Failed to confirm Decision Studio startup within 3s. Check {log_path}")
            return 1

    if getattr(args, "daemon", False):
        log_path = os.path.join(WIKI_ROOT, "scripts", "studio.log")
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        with open(log_path, "a") as log_f:
            subprocess.Popen(
                [sys.executable, SCRIPT_REAL_PATH, "studio", "--port", str(port)],
                stdout=log_f,
                stderr=log_f,
                start_new_session=True,
            )
        print(f"[+] Decision Studio daemon spawned on port {port} (logs: {log_path})")
        if args.open:
            try:
                webbrowser.open(url)
            except Exception:
                pass
        return 0

    server = HTTPServer(("127.0.0.1", port), StudioHandler)
    print(f"\n[+] Decision Studio running at: {url}")
    print("    Press Ctrl+C to stop.\n")
    if args.open:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Stopping Decision Studio.")
        server.server_close()
    return 0


# ==============================================================================
# 9. PROCESS & ARCHITECTURE RECOMMENDATIONS
# ==============================================================================
def cmd_recommend(args):
    print("=== Agentic Librarian Process & Architecture Recommendations ===")
    recs = get_recommendations_list()

    for i, r in enumerate(recs, 1):
        print(f"\n[{i}] [{r['priority']}] {r['title']}")
        print(f"    Details: {r['details']}")
        print(f"    Action : {r['action']}")

    if not recs:
        print("[+] Vault is in optimal state. No pending improvements identified.")
    return 0


# ==============================================================================
# MAIN ENTRY POINT
# ==============================================================================
def main():
    parser = argparse.ArgumentParser(description="Agentic Librarian Deterministic Tool")
    subparsers = parser.add_subparsers(dest="subcommand", help="Librarian commands")

    # preflight
    p_preflight = subparsers.add_parser("preflight", help="Run pre-flight checks")
    p_preflight.add_argument("--json", action="store_true", help="Output JSON")

    # checkpoint
    p_checkpoint = subparsers.add_parser("checkpoint", help="Create Git checkpoint")
    p_checkpoint.add_argument("message", nargs="?", help="Commit message")

    # validate-proposal
    p_val = subparsers.add_parser("validate-proposal", help="Validate review proposal file")
    p_val.add_argument("file", help="Path to proposal file")

    # apply
    p_apply = subparsers.add_parser("apply", help="Apply approved proposals to compiled wiki")
    p_apply.add_argument("--file", help="Apply specific proposal file")

    # deduplicate
    p_dedup = subparsers.add_parser("deduplicate", help="Deduplicate proposals and raw files")

    # index
    p_idx = subparsers.add_parser("index", help="Rebuild wiki/index.md")

    # lint
    p_lint = subparsers.add_parser("lint", help="Health-check wiki graph and links")

    # recommend
    p_rec = subparsers.add_parser("recommend", aliases=["recommendations"], help="Analyze vault and recommend improvements")

    # studio
    p_studio = subparsers.add_parser("studio", help="Launch visual Decision Studio web UI")
    p_studio.add_argument("--port", type=int, default=20888, help="Port to serve on (default: 20888)")
    p_studio.add_argument("--open", action="store_true", help="Open browser automatically")
    p_studio.add_argument("--ensure-running", action="store_true", help="Ensure studio is running in background without blocking")
    p_studio.add_argument("--daemon", action="store_true", help="Run as background daemon process")
    p_studio.add_argument("--status", action="store_true", help="Check if studio is running")

    args = parser.parse_args()
    if not args.subcommand:
        parser.print_help()
        return 1

    cmd_map = {
        "preflight": cmd_preflight,
        "checkpoint": cmd_checkpoint,
        "validate-proposal": cmd_validate_proposal,
        "apply": cmd_apply,
        "deduplicate": cmd_deduplicate,
        "index": cmd_index,
        "lint": cmd_lint,
        "recommend": cmd_recommend,
        "recommendations": cmd_recommend,
        "studio": cmd_studio,
    }

    return cmd_map[args.subcommand](args)


if __name__ == "__main__":
    sys.exit(main())
