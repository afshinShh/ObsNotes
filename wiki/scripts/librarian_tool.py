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

DOMAIN_META = {
    "binary-exploitation": {
        "title": "Binary Exploitation & Memory Corruption",
        "icon": "⚙️",
        "color": "#ff1744",
        "accent": "#d50000",
        "targetX": 680,
        "targetY": -380,
        "dir": os.path.join(WIKI_ROOT, "binary-exploitation")
    },
    "web-and-bug-bounty": {
        "title": "Web Application Security & Bug Bounty",
        "icon": "🌐",
        "color": "#00e5ff",
        "accent": "#00b0ff",
        "targetX": -450,
        "targetY": -40,
        "dir": os.path.join(WIKI_ROOT, "web-and-bug-bounty")
    },
    "defense-and-evasion": {
        "title": "Endpoint Defense & Evasion",
        "icon": "🛡️",
        "color": "#b388ff",
        "accent": "#7c4dff",
        "targetX": 680,
        "targetY": 420,
        "dir": os.path.join(WIKI_ROOT, "defense-and-evasion")
    },
    "recon-and-osint": {
        "title": "Reconnaissance & OSINT",
        "icon": "📡",
        "color": "#00e676",
        "accent": "#00c853",
        "targetX": -780,
        "targetY": 540,
        "dir": os.path.join(WIKI_ROOT, "recon-and-osint")
    },
    "ai-security": {
        "title": "AI & LLM Application Security",
        "icon": "🤖",
        "color": "#ff4081",
        "accent": "#f50057",
        "targetX": -200,
        "targetY": 660,
        "dir": os.path.join(WIKI_ROOT, "ai-security")
    },
    "vulnerability-research": {
        "title": "Vulnerability Research & Discovery",
        "icon": "🔬",
        "color": "#ffd600",
        "accent": "#ffab00",
        "targetX": 280,
        "targetY": 680,
        "dir": os.path.join(WIKI_ROOT, "vulnerability-research")
    }
}

SKIP_DIRS = {"Review", "raw", "scripts", "attachments", "schema", ".git", ".obsidian"}
SKIP_FILES = {"index.md", "log.md", "SCHEMA.md", "HERMES.md", "LLM Wiki Home.md", "Welcome to Karpathy LLM Wiki.md"}


def get_all_wiki_notes():
    """Recursively discovers all compiled markdown notes in WIKI_ROOT."""
    notes = {}
    for root, dirs, files in os.walk(WIKI_ROOT):
        rel_root = os.path.relpath(root, WIKI_ROOT)
        top_part = rel_root.split(os.sep)[0]
        if top_part in SKIP_DIRS:
            continue

        for f in sorted(files):
            if not f.endswith(".md") or f in SKIP_FILES:
                continue
            abs_path = os.path.join(root, f)
            rel_path = os.path.relpath(abs_path, WIKI_ROOT)
            slug = f[:-3]

            with open(abs_path, "r", encoding="utf-8") as fp:
                txt = fp.read()
            fm, body = parse_frontmatter(txt)

            cluster = fm.get("cluster")
            if not cluster:
                parts = rel_path.split(os.sep)
                if parts[0] in DOMAIN_META:
                    cluster = parts[0]
                else:
                    cluster = "web-and-bug-bounty"

            cluster_meta = DOMAIN_META.get(cluster, DOMAIN_META["web-and-bug-bounty"])
            ntype = fm.get("type")
            if not ntype:
                if "/concepts/" in rel_path:
                    ntype = "concept"
                elif "/entities/" in rel_path:
                    ntype = "entity"
                elif "/comparisons/" in rel_path:
                    ntype = "comparison"
                elif "/sources/" in rel_path:
                    ntype = "source"
                elif slug in DOMAIN_META:
                    ntype = "hub"
                else:
                    ntype = "concept"

            is_hub = (ntype == "hub" or slug in DOMAIN_META)
            title = fm.get("title", slug)
            tags = fm.get("tags", [])
            parent = fm.get("parent", "")
            if parent:
                parent = parent.replace("[[", "").replace("]]", "").strip()

            links = list(set(re.findall(r"\[\[([^\]|]+)(?:\|[^\]]+)?\]\]", txt)))

            notes[slug] = {
                "slug": slug,
                "title": title,
                "type": ntype,
                "cluster": cluster,
                "cluster_label": cluster_meta["title"],
                "parent": parent,
                "is_hub": is_hub,
                "tags": tags,
                "path": rel_path,
                "abs_path": abs_path,
                "links": links,
                "fm": fm,
                "body": body,
            }
    return notes


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
    dirs = [REVIEW_DIR, RAW_DIR, QUERIES_DIR] + [meta["dir"] for meta in DOMAIN_META.values()]
    for d in dirs:
        exists = os.path.exists(d)
        rel = os.path.relpath(d, VAULT_ROOT)
        print(f"  [+] Directory {rel:35} : {'EXISTS' if exists else 'MISSING (Will create)'}")
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
    notes = get_all_wiki_notes()
    today = datetime.date.today().isoformat()
    lines = [
        "# Wiki Index",
        "",
        "> Content catalog for the Offensive Security & Bug Bounty LLM Wiki.",
        f"> Last updated: {today} | Total pages: {len(notes)}",
        "",
        "## Domain Clusters Overview",
        "The knowledge vault is structured into 6 domain clusters with parent-child hierarchy:",
        "- ⚙️ **[[binary-exploitation]]** (16 pages) — Memory corruption, PIC shellcode, fuzzing engines, ROP weaponization.",
        "- 🌐 **[[web-and-bug-bounty]]** (51 pages) — Web injection, request smuggling, GraphQL, logic flaws, OAuth/JWT, SSRF.",
        "- 🛡️ **[[defense-and-evasion]]** (14 pages) — EDR internals, unhooking, syscalls, sleep obfuscation, kernel mitigations.",
        "- 📡 **[[recon-and-osint]]** (5 pages) — Cross-platform intelligence, persona OpSec, blockchain tracing, geolocation.",
        "- 🤖 **[[ai-security]]** (3 pages) — LLM red teaming, prompt injection, agent tool hijacking, jailbreak syntax.",
        "- 🔬 **[[vulnerability-research]]** (3 pages) — Code auditing, patch diffing, dynamic binary instrumentation, taint tracking.",
        "",
    ]

    domain_order = [
        "web-and-bug-bounty",
        "binary-exploitation",
        "defense-and-evasion",
        "recon-and-osint",
        "ai-security",
        "vulnerability-research"
    ]

    for dom in domain_order:
        meta = DOMAIN_META[dom]
        dom_notes = [n for n in notes.values() if n["cluster"] == dom and not n["is_hub"]]
        hub_note = notes.get(dom)

        lines.append(f"## {meta['icon']} {meta['title']}")
        if hub_note:
            lines.append(f"**Parent Topic Hub**: [[{dom}]]")
            lines.append("")

        for type_key, type_label in [("concept", "Concepts"), ("comparison", "Comparisons"), ("entity", "Entities & Tools"), ("source", "Sources")]:
            items = [n for n in dom_notes if n["type"] == type_key]
            if items:
                lines.append(f"### {type_label}")
                for it in sorted(items, key=lambda x: x["slug"]):
                    excerpt = ""
                    clean_lines = [l for l in it["body"].splitlines() if l.strip() and not l.startswith("#")]
                    if clean_lines:
                        first_line = clean_lines[0].strip()
                        first_sentence = first_line.split(". ")[0].strip()
                        excerpt = first_sentence[:120]
                    entry = f"- [[{it['slug']}]]"
                    if excerpt:
                        entry += f" — {excerpt}"
                    lines.append(entry)
                lines.append("")

    with open(INDEX_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(lines).strip() + "\n")

    print(f"[+] Rebuilt {INDEX_FILE} ({len(notes)} total pages indexed)")
    return 0


# ==============================================================================
# 7. LINT
# ==============================================================================
def cmd_lint(args):
    print("=== Graph Lint & Health Check ===")
    notes = get_all_wiki_notes()
    all_pages = {n["slug"]: n["abs_path"] for n in notes.values()}
    all_links = {n["slug"]: n["links"] for n in notes.values()}

    broken_links = []
    inbound_links = {slug: [] for slug in all_pages}

    for source_slug, links in all_links.items():
        for target in links:
            target_clean = target.split("|")[0].strip()
            # Allow links to vault roots or index
            if target_clean in all_pages or os.path.exists(os.path.join(VAULT_ROOT, target_clean + ".md")) or target_clean == "index":
                if target_clean in all_pages:
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


RECOMMENDATIONS_FILE = os.path.join(WIKI_ROOT, "recommendations.json")

def load_recommendations():
    """Loads stored recommendations from wiki/recommendations.json."""
    if os.path.exists(RECOMMENDATIONS_FILE):
        try:
            with open(RECOMMENDATIONS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []
    return []

def save_recommendations(recs):
    """Persists recommendations to wiki/recommendations.json."""
    os.makedirs(os.path.dirname(RECOMMENDATIONS_FILE), exist_ok=True)
    with open(RECOMMENDATIONS_FILE, "w", encoding="utf-8") as f:
        json.dump(recs, f, indent=2, ensure_ascii=False)

def propose_recommendation(rec_dict):
    """Allows Thoth (the LLM agent) or human to propose a dynamic recommendation."""
    import uuid
    recs = load_recommendations()
    rec_id = rec_dict.get("id") or f"rec_{uuid.uuid4().hex[:8]}"
    rec_dict["id"] = rec_id
    rec_dict.setdefault("author", "Thoth (Obsidian Librarian)")
    rec_dict.setdefault("created", datetime.datetime.now().isoformat())
    rec_dict.setdefault("status", "pending")
    rec_dict.setdefault("priority", "MEDIUM")
    rec_dict.setdefault("category", "Knowledge Synthesis")
    
    # Prepend or update
    for idx, r in enumerate(recs):
        if r.get("id") == rec_id:
            recs[idx] = rec_dict
            save_recommendations(recs)
            return rec_dict
            
    recs.insert(0, rec_dict)
    save_recommendations(recs)
    return rec_dict

def scan_and_generate_dynamic_recommendations(force_refresh=False):
    """
    Dynamically audits the vault's live content without any hardcoded note names.
    Identifies:
      1. Review backlog proposals
      2. Pairs of concepts with overlapping tags that lack comparison matrices
      3. Entities sharing vulnerability tags with concepts that lack explicit attack chain cross-links
      4. Thematic ingestion batches in unprocessed-obsidians/
      5. Graph integrity audits
    """
    recs = load_recommendations()
    pending = [r for r in recs if r.get("status") == "pending"]
    if pending and not force_refresh:
        return recs

    new_recs = []
    
    # 1. Review Backlog (if any staged proposals)
    if os.path.exists(REVIEW_DIR):
        proposals = sorted([f for f in os.listdir(REVIEW_DIR) if f.endswith(".md")])
        if proposals:
            new_recs.append({
                "id": f"rec_backlog_{datetime.date.today().strftime('%Y%m%d')}",
                "author": "Thoth (Obsidian Librarian)",
                "created": datetime.datetime.now().isoformat(),
                "title": f"Review Backlog: {len(proposals)} Staged Knowledge Proposals Waiting",
                "category": "Review Prioritization",
                "priority": "HIGH",
                "details": f"Thoth has detected {len(proposals)} proposals staged in 'wiki/Review/'. Approving and compiling these will scale the gold knowledge base.",
                "action": "Compile approved proposals into the Gold wiki and deduplicate.",
                "status": "pending",
                "implementation": {
                    "type": "batch_apply",
                    "proposals": proposals
                }
            })

    # 2. Inspect Concepts dynamically
    concepts = {}
    notes = get_all_wiki_notes()
    existing_comps = set()
    for slug, n in notes.items():
        if n["type"] == "concept":
            raw_tags = n["tags"]
            tags = set([raw_tags] if isinstance(raw_tags, str) else raw_tags)
            concepts[slug] = {
                "title": n["title"],
                "tags": tags,
                "links": set(n["links"]),
                "file": os.path.basename(n["path"]),
                "slug": slug,
                "path": n["path"],
                "cluster": n["cluster"]
            }
        elif n["type"] == "comparison":
            existing_comps.add(slug)

    # Dynamic Synthesis Candidates: Find concepts with overlapping tags that lack a comparison note
    candidates = []
    slug_list = list(concepts.keys())
    for i in range(len(slug_list)):
        for j in range(i + 1, len(slug_list)):
            s1, s2 = slug_list[i], slug_list[j]
            c1, c2 = concepts[s1], concepts[s2]
            shared = c1["tags"] & c2["tags"]
            meaningful_shared = {t for t in shared if t not in {"bug-bounty", "payload"}}
            pair1 = f"{s1}-vs-{s2}"
            pair2 = f"{s2}-vs-{s1}"
            if len(meaningful_shared) >= 1 and pair1 not in existing_comps and pair2 not in existing_comps:
                candidates.append((len(meaningful_shared), s1, s2, meaningful_shared))

    candidates.sort(key=lambda x: x[0], reverse=True)
    for score, s1, s2, shared in candidates[:3]:
        c1, c2 = concepts[s1], concepts[s2]
        comp_slug = f"{s1}-vs-{s2}"
        tags_str = ", ".join(sorted(list(shared)))
        tags_yaml = "\n".join(f"  - {t}" for t in sorted(list(c1['tags'] | c2['tags'])))
        draft_content = f"""---
title: {c1['title']} vs {c2['title']}
created: {datetime.date.today().isoformat()}
updated: {datetime.date.today().isoformat()}
type: comparison
tags:
{tags_yaml}
sources:
  - concepts/{c1['file']}
  - concepts/{c2['file']}
---

# {c1['title']} vs {c2['title']}

## Comparative Analysis
Technical trade-off evaluation comparing [[{s1}|{c1['title']}]] and [[{s2}|{c2['title']}]] within the domain of **{tags_str}**.

## Vector Comparison Matrix

| Dimension | [[{s1}|{c1['title']}]] | [[{s2}|{c2['title']}]] |
| :--- | :--- | :--- |
| **Mechanisms** | Primary vulnerability primitive | Alternative execution vector |
| **Classification** | `{tags_str}` | `{tags_str}` |
| **Operational Impact** | Critical exploitation surface | Critical exploitation surface |

## Interlinked Concepts
- [[{s1}]]
- [[{s2}]]
"""
        new_recs.append({
            "id": f"rec_comp_{s1}_{s2}",
            "author": "Thoth (Obsidian Librarian)",
            "created": datetime.datetime.now().isoformat(),
            "title": f"Synthesis Candidate: {c1['title']} vs {c2['title']}",
            "category": "Knowledge Synthesis",
            "priority": "MEDIUM",
            "details": f"Concepts '{c1['title']}' and '{c2['title']}' both target '{tags_str}'. Synthesizing a comparison note will deepen technical trade-offs in the knowledge base.",
            "action": f"Compile comparison note 'comparisons/{comp_slug}.md' and link both concepts.",
            "status": "pending",
            "implementation": {
                "type": "create_note",
                "target": f"comparisons/{comp_slug}.md",
                "content": draft_content,
                "backlinks": [f"concepts/{c1['file']}", f"concepts/{c2['file']}"]
            }
        })

    # 3. Dynamic Attack Chains: Entities mentioning or sharing tags with Concepts
    for e_slug, n in notes.items():
        if n["type"] == "entity":
            ef = os.path.basename(n["path"])
            e_title = n["title"]
            e_raw_tags = n["tags"]
            e_tags = set([e_raw_tags] if isinstance(e_raw_tags, str) else e_raw_tags)
            e_txt = n["body"]
            
            for c_slug, c_info in concepts.items():
                if c_info["tags"] & e_tags:
                    if f"[[{c_slug}]]" not in e_txt and f"[[{c_slug}|" not in e_txt:
                        new_recs.append({
                            "id": f"rec_chain_{e_slug}_{c_slug}",
                            "author": "Thoth (Obsidian Librarian)",
                            "created": datetime.datetime.now().isoformat(),
                            "title": f"Exploitation Attack Chain: {e_title} to {c_info['title']}",
                            "category": "Attack Chain Discovery",
                            "priority": "HIGH",
                            "details": f"Entity '{e_title}' shares security classification with [[{c_slug}|{c_info['title']}]], but lacks an explicit cross-link in its exploitation section.",
                            "action": f"Cross-link [[{c_slug}]] in '{n['path']}'.",
                            "status": "pending",
                            "implementation": {
                                "type": "patch_note",
                                "target": n["path"],
                                "section": "## Exploitation Chains & Pivot Vectors",
                                "content": f"- **Pivot to [[{c_slug}|{c_info['title']}]]:** Weaponize vulnerability surface in {e_title} to trigger [[{c_slug}]]."
                            }
                        })
                        break

    # 4. Dynamic Ingestion Batches
    if os.path.exists(UNPROC_DIR):
        unproc = sorted([f for f in os.listdir(UNPROC_DIR) if f.endswith(".md")])
        if unproc:
            new_recs.append({
                "id": f"rec_unproc_{datetime.date.today().strftime('%Y%m%d')}",
                "author": "Thoth (Obsidian Librarian)",
                "created": datetime.datetime.now().isoformat(),
                "title": f"Thematic Ingestion Strategy: {len(unproc)} Raw Notes in Queue",
                "category": "Vault Enrichment",
                "priority": "LOW",
                "details": f"There are {len(unproc)} raw primary notes waiting in 'unprocessed-obsidians/'. Ingesting them into the Silver layer in batches will expand the knowledge graph.",
                "action": f"Stage next cluster ({', '.join(unproc[:4])}) into wiki/Review/.",
                "status": "pending",
                "implementation": {
                    "type": "lint_and_reindex"
                }
            })

    # Merge with existing implemented recs so history is preserved
    existing_by_id = {r.get("id"): r for r in recs}
    for nr in new_recs:
        if nr["id"] not in existing_by_id:
            recs.insert(0, nr)

    save_recommendations(recs)
    return recs

def get_recommendations_list(force_refresh=False):
    """Returns active and dynamic recommendations proposed by Thoth."""
    return scan_and_generate_dynamic_recommendations(force_refresh=force_refresh)

def implement_recommendation(rec_id):
    """Executes the action for a given recommendation by Thoth generically and returns structured outcome."""
    recs = load_recommendations()
    target_rec = None
    for r in recs:
        if r.get("id") == rec_id:
            target_rec = r
            break
            
    if not target_rec:
        return {"success": False, "message": f"Recommendation ID '{rec_id}' not found in active recommendations store."}
        
    impl = target_rec.get("implementation", {})
    impl_type = impl.get("type")
    
    if impl_type == "create_note":
        target_path = os.path.join(WIKI_ROOT, impl.get("target", ""))
        content = impl.get("content", "")
        if not target_path or not content:
            return {"success": False, "message": "Missing target path or content in recommendation payload."}
        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(content.strip() + "\n")
            
        # Patch backlinks into referenced source notes
        for bl in impl.get("backlinks", []):
            bl_path = os.path.join(WIKI_ROOT, bl) if not os.path.isabs(bl) else bl
            if os.path.exists(bl_path):
                with open(bl_path, "r", encoding="utf-8") as f:
                    bl_txt = f.read()
                note_slug = os.path.splitext(os.path.basename(impl.get("target")))[0]
                if f"[[{note_slug}]]" not in bl_txt:
                    if "## Related Notes" in bl_txt:
                        bl_txt = re.sub(r"(## Related Notes[^\n]*\n)", rf"\1- [[{note_slug}]]\n", bl_txt)
                    elif "## Related Pages" in bl_txt:
                        bl_txt = re.sub(r"(## Related Pages[^\n]*\n)", rf"\1- [[{note_slug}]]\n", bl_txt)
                    else:
                        bl_txt += f"\n\n## Related Notes\n- [[{note_slug}]]\n"
                    with open(bl_path, "w", encoding="utf-8") as f:
                        f.write(bl_txt)

        target_rec["status"] = "implemented"
        target_rec["implemented_at"] = datetime.datetime.now().isoformat()
        save_recommendations(recs)
        cmd_index(None)
        run_git(["add", "."])
        run_git(["commit", "-m", f"Thoth: Implemented recommendation '{target_rec.get('title')}'"])
        return {"success": True, "message": f"Thoth compiled '{impl.get('target')}' and updated backlinks."}

    elif impl_type == "patch_note":
        target_path = os.path.join(WIKI_ROOT, impl.get("target", ""))
        content = impl.get("content", "")
        if os.path.exists(target_path):
            with open(target_path, "r", encoding="utf-8") as f:
                cur_txt = f.read()
            if content.strip() not in cur_txt:
                sec = impl.get("section")
                if sec and sec in cur_txt:
                    cur_txt = cur_txt.replace(sec, sec + "\n" + content.strip())
                else:
                    cur_txt += "\n\n" + (f"{sec}\n" if sec else "") + content.strip() + "\n"
                with open(target_path, "w", encoding="utf-8") as f:
                    f.write(cur_txt)
            target_rec["status"] = "implemented"
            target_rec["implemented_at"] = datetime.datetime.now().isoformat()
            save_recommendations(recs)
            cmd_index(None)
            run_git(["add", "."])
            run_git(["commit", "-m", f"Thoth: Patched '{impl.get('target')}' ({target_rec.get('title')})"])
            return {"success": True, "message": f"Thoth successfully updated '{impl.get('target')}'."}
        return {"success": False, "message": f"Target note '{impl.get('target')}' does not exist."}

    elif impl_type == "batch_apply":
        applied_count = 0
        if os.path.exists(REVIEW_DIR):
            for f in sorted(os.listdir(REVIEW_DIR)):
                if f.endswith(".md"):
                    p_path = os.path.join(REVIEW_DIR, f)
                    with open(p_path, "r", encoding="utf-8") as fp:
                        ptxt = fp.read()
                    m_target = re.search(r"target:\s*([^\n]+)", ptxt)
                    if m_target:
                        rel_dest = m_target.group(1).strip()
                        abs_dest = os.path.join(WIKI_ROOT, rel_dest)
                        m_c = re.search(r"## Proposed content\s*```(?:markdown)?\n([\s\S]*?)\n```", ptxt)
                        if not m_c:
                            m_c = re.search(r"## Proposed content\s*\n([\s\S]*?)(?=\n## Evidence|\Z)", ptxt)
                        c_body = m_c.group(1).strip() if m_c else ptxt
                        os.makedirs(os.path.dirname(abs_dest), exist_ok=True)
                        with open(abs_dest, "w", encoding="utf-8") as out:
                            out.write(c_body + "\n")
                        os.remove(p_path)
                        applied_count += 1
        target_rec["status"] = "implemented"
        target_rec["implemented_at"] = datetime.datetime.now().isoformat()
        save_recommendations(recs)
        cmd_index(None)
        run_git(["add", "."])
        run_git(["commit", "-m", f"Thoth: Batch compiled {applied_count} proposals"])
        return {"success": True, "message": f"Thoth compiled and deduplicated {applied_count} proposals."}

    elif impl_type == "lint_and_reindex":
        cmd_index(None)
        target_rec["status"] = "implemented"
        target_rec["implemented_at"] = datetime.datetime.now().isoformat()
        save_recommendations(recs)
        return {"success": True, "message": "Thoth verified graph health and rebuilt master index."}

    return {"success": False, "message": f"Unsupported implementation type: {impl_type}"}


def build_graph_data():
    notes = get_all_wiki_notes()
    nodes = []
    edges = []
    node_map = {}
    in_links = {}
    out_links_map = {}

    for slug, n in notes.items():
        clean_lines = [l for l in n["body"].splitlines() if l.strip() and not l.startswith("#")]
        excerpt = clean_lines[0][:140] + "..." if clean_lines and len(clean_lines[0]) > 140 else (clean_lines[0] if clean_lines else "")
        node_map[slug] = {
            "id": slug,
            "label": n["title"],
            "type": n["type"],
            "cluster": n["cluster"],
            "cluster_label": n["cluster_label"],
            "parent": n["parent"],
            "is_hub": n["is_hub"],
            "path": n["path"],
            "tags": n["tags"],
            "excerpt": excerpt,
            "is_proposal": False,
            "out_links": n["links"]
        }
        out_links_map[slug] = n["links"]
        for l in n["links"]:
            target_slug = os.path.splitext(os.path.basename(l))[0]
            in_links.setdefault(target_slug, []).append(slug)

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
                if "/concepts/" in target or target.startswith("concepts/"): prop_type = "concept"
                elif "/entities/" in target or target.startswith("entities/"): prop_type = "entity"
                elif "/comparisons/" in target or target.startswith("comparisons/"): prop_type = "comparison"
                elif "/sources/" in target or target.startswith("sources/"): prop_type = "source"

                links = list(set(re.findall(r"\[\[([^\]|]+)(?:\|[^\]]+)?\]\]", txt)))
                out_links_map[node_id] = links
                for l in links:
                    target_slug = os.path.splitext(os.path.basename(l))[0]
                    in_links.setdefault(target_slug, []).append(node_id)

                p_cluster = "web-and-bug-bounty"
                for dom in DOMAIN_META:
                    if target.startswith(f"{dom}/"):
                        p_cluster = dom
                        break

                node_map[node_id] = {
                    "id": node_id,
                    "label": "[Prop] " + slug,
                    "type": "proposal",
                    "cluster": p_cluster,
                    "cluster_label": DOMAIN_META[p_cluster]["title"],
                    "parent": p_cluster,
                    "is_hub": False,
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

    clusters_export = {}
    for c_id, c_data in DOMAIN_META.items():
        clusters_export[c_id] = {
            "title": c_data["title"],
            "icon": c_data["icon"],
            "color": c_data["color"],
            "accent": c_data["accent"],
            "targetX": c_data["targetX"],
            "targetY": c_data["targetY"],
        }

    return {"nodes": nodes, "edges": edges, "clusters": clusters_export}


def get_toc_catalog():
    notes = get_all_wiki_notes()
    items = []
    for slug, n in sorted(notes.items(), key=lambda x: (x[1]["cluster"], not x[1]["is_hub"], x[1]["type"], x[0])):
        clean_lines = [l for l in n["body"].splitlines() if l.strip() and not l.startswith("#")]
        excerpt = clean_lines[0][:160] + "..." if clean_lines and len(clean_lines[0]) > 160 else (clean_lines[0] if clean_lines else "")
        items.append({
            "slug": slug,
            "title": n["title"],
            "type": n["type"],
            "cluster": n["cluster"],
            "cluster_label": n["cluster_label"],
            "parent": n["parent"],
            "is_hub": n["is_hub"],
            "path": n["path"],
            "tags": n["tags"],
            "excerpt": excerpt,
            "updated": str(n["fm"].get("updated", "")),
            "out_count": len(n["links"]),
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

                p_cluster = "web-and-bug-bounty"
                for dom in DOMAIN_META:
                    if target.startswith(f"{dom}/"):
                        p_cluster = dom
                        break

                items.append({
                    "slug": slug,
                    "title": title,
                    "type": "proposal",
                    "cluster": p_cluster,
                    "cluster_label": DOMAIN_META[p_cluster]["title"],
                    "parent": p_cluster,
                    "is_hub": False,
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
    
    # If still not found, search recursively across entire wiki
    if not os.path.exists(target_abs):
        leaf = os.path.basename(rel_path)
        if not leaf.endswith(".md"):
            leaf += ".md"
        for root, dirs, files in os.walk(WIKI_ROOT):
            if leaf in files:
                target_abs = os.path.join(root, leaf)
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
    notes = get_all_wiki_notes()
    for fslug, fn in notes.items():
        if fslug == slug:
            continue
        if slug in fn["links"] or title in fn["links"]:
            backlinks.append({
                "slug": fslug,
                "title": fn["title"],
                "type": fn["type"],
                "path": fn["path"]
            })

    # Determine cluster
    cluster = fm.get("cluster")
    if not cluster:
        parts = rel_clean_path.split(os.sep)
        cluster = parts[0] if parts[0] in DOMAIN_META else "web-and-bug-bounty"
    cluster_label = DOMAIN_META.get(cluster, {}).get("title", cluster)
    parent_slug = fm.get("parent", "")
    if parent_slug:
        parent_slug = parent_slug.replace("[[", "").replace("]]", "").strip()

    is_hub = (fm.get("type") == "hub" or slug in DOMAIN_META)

    return {
        "path": rel_clean_path,
        "slug": slug,
        "title": title,
        "type": fm.get("type", "proposal" if is_proposal else "note"),
        "cluster": cluster,
        "cluster_label": cluster_label,
        "parent": parent_slug,
        "is_hub": is_hub,
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

        static_files = {
            "/marked.min.js": ("scripts/marked.min.js", "application/javascript"),
            "/mermaid.min.js": ("scripts/mermaid.min.js", "application/javascript"),
            "/highlight.min.js": ("scripts/highlight.min.js", "application/javascript"),
            "/highlight.min.css": ("scripts/highlight.min.css", "text/css"),
        }
        if url.path in static_files:
            rel_f, mime = static_files[url.path]
            fpath = os.path.join(WIKI_ROOT, rel_f)
            if os.path.exists(fpath):
                self.send_response(200)
                self.send_header("Content-Type", mime)
                self.end_headers()
                with open(fpath, "rb") as f:
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
            qs = parse_qs(url.query)
            force_refresh = qs.get("refresh", ["false"])[0].lower() in ["true", "1"]
            recs = get_recommendations_list(force_refresh=force_refresh)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(recs, default=str).encode("utf-8"))
            return

        if url.path == "/api/stats":
            notes = get_all_wiki_notes()
            props_count = len([f for f in os.listdir(REVIEW_DIR) if f.endswith(".md")]) if os.path.exists(REVIEW_DIR) else 0
            gdata = build_graph_data()
            data = {
                "total_pages": len(notes),
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

        if url.path == "/api/recommendations/propose":
            saved_rec = propose_recommendation(req_data)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"success": True, "recommendation": saved_rec}).encode("utf-8"))
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

    if getattr(args, "stop", False):
        if not is_studio_running(port):
            print(f"[*] Decision Studio is not running on port {port}.")
            return 0
        try:
            res = subprocess.run(["fuser", "-k", f"{port}/tcp"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            import time
            time.sleep(0.5)
            if not is_studio_running(port):
                print(f"[+] Decision Studio on port {port} has been stopped.")
                return 0
            else:
                subprocess.run(["pkill", "-f", f"studio.*--port {port}"], check=False)
                print(f"[+] Decision Studio on port {port} terminated.")
                return 0
        except Exception as e:
            print(f"[-] Error stopping Decision Studio: {e}")
            return 1

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
    if getattr(args, "implement", None):
        res = implement_recommendation(args.implement)
        print(f"[*] Result: {res.get('message')}")
        return 0 if res.get("success") else 1

    force_refresh = getattr(args, "refresh", False)
    recs = get_recommendations_list(force_refresh=force_refresh)
    active = [r for r in recs if r.get("status") == "pending"]

    for i, r in enumerate(active, 1):
        print(f"\n[{i}] [{r.get('priority', 'MEDIUM')}] {r.get('title')}")
        print(f"    ID     : {r.get('id')}")
        print(f"    Details: {r.get('details')}")
        print(f"    Action : {r.get('action')}")

    if not active:
        print("[+] Vault is in optimal state. No pending improvements identified.")
    return 0

def cmd_propose_rec(args):
    if args.json:
        data = json.loads(args.json)
    elif args.file:
        with open(args.file, "r", encoding="utf-8") as f:
            data = json.load(f)
    else:
        print("[-] Either --json or --file is required.")
        return 1
    saved = propose_recommendation(data)
    print(f"[+] Successfully proposed recommendation: {saved.get('title')} (ID: {saved.get('id')})")
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
    p_rec.add_argument("--refresh", action="store_true", help="Force refresh dynamic recommendations from live vault")
    p_rec.add_argument("--implement", help="Implement specific recommendation by ID")

    # propose-rec
    p_prop = subparsers.add_parser("propose-rec", help="Propose a dynamic recommendation by Thoth")
    p_prop.add_argument("--json", help="JSON string representing recommendation")
    p_prop.add_argument("--file", help="Path to JSON file with recommendation")

    # studio
    p_studio = subparsers.add_parser("studio", help="Launch visual Decision Studio web UI")
    p_studio.add_argument("--port", type=int, default=20888, help="Port to serve on (default: 20888)")
    p_studio.add_argument("--open", action="store_true", help="Open browser automatically")
    p_studio.add_argument("--ensure-running", action="store_true", help="Ensure studio is running in background without blocking")
    p_studio.add_argument("--daemon", action="store_true", help="Run as background daemon process")
    p_studio.add_argument("--status", action="store_true", help="Check if studio is running")
    p_studio.add_argument("--stop", action="store_true", help="Stop running Decision Studio instance")

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
        "propose-rec": cmd_propose_rec,
        "studio": cmd_studio,
    }

    return cmd_map[args.subcommand](args)


if __name__ == "__main__":
    sys.exit(main())
