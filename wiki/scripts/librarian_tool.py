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
# 8. DECISION STUDIO (Web Review UI)
# ==============================================================================
STUDIO_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Agentic Librarian — Decision Studio</title>
  <script src="/marked.min.js"></script>
  <style>
    :root {
      --bg: #1a1a20;
      --sidebar-bg: #141418;
      --card-bg: #22222b;
      --card-hover: #2c2c37;
      --accent: #7c4dff;
      --accent-hover: #966eff;
      --text: #e0e0e8;
      --muted: #9e9ea8;
      --border: #323240;
      --success: #00c853;
      --danger: #ff5252;
      --warn: #ffd600;
      --blue: #40c4ff;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
    body { background: var(--bg); color: var(--text); display: flex; height: 100vh; overflow: hidden; }
    #sidebar { width: 400px; border-right: 1px solid var(--border); display: flex; flex-direction: column; background: var(--sidebar-bg); }
    #header { padding: 16px 18px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; }
    #header h2 { font-size: 1.05rem; color: #fff; display: flex; align-items: center; gap: 8px; }
    #stats { padding: 10px 18px; background: rgba(124, 77, 255, 0.08); border-bottom: 1px solid var(--border); font-size: 0.8rem; color: var(--muted); display: flex; justify-content: space-between; }
    #proposals-list { flex: 1; overflow-y: auto; padding: 12px; }
    
    .proposal-card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; padding: 12px 14px; margin-bottom: 10px; cursor: pointer; transition: all 0.15s; }
    .proposal-card:hover { border-color: var(--accent); background: var(--card-hover); }
    .proposal-card.active { border-color: var(--accent); background: #2f2f3d; }
    .card-title { font-weight: 600; font-size: 0.92rem; margin-bottom: 6px; color: #fff; word-break: break-all; }
    .card-meta { font-size: 0.78rem; color: var(--muted); display: flex; justify-content: space-between; align-items: center; }
    .card-actions { display: flex; gap: 6px; margin-top: 8px; border-top: 1px solid rgba(255,255,255,0.06); padding-top: 8px; }
    .card-btn { padding: 3px 8px; font-size: 0.75rem; border-radius: 4px; border: none; cursor: pointer; font-weight: 600; transition: 0.1s; }
    
    .badge { padding: 2px 7px; border-radius: 10px; font-size: 0.72rem; font-weight: bold; text-transform: uppercase; }
    .badge-pending { background: #3e381e; color: var(--warn); }
    .badge-approve { background: #1b3d27; color: var(--success); }
    .badge-reject { background: #3d1b1b; color: var(--danger); }
    .badge-applied { background: #1a237e; color: #82b1ff; }
    .badge-op-new { background: rgba(0, 200, 83, 0.15); color: #00e676; }
    .badge-op-update { background: rgba(64, 196, 255, 0.15); color: #40c4ff; }

    #main { flex: 1; display: flex; flex-direction: column; background: var(--bg); overflow: hidden; }
    #toolbar { padding: 12px 24px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; background: #1f1f26; }
    .toolbar-left { display: flex; align-items: center; gap: 8px; }
    .btn-group { display: flex; gap: 8px; align-items: center; }
    button { padding: 7px 14px; border: none; border-radius: 6px; font-weight: 600; cursor: pointer; transition: 0.15s; font-size: 0.82rem; }
    .btn-approve { background: var(--success); color: #000; }
    .btn-approve:hover { filter: brightness(1.15); }
    .btn-reject { background: var(--danger); color: #fff; }
    .btn-apply-one { background: var(--blue); color: #000; }
    .btn-apply-one:hover { filter: brightness(1.15); }
    .btn-apply-all { background: var(--accent); color: #fff; }
    .btn-apply-all:hover { background: var(--accent-hover); }

    #tab-bar { display: none; background: #18181f; border-bottom: 1px solid var(--border); padding: 0 24px; }
    .tab { padding: 10px 16px; font-size: 0.85rem; font-weight: 600; color: var(--muted); cursor: pointer; border-bottom: 2px solid transparent; transition: 0.15s; }
    .tab:hover { color: #fff; }
    .tab.active { color: #fff; border-bottom-color: var(--accent); }

    #content-view { flex: 1; overflow-y: auto; padding: 24px 30px; }
    
    .markdown-body { color: #e0e0e8; line-height: 1.6; font-size: 0.95rem; }
    .markdown-body h1 { font-size: 1.6rem; color: #fff; margin: 18px 0 10px; border-bottom: 1px solid var(--border); padding-bottom: 6px; }
    .markdown-body h2 { font-size: 1.3rem; color: #fff; margin: 18px 0 10px; border-bottom: 1px solid var(--border); padding-bottom: 6px; }
    .markdown-body h3 { font-size: 1.1rem; color: #fff; margin: 14px 0 8px; }
    .markdown-body p { margin-bottom: 12px; }
    .markdown-body ul, .markdown-body ol { margin-left: 22px; margin-bottom: 14px; }
    .markdown-body li { margin-bottom: 4px; }
    .markdown-body table { width: 100%; border-collapse: collapse; margin-bottom: 16px; }
    .markdown-body th, .markdown-body td { border: 1px solid var(--border); padding: 8px 12px; text-align: left; }
    .markdown-body th { background: #23232c; color: #fff; font-weight: 600; }
    .markdown-body tr:nth-child(even) { background: rgba(255,255,255,0.02); }
    .markdown-body code { background: #131318; padding: 2px 6px; border-radius: 4px; color: #ff80ab; font-size: 0.88em; font-family: monospace; }
    .markdown-body pre { background: #131318; padding: 14px; border-radius: 6px; border: 1px solid var(--border); overflow-x: auto; margin-bottom: 14px; }
    .markdown-body pre code { background: transparent; padding: 0; color: #b0bec5; }
    .markdown-body blockquote { border-left: 4px solid var(--accent); padding-left: 14px; color: var(--muted); margin-bottom: 14px; }
    .wikilink { background: rgba(124, 77, 255, 0.16); color: #b388ff; padding: 2px 6px; border-radius: 4px; font-weight: 500; font-family: monospace; }

    .diff-box { background: #111115; border: 1px solid var(--border); border-radius: 8px; padding: 14px; font-family: monospace; font-size: 0.85rem; line-height: 1.45; overflow-x: auto; }
    .diff-line { white-space: pre-wrap; padding: 1px 6px; }
    .diff-add { background: rgba(0, 200, 83, 0.18); color: #00e676; }
    .diff-del { background: rgba(255, 82, 82, 0.18); color: #ff5252; }
    .diff-hunk { background: rgba(124, 77, 255, 0.2); color: #80d8ff; font-weight: bold; }
    .diff-ctx { color: #888894; }
    .banner { padding: 10px 14px; border-radius: 6px; margin-bottom: 14px; font-size: 0.85rem; font-weight: 500; }
    .banner-new { background: rgba(0, 200, 83, 0.1); border: 1px solid var(--success); color: #00e676; }
    .banner-update { background: rgba(64, 196, 255, 0.1); border: 1px solid var(--blue); color: #40c4ff; }

    .feedback-box { margin-top: 24px; background: #1f1f26; padding: 16px; border-radius: 8px; border: 1px solid var(--border); }
    textarea { width: 100%; height: 75px; background: #141418; border: 1px solid var(--border); border-radius: 6px; color: #fff; padding: 10px; margin-top: 8px; resize: vertical; }
  </style>
</head>
<body>
  <div id="sidebar">
    <div id="header">
      <h2>🧠 Decision Studio</h2>
      <button class="btn-apply-all" onclick="applyAll()">⚡ Apply Approved</button>
    </div>
    <div id="stats">
      <span>Pending: <b id="stat-pending">0</b></span>
      <span>Wiki Pages: <b id="stat-pages">0</b></span>
      <span>Health: <b id="stat-health" style="color:var(--success)">OK</b></span>
    </div>
    <div id="proposals-list">Loading proposals...</div>
  </div>
  <div id="main">
    <div id="toolbar">
      <div class="toolbar-left" id="active-title" style="font-weight: 600; font-size: 1.05rem; color: #fff;">Select a Proposal</div>
      <div class="btn-group" id="actions" style="display:none;">
        <button class="btn-approve" onclick="setDecision('approve')">✓ Approve</button>
        <button class="btn-reject" onclick="setDecision('reject')">✕ Reject</button>
        <button class="btn-apply-one" onclick="applyThis()">⚡ Apply This Proposal</button>
      </div>
    </div>
    <div id="tab-bar">
      <div class="tab active" data-tab="preview" onclick="switchTab('preview')">📖 Rendered Preview</div>
      <div class="tab" data-tab="diff" onclick="switchTab('diff')">🔍 File Diff / Changes</div>
      <div class="tab" data-tab="raw" onclick="switchTab('raw')">📝 Raw Markdown</div>
    </div>
    <div id="content-view">
      <div style="color: var(--muted); text-align: center; margin-top: 100px;">
        <h3>No Proposal Selected</h3>
        <p style="margin-top: 8px;">Select a proposal from the left panel to review parsed content, diffs, and grant approval.</p>
      </div>
    </div>
  </div>

  <script>
    let proposals = [];
    let activeProposal = null;
    let currentTab = 'preview';

    async function loadData(keepActive=false) {
      const res = await fetch('/api/proposals');
      proposals = await res.json();
      const statsRes = await fetch('/api/stats');
      const stats = await statsRes.json();

      document.getElementById('stat-pending').innerText = proposals.filter(p => p.decision === 'pending').length;
      document.getElementById('stat-pages').innerText = stats.total_pages;

      const list = document.getElementById('proposals-list');
      if (proposals.length === 0) {
        list.innerHTML = '<div style="color:var(--muted); text-align:center; padding:20px;">No pending proposals in Review/</div>';
        if (!keepActive) {
          document.getElementById('active-title').innerText = 'No Proposals';
          document.getElementById('actions').style.display = 'none';
          document.getElementById('tab-bar').style.display = 'none';
          document.getElementById('content-view').innerHTML = '<div style="color:var(--muted); text-align:center; margin-top:100px;"><h3>All caught up!</h3><p style="margin-top:8px;">No pending proposals in Review/</p></div>';
          activeProposal = null;
        }
        return;
      }

      list.innerHTML = proposals.map((p, idx) => `
        <div class="proposal-card ${activeProposal && activeProposal.filename === p.filename ? 'active' : ''}" onclick="selectProposal(${idx})">
          <div class="card-title">${escapeHtml(p.target)}</div>
          <div class="card-meta">
            <span class="badge ${p.target_exists ? 'badge-op-update' : 'badge-op-new'}">${p.target_exists ? '🔄 Update' : '✨ New'}</span>
            <span class="badge badge-${p.decision}">${p.decision}</span>
          </div>
          <div class="card-actions" onclick="event.stopPropagation()">
            <button class="card-btn" style="background:var(--success); color:#000;" title="Approve" onclick="setCardDecision('${escapeHtml(p.filename)}', 'approve')">✓ Approve</button>
            <button class="card-btn" style="background:var(--danger); color:#fff;" title="Reject" onclick="setCardDecision('${escapeHtml(p.filename)}', 'reject')">✕ Reject</button>
            <button class="card-btn" style="background:var(--blue); color:#000;" title="Apply this proposal now" onclick="applySingleProposal('${escapeHtml(p.filename)}')">⚡ Apply</button>
          </div>
        </div>
      `).join('');

      if (keepActive && activeProposal) {
        const found = proposals.find(p => p.filename === activeProposal.filename);
        if (found) {
          activeProposal = found;
          renderProposal();
        }
      } else if (!activeProposal && proposals.length > 0) {
        selectProposal(0);
      }
    }

    function selectProposal(idx) {
      activeProposal = proposals[idx];
      renderProposal();
    }

    function renderProposal() {
      if (!activeProposal) return;
      document.getElementById('active-title').innerHTML = `
        <span>${escapeHtml(activeProposal.target)}</span>
        <span class="badge ${activeProposal.target_exists ? 'badge-op-update' : 'badge-op-new'}" style="margin-left:8px;">${activeProposal.target_exists ? 'Update' : 'New File'}</span>
        <span class="badge badge-${activeProposal.decision}" style="margin-left:4px;">${activeProposal.decision}</span>
      `;
      document.getElementById('actions').style.display = 'flex';
      document.getElementById('tab-bar').style.display = 'flex';

      const view = document.getElementById('content-view');
      let mainContentHtml = '';

      if (currentTab === 'preview') {
        const rendered = renderMarkdown(activeProposal.proposed_content || activeProposal.body);
        mainContentHtml = `<div class="markdown-body">${rendered}</div>`;
      } else if (currentTab === 'diff') {
        if (activeProposal.target_exists) {
          mainContentHtml = `
            <div class="banner banner-update">🔄 Comparing existing file <code>${escapeHtml(activeProposal.target)}</code> with proposal</div>
            <div class="diff-box">${renderDiff(activeProposal.diff_text)}</div>
          `;
        } else {
          mainContentHtml = `
            <div class="banner banner-new">✨ New File — will be created at <code>wiki/${escapeHtml(activeProposal.target)}</code></div>
            <div class="diff-box">${renderDiff(activeProposal.proposed_content.split('\\n').map(l => '+' + l).join('\\n'))}</div>
          `;
        }
      } else if (currentTab === 'raw') {
        mainContentHtml = `<pre style="background:#131318; padding:16px; border-radius:8px; border:1px solid var(--border); overflow-x:auto; color:#b0bec5; font-size:0.88rem; line-height:1.5;">${escapeHtml(activeProposal.proposed_content || activeProposal.body)}</pre>`;
      }

      view.innerHTML = `
        <div style="margin-bottom:14px; font-size:0.85rem; color:var(--muted);">
          Source notes: <code>${escapeHtml(activeProposal.sources.join(', '))}</code>
        </div>
        ${mainContentHtml}
        <div class="feedback-box">
          <h4 style="color:#fff; font-size:0.9rem;">Human Feedback / Instructions:</h4>
          <textarea id="feedback-input" placeholder="Type instructions or revisions for the agent...">${escapeHtml(activeProposal.feedback || '')}</textarea>
          <button style="margin-top:8px; background:var(--border); color:#fff;" onclick="saveFeedback()">Save Feedback</button>
        </div>
      `;

      const cards = document.querySelectorAll('.proposal-card');
      cards.forEach((c, i) => {
        if (proposals[i] && proposals[i].filename === activeProposal.filename) {
          c.classList.add('active');
        } else {
          c.classList.remove('active');
        }
      });
    }

    function switchTab(tab) {
      currentTab = tab;
      document.querySelectorAll('.tab').forEach(t => {
        t.classList.toggle('active', t.getAttribute('data-tab') === tab);
      });
      renderProposal();
    }

    function renderMarkdown(md) {
      if (!md) return '';
      let frontmatterHtml = '';
      let bodyMd = md;

      if (md.startsWith('---')) {
        const parts = md.split('---');
        if (parts.length >= 3) {
          const fmLines = parts[1].trim().split('\\n');
          const meta = {};
          fmLines.forEach(l => {
            const colon = l.indexOf(':');
            if (colon !== -1) {
              const k = l.substring(0, colon).trim();
              const v = l.substring(colon + 1).trim();
              if (k && !k.startsWith('#')) meta[k] = v;
            }
          });
          bodyMd = parts.slice(2).join('---').trim();
          
          frontmatterHtml = `
            <div style="background:#202028; border:1px solid var(--border); border-radius:6px; padding:12px 16px; margin-bottom:18px; font-size:0.83rem;">
              <div style="display:flex; flex-wrap:wrap; gap:12px; color:var(--muted);">
                ${Object.entries(meta).map(([k, v]) => `<div><strong style="color:#fff;">${escapeHtml(k)}:</strong> <span style="color:#b388ff;">${escapeHtml(v)}</span></div>`).join('')}
              </div>
            </div>
          `;
        }
      }

      let text = bodyMd.replace(/\\[\\[([^\\]|]+)(?:\\|([^\\]]+))?\\]\\]/g, (match, target, alias) => {
        return `<span class="wikilink">[[${alias || target}]]</span>`;
      });
      let parsed = '';
      if (window.marked && window.marked.parse) {
        try {
          parsed = marked.parse(text);
        } catch(e) {
          parsed = '<pre>' + escapeHtml(text) + '</pre>';
        }
      } else {
        parsed = '<pre>' + escapeHtml(text) + '</pre>';
      }
      return frontmatterHtml + parsed;
    }

    function renderDiff(diffText) {
      if (!diffText) return '<div style="color:var(--muted); padding:10px;">No differences detected.</div>';
      return diffText.split('\\n').map(line => {
        let cls = 'diff-ctx';
        if (line.startsWith('+') && !line.startsWith('+++')) cls = 'diff-add';
        else if (line.startsWith('-') && !line.startsWith('---')) cls = 'diff-del';
        else if (line.startsWith('@@')) cls = 'diff-hunk';
        return `<div class="diff-line ${cls}">${escapeHtml(line)}</div>`;
      }).join('');
    }

    function escapeHtml(text) {
      if (!text) return '';
      return String(text).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    }

    async function setCardDecision(filename, decision) {
      await fetch('/api/proposals/decision', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ filename: filename, decision: decision })
      });
      loadData(true);
    }

    async function setDecision(decision) {
      if (!activeProposal) return;
      await setCardDecision(activeProposal.filename, decision);
    }

    async function applySingleProposal(filename) {
      if (!confirm(`Apply proposal ${filename} into compiled wiki now?`)) return;
      const res = await fetch('/api/proposals/apply-single', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ filename: filename })
      });
      const data = await res.json();
      if (data.success) {
        alert(`Successfully applied: ${filename}`);
        loadData(false);
      } else {
        alert(`Apply failed: ${data.message}`);
      }
    }

    async function applyThis() {
      if (!activeProposal) return;
      await applySingleProposal(activeProposal.filename);
    }

    async function saveFeedback() {
      if (!activeProposal) return;
      const fb = document.getElementById('feedback-input').value;
      await fetch('/api/proposals/feedback', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ filename: activeProposal.filename, feedback: fb })
      });
      alert('Feedback saved to proposal note!');
      loadData(true);
    }

    async function applyAll() {
      if (!confirm("Apply all approved proposals into compiled wiki pages?")) return;
      const res = await fetch('/api/apply', { method: 'POST' });
      const data = await res.json();
      alert(data.message);
      loadData(false);
    }

    loadData();
    setInterval(() => loadData(true), 10000);
  </script>
</body>
</html>
"""


class StudioHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        url = urlparse(self.path)
        if url.path == "/" or url.path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(STUDIO_HTML.encode("utf-8"))
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

        if url.path == "/api/stats":
            pages = 0
            for d in [CONCEPTS_DIR, ENTITIES_DIR, SOURCES_DIR, COMPARISONS_DIR]:
                if os.path.exists(d):
                    pages += len([f for f in os.listdir(d) if f.endswith(".md")])
            data = {"total_pages": pages}
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
    recs = []

    # 1. Check Pending Decisions
    props = []
    if os.path.exists(REVIEW_DIR):
        props = [p for p in os.listdir(REVIEW_DIR) if p.endswith(".md")]
    if props:
        recs.append({
            "type": "decision_gate",
            "priority": "HIGH",
            "title": f"{len(props)} Staged Review Proposals Waiting for Decision",
            "details": f"There are {len(props)} proposals in wiki/Review/. Decision Studio is active at http://127.0.0.1:20888.",
            "action": "Review in Decision Studio and run 'librarian apply' to compile."
        })

    # 2. Analyze Unprocessed Notes Clustering
    unproc_dir = os.path.join(VAULT_ROOT, "unprocessed-obsidians")
    if os.path.exists(unproc_dir):
        files = [f for f in os.listdir(unproc_dir) if f.endswith(".md")]
        clusters = {
            "Auth & Session": ["jwt.md", "oauth.md", "idor.md"],
            "Web Injection": ["sql-injection.md", "xss.md", "xxe.md", "ssrf.md", "ssti.md", "parameter-pollution.md"],
            "Protocols & Desync": ["req-smuggle.md", "graphql.md"],
            "Binary & Low-Level": ["insecure-deserialization.md", "shellcode.md", "fuzzing.md"],
            "Recon & OSINT": ["osint.md", "osint-method.md"],
            "Defenses & Evasion": ["edr.md", "mitigations.md", "initial-access.md"]
        }
        found_clusters = {}
        for cname, cfiles in clusters.items():
            matching = [f for f in files if f in cfiles]
            if matching:
                found_clusters[cname] = matching

        if found_clusters:
            details = ", ".join([f"{k} ({len(v)} notes: {', '.join(v[:3])})" for k, v in found_clusters.items()])
            recs.append({
                "type": "batch_enrichment",
                "priority": "MEDIUM",
                "title": f"Batch Ingestion Opportunity: {len(files)} Unprocessed Notes",
                "details": f"Recommended ingestion by theme: {details}",
                "action": "Ingest related clusters together so the LLM creates rich, cross-linked concepts in single batches."
            })

    # 3. Cross-linking & Comparison Opportunities
    compiled_concepts = []
    if os.path.exists(CONCEPTS_DIR):
        compiled_concepts = [f[:-3] for f in os.listdir(CONCEPTS_DIR) if f.endswith(".md")]

    if "blind-ssrf-gopher-redis-rce" in compiled_concepts and "fastcgi-ssrf-exploitation" in compiled_concepts:
        if not os.path.exists(os.path.join(COMPARISONS_DIR, "redis-vs-fastcgi-ssrf-pivoting.md")):
            recs.append({
                "type": "comparison_synthesis",
                "priority": "LOW",
                "title": "Comparison Candidate: Redis vs FastCGI SSRF Pivoting",
                "details": "Both internal Gopher SSRF primitives are compiled. A comparison note evaluating preconditions, stealth, and OS access limits would deepen the knowledge base.",
                "action": "Generate comparison under wiki/comparisons/redis-vs-fastcgi-ssrf-pivoting.md"
            })

    # 4. Schema & Taxonomy Check
    schema_tags = load_schema_taxonomy()
    used_tags = set()
    for cat_dir in [CONCEPTS_DIR, ENTITIES_DIR]:
        if os.path.exists(cat_dir):
            for f in os.listdir(cat_dir):
                if f.endswith(".md"):
                    with open(os.path.join(cat_dir, f), "r", encoding="utf-8") as fp:
                        txt = fp.read()
                    fm, _ = parse_frontmatter(txt)
                    for t in fm.get("tags", []):
                        used_tags.add(t)

    unlisted_tags = [t for t in used_tags if t not in schema_tags]
    if unlisted_tags:
        recs.append({
            "type": "schema_governance",
            "priority": "LOW",
            "title": f"Taxonomy Extension: {len(unlisted_tags)} Tags Not in SCHEMA.md",
            "details": f"Tags used but unlisted in taxonomy: {', '.join(unlisted_tags)}",
            "action": "Add these tags to ## Tag Taxonomy in wiki/SCHEMA.md to preserve schema integrity."
        })

    # Output recommendations
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
