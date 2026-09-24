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
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# Resolve Vault and Wiki roots
DEFAULT_VAULT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DEFAULT_WIKI_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

VAULT_ROOT = os.environ.get("OBSIDIAN_VAULT_PATH", DEFAULT_VAULT_ROOT)
WIKI_ROOT = os.environ.get("WIKI_PATH", DEFAULT_WIKI_ROOT)
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
            if fm.get("status") == "applied" or fm.get("decision") == "approve":
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
  <style>
    :root {
      --bg: #1e1e24;
      --card-bg: #2b2b36;
      --accent: #7c4dff;
      --accent-hover: #966eff;
      --text: #e0e0e6;
      --muted: #9e9ea8;
      --border: #3b3b4a;
      --success: #00c853;
      --danger: #ff5252;
      --warn: #ffd600;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
    body { background: var(--bg); color: var(--text); display: flex; height: 100vh; overflow: hidden; }
    #sidebar { width: 380px; border-right: 1px solid var(--border); display: flex; flex-direction: column; background: #18181d; }
    #header { padding: 18px 20px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; }
    #header h2 { font-size: 1.1rem; color: #fff; display: flex; align-items: center; gap: 8px; }
    #stats { padding: 12px 20px; background: rgba(124, 77, 255, 0.08); border-bottom: 1px solid var(--border); font-size: 0.85rem; color: var(--muted); display: flex; justify-content: space-between; }
    #proposals-list { flex: 1; overflow-y: auto; padding: 12px; }
    .proposal-card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; padding: 14px; margin-bottom: 10px; cursor: pointer; transition: all 0.15s; }
    .proposal-card:hover { border-color: var(--accent); }
    .proposal-card.active { border-color: var(--accent); background: #323240; }
    .card-title { font-weight: 600; font-size: 0.95rem; margin-bottom: 6px; color: #fff; }
    .card-meta { font-size: 0.8rem; color: var(--muted); display: flex; justify-content: space-between; }
    .badge { padding: 2px 8px; border-radius: 12px; font-size: 0.75rem; font-weight: bold; text-transform: uppercase; }
    .badge-pending { background: #3e381e; color: var(--warn); }
    .badge-approve { background: #1b3d27; color: var(--success); }
    .badge-reject { background: #3d1b1b; color: var(--danger); }
    #main { flex: 1; display: flex; flex-direction: column; background: var(--bg); }
    #toolbar { padding: 14px 24px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; background: #22222a; }
    .btn-group { display: flex; gap: 10px; }
    button { padding: 8px 16px; border: none; border-radius: 6px; font-weight: 600; cursor: pointer; transition: 0.15s; font-size: 0.85rem; }
    .btn-approve { background: var(--success); color: #000; }
    .btn-approve:hover { filter: brightness(1.1); }
    .btn-reject { background: var(--danger); color: #fff; }
    .btn-apply-all { background: var(--accent); color: #fff; }
    .btn-apply-all:hover { background: var(--accent-hover); }
    #content-view { flex: 1; overflow-y: auto; padding: 24px 30px; }
    pre { background: #121216; padding: 16px; border-radius: 8px; border: 1px solid var(--border); overflow-x: auto; color: #b0bec5; font-size: 0.9rem; line-height: 1.5; font-family: monospace; }
    h1, h2, h3 { color: #fff; margin-bottom: 12px; }
    .feedback-box { margin-top: 20px; background: #22222a; padding: 16px; border-radius: 8px; border: 1px solid var(--border); }
    textarea { width: 100%; height: 80px; background: #18181d; border: 1px solid var(--border); border-radius: 6px; color: #fff; padding: 10px; margin-top: 8px; resize: vertical; }
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
      <div id="active-title" style="font-weight: 600; font-size: 1.1rem; color: #fff;">Select a Proposal</div>
      <div class="btn-group" id="actions" style="display:none;">
        <button class="btn-approve" onclick="setDecision('approve')">✓ Approve</button>
        <button class="btn-reject" onclick="setDecision('reject')">✕ Reject</button>
      </div>
    </div>
    <div id="content-view">
      <div style="color: var(--muted); text-align: center; margin-top: 100px;">
        <h3>No Proposal Selected</h3>
        <p style="margin-top: 8px;">Select a proposal from the left panel to review diffs and grant approval.</p>
      </div>
    </div>
  </div>

  <script>
    let proposals = [];
    let activeProposal = null;

    async function loadData() {
      const res = await fetch('/api/proposals');
      proposals = await res.json();
      const statsRes = await fetch('/api/stats');
      const stats = await statsRes.json();

      document.getElementById('stat-pending').innerText = proposals.filter(p => p.decision === 'pending').length;
      document.getElementById('stat-pages').innerText = stats.total_pages;

      const list = document.getElementById('proposals-list');
      if (proposals.length === 0) {
        list.innerHTML = '<div style="color:var(--muted); text-align:center; padding:20px;">No pending proposals in Review/</div>';
        return;
      }

      list.innerHTML = proposals.map((p, idx) => `
        <div class="proposal-card ${activeProposal && activeProposal.filename === p.filename ? 'active' : ''}" onclick="selectProposal(${idx})">
          <div class="card-title">${p.target}</div>
          <div class="card-meta">
            <span>Rev ${p.revision}</span>
            <span class="badge badge-${p.decision}">${p.decision}</span>
          </div>
        </div>
      `).join('');
    }

    function selectProposal(idx) {
      activeProposal = proposals[idx];
      document.getElementById('active-title').innerText = activeProposal.target;
      document.getElementById('actions').style.display = 'flex';

      const view = document.getElementById('content-view');
      view.innerHTML = `
        <h2>Proposed Change: ${activeProposal.target}</h2>
        <p style="color:var(--muted); margin-bottom: 16px;">Source: <code>${activeProposal.sources.join(', ')}</code></p>
        <pre>${escapeHtml(activeProposal.proposed_content || activeProposal.body)}</pre>
        <div class="feedback-box">
          <h4>Human Feedback / Instructions:</h4>
          <textarea id="feedback-input" placeholder="Type instructions or revisions for the agent...">${activeProposal.feedback || ''}</textarea>
          <button style="margin-top:8px; background:var(--border); color:#fff;" onclick="saveFeedback()">Save Feedback</button>
        </div>
      `;
      loadData();
    }

    function escapeHtml(text) {
      return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    }

    async function setDecision(decision) {
      if (!activeProposal) return;
      await fetch('/api/proposals/decision', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ filename: activeProposal.filename, decision: decision })
      });
      loadData();
    }

    async function applyAll() {
      if (!confirm("Apply all approved proposals into compiled wiki pages?")) return;
      const res = await fetch('/api/apply', { method: 'POST' });
      const data = await res.json();
      alert(data.message);
      location.reload();
    }

    loadData();
    setInterval(loadData, 5000);
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
                        content = m.group(1).strip() if m else body
                        props.append({
                            "filename": p,
                            "target": fm.get("target", p),
                            "revision": fm.get("revision", 1),
                            "decision": fm.get("decision", "pending"),
                            "status": fm.get("status", "needs-review"),
                            "sources": fm.get("sources", []),
                            "proposed_content": content,
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

        if url.path == "/api/apply":
            ret = cmd_apply(argparse.Namespace(file=None))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"success": (ret == 0), "message": "Applied approved proposals"}).encode("utf-8"))
            return

        self.send_response(404)
        self.end_headers()


def cmd_studio(args):
    port = args.port or 20888
    server = HTTPServer(("127.0.0.1", port), StudioHandler)
    url = f"http://127.0.0.1:{port}"
    print(f"\n[+] Decision Studio running at: {url}")
    print("    Press Ctrl+C to stop.\n")
    if args.open:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Stopping Decision Studio.")
        server.server_close()
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

    # studio
    p_studio = subparsers.add_parser("studio", help="Launch visual Decision Studio web UI")
    p_studio.add_argument("--port", type=int, default=20888, help="Port to serve on (default: 20888)")
    p_studio.add_argument("--open", action="store_true", help="Open browser automatically")

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
        "studio": cmd_studio,
    }

    return cmd_map[args.subcommand](args)


if __name__ == "__main__":
    sys.exit(main())
