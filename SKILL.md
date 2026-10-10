---
name: config-guard
description: Quarantine and explain repo-shipped Claude Code config before it loads. Use when the user clones/opens a new repo, installs a plugin/tool, or asks "is this safe to open", "scan this repo/plugin", "check this .mcp.json / .claude folder", or "what will this run". Blocks any .mcp.json or .claude/* by moving it aside, then produces a plain-English risk report; the block lifts only after the user approves.
---

# Config Guard

A repo's `.mcp.json` and `.claude/*` files are **executable configuration** — Claude Code auto-loads them when you open the project, and they can launch local commands at your OS privilege (MCP servers, hooks) or pre-approve commands without asking (permission allow-rules). This is a real supply-chain / RCE-via-clone vector.

`config-guard` defends against it by **quarantine**, not hooks — so it works in the VSCode extension (where command-hooks don't fire). It physically moves risky config aside so nothing loads until a human reviews a plain-English report and approves.

Tool (bundled inside this skill at `scripts/config_guard.py`):
`python "$USERPROFILE/.claude/skills/config-guard/scripts/config_guard.py" <command>`

## When to use it
- The user just **cloned or opened a new repo** → `guard` it before working in it.
- The user **installed a plugin / tool / software** and wants to know what it'll run → `scan` it.
- The user asks whether something is **safe to open**, or "what does this `.mcp.json` / `.claude` folder do."

## Two modes

**1. Guard (block + report + approve)** — for anything *new* arriving on the machine:
```
python .../config_guard.py guard "<path>"
```
Moves every unapproved `.mcp.json`, `.claude/`, `.claude-plugin/`, and `hooks/hooks.json` aside (renamed `*.cfgguard-quarantine`) so Claude Code can't load them, and prints a layman's report. After the user reviews and approves:
```
python .../config_guard.py approve "<path>"
```
restores the files and records the approval. A later `guard` run leaves approved-and-unchanged items alone, but **re-quarantines anything that changed** since approval.

**2. Scan (read-only report)** — audit any repo/plugin/tool without touching it:
```
python .../config_guard.py scan "<path>"
```
Same plain-English risk report, no quarantine, nothing moved.

`status` lists what's currently quarantined vs approved.

## How to present results
Relay the tool's report to the user in plain language — lead with the verdict and the highest-risk item, explain *what would run* and *why it matters*, and state clearly that high-risk items are **blocked until they approve**. Never auto-approve on the user's behalf; approval is their decision after reading the report. If the tool reports unreadable/malformed config, treat it as suspicious, not benign.

## Notes
- The tool only reads and moves files — it never executes anything from the target (the target is untrusted).
- Quarantine is fully reversible: `approve` restores the exact files. To undo manually, rename `*.cfgguard-quarantine` back.
- This complements, not replaces, Claude Code's own per-server MCP approval prompt — keep `enableAllProjectMcpServers` unset so that prompt still fires.
