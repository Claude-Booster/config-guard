#!/usr/bin/env python3
"""config-guard: quarantine and explain repo-shipped Claude Code config before it loads.

SAFETY: This tool reads UNTRUSTED repository files. It ONLY reads bytes/text and
parses JSON, and it ONLY moves files/directories (quarantine/restore). It NEVER
imports, executes, or evaluates any content from the target being scanned.

Stdlib only. Windows-safe (pathlib, shutil, os.replace).
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
from datetime import datetime
from pathlib import Path

QUARANTINE_SUFFIX = ".cfgguard-quarantine"
SKIP_DIRS = {".git", "node_modules", ".venv", "dist", "build", "__pycache__"}


# --------------------------------------------------------------------------- #
# State dir / ledger
# --------------------------------------------------------------------------- #
def get_home() -> Path:
    """Return the state directory (ledger + reports).

    Overridable via CONFIG_GUARD_HOME so tests never touch the real ledger.
    """
    env = os.environ.get("CONFIG_GUARD_HOME")
    if env:
        base = Path(env)
    else:
        base = Path.home() / ".claude" / "config-guard"
    base.mkdir(parents=True, exist_ok=True)
    (base / "reports").mkdir(parents=True, exist_ok=True)
    return base


def ledger_path(home: Path) -> Path:
    return home / "ledger.json"


def load_ledger(home: Path) -> dict:
    p = ledger_path(home)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_ledger(home: Path, ledger: dict) -> None:
    ledger_path(home).write_text(
        json.dumps(ledger, indent=2, sort_keys=True), encoding="utf-8"
    )


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


# --------------------------------------------------------------------------- #
# Safe reading (text only, never execute)
# --------------------------------------------------------------------------- #
def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def load_json(path: Path):
    """Return (data, error). Never raises; error is None on success."""
    raw = read_text(path)
    try:
        return json.loads(raw), None
    except Exception as exc:  # malformed / unreadable
        return None, str(exc)


# --------------------------------------------------------------------------- #
# Hashing
# --------------------------------------------------------------------------- #
def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    try:
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
    except Exception:
        return ""
    return h.hexdigest()


def sha256_dir(path: Path) -> str:
    """sha256 over sorted '<relpath>\\0<filehash>' lines of all files within."""
    lines = []
    for dirpath, dirnames, filenames in os.walk(path):
        # keep hashing stable & avoid quarantine artifacts
        dirnames[:] = [
            d for d in dirnames if not d.endswith(QUARANTINE_SUFFIX)
        ]
        for fname in filenames:
            fpath = Path(dirpath) / fname
            rel = fpath.relative_to(path).as_posix()
            lines.append(f"{rel}\0{sha256_file(fpath)}")
    lines.sort()
    h = hashlib.sha256()
    h.update("\n".join(lines).encode("utf-8"))
    return h.hexdigest()


def compute_hash(kind_is_dir: bool, path: Path) -> str:
    if kind_is_dir:
        return sha256_dir(path)
    return sha256_file(path)


# --------------------------------------------------------------------------- #
# Target discovery
# --------------------------------------------------------------------------- #
# Each target: dict(path=Path, is_dir=bool, kind=str)
def find_targets(root: Path) -> list:
    root = root.resolve()
    targets = []
    if not root.exists():
        return targets

    # If the root itself is a target-named file, handle directly.
    if root.is_file() and root.name == ".mcp.json":
        targets.append({"path": root, "is_dir": False, "kind": "mcp"})
        return targets

    for dirpath, dirnames, filenames in os.walk(root):
        dp = Path(dirpath)

        # Prune directories we must not descend into.
        keep = []
        for d in list(dirnames):
            if d in SKIP_DIRS or d.endswith(QUARANTINE_SUFFIX):
                continue
            keep.append(d)
        dirnames[:] = keep

        # Directory targets: whole dir is quarantined; don't descend further.
        for d in list(dirnames):
            if d == ".claude":
                targets.append(
                    {"path": dp / d, "is_dir": True, "kind": "claude-config"}
                )
                dirnames.remove(d)
            elif d == ".claude-plugin":
                targets.append(
                    {"path": dp / d, "is_dir": True, "kind": "claude-plugin"}
                )
                dirnames.remove(d)

        # File targets.
        for f in filenames:
            if f == ".mcp.json":
                targets.append({"path": dp / f, "is_dir": False, "kind": "mcp"})
            elif f == "hooks.json" and dp.name == "hooks":
                targets.append({"path": dp / f, "is_dir": False, "kind": "hooks"})

    return targets


# --------------------------------------------------------------------------- #
# Findings / analysis
# A finding: dict(risk, file, what, lines=[...], check)
# --------------------------------------------------------------------------- #
RISK_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}

_SHELL_HINT = re.compile(
    r"(?:```(?:bash|sh|shell|powershell|cmd))|(?:\b(?:curl|wget|bash|sh|powershell|pwsh|cmd|npm|pip|python|node|rm|Invoke-WebRequest|iwr)\b\s)",
    re.IGNORECASE,
)


def mk(risk, file, what, lines, check):
    return {
        "risk": risk,
        "file": file,
        "what": what,
        "lines": list(lines),
        "check": check,
    }


def analyze_mcp(path: Path, display: str) -> list:
    findings = []
    data, err = load_json(path)
    if err is not None:
        findings.append(
            mk(
                "HIGH",
                display,
                "a Claude 'MCP' config (lists external programs/services Claude auto-starts)",
                ["Unreadable config -- can't verify what it does; treat as suspicious."],
                "Open this file by hand and read it before trusting this repo; broken "
                "config can still be loaded and may hide what it really launches.",
            )
        )
        return findings

    servers = {}
    if isinstance(data, dict) and isinstance(data.get("mcpServers"), dict):
        servers = data["mcpServers"]

    if not servers:
        findings.append(
            mk(
                "LOW",
                display,
                "a Claude 'MCP' config (lists external programs/services Claude auto-starts)",
                ["No servers declared."],
                "Nothing auto-starts from this file, but confirm it stays empty.",
            )
        )
        return findings

    for sname, s in servers.items():
        if not isinstance(s, dict):
            continue
        lines = []
        risk = "LOW"
        if "command" in s:
            cmd = str(s.get("command", ""))
            args = s.get("args", [])
            argstr = (
                " ".join(str(a) for a in args)
                if isinstance(args, list)
                else str(args)
            )
            lines.append(
                f"Runs a program on your computer: `{(cmd + ' ' + argstr).strip()}`"
            )
            risk = "HIGH"
        elif "url" in s or s.get("type") in ("http", "sse"):
            url = s.get("url", s.get("type", ""))
            lines.append(f"Connects Claude to an external service: `{url}`")
            risk = "MEDIUM"

        secret_keys = []
        if isinstance(s.get("env"), dict):
            secret_keys += list(s["env"].keys())
        if isinstance(s.get("headers"), dict):
            secret_keys += list(s["headers"].keys())
        if secret_keys:
            lines.append(
                "Sends credentials/secrets (keys: " + ", ".join(secret_keys) + ")"
            )

        if not lines:
            lines.append("Server with no command/url -- unclear what it does.")

        findings.append(
            mk(
                risk,
                f"{display}  ->  server '{sname}'",
                "an auto-started helper ('MCP server') Claude launches when this repo opens",
                lines,
                "Make sure you recognise this program/service. A program entry runs at "
                "your own user privilege the moment Claude loads; do not approve unknown "
                "commands.",
            )
        )
    return findings


def _analyze_settings_file(path: Path, display: str) -> list:
    findings = []
    data, err = load_json(path)
    if err is not None:
        findings.append(
            mk(
                "HIGH",
                display,
                "Claude settings for this repo",
                ["Unreadable settings -- can't verify what it does; treat as suspicious."],
                "Open the file by hand; malformed settings can still enable auto-run behaviour.",
            )
        )
        return findings
    if not isinstance(data, dict):
        return findings

    hooks = data.get("hooks")
    if hooks:
        lines = []
        if isinstance(hooks, dict):
            for event, spec in hooks.items():
                for cmd in _extract_hook_commands(spec):
                    lines.append(
                        f"Auto-runs a command when you use Claude [{event}]: `{cmd}`"
                    )
        if not lines:
            lines.append("Auto-runs commands on Claude events (details unreadable).")
        findings.append(
            mk(
                "HIGH",
                display,
                "Claude settings for this repo",
                lines,
                "A 'hook' is a command Claude runs automatically on an event (e.g. every "
                "time you run a tool). Read each command above before approving -- a hook "
                "plus a network-allow rule can quietly send your files off the machine.",
            )
        )

    perms = data.get("permissions")
    if isinstance(perms, dict):
        allow = perms.get("allow")
        if isinstance(allow, list) and allow:
            rules = ", ".join(str(a) for a in allow)
            findings.append(
                mk(
                    "HIGH",
                    display,
                    "Claude settings for this repo",
                    [f"Pre-approves commands without asking you: `{rules}`"],
                    "These rules let Claude run matching commands with no confirmation "
                    "prompt. Anything mentioning `Bash` or network tools (curl/wget) is "
                    "especially risky -- remove rules you did not add yourself.",
                )
            )

    if data.get("enableAllProjectMcpServers") is True:
        findings.append(
            mk(
                "HIGH",
                display,
                "Claude settings for this repo",
                ["Auto-enables every MCP server this repo ships (no prompt): "
                 "`enableAllProjectMcpServers: true`"],
                "This silently turns on all the external programs/services declared in "
                "the repo. Confirm you trust every one of them first.",
            )
        )

    env = data.get("env")
    if isinstance(env, dict) and env:
        findings.append(
            mk(
                "MEDIUM",
                display,
                "Claude settings for this repo",
                ["Sets environment variables: " + ", ".join(env.keys())],
                "Environment variables can change how programs behave or point them at "
                "attacker-controlled servers. Check each key/value.",
            )
        )
    return findings


def _extract_hook_commands(spec) -> list:
    """Pull command strings out of a hooks event spec (various shapes)."""
    cmds = []

    def walk(obj):
        if isinstance(obj, dict):
            if "command" in obj and isinstance(obj["command"], str):
                cmds.append(obj["command"])
            for v in obj.values():
                walk(v)
        elif isinstance(obj, list):
            for v in obj:
                walk(v)

    walk(spec)
    if not cmds and isinstance(spec, str):
        cmds.append(spec)
    return cmds


def _analyze_doc_items(base: Path, display: str) -> list:
    """Skills / agents / commands -> LOW (bump to MEDIUM if shell-y)."""
    findings = []
    specs = [
        ("skills", "SKILL.md", "skill", True),
        ("agents", None, "agent", False),
        ("commands", None, "command", False),
    ]
    for sub, fixed_name, label, nested in specs:
        root = base / sub
        if not root.is_dir():
            continue
        md_files = []
        if fixed_name:
            for child in sorted(root.iterdir()):
                if child.is_dir():
                    f = child / fixed_name
                    if f.is_file():
                        md_files.append(f)
        else:
            md_files = sorted(root.glob("*.md"))
        for f in md_files:
            text = read_text(f)
            name = f.parent.name if fixed_name else f.stem
            risk = "LOW"
            reason = []
            fm = _frontmatter(text)
            if "allowed-tools" in fm:
                risk = "MEDIUM"
                reason.append("declares `allowed-tools` (pre-authorised tool access)")
            if _SHELL_HINT.search(text):
                risk = "MEDIUM"
                reason.append("body contains shell commands")
            lines = [f"Adds a {label} '{name}' Claude can load"]
            if reason:
                lines.append("Note: " + "; ".join(reason))
            findings.append(
                mk(
                    risk,
                    f"{display}/{sub}/{name}",
                    f"a Claude {label} shipped by this repo",
                    lines,
                    f"A {label} is instructions Claude can pull into context. Skim it "
                    "for commands or tool permissions before approving.",
                )
            )
    return findings


def _frontmatter(text: str) -> str:
    if text.startswith("---"):
        end = text.find("\n---", 3)
        if end != -1:
            return text[3:end]
    return ""


def analyze_claude_dir(path: Path, display: str) -> list:
    findings = []
    for name in ("settings.json", "settings.local.json"):
        f = path / name
        if f.is_file():
            findings += _analyze_settings_file(f, f"{display}/{name}")
    # Nested hooks.json inside .claude/hooks/
    hjson = path / "hooks" / "hooks.json"
    if hjson.is_file():
        findings += analyze_hooks_json(hjson, f"{display}/hooks/hooks.json")
    findings += _analyze_doc_items(path, display)
    if not findings:
        findings.append(
            mk(
                "LOW",
                display,
                "a .claude config folder shipped by this repo",
                ["No hooks, permission rules, or auto-run settings detected."],
                "Still skim the folder's contents before approving.",
            )
        )
    return findings


def analyze_hooks_json(path: Path, display: str) -> list:
    data, err = load_json(path)
    if err is not None:
        return [
            mk(
                "HIGH",
                display,
                "a hooks file (commands Claude auto-runs on events)",
                ["Unreadable hooks file -- treat as suspicious."],
                "Open it by hand before trusting the repo.",
            )
        ]
    cmds = _extract_hook_commands(data)
    lines = [f"Auto-runs a command when you use Claude: `{c}`" for c in cmds] or [
        "Declares event hooks (commands that run automatically)."
    ]
    return [
        mk(
            "HIGH",
            display,
            "a hooks file (commands Claude auto-runs on events)",
            lines,
            "Read every command above before approving; hooks run on their own with no "
            "prompt and can execute anything.",
        )
    ]


def analyze_plugin(path: Path, display: str) -> list:
    findings = []
    pj = path / "plugin.json"
    if pj.is_file():
        data, err = load_json(pj)
        if err is not None:
            findings.append(
                mk(
                    "HIGH",
                    f"{display}/plugin.json",
                    "a Claude plugin manifest",
                    ["Unreadable plugin manifest -- treat as suspicious."],
                    "Open it by hand before trusting the repo.",
                )
            )
        elif isinstance(data, dict) and data.get("hooks"):
            findings.append(
                mk(
                    "HIGH",
                    f"{display}/plugin.json",
                    "a Claude plugin manifest that declares hooks",
                    ["Declares hooks -- commands that auto-run on Claude events."],
                    "Read the referenced hook commands before approving; they run "
                    "automatically with no prompt.",
                )
            )
    hjson = path / "hooks" / "hooks.json"
    if hjson.is_file():
        findings += analyze_hooks_json(hjson, f"{display}/hooks/hooks.json")
    if not findings:
        findings.append(
            mk(
                "LOW",
                display,
                "a .claude-plugin folder shipped by this repo",
                ["No auto-run hooks detected in the plugin manifest."],
                "Still skim the folder before approving.",
            )
        )
    return findings


def analyze_target(target: dict, display: str) -> list:
    kind = target["kind"]
    path = target["path"]
    if kind == "mcp":
        return analyze_mcp(path, display)
    if kind == "claude-config":
        return analyze_claude_dir(path, display)
    if kind == "claude-plugin":
        return analyze_plugin(path, display)
    if kind == "hooks":
        return analyze_hooks_json(path, display)
    return []


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #
def _display_path(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def build_report(root: Path, analyzed: list, action: str, quarantined: list,
                 approve_cmd: str) -> str:
    """analyzed: list of dict(target, findings, changed, state)."""
    all_findings = []
    for item in analyzed:
        all_findings.extend(item["findings"])

    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in all_findings:
        counts[f["risk"]] = counts.get(f["risk"], 0) + 1

    out = []
    if counts["HIGH"]:
        verdict = "DO NOT trust this folder yet -- it can run commands on your computer."
    elif counts["MEDIUM"]:
        verdict = "Caution -- this folder can reach external services or set hidden options."
    elif all_findings:
        verdict = "Looks low-risk, but review before approving."
    else:
        verdict = "No Claude auto-config found here."

    out.append("=" * 70)
    out.append("config-guard report")
    out.append("Scanned: " + str(root))
    out.append("When: " + now_iso())
    out.append("-" * 70)
    out.append("VERDICT: " + verdict)
    out.append(
        f"Found: {counts['HIGH']} HIGH-risk, {counts['MEDIUM']} MEDIUM-risk, "
        f"{counts['LOW']} low-risk item(s) across {len(analyzed)} config location(s)."
    )
    out.append("")
    out.append(
        "Plain English: when you open a repo, Claude Code may auto-load config it "
        "ships (an .mcp.json, or a .claude folder). That config can launch programs "
        "or run commands by itself. Below is what this folder would do."
    )
    out.append("")

    # Note changed items
    changed = [i for i in analyzed if i.get("changed")]
    if changed:
        out.append("CHANGED SINCE YOU APPROVED:")
        for i in changed:
            out.append("  - " + i["display"] +
                       "  (content differs from what you approved before -- re-review)")
        out.append("")

    for risk in ("HIGH", "MEDIUM", "LOW"):
        group = [f for f in all_findings if f["risk"] == risk]
        if not group:
            continue
        label = {
            "HIGH": "HIGH RISK -- can run code / commands on your machine",
            "MEDIUM": "MEDIUM RISK -- external connections or hidden settings",
            "LOW": "LOW RISK -- adds instructions Claude can load",
        }[risk]
        out.append("#" * 70)
        out.append(f"[{risk}] {label}")
        out.append("#" * 70)
        for f in group:
            out.append("")
            out.append(f"  File: {f['file']}")
            out.append(f"  What this is: {f['what']}")
            for ln in f["lines"]:
                out.append(f"      - {ln}")
            out.append(f"  What to check: {f['check']}")
        out.append("")

    out.append("=" * 70)
    out.append("STATUS")
    out.append("-" * 70)
    if action == "scan":
        out.append("Nothing was moved. This was a read-only scan.")
        out.append("To block these until you review them, run:")
        out.append(f"    python config_guard.py guard \"{root}\"")
    elif action == "guard":
        if quarantined:
            out.append("The following were QUARANTINED (moved aside so Claude cannot "
                        "load them):")
            for q in quarantined:
                out.append(f"    {q}")
            out.append("")
            out.append("After you have reviewed the items above and trust them, lift "
                        "the block with:")
            out.append(f"    {approve_cmd}")
        else:
            out.append("Nothing needed quarantining (already approved and unchanged, "
                        "or nothing found).")
    elif action == "approve":
        out.append("Approved items were restored to their original locations.")
    out.append("=" * 70)
    return "\n".join(out)


def sanitize(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-") or "target"


def write_report(home: Path, root: Path, text: str) -> Path:
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    fname = f"{ts}-{sanitize(root.name)}.md"
    out = home / "reports" / fname
    out.write_text(text, encoding="utf-8")
    return out


# --------------------------------------------------------------------------- #
# Quarantine mechanics
# --------------------------------------------------------------------------- #
def quarantine_dest(path: Path) -> Path:
    return path.with_name(path.name + QUARANTINE_SUFFIX)


def do_quarantine(path: Path) -> Path:
    """Move path -> path.cfgguard-quarantine. Returns the quarantine path.

    If the destination already exists, treat as already-quarantined (no move).
    """
    dest = quarantine_dest(path)
    if dest.exists():
        return dest
    if not path.exists():
        return dest
    shutil.move(str(path), str(dest))
    return dest


def do_restore(path: Path) -> bool:
    """Move path.cfgguard-quarantine back to path. Returns True if restored."""
    src = quarantine_dest(path)
    if not src.exists():
        return False
    if path.exists():
        # original already present; drop the stale quarantine copy conservatively
        return False
    shutil.move(str(src), str(path))
    return True


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #
def key_for(path: Path) -> str:
    return str(path.resolve())


def cmd_scan(args) -> int:
    home = get_home()
    root = Path(args.path).resolve()
    targets = find_targets(root)
    analyzed = []
    for t in targets:
        display = _display_path(root, t["path"])
        analyzed.append({
            "target": t,
            "display": display,
            "findings": analyze_target(t, display),
            "changed": False,
        })
    report = build_report(root, analyzed, "scan", [], "")
    out = write_report(home, root, report)
    print(report)
    print(f"\n(Report saved to: {out})")
    return 0


def cmd_guard(args) -> int:
    home = get_home()
    root = Path(args.path).resolve()
    ledger = load_ledger(home)
    targets = find_targets(root)

    analyzed = []
    quarantined_display = []
    for t in targets:
        path = t["path"]
        display = _display_path(root, path)
        k = key_for(path)
        cur_hash = compute_hash(t["is_dir"], path)
        entry = ledger.get(k)
        changed = False

        approved_unchanged = (
            entry is not None
            and entry.get("state") == "approved"
            and entry.get("hash") == cur_hash
        )

        findings = analyze_target(t, display)

        if approved_unchanged:
            # leave in place
            analyzed.append({
                "target": t, "display": display, "findings": findings,
                "changed": False,
            })
            continue

        if entry is not None and entry.get("state") == "approved" and \
                entry.get("hash") != cur_hash:
            changed = True

        dest = do_quarantine(path)
        ledger[k] = {
            "state": "quarantined",
            "hash": cur_hash,
            "kind": t["kind"],
            "updated_at": now_iso(),
        }
        quarantined_display.append(str(dest))
        analyzed.append({
            "target": t, "display": display, "findings": findings,
            "changed": changed,
        })

    save_ledger(home, ledger)
    approve_cmd = f"python config_guard.py approve \"{root}\""
    report = build_report(root, analyzed, "guard", quarantined_display, approve_cmd)
    out = write_report(home, root, report)
    print(report)
    print(f"\n(Report saved to: {out})")
    return 0


def cmd_approve(args) -> int:
    home = get_home()
    root = Path(args.path).resolve()
    ledger = load_ledger(home)
    restored = []
    root_str = str(root)

    for k, entry in list(ledger.items()):
        if entry.get("state") != "quarantined":
            continue
        kp = Path(k)
        # under the given path?
        try:
            is_under = (kp == root) or (root_str == os.path.commonpath([root_str, k]))
        except ValueError:
            is_under = False
        if not is_under:
            continue
        ok = do_restore(kp)
        if ok or not quarantine_dest(kp).exists():
            is_dir = entry.get("kind") in ("claude-config", "claude-plugin")
            new_hash = compute_hash(is_dir, kp) if kp.exists() else entry.get("hash")
            ledger[k] = {
                "state": "approved",
                "hash": new_hash,
                "kind": entry.get("kind"),
                "updated_at": now_iso(),
            }
            restored.append(k)

    save_ledger(home, ledger)
    if restored:
        print("Restored and APPROVED (Claude will now load these again):")
        for r in restored:
            print(f"    {r}")
    else:
        print("Nothing to approve under: " + root_str)
    return 0


def cmd_status(args) -> int:
    home = get_home()
    ledger = load_ledger(home)
    if not ledger:
        print("Ledger is empty (nothing scanned/guarded yet).")
        print("Ledger location: " + str(ledger_path(home)))
        return 0
    print(f"{'STATE':<12} {'HASH':<10} {'UPDATED':<22} PATH")
    print("-" * 80)
    for k in sorted(ledger):
        e = ledger[k]
        short = (e.get("hash") or "")[:8]
        print(f"{e.get('state',''):<12} {short:<10} "
              f"{e.get('updated_at',''):<22} {k}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="config_guard.py",
        description="Quarantine and explain repo-shipped Claude Code config "
                    "before it can auto-run.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="Read-only: find + explain config, move nothing.")
    s.add_argument("path")
    s.set_defaults(func=cmd_scan)

    g = sub.add_parser("guard", help="Quarantine risky config until you approve it.")
    g.add_argument("path")
    g.set_defaults(func=cmd_guard)

    a = sub.add_parser("approve", help="Restore + approve quarantined config.")
    a.add_argument("path")
    a.set_defaults(func=cmd_approve)

    st = sub.add_parser("status", help="Show the ledger.")
    st.set_defaults(func=cmd_status)

    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
