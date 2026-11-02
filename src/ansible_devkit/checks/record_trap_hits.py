#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""record_trap_hits — append a JSONL record every time a known trap is caught in a file Claude
just edited, so the repeat offenders become DATA instead of anecdote.

WHY THIS EXISTS
    A rulebook's "known traps" list grows by accretion: every entry is added after the trap has
    already cost someone real time, until it spans dozens of traps across regex/YAML/Jinja/Ansible
    semantics. It records that each trap happened, but NOT how often, NOT which ones keep
    recurring, and NOT whether the countermeasure worked. Two consequences:

      - Prioritisation is guesswork. A trap like YAMLESC-01 ("join('\\n') in a block scalar
        produced a literal \\n") can be hit dozens of times across sessions while nothing in the
        repo can show that, so it stays a [you] bullet in a long list rather than becoming the
        FAIL rule it deserves to be.
      - A fixed trap looks identical to a trap nobody happened to hit lately, so a rule that is
        ready to retire can never be identified with confidence.

    This hook closes that loop. It runs AFTER a successful Write/Edit, re-runs the existing
    static checks over just the touched file, and appends one record per finding. It is telemetry,
    not a gate: it NEVER blocks and NEVER changes an exit code, because a recorder that can fail
    a tool call would be a new failure mode in front of every edit.

WHAT IT DELIBERATELY DOES NOT DO
    It does not judge whether the finding was later fixed, or attribute intent. A record means
    "this pattern was present in this file at this moment", which is exactly the signal needed to
    rank traps by frequency. Pairing an edit with its later fix is a reporting concern, handled by
    `devkit trap-report` reading the log, not by this hook.

OUTPUT
    logs/trap-hits/<YYYY-MM>.jsonl in the MAIN checkout (never a worktree's own logs/ — the same
    reasoning as a shared run-log directory: the repo has ONE history, and a `git worktree remove`
    must not be able to destroy it).

Exit code is ALWAYS 0.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

HOOK_DIR = Path(__file__).resolve().parent

# Where the log goes is per-repo data (devkit.toml [trap_hits]): the directory, relative to the MAIN
# checkout, and the environment variable that redirects it. Both have defaults, and a broken
# devkit.toml falls back to them: this is telemetry, and it must never fail the edit it observes.
REPO = Path.cwd()
LOG_DIR_REL = "logs/trap-hits"
LOG_DIR_ENV = "DEVKIT_TRAP_LOG_DIR"
try:
    sys.path.insert(0, str(HOOK_DIR))
    import _devkit_config

    _CFG = _devkit_config.load()
    REPO = _CFG.root
    LOG_DIR_REL = _CFG.string("trap_hits.log_dir", LOG_DIR_REL)
    LOG_DIR_ENV = _CFG.string("trap_hits.log_dir_env", LOG_DIR_ENV)
except Exception:  # noqa: BLE001 — see above: never fail
    pass


def main_checkout() -> Path:
    """Resolve the MAIN checkout, so logs never live inside a worktree that may be removed."""
    try:
        cp = subprocess.run(
            ["git", "worktree", "list", "--porcelain"],
            cwd=REPO,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if cp.returncode == 0 and cp.stdout.strip():
            # `git worktree list` prints the MAIN checkout first. trap_report.py uses the same
            # derivation — deliberately the same mechanism, so the two cannot drift into
            # disagreeing about where the shared log lives.
            for ln in cp.stdout.splitlines():
                if ln.startswith("worktree "):
                    return Path(ln.split(" ", 1)[1].strip())
    except Exception:
        pass
    return REPO


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return 0

    tool = payload.get("tool_name") or ""
    if tool not in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        return 0

    ti = payload.get("tool_input") or {}
    target = ti.get("file_path") or ti.get("notebook_path") or ""
    if not target:
        return 0
    tp = Path(target)
    if tp.suffix not in (".yml", ".yaml"):
        return 0
    if not tp.exists():
        return 0

    checker = HOOK_DIR / "check_silent_guards.py"
    if not checker.exists():
        return 0

    try:
        cp = subprocess.run(
            [sys.executable, str(checker), str(tp)],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except Exception:
        return 0

    findings = []
    for line in cp.stdout.splitlines():
        line = line.strip()
        if not (line.startswith("FAIL [") or line.startswith("WARN [")):
            continue
        level, _, rest = line.partition(" [")
        rule, _, tail = rest.partition("]")
        loc, _, msg = tail.lstrip(": ").partition(": ")
        findings.append({"level": level, "rule": rule, "where": loc.strip(), "message": msg[:400]})

    if not findings:
        return 0

    # LOG_DIR_ENV (DEVKIT_TRAP_LOG_DIR here) exists so the test suite can record into a temporary
    # directory instead of the repo's real telemetry log. Without it the tests dirty the very
    # history they verify — which they did, and the records had to be scrubbed by hand twice
    # before this was added.
    override = os.environ.get(LOG_DIR_ENV)
    log_dir = Path(override) if override else main_checkout() / LOG_DIR_REL
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        return 0

    now = datetime.now(timezone.utc)
    rec = {
        "_event": "trap_hit",
        "ts": now.isoformat(),
        "tool": tool,
        "file": str(tp),
        "session": payload.get("session_id") or os.environ.get("CLAUDE_SESSION_ID") or "",
        "rules": sorted({f["rule"] for f in findings}),
        "n_findings": len(findings),
        "findings": findings,
    }
    try:
        with (log_dir / f"{now:%Y-%m}.jsonl").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, sort_keys=True) + "\n")
    except Exception:
        return 0
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        # A telemetry recorder must never be able to fail the edit it is observing.
        sys.exit(0)
