#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""trap_report — rank the repo's known traps by how often they are actually hit.

Reads the trap-hit log (written by record_trap_hits.py) and prints traps
ordered by frequency, so the worst repeat offender is the first thing you see.

WHY RANK AT ALL
    A rulebook lists its traps as equals. They are not equals: a few account for most of the
    wasted time. Without counts, the response to "which trap should become a FAIL rule next?" is
    a memory contest, and memory is exactly what fails across sessions. This turns the question
    into a query.

READING THE OUTPUT
    A high count means the pattern keeps being WRITTEN, i.e. the current countermeasure (a
    rulebook bullet, a WARN rule) is not preventing it — a candidate for promotion to FAIL, or
    for a skill that supplies the correct form up front. A count that drops to zero after a rule
    lands is evidence the rule works, and the signal that a trap may be retirable.

    'sessions' matters as much as 'hits': 20 hits in one session is one bad afternoon, while 20
    hits across 15 sessions is a systemic trap that every new session walks into.

USAGE
    devkit trap-report                 # all recorded history
    devkit trap-report --since 2025-01 # only that month onward
    devkit trap-report --json
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _devkit_config  # noqa: E402

# Per-repo (devkit.toml [trap_hits]), with the same defaults as record_trap_hits.py: the two must
# agree about where the log lives, so they read the same keys through the same loader.
try:
    _CFG = _devkit_config.load()
    REPO = _CFG.root
    LOG_DIR_REL = _CFG.string("trap_hits.log_dir", "logs/trap-hits")
    LOG_DIR_ENV = _CFG.string("trap_hits.log_dir_env", "DEVKIT_TRAP_LOG_DIR")
except _devkit_config.ConfigError as _exc:
    _devkit_config.fatal("trap_report", _exc)


def _main_checkout() -> Path:
    """The MAIN checkout, matching record_trap_hits.py exactly.

    The log lives in the main checkout even when this runs from a worktree — otherwise the report
    silently reads an empty directory and prints "no records yet" while the real history sits
    elsewhere.
    """
    try:
        cp = subprocess.run(
            ["git", "worktree", "list", "--porcelain"],
            cwd=REPO,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if cp.returncode == 0 and cp.stdout.strip():
            # `git worktree list` prints the MAIN checkout first. record_trap_hits.py uses the
            # same derivation — deliberately the same mechanism, so the two cannot drift into
            # disagreeing about where the shared log lives.
            for ln in cp.stdout.splitlines():
                if ln.startswith("worktree "):
                    return Path(ln.split(" ", 1)[1].strip())
    except Exception:
        pass
    return REPO


# LOG_DIR_ENV (DEVKIT_TRAP_LOG_DIR here) mirrors record_trap_hits.py, so a redirected recorder can be
# read back by a redirected report. Kept symmetric deliberately: a writer and reader that disagree
# about where the log lives is the failure this whole file exists to make visible.
LOG_DIR = (
    Path(os.environ[LOG_DIR_ENV]) if os.environ.get(LOG_DIR_ENV) else _main_checkout() / LOG_DIR_REL
)


def load(since: str | None) -> list[dict]:
    recs: list[dict] = []
    if not LOG_DIR.is_dir():
        return recs
    for f in sorted(LOG_DIR.glob("*.jsonl")):
        if since and f.stem < since:
            continue
        for line in f.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except Exception:
                continue  # a corrupt line must never break the report
            if r.get("_event") == "trap_hit":
                recs.append(r)
    return recs


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--since", help="only months >= this YYYY-MM")
    ap.add_argument("--json", action="store_true", dest="as_json")
    args = ap.parse_args()

    recs = load(args.since)
    if not recs:
        print("trap_report: no records yet.")
        print(f"  expected at: {LOG_DIR}")
        print("  the recorder runs on PostToolUse for Write/Edit of .yml/.yaml files.")
        return 0

    hits: dict[str, int] = defaultdict(int)
    sessions: dict[str, set[str]] = defaultdict(set)
    files: dict[str, set[str]] = defaultdict(set)
    levels: dict[str, str] = {}

    for r in recs:
        for f in r.get("findings", []):
            rule = f.get("rule", "?")
            hits[rule] += 1
            levels[rule] = f.get("level", "?")
            if r.get("session"):
                sessions[rule].add(r["session"])
            files[rule].add(r.get("file", "?"))

    ranked = sorted(hits.items(), key=lambda kv: (-kv[1], kv[0]))

    if args.as_json:
        print(
            json.dumps(
                [
                    {
                        "rule": k,
                        "level": levels.get(k),
                        "hits": v,
                        "sessions": len(sessions[k]),
                        "files": len(files[k]),
                    }
                    for k, v in ranked
                ],
                indent=2,
            )
        )
        return 0

    print(f"trap_report — {len(recs)} recorded edit(s) carrying at least one finding\n")
    print(f"{'rule':20} {'lvl':5} {'hits':>5} {'sessions':>9} {'files':>6}")
    print("-" * 52)
    for rule, n in ranked:
        print(
            f"{rule:20} {levels.get(rule,'?'):5} {n:>5} {len(sessions[rule]):>9} {len(files[rule]):>6}"
        )
    print("\nWorst repeat offender first. High 'sessions' = a trap every new session walks into;")
    print("promote it to FAIL or give it a skill.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
