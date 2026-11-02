#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for check_regex_anchors.py (ICASE-01).

Run:  uv run tests/suites/test_check_regex_anchors.py

Why each near-miss exists — every one is a false positive this rule actually produced:
  - a case-SENSITIVE `(?=[A-Z])` in a file that ALSO compiles something with IGNORECASE is the
    CORRECT fix for this trap, so a file-level flag test condemns the fix itself (it did);
  - a fixed 3-line window bled into the NEXT pattern's flags and flagged that same correct branch;
  - prose in a DOCSTRING describing the trap is not an instance of it — the rule's first two
    findings a rule like this produces are its own documentation and the fixtures that test it.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

from _paths import CHECKS, ROOT  # noqa: F401 — tests/suites/_paths.py

SCRIPT = CHECKS / "check_regex_anchors.py"


def run(path: Path) -> tuple[int, str]:
    p = subprocess.run(
        [sys.executable, str(SCRIPT), str(path)], capture_output=True, text=True, timeout=60
    )
    return p.returncode, p.stdout + p.stderr


CASES: list[tuple[str, str, bool, str]] = [
    (
        "bad.py",
        # regex-check: ignore ICASE-01 — this IS the bad pattern, as fixture data for the catch case
        'import re\nP = re.compile(r"(pass|token)(?=[A-Z])", re.IGNORECASE)\n',
        True,
        "[A-Z] lookaround under IGNORECASE",
    ),
    (
        "case_sensitive.py",
        'import re\nC = re.compile(r"(pass)(?=[A-Z])")\n'
        'S = re.compile(r"(pass)[_-]", re.IGNORECASE)\n',
        False,
        "case-SENSITIVE camelCase branch beside an IGNORECASE one (the fix)",
    ),
    (
        "both_cases.py",
        'import re\nB = re.compile(r"[A-Za-z]+(?=[A-Za-z])", re.IGNORECASE)\n',
        False,
        "class already spans both cases",
    ),
    (
        "no_icase.py",
        'import re\nN = re.compile(r"(pass)(?=[A-Z])")\n',
        False,
        "no IGNORECASE anywhere",
    ),
    (
        "docstring.py",
        'import re\n\n\ndef f():\n    """Under IGNORECASE a `(?=[A-Z])` boundary bounds nothing."""\n'
        '    return re.compile(r"x", re.IGNORECASE)\n',
        False,
        "prose in a docstring describing the trap",
    ),
    (
        "no_lookaround.py",
        'import re\nL = re.compile(r"[A-Z]+", re.IGNORECASE)\n',
        False,
        "[A-Z] not doing boundary work",
    ),
    (
        "suppressed.py",
        "import re\n# regex-check: ignore ICASE-01 — intentional, matched case-insensitively on purpose\n"
        'P = re.compile(r"(pass)(?=[A-Z])", re.IGNORECASE)\n',
        False,
        "suppression WITH a reason",
    ),
    (
        "bare_suppress.py",
        "import re\n# regex-check: ignore ICASE-01 —\n"
        'P = re.compile(r"(pass)(?=[A-Z])", re.IGNORECASE)\n',
        True,
        "bare suppression (no reason) does NOT suppress",
    ),
]


def main() -> int:
    failures = []
    with tempfile.TemporaryDirectory(prefix="regex_anchors_test_") as td:
        tmp = Path(td)
        for name, content, want, label in CASES:
            p = tmp / name
            p.write_text(content)
            rc, out = run(p)
            fired = "[ICASE-01]" in out
            ok = fired is want
            verb = "catch " if want else "exempt"
            print(f"  {'PASS' if ok else 'FAIL'}  ICASE-01 {verb} {label}")
            if not ok:
                failures.append(
                    f"ICASE-01 {'did not fire' if want else 'false-positived'} on {label}:\n{out}"
                )

    # --- the WORKTREE SKIP ------------------------------------------------------------------
    # A worktree is a full second checkout, so scanning it double-reports every finding against a
    # path that is not the one to fix. A skip spelt `claude/worktrees/` while worktrees live at
    # `.claude/worktrees/` matches NOTHING -- and no test of the rule itself notices, because
    # that covers the rule, never which files it chooses to look at.
    #
    # The skip is judged relative to the repo root (devkit.toml's root rule: the git toplevel of the
    # directory this suite runs from, which is this repo),
    # so this fixture must live under the real repo, not a tmpdir -- a tmpdir takes the ValueError
    # branch, compares an absolute path, and matches no prefix at all. That is precisely why the
    # obvious tmpdir version of this test would pass against BOTH the broken and fixed checker.
    repo = ROOT
    # regex-check: ignore ICASE-01 — fixture DATA for the skip cases, not a pattern this file uses
    bad = 'import re\nP = re.compile(r"(pass|token)(?=[A-Z])", re.IGNORECASE)\n'
    fixture = repo / ".claude" / "worktrees" / "_skiptest" / "inside.py"
    try:
        fixture.parent.mkdir(parents=True, exist_ok=True)
        fixture.write_text(bad)
        rc, out = run(fixture)
        skipped = "inside.py" not in out
        print(f"  {'PASS' if skipped else 'FAIL'}  skip    .claude/worktrees/ is SKIPPED")
        if not skipped:
            failures.append(f"worktree skip: .claude/worktrees/ was SCANNED:\n{out}")
    finally:
        if fixture.exists():
            fixture.unlink()
        for d in (fixture.parent, fixture.parent.parent):
            try:
                d.rmdir()
            except OSError:
                pass

    # The near-miss: a path that merely CONTAINS the word must still be scanned, so the skip
    # cannot quietly widen into "ignore anything with claude/worktrees in the name".
    near = CHECKS / "_skiptest_claude_worktrees_lookalike.py"
    try:
        near.write_text(bad)
        rc, out = run(near)
        scanned = near.name in out
        print(f"  {'PASS' if scanned else 'FAIL'}  skip    a look-alike path is still scanned")
        if not scanned:
            failures.append(f"worktree skip: look-alike path was wrongly skipped:\n{out}")
    finally:
        if near.exists():
            near.unlink()

    print(f"\n{len(CASES) + 2 - len(failures)}/{len(CASES) + 2} passed")
    for f in failures:
        print(f"  FAILED: {f}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
