#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""check_ci_covers_hook_tests — every hook test suite on disk must be RUN by CI.

WHY THIS EXISTS
    A CI workflow that enumerates its test suites by hand, as literal `python3 <dir>/test_*.py`
    lines, forgets one silently: the suite passes locally, the local aggregate is green, the PR
    is green — and the suite simply never runs in CI. Nothing reports a suite that isn't there,
    and two authors adding suites in the same week conflict in that one hand-maintained list.

    Deleting a line from the workflow is also a FAIL rather than a quiet loss of coverage.

WHAT THIS IS NOT
    It is not a replacement for the split between the stdlib-only group (runs on EVERY change,
    docs included) and the PyYAML group (skipped on a docs-only change). This check only proves a
    suite is referenced SOMEWHERE in the workflow — deciding which group it belongs in is a
    judgement about its imports, and is left to the author. The check tells you that you forgot;
    it does not guess where it goes.

USAGE
    devkit check ci-covers-hook-tests

Exit codes: 0 = every suite is referenced, 1 = at least one is not, 2 = usage/internal error.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _devkit_config  # noqa: E402

# Per-repo data (devkit.toml [ci_coverage]). The suite directories are REQUIRED: where a repo keeps
# its test suites is not guessable, and a wrong guess finds no suites.
# Workflows that may satisfy the requirement. A suite run by a dedicated workflow is covered, and
# need not also appear in the primary one — what matters is that SOME workflow runs it.
try:
    _CFG = _devkit_config.load()
    REPO = _CFG.root
    SUITE_DIRS = _CFG.str_list("ci_coverage.suite_dirs")
    WORKFLOW_DIR = REPO / _CFG.string("ci_coverage.workflow_dir", ".github/workflows")
    PRIMARY_WORKFLOW = _CFG.string("ci_coverage.primary_workflow", ".github/workflows/ci.yml")
except _devkit_config.ConfigError as _exc:
    _devkit_config.fatal("check_ci_covers_hook_tests", _exc)


def main() -> int:
    for rel in SUITE_DIRS:
        if not (REPO / rel).is_dir():
            print(f"check_ci_covers_hook_tests: no such directory: {REPO / rel}", file=sys.stderr)
            return 2
    if not WORKFLOW_DIR.is_dir():
        print(f"check_ci_covers_hook_tests: no such directory: {WORKFLOW_DIR}", file=sys.stderr)
        return 2

    workflows = sorted(WORKFLOW_DIR.glob("*.yml")) + sorted(WORKFLOW_DIR.glob("*.yaml"))
    blob = "\n".join(w.read_text(encoding="utf-8") for w in workflows)

    suites = sorted(p.name for rel in SUITE_DIRS for p in (REPO / rel).glob("test_*.py"))
    if not suites:
        print("check_ci_covers_hook_tests: found no test_*.py suites — that is itself suspicious.")
        return 1

    missing = [s for s in suites if s not in blob]

    for s in suites:
        print(f"  {'MISSING' if s in missing else 'ok     '}  {s}")

    if missing:
        names = ", ".join(missing)
        print(
            f"\ncheck_ci_covers_hook_tests: {len(missing)} FAIL — these suites exist but NO "
            f"workflow runs them: {names}\n"
            "  A suite CI never runs is worse than no suite: it is green locally, green on the PR, "
            "and silently absent from the gate.\n"
            f"  Fix: add `python3 {SUITE_DIRS[0]}/<suite>` to the right group in "
            f"{PRIMARY_WORKFLOW} —\n"
            "  the stdlib-only group (runs on every change, docs included) or the PyYAML group "
            "(skipped on docs-only).\n"
            "  If the suite shells out to a script that imports PyYAML, it belongs in the PyYAML "
            "group even if it is stdlib-only itself.",
            file=sys.stderr,
        )
        return 1

    print(
        f"\ncheck_ci_covers_hook_tests: 0 FAIL — all {len(suites)} hook test suite(s) are run by "
        f"a workflow."
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # pragma: no cover
        print(f"check_ci_covers_hook_tests: internal error: {exc}", file=sys.stderr)
        sys.exit(2)
