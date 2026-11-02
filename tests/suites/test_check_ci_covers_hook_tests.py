#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for check_ci_covers_hook_tests.py.

Run:  uv run tests/suites/test_check_ci_covers_hook_tests.py

The FAIL fixture is the whole point: this check's job is to notice an omission, and a check that
has never been observed failing is indistinguishable from one that cannot fail. So the cases are
(a) the real repo passes, (b) a planted suite that no workflow runs is CAUGHT, and (c) a planted
suite that IS named in a workflow is exempt — proving the check reads the workflows rather than
just counting files.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from _paths import CHECKS, ROOT  # noqa: F401 — tests/suites/_paths.py

SCRIPT = CHECKS / "check_ci_covers_hook_tests.py"
LOADER = CHECKS / "_devkit_config.py"
REPO = ROOT


def run(repo: Path) -> tuple[int, str]:
    # A planted copy of the checker in the fixture repo, else the packaged one (the real repo).
    exe = repo / "checks" / SCRIPT.name
    if not exe.is_file():
        exe = SCRIPT
    p = subprocess.run(
        [sys.executable, str(exe)],
        cwd=repo,
        capture_output=True,
        text=True,
        timeout=60,
    )
    return p.returncode, p.stdout + p.stderr


def main() -> int:
    failures: list[str] = []
    cases = 0

    # (a) the real repo must pass
    cases += 1
    rc, out = run(REPO)
    ok = rc == 0
    print(f"  {'PASS' if ok else 'FAIL'}  the real repo: every suite is run by a workflow")
    if not ok:
        failures.append(f"real repo failed:\n{out}")

    # (b)+(c) planted suites in a throwaway copy of the tree
    with tempfile.TemporaryDirectory(prefix="ci_covers_test_") as td:
        tmp = Path(td) / "repo"
        (tmp / "checks").mkdir(parents=True)
        (tmp / ".github" / "workflows").mkdir(parents=True)
        shutil.copy(SCRIPT, tmp / "checks" / SCRIPT.name)
        shutil.copy(LOADER, tmp / "checks" / LOADER.name)

        # (d) no devkit.toml: the suite directories are repo data with no default, so the check
        # must refuse (exit 2, naming the key) rather than report a clean repo it never looked at.
        cases += 1
        rc, out = run(tmp)
        loud = rc == 2 and "ci_coverage.suite_dirs" in out
        print(f"  {'PASS' if loud else 'FAIL'}  no devkit.toml: exits 2 naming the missing key")
        if not loud:
            failures.append(f"missing config was not loud (rc={rc}):\n{out}")
        (tmp / "devkit.toml").write_text('[ci_coverage]\nsuite_dirs = ["checks"]\n')

        (tmp / "checks" / "test_covered.py").write_text("# covered\n")
        (tmp / "checks" / "test_forgotten.py").write_text("# forgotten\n")
        (tmp / ".github" / "workflows" / "ci.yml").write_text(
            "on: [pull_request]\njobs:\n  v:\n    steps:\n"
            "      - run: python3 checks/test_covered.py\n"
        )

        cases += 1
        rc, out = run(tmp)
        caught = rc == 1 and "test_forgotten.py" in out
        exempt = "MISSING  test_covered.py" not in out
        print(f"  {'PASS' if caught else 'FAIL'}  catches a suite no workflow runs")
        if not caught:
            failures.append(f"did not catch the forgotten suite (rc={rc}):\n{out}")

        cases += 1
        print(f"  {'PASS' if exempt else 'FAIL'}  exempts a suite a workflow does run")
        if not exempt:
            failures.append(f"false-positived on the covered suite:\n{out}")

    print(f"\n{cases - len(failures)}/{cases} passed")
    for f in failures:
        print(f"  FAILED: {f}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
