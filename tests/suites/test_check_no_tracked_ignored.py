#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for check_no_tracked_ignored.py (TRACKIGNORE-01 / SELFLINK-01).

Run:  uv run tests/suites/test_check_no_tracked_ignored.py

Each case is built in a THROWAWAY git repo, so the assertions are about the checker's logic rather
than about this repo's current contents. The catch cases reproduce the defect: a path that
.gitignore lists, force-added, whose content is an absolute self-referential symlink.

The near-misses are what stop this becoming noise — a tracked symlink with a RELATIVE target that
points somewhere real is a legitimate thing to commit, and so is any ordinary tracked file that no
ignore rule mentions.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

from _paths import CHECKS, ROOT  # noqa: F401 — tests/suites/_paths.py

SCRIPT = CHECKS / "check_no_tracked_ignored.py"
LOADER = CHECKS / "_devkit_config.py"


def git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True, timeout=60)


def new_repo(tmp: Path, name: str) -> Path:
    repo = tmp / name
    (repo / "checks").mkdir(parents=True)
    git(repo, "init", "-q")
    git(repo, "config", "user.email", "t@example.com")
    git(repo, "config", "user.name", "t")
    # The checker checks the repo it is RUN in (cwd's git toplevel), so it runs with cwd=repo;
    # the copy (and its loader) live in the fake repo too, so nothing resolves the real one.
    (repo / "checks" / SCRIPT.name).write_text(SCRIPT.read_text())
    (repo / "checks" / LOADER.name).write_text(LOADER.read_text())
    return repo


def run(repo: Path) -> tuple[int, str]:
    cp = subprocess.run(
        [sys.executable, str(repo / "checks" / SCRIPT.name)],
        cwd=repo,
        capture_output=True,
        text=True,
        timeout=120,
    )
    return cp.returncode, cp.stdout + cp.stderr


def main() -> int:
    failures: list[str] = []
    cases = 0

    with tempfile.TemporaryDirectory(prefix="tracked_ignored_test_") as td:
        tmp = Path(td)

        # ---- catch: the original shape, exactly ---------------------------------------------
        r = new_repo(tmp, "selflink")
        (r / ".gitignore").write_text("collections.galaxy/\ncollections.galaxy\n")
        (r / "collections.galaxy").symlink_to(r / "collections.galaxy")
        git(r, "add", ".gitignore")
        git(r, "add", "-f", "collections.galaxy")
        cases += 2
        rc, out = run(r)
        for rule, label in [
            ("TRACKIGNORE-01", "tracked despite being gitignored"),
            ("SELFLINK-01", "absolute self-referential symlink"),
        ]:
            ok = rule in out
            print(f"  {'PASS' if ok else 'FAIL'}  {rule} catch  {label}")
            if not ok:
                failures.append(f"{rule} did not fire on the self-link shape:\n{out}")

        # ---- exempt: an ordinary tracked file -----------------------------------------------
        r2 = new_repo(tmp, "ordinary")
        (r2 / ".gitignore").write_text("venv/\n")
        (r2 / "real.txt").write_text("hello\n")
        git(r2, "add", ".gitignore", "real.txt")
        cases += 1
        rc, out = run(r2)
        ok = "TRACKIGNORE-01" not in out and "SELFLINK-01" not in out
        print(f"  {'PASS' if ok else 'FAIL'}  exempt  an ordinary tracked file")
        if not ok:
            failures.append(f"false-positived on an ordinary file:\n{out}")

        # ---- exempt: a RELATIVE symlink to something real ----------------------------------
        r3 = new_repo(tmp, "relative")
        (r3 / ".gitignore").write_text("venv/\n")
        (r3 / "target.txt").write_text("x\n")
        (r3 / "link.txt").symlink_to("target.txt")
        git(r3, "add", ".gitignore", "target.txt", "link.txt")
        cases += 1
        rc, out = run(r3)
        ok = "SELFLINK-01" not in out
        print(f"  {'PASS' if ok else 'FAIL'}  exempt  relative symlink to a real file")
        if not ok:
            failures.append(f"false-positived on a legitimate relative symlink:\n{out}")

        # ---- catch: tracked-and-ignored, but NOT a symlink (a plain file) -------------------
        r4 = new_repo(tmp, "plainfile")
        (r4 / ".gitignore").write_text("secrets.env\n")
        (r4 / "secrets.env").write_text("K=v\n")
        git(r4, "add", ".gitignore")
        git(r4, "add", "-f", "secrets.env")
        cases += 1
        rc, out = run(r4)
        ok = "TRACKIGNORE-01" in out
        print(
            f"  {'PASS' if ok else 'FAIL'}  TRACKIGNORE-01 catch  gitignored plain file, force-added"
        )
        if not ok:
            failures.append(f"TRACKIGNORE-01 missed a force-added ignored file:\n{out}")

    print(f"\n{cases - len(failures)}/{cases} passed")
    for f in failures:
        print(f"  FAILED: {f}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
