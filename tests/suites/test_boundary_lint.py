#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Cases for boundary_lint.py: a configured estate fact in an engine path, and the two modes.

The registry runs boundary-lint with `--enforce` (so `devkit check all` gates), and a consuming
repository still working off a backlog runs `devkit check boundary-lint --warn`, which must stay a
REPORT: exit 0 with the findings printed. Three directions: an estate fact under an engine root is
found; `--enforce` exits 1 on it and `--enforce --warn` (what the registry plus the caller produce)
exits 0 on it; a data path (exempt) and a clean file are not findings.

Run: uv run tests/suites/test_boundary_lint.py   (from the repo root)
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

from _paths import CHECKS  # tests/suites/_paths.py

SCRIPT = CHECKS / "boundary_lint.py"

CONFIG = """
[boundary]
engine_roots = ["roles"]
exempt_substr = ["/vars/"]
exempt_basenames = []
patterns = [
  { regex = '\\b192\\.0\\.2\\.\\d{1,3}\\b', label = "fixture TEST-NET IP" },
]
"""

FAILURES: list[str] = []
CASES = 0


def record(ok: bool, label: str, detail: str = "") -> None:
    global CASES
    CASES += 1
    print(f"  {'PASS' if ok else 'FAIL'}  {label}")
    if not ok:
        FAILURES.append(f"{label}\n{detail}")


def run(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = {k: v for k, v in os.environ.items() if k != "DEVKIT_ROOT"}
    env["DEVKIT_ROOT"] = str(repo)
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args], cwd=repo, env=env, capture_output=True, text=True
    )


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="boundary_") as td:
        repo = Path(td)
        (repo / "devkit.toml").write_text(CONFIG)
        (repo / "roles" / "r" / "tasks").mkdir(parents=True)
        (repo / "roles" / "r" / "vars").mkdir(parents=True)
        (repo / "roles" / "r" / "tasks" / "main.yml").write_text(
            "- name: ping the gateway\n  ansible.builtin.command: ping -c1 192.0.2.1\n"
        )
        (repo / "roles" / "r" / "vars" / "main.yml").write_text("r_gateway: 192.0.2.1\n")
        (repo / "roles" / "r" / "tasks" / "clean.yml").write_text(
            "- name: ping the gateway\n  ansible.builtin.command: ping -c1 {{ r_gateway }}\n"
        )

        warn = run(repo, "--warn")
        record(warn.returncode == 0, "--warn exits 0 with findings (a report)", warn.stderr)
        record("tasks/main.yml:2" in warn.stdout, "the engine-path fact is found", warn.stdout)
        record(
            "vars/main.yml" not in warn.stdout, "near-miss: the exempt data path is not a finding"
        )
        record("clean.yml" not in warn.stdout, "near-miss: a templated reference is not a finding")
        record("1 estate-fact leak(s)" in warn.stderr, "exactly one leak counted", warn.stderr)

        enforce = run(repo, "--enforce")
        record(enforce.returncode == 1, "--enforce exits 1 on a finding", enforce.stderr)

        both = run(repo, "--enforce", "--warn")
        record(
            both.returncode == 0 and "[WARN]" in both.stderr,
            "--enforce --warn (registry + caller) is still a report: --warn wins",
            both.stderr,
        )

        (repo / "roles" / "r" / "tasks" / "main.yml").write_text(
            "- name: ping the gateway\n  ansible.builtin.command: ping -c1 {{ r_gateway }}\n"
        )
        clean = run(repo, "--enforce")
        record(
            clean.returncode == 0 and "0 estate-fact leak(s)" in clean.stderr,
            "a clean tree exits 0 enforcing",
        )

    print(f"\n{CASES - len(FAILURES)}/{CASES} passed")
    for f in FAILURES:
        print(f"  FAILED: {f}")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
