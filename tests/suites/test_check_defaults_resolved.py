#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for RESOLVE-02 (check_defaults_resolved.py).

A check ships with BOTH directions: a fixture that must FAIL and a near-miss that must PASS. The
near-miss is not a formality here — a rule that pattern-matches the assignment is almost all
false positives (see the module docstring).
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

from _paths import CHECKS, ROOT  # noqa: F401 — tests/suites/_paths.py

CHECKER = CHECKS / "check_defaults_resolved.py"


def run(root: Path) -> tuple[int, str]:
    p = subprocess.run(
        [sys.executable, str(CHECKER), "--root", str(root)],
        capture_output=True,
        text=True,
    )
    return p.returncode, p.stdout + p.stderr


def make_role(root: Path, name: str, defaults: str, tasks: str = "", templates: str = "") -> None:
    r = root / "roles" / name
    (r / "defaults").mkdir(parents=True, exist_ok=True)
    (r / "defaults" / "main.yml").write_text(defaults)
    if tasks:
        (r / "tasks").mkdir(parents=True, exist_ok=True)
        (r / "tasks" / "setup_vars.yml").write_text(tasks)
    if templates:
        (r / "templates").mkdir(parents=True, exist_ok=True)
        (r / "templates" / "x.j2").write_text(templates)


FAILURES: list[str] = []


def expect(cond: bool, msg: str) -> None:
    if cond:
        print(f"  ok   {msg}")
    else:
        print(f"  FAIL {msg}")
        FAILURES.append(msg)


def main() -> int:
    # ---- MUST FAIL: one option resolved, one not ----------------------------------------------
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        make_role(
            root,
            "drifted",
            defaults="demo_a__default: false\ndemo_b__default: false\n",
            # The resolver reads demo_a and never reads demo_b.
            tasks='- name: Resolve\n  set_fact:\n    demo_a: "{{ demo_a | default(demo_a__default) }}"\n',
        )
        rc, out = run(root)
        expect(rc == 1, "FIXTURE: a default nothing reads exits 1")
        expect("demo_b__default" in out, "FIXTURE: names the unresolved option")
        expect("demo_a__default" not in out, "FIXTURE: does NOT flag the resolved one")

    # ---- NEAR MISS 1: folded scalar. The naive pattern-match version FAILED this. ---------
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        make_role(
            root,
            "folded",
            defaults="demo_window__default: 3600\n",
            tasks=(
                "- name: Resolve\n  set_fact:\n    demo_window: >-\n"
                "      {{ demo_window | default(demo_window__default) }}\n"
            ),
        )
        rc, out = run(root)
        expect(rc == 0, "NEAR MISS: a folded-scalar resolver line PASSES")

    # ---- NEAR MISS 2: resolved inline in a TEMPLATE -----------------------------------
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        make_role(
            root,
            "intemplate",
            defaults="docker_tcp_bind__default: 127.0.0.1:2376\n",
            templates="ExecStart=dockerd -H tcp://{{ docker_tcp_bind | default(docker_tcp_bind__default) }}\n",
        )
        rc, out = run(root)
        expect(rc == 0, "NEAR MISS: resolved inline in a template PASSES")

    # ---- NEAR MISS 3: a GENERATED resolver is skipped entirely (RESOLVE-01's guard) -------
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        make_role(
            root,
            "generated",
            defaults="anything__default: 1\nalso_missing__default: 2\n",
            tasks=(
                "- name: Resolve\n  when: not (_generated__argspec_resolved | default(false))\n"
                "  set_fact:\n    _generated__argspec_resolved: true\n"
            ),
        )
        rc, out = run(root)
        expect(rc == 0, "NEAR MISS: a generated (guarded) resolver is skipped")

    # ---- NEAR MISS 4: a role with no generated defaults at all ---------------------------
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        make_role(
            root, "plain", defaults="some_plain_var: true\n", tasks="- name: x\n  debug: {msg: y}\n"
        )
        rc, out = run(root)
        expect(rc == 0, "NEAR MISS: a role with no *__default vars PASSES")

    print()
    if FAILURES:
        print(f"check_defaults_resolved tests: {len(FAILURES)} FAILED")
        return 1
    print("check_defaults_resolved tests: all passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
