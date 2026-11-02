#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for record_trap_hits.py — the PostToolUse trap-hit recorder.

Run:  uv run tests/suites/test_record_trap_hits.py

WHAT THESE PROVE, and why each case exists:

  1. The log resolves to the MAIN checkout, from a worktree as well as from the main checkout.
     Without it a relative path puts the log in whichever checkout ran the edit, and
     `git worktree remove` then deletes it. The
     recorder must agree with whatever else derives the main checkout (a Makefile's run-log
     dir, trap_report.py) — and agree by using the SAME derivation (`git worktree list`, main
     checkout printed first), not a second mechanism that happens to return the same answer today.

  2. It ALWAYS exits 0, for every malformed input. It runs on PostToolUse in front of every edit,
     so a recorder that can fail is a new failure mode added to every Write/Edit. Telemetry must
     never be able to cost you the edit it is observing.

  3. It records a real finding, and ignores what it should ignore (non-YAML, other tools, missing
     files) — otherwise "0 records" is indistinguishable between "clean tree" and "recorder broken",
     which is the silent-guard shape.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from _paths import CHECKS, ROOT  # noqa: F401 — tests/suites/_paths.py

SCRIPT = CHECKS / "record_trap_hits.py"
REPO = ROOT


def run(payload: str, log_dir: Path | None = None) -> tuple[int, str]:
    """Invoke the recorder. `log_dir` redirects its output via DEVKIT_TRAP_LOG_DIR so these tests
    never write into the repository's own trap-hit log."""
    env = dict(os.environ)
    if log_dir is not None:
        env["DEVKIT_TRAP_LOG_DIR"] = str(log_dir)
    p = subprocess.run(
        [sys.executable, str(SCRIPT)],
        input=payload,
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
    )
    return p.returncode, p.stdout + p.stderr


def worktree_list_main_checkout() -> str:
    """The first entry of `git worktree list` — the derivation every reader of the log must share."""
    cp = subprocess.run(
        ["git", "worktree", "list", "--porcelain"],
        cwd=REPO,
        capture_output=True,
        text=True,
    )
    for ln in cp.stdout.splitlines():
        if ln.startswith("worktree "):
            return ln.split(" ", 1)[1].strip()
    return ""


def main() -> int:
    failures: list[str] = []
    cases = 0

    # ---- 1. agrees with `git worktree list`, and is the SAME mechanism -----------------------------
    sys.path.insert(0, str(SCRIPT.parent))
    from record_trap_hits import main_checkout  # noqa: E402

    cases += 1
    want = worktree_list_main_checkout()
    got = str(main_checkout())
    ok = want and got == want
    print(f"  {'PASS' if ok else 'FAIL'}  log dir resolves to the MAIN checkout ({got})")
    if not ok:
        failures.append(f"main_checkout()={got!r} but `git worktree list` says {want!r}")

    cases += 1
    src = SCRIPT.read_text()
    ok = "git-common-dir" not in src and '"worktree", "list"' in src
    print(
        f"  {'PASS' if ok else 'FAIL'}  derives it from `git worktree list` (never git-common-dir)"
    )
    if not ok:
        failures.append(
            "recorder must derive the main checkout from `git worktree list`, the derivation "
            "trap_report.py shares, or the two can drift apart"
        )

    # ---- 2. never fails, whatever it is handed ---------------------------------------------
    for label, payload in [
        ("empty stdin", ""),
        ("not json", "not json at all"),
        ("empty object", "{}"),
        ("no tool_input", '{"tool_name":"Edit"}'),
        ("missing file", '{"tool_name":"Edit","tool_input":{"file_path":"/nope/x.yml"}}'),
        ("null file_path", '{"tool_name":"Edit","tool_input":{"file_path":null}}'),
        ("unicode path", '{"tool_name":"Edit","tool_input":{"file_path":"/tmp/\\u00e9.yml"}}'),
    ]:
        cases += 1
        rc, out = run(payload)
        ok = rc == 0
        print(f"  {'PASS' if ok else 'FAIL'}  exits 0 on {label}")
        if not ok:
            failures.append(f"nonzero exit ({rc}) on {label}: {out}")

    # ---- 3. records what it should, ignores what it should ---------------------------------
    with tempfile.TemporaryDirectory(prefix="trap_hits_test_") as td:
        tmp = Path(td)
        buggy = tmp / "buggy.yml"
        buggy.write_text(
            "---\n- hosts: localhost\n  tasks:\n    - ansible.builtin.set_fact:\n"
            "        n: >-\n          {{ s.split('\\n') | length }}\n"
        )
        clean = tmp / "clean.yml"
        clean.write_text(
            "---\n- hosts: localhost\n  tasks:\n    - ansible.builtin.set_fact:\n"
            "        n: \"{{ s.split('\\n') | length }}\"\n"
        )
        notyaml = tmp / "notes.txt"
        notyaml.write_text("nothing to see")

        log = tmp / "trap-log"  # NOT the real log — see run()

        def count() -> int:
            if not log.is_dir():
                return 0
            return sum(
                1
                for f in log.glob("*.jsonl")
                for line in f.read_text().splitlines()
                if line.strip()
            )

        # (label, tool_name, target file, expected new records)
        record_cases: list[tuple[str, str, Path, int]] = [
            ("a YAML file with a trap", "Edit", buggy, 1),
            ("a clean YAML file", "Edit", clean, 0),
            ("a non-YAML file", "Write", notyaml, 0),
            ("a non-edit tool", "Bash", buggy, 0),
        ]
        for label, tool_name, target, want_delta in record_cases:
            cases += 1
            before = count()
            rc, out = run(
                json.dumps(
                    {
                        "tool_name": tool_name,
                        "session_id": "selftest",
                        "tool_input": {"file_path": str(target)},
                    }
                ),
                log_dir=log,
            )
            delta = count() - before
            ok = rc == 0 and delta == want_delta
            print(
                f"  {'PASS' if ok else 'FAIL'}  {label}: {delta} record(s) "
                f"(expected {want_delta})"
            )
            if not ok:
                failures.append(f"{label}: rc={rc} delta={delta} want={want_delta} {out}")

    print(f"\n{cases - len(failures)}/{cases} passed")
    for f in failures:
        print(f"  FAILED: {f}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
