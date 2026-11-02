# SPDX-License-Identifier: GPL-3.0-or-later
"""Run every stand-alone suite under tests/suites/ as its own pytest case.

The suites were written as scripts, each printing a PASS/FAIL line per case and exiting non-zero on
any failure, so they can be run on their own (`uv run tests/suites/test_check_silent_guards.py`)
and by any CI without pytest. This file is the pytest face of the same thing: one parametrised
case per suite, discovered by glob — so a new suite dropped into tests/suites/ runs here with no
registration, and a suite that CI does not run cannot exist (which is what check-ci-covers-hook-
tests asserts about THIS file in turn).

Every suite runs with cwd = the repository root, because several checkers resolve the repository
they check from the working directory's git toplevel (see `_devkit_config.py`).
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SUITES = sorted((ROOT / "tests" / "suites").glob("test_*.py"))


def test_there_are_suites() -> None:
    assert len(SUITES) >= 15, [p.name for p in SUITES]


@pytest.mark.parametrize("suite", SUITES, ids=[p.name for p in SUITES])
def test_suite(suite: Path) -> None:
    env = {k: v for k, v in os.environ.items() if k != "DEVKIT_ROOT"}
    proc = subprocess.run(
        [sys.executable, str(suite)],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=900,
    )
    report = proc.stdout + proc.stderr
    assert proc.returncode == 0, f"{suite.name} exited {proc.returncode}\n{report[-6000:]}"
    # A suite that prints nothing has not run its cases; "0/0 passed" is not a pass. The suites
    # report in a few styles: per-case PASS/ok lines with an "N/M passed" total, unittest's
    # "Ran N tests ... OK", "ALL PASS" / "all passed", or "0 failure(s)" after PASS lines.
    total = re.search(r"(\d+)/(\d+) passed", report)
    ran = re.search(r"Ran (\d+) tests?", report)
    if total:
        assert total.group(1) == total.group(2) != "0", report[-2000:]
    elif ran:
        assert int(ran.group(1)) > 0 and "\nOK" in report, report[-2000:]
    else:
        positive = ("ALL PASS", "all passed", "0 failure(s)")
        assert any(m in report for m in positive), report[-2000:]
        assert re.search(r"^  (?:PASS|ok) ", report, re.M), report[-2000:]
