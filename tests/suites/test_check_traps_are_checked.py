#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for check_traps_are_checked.py (TRAPTAG-01).

Run:  uv run tests/suites/test_check_traps_are_checked.py

The case that matters most is the REAL rulebook (this package's docs/RULES.md): a synthetic fixture
would pass forever while the document drifted back to bare `[you]` bullets, which is precisely the failure this rule exists to
prevent. The legend exemption is here because the rule would otherwise flag the legend — the
three lines that DEFINE the tags are not themselves traps.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

from _paths import CHECKS, ROOT  # noqa: F401 — tests/suites/_paths.py
import _paths

_paths.use_fixture_config()

SCRIPT = CHECKS / "check_traps_are_checked.py"
REAL_DOC = ROOT / "docs" / "RULES.md"

HEADER = "## Known traps in this codebase\n\n"


def run(path: Path) -> tuple[int, str]:
    p = subprocess.run(
        [sys.executable, str(SCRIPT), str(path)], capture_output=True, text=True, timeout=60
    )
    return p.returncode, p.stdout + p.stderr


CASES: list[tuple[str, str, bool, str]] = [
    (
        "bare_you.md",
        HEADER + "- **[you]** **Something nobody checks.** It bites regularly.\n",
        True,
        "bare [you] with no reason",
    ),
    (
        "you_with_reason.md",
        HEADER + "- **[you: needs runtime state this checker cannot model]** **Something.**\n",
        False,
        "[you: reason] is accepted",
    ),
    (
        "fail_tagged.md",
        HEADER + "- **[FAIL PIPEQ-01]** **A checked trap.**\n",
        False,
        "[FAIL RULE-ID] is accepted",
    ),
    (
        "warn_tagged.md",
        HEADER + "- **[warn DIGRC-01]** **A heuristic trap.**\n",
        False,
        "[warn RULE-ID] is accepted",
    ),
    (
        "legend.md",
        HEADER
        + "- **[FAIL]** — a deterministic rule; CI will not merge it.\n"
        + "- **[you: <reason>]** — no machine check exists, AND the reason says why.\n",
        False,
        "the LEGEND defining the tags is not a trap",
    ),
    (
        "outside_section.md",
        "## Other conventions\n\n- **[you]** **Not in the traps section.**\n",
        False,
        "bullets outside the Known-traps section are out of scope",
    ),
    (
        "no_section.md",
        "# A doc with no trap section at all\n\nProse only.\n",
        False,
        "a doc with no trap section passes",
    ),
]


def main() -> int:
    failures = []
    with tempfile.TemporaryDirectory(prefix="traptag_test_") as td:
        tmp = Path(td)
        for name, content, want, label in CASES:
            p = tmp / name
            p.write_text(content)
            rc, out = run(p)
            fired = "[TRAPTAG-01]" in out
            ok = fired is want
            verb = "catch " if want else "exempt"
            print(f"  {'PASS' if ok else 'FAIL'}  TRAPTAG-01 {verb} {label}")
            if not ok:
                failures.append(
                    f"TRAPTAG-01 {'did not fire' if want else 'false-positived'} on {label}:\n{out}"
                )

    total = len(CASES)
    if REAL_DOC.is_file():
        total += 1
        rc, out = run(REAL_DOC)
        ok = rc == 0
        print(f"  {'PASS' if ok else 'FAIL'}  the REAL docs/RULES.md has no untagged traps")
        if not ok:
            failures.append(f"real docs/RULES.md has untagged traps:\n{out}")

    print(f"\n{total - len(failures)}/{total} passed")
    for f in failures:
        print(f"  FAILED: {f}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
