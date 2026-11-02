#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Cases for check_docs_drift.py (DOCRULE-01) — including that the rule can actually FIRE.

A docs checker that silently passes everything is worse than none, because it certifies the drift.
So: a rulebook documenting one rule while the checkers enforce dozens must FAIL; a rulebook
documenting every rule — in either accepted form — must PASS; and the rule must be OPT-IN, since it
is a claim about the rulebook and not about markdown in general.

Run: uv run tests/suites/test_check_docs_drift.py   (from the repo root)
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import _paths
from _paths import CHECKS, ROOT  # noqa: F401 — tests/suites/_paths.py

_paths.use_fixture_config()

sys.path.insert(0, str(CHECKS))

from check_docs_drift import _enforced_rule_ids, check  # noqa: E402

FAILURES: list[str] = []
CASES = 0


def record(ok: bool, label: str, detail: str = "") -> None:
    global CASES
    CASES += 1
    print(f"  {'PASS' if ok else 'FAIL'}  {label}")
    if not ok:
        FAILURES.append(f"{label}\n{detail}")


def main() -> int:
    enforced = _enforced_rule_ids()
    record(len(enforced) > 10, f"the configured sources enumerate rules ({len(enforced)})")

    with tempfile.TemporaryDirectory(prefix="docrule_") as td:
        tmp = Path(td)

        thin = tmp / "RULES.md"
        thin.write_text("Only one trap here: **[FAIL META-01]** and nothing else.\n")
        problems = check(thin, check_rule_coverage=True)
        record(
            any("[DOCRULE-01]" in p for p in problems) and len(problems) == len(enforced) - 1,
            "catch   an under-documented rulebook: one finding per missing rule",
            "\n".join(problems),
        )
        record(
            not check(thin),
            "opt-in  silent on a plain snippet (coverage is a claim about the RULEBOOK)",
        )

        tagged = tmp / "tagged.md"
        tagged.write_text("".join(f"- **[FAIL {r}]** a rule.\n" for r in sorted(enforced)))
        record(
            check(tagged, check_rule_coverage=True) == [],
            "exempt  every rule documented as a [FAIL ...] tag passes",
        )

        ticked = tmp / "ticked.md"
        ticked.write_text("".join(f"Checked by `{r}`.\n" for r in sorted(enforced)))
        record(
            check(ticked, check_rule_coverage=True) == [],
            "exempt  every rule documented in backticks passes",
        )

        # The near-miss: a bare mention without either form is NOT documentation of the rule.
        bare = tmp / "bare.md"
        bare.write_text("".join(f"Something about {r} here.\n" for r in sorted(enforced)))
        record(
            len(check(bare, check_rule_coverage=True)) == len(enforced),
            "catch   a bare mention (no tag, no backticks) does not count",
        )

        missing = tmp / "gone.md"
        record(
            check(missing, check_rule_coverage=True) and "cannot read" in check(missing)[0],
            "an unreadable document is a finding, never a pass",
        )

    # The real document: this package's own rulebook must document every rule its checkers emit.
    real = ROOT / "docs" / "RULES.md"
    problems = check(real, check_rule_coverage=True)
    record(real.is_file() and not problems, "the REAL docs/RULES.md documents every enforced rule",
           "\n".join(problems))  # fmt: skip

    print(f"\n{CASES - len(FAILURES)}/{CASES} passed")
    for f in FAILURES:
        print(f"  FAILED: {f}")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
