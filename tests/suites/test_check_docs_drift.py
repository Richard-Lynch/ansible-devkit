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

import re
import sys
import tempfile
from pathlib import Path

import _paths
from _paths import CHECKS, ROOT  # noqa: F401 — tests/suites/_paths.py

_paths.use_fixture_config()

sys.path.insert(0, str(CHECKS))

import _devkit_config  # noqa: E402
import check_docs_drift as cdd  # noqa: E402
from check_docs_drift import _enforced_rule_ids, _rule_source_command, check  # noqa: E402

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

    # `devkit:<check>` sources: a repository with no copy of the checks names them by check name.
    import subprocess

    cmd = _rule_source_command("devkit:silent-guards")
    record(
        cmd[1:5] == ["-m", "ansible_devkit.cli", "check", "silent-guards"]
        and cmd[-1] == "--list-rules",
        "devkit: source becomes `devkit check <name> --list-rules`",
        str(cmd),
    )
    cp = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=120)
    ids = set(re.findall(r"^([A-Z]+-[0-9]+)", cp.stdout, re.M))
    record(
        cp.returncode == 0 and {"META-01", "YAMLESC-01"} <= ids,
        f"the devkit: source lists the check's rules ({len(ids)} IDs)",
        cp.stdout[-500:] + cp.stderr[-500:],
    )
    try:
        _rule_source_command("devkit:Not A Check")
        record(False, "catch   a malformed devkit: name is refused")
    except _devkit_config.ConfigError:
        record(True, "catch   a malformed devkit: name is refused")
    real_cmd = cdd._rule_source_command
    cdd._rule_source_command = lambda rel: ["/nonexistent/python", "--list-rules"]
    try:
        cdd._enforced_rule_ids()
        record(False, "catch   a rule source that cannot run is a config error, not an empty set")
    except _devkit_config.ConfigError:
        record(True, "catch   a rule source that cannot run is a config error, not an empty set")
    finally:
        cdd._rule_source_command = real_cmd

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
