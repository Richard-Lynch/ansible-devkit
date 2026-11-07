#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Fail if a rule the checkers ENFORCE is documented nowhere in the rulebook (DOCRULE-01).

WHY THIS EXISTS. A repo's rulebook (devkit.toml `docs.rulebook`) and the rule set in its checkers
are two hand-maintained lists describing the same thing, so they drift: a rule gets ENFORCED by a
checker and mentioned nowhere in the document that is supposed to explain it, and a reader of the
rulebook meets a CI failure citing a rule the rulebook has never heard of. A CI failure nobody can
look up is unactionable.

  DOCRULE-01  every rule ID a configured checker can emit appears in the rulebook, either as a
              trap tag (`[FAIL RULE-01]` / `[warn RULE-01]`) or in backticks where its mechanism
              is explained.

The rule IDs come from the checkers themselves: every path in devkit.toml `docs.rule_sources` is
run with `--list-rules` and its output parsed. Derived from the code rather than kept as a second
list here — a checker that hard-codes the ruleset it is verifying would drift in exactly the way
this rule exists to catch. The reverse direction (documented but unimplemented) is deliberately
NOT checked: a trap documented with no machine check is the honest state for most of them.

This is the generic half of a wider docs-drift check; a repo may add its own rules (paths that
must resolve, counts that must not be hard-coded) beside it.

Run: devkit check docs-drift [RULEBOOK ...]      (default: devkit.toml docs.rulebook)
Exit: 0 clean, 1 findings, 2 config error (a rule source missing or unable to list its rules).
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _devkit_config  # noqa: E402

# The repo is the one this runs in (devkit.toml's root rule). The rulebook's name and the checkers
# whose --list-rules define the enforced rule set are per-repo data in devkit.toml [docs].
try:
    _CFG = _devkit_config.load()
    REPO = _CFG.root
    RULEBOOK = _CFG.string("docs.rulebook", "RULES.md")
except _devkit_config.ConfigError as _exc:
    _devkit_config.fatal("check_docs_drift", _exc)

RULE_ID = re.compile(r"^([A-Z]+-[0-9]+)", re.MULTILINE)
TAGGED = re.compile(r"\[(?:FAIL|warn) ([A-Z]+-[0-9]+)\]")
BACKTICKED = re.compile(r"`([A-Z]+-[0-9]+)`")


DEVKIT_SOURCE = "devkit:"


def _rule_source_command(rel: str) -> list[str]:
    """The `--list-rules` command for one `docs.rule_sources` entry.

    Two forms. A repo path (`scripts/hooks/check_x.py`) runs that script. `devkit:<check>` names a
    check THIS package provides and runs `devkit check <name> --list-rules` through the same
    interpreter, so a consuming repository that deleted its own copies of the generic checks can
    still have DOCRULE-01 compare its rulebook against the rules it actually enforces. An unknown
    check name makes devkit exit non-zero, which the caller turns into a ConfigError — never an
    empty, vacuously-satisfied set.
    """
    if rel.startswith(DEVKIT_SOURCE):
        name = rel[len(DEVKIT_SOURCE) :]
        if not re.fullmatch(r"[a-z][a-z0-9-]*", name):
            raise _devkit_config.ConfigError(
                f"docs.rule_sources entry '{rel}': a devkit check name is lowercase words and hyphens"
            )
        return [sys.executable, "-m", "ansible_devkit.cli", "check", name, "--list-rules"]
    exe = REPO / rel
    if not exe.is_file():
        raise _devkit_config.ConfigError(
            f"docs.rule_sources names '{rel}', which does not exist under {REPO}"
        )
    return [sys.executable, str(exe), "--list-rules"]


def _enforced_rule_ids() -> set[str]:
    """Every rule ID the configured checkers can actually emit, from their own --list-rules."""
    ids: set[str] = set()
    # REQUIRED, and each source must exist: an empty or stale list would make DOCRULE-01 vacuously
    # true, which is a silent guard in the checker that exists to catch them.
    for rel in _CFG.str_list("docs.rule_sources"):
        try:
            cp = subprocess.run(
                _rule_source_command(rel),
                cwd=REPO,
                capture_output=True,
                text=True,
                timeout=60,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            # A source that cannot even START (interpreter missing, timeout) must not contribute
            # an empty set: DOCRULE-01 would then pass on every rule it would have listed.
            raise _devkit_config.ConfigError(f"`{rel} --list-rules` could not run: {exc}") from exc
        if cp.returncode != 0:
            # A source that cannot list its rules (its own config error, say) contributes none,
            # and DOCRULE-01 would then pass vacuously for every rule it enforces.
            raise _devkit_config.ConfigError(
                f"`{rel} --list-rules` exited {cp.returncode}: {cp.stderr.strip()[:300]}"
            )
        ids |= set(RULE_ID.findall(cp.stdout))
    return ids


def check(path: Path, *, check_rule_coverage: bool = False) -> list[str]:
    """DOCRULE-01 over one document.

    Document-level, not line-level: a rule ID may be documented anywhere in the file. It is also a
    claim about the RULEBOOK specifically, so it is opt-in — applying it to an arbitrary markdown
    snippet would flag every rule as undocumented.
    """
    try:
        text = path.read_text(errors="replace")
    except OSError as exc:
        return [f"{path}: cannot read ({exc})"]
    if not check_rule_coverage:
        return []
    documented = set(TAGGED.findall(text)) | set(BACKTICKED.findall(text))
    return [
        f"{path.name}: [DOCRULE-01] rule '{rule}' is ENFORCED by a checker but appears nowhere in "
        f"this document. A CI failure citing a rule the rulebook never mentions is unactionable. "
        f"Add it to the trap section tagged [FAIL {rule}] or [warn {rule}], or as `{rule}` where "
        f"its mechanism is explained."
        for rule in sorted(_enforced_rule_ids() - documented)
    ]


def main(argv: list[str]) -> int:
    args = argv[1:] or [RULEBOOK]
    problems: list[str] = []
    scanned = 0
    for arg in args:
        path = Path(arg)
        if not path.is_absolute():
            path = REPO / path
        if not path.is_file():
            print(f"FAIL {arg}: no such file")
            return 1
        scanned += 1
        # Rule coverage applies to the rulebook itself, not to any doc passed in.
        try:
            problems.extend(check(path, check_rule_coverage=(path.name == Path(RULEBOOK).name)))
        except _devkit_config.ConfigError as exc:
            _devkit_config.fatal("check_docs_drift", exc)

    for p in problems:
        print(f"FAIL {p}")
    print(f"\ncheck_docs_drift: {len(problems)} FAIL across {scanned} doc(s) scanned.")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
