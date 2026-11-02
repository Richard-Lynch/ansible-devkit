#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""check_traps_are_checked — every trap in the rulebook must name a rule, or say why it cannot.

THE CONVENTION THIS ENFORCES
    A trap written down but not checked is a trap that recurs. A rulebook's trap list grows by
    accretion — every entry added after the trap has already cost time — and a bare `[you]` tag
    ("a human must remember this") hides two different claims: "nobody has written the rule yet"
    and "this cannot be checked mechanically". Only the second may stay; a trap left under the
    first keeps being hit while a FAIL rule would catch every instance.

    So: adding a trap to the rulebook means one of three tags, and this check enforces the choice.

      [FAIL <RULE-ID>]  a deterministic rule that gates CI
      [warn <RULE-ID>]  a heuristic rule with plausible false positives, reported not enforced
      [you: <reason>]   NOT mechanically checkable, and the reason says WHY

    The third form is deliberately more effort to write than the old bare `[you]`, because that is
    the whole point: "no machine check exists" must be an argued position, not a default. A reason
    that is really "nobody has tried yet" reads as exactly that under review.

WHAT COUNTS AS A REASON
    Anything non-empty — this check cannot judge quality, and pretending to would make it
    suppressible theatre. What it can do is force the sentence to exist, and make a bare `[you]`
    impossible to leave behind. Reviewers judge the sentence.

RELATED
    DOCRULE-01 (check_docs_drift.py) enforces the OTHER direction: every rule a checker can emit
    must be documented here. Together they keep the trap list and the rule set married.

Exit codes: 0 = clean, 1 = at least one untagged/unjustified trap, 2 = usage/internal error.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _devkit_config  # noqa: E402

# Per-repo data (devkit.toml [docs]): the rulebook checked by default, and the heading that opens
# its trap section. The heading is REQUIRED: a section that is never found is skipped, so a guessed
# default would make this check pass over a rulebook it never read.
try:
    _CFG = _devkit_config.load()
    REPO = _CFG.root
    RULEBOOK = _CFG.string("docs.rulebook", "RULES.md")
    TRAP_SECTION_START = _CFG.string("docs.trap_section")
except _devkit_config.ConfigError as _exc:
    _devkit_config.fatal("check_traps_are_checked", _exc)

# A Known-traps bullet: "- **[FAIL X-01]**", "- **[warn X-01]**", "- **[you]**", "- **[you: ...]**"
TRAP_BULLET_RE = re.compile(r"^\s*-\s+\*\*\[(?P<tag>[^\]]+)\]\*\*")
TAGGED_RULE_RE = re.compile(r"^(?:FAIL|warn)\s+[A-Z]+-\d+$")
YOU_WITH_REASON_RE = re.compile(r"^you\s*:\s*(?P<reason>\S.*)$")
BARE_YOU_RE = re.compile(r"^you$")


def check(path: Path) -> list[str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        return [f"{path}: cannot read ({exc})"]

    try:
        start = next(i for i, ln in enumerate(lines) if ln.startswith(TRAP_SECTION_START))
    except StopIteration:
        # No trap section is not a failure — this check is about the section's CONTENTS.
        return []

    problems: list[str] = []
    for i in range(start, len(lines)):
        line = lines[i]
        # Stop at the next top-level section.
        if i > start and line.startswith("## "):
            break
        m = TRAP_BULLET_RE.match(line)
        if not m:
            continue
        tag = m.group("tag").strip()
        # The LEGEND defines the tags ("- **[you]** — no machine check exists") and is not itself a
        # trap. A legend entry is a bare tag followed by an em-dash definition, with no trap text.
        if re.match(r"^\s*-\s+\*\*\[[^\]]+\]\*\*\s+—", line):
            continue
        if TAGGED_RULE_RE.match(tag) or YOU_WITH_REASON_RE.match(tag):
            continue
        if BARE_YOU_RE.match(tag):
            problems.append(
                f"{path.name}:{i + 1}: [TRAPTAG-01] trap tagged bare **[you]** with no reason. "
                "A trap nobody checks is a trap that recurs — the YAMLESC-01 escape trap sat as a "
                "bare [you] is how a detectable trap keeps being hit. Either write the rule and tag "
                "it [FAIL <ID>]/[warn <ID>], or state why it cannot be checked: "
                "**[you: <reason>]**."
            )
        elif not tag.startswith(("FAIL", "warn", "you")):
            # Some other bracket tag — not a trap bullet (e.g. a legend entry). Ignore quietly.
            continue
        else:
            problems.append(
                f"{path.name}:{i + 1}: [TRAPTAG-01] trap tag '{tag}' is malformed. Use "
                "**[FAIL <RULE-ID>]**, **[warn <RULE-ID>]**, or **[you: <reason>]**."
            )
    return problems


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("paths", nargs="*", default=[RULEBOOK])
    args = ap.parse_args()

    problems: list[str] = []
    scanned = 0
    for arg in args.paths:
        p = Path(arg)
        if not p.is_absolute():
            p = REPO / p
        if not p.is_file():
            print(f"FAIL {arg}: no such file")
            return 1
        scanned += 1
        problems.extend(check(p))

    for pr in problems:
        print(f"FAIL {pr}")
    print(f"\ncheck_traps_are_checked: {len(problems)} FAIL across {scanned} doc(s) scanned.")
    return 1 if problems else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # pragma: no cover
        print(f"check_traps_are_checked: internal error: {exc}", file=sys.stderr)
        sys.exit(2)
