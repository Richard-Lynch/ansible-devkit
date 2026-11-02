#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""check_regex_anchors — patterns in this repo's PYTHON that look anchored and are not.

WHY A SEPARATE CHECKER
    check_silent_guards.py scans .yml/.yaml only (SCAN_SUFFIXES), so a rule about Python regex
    literals placed there is a rule that can never fire — the exact defect that file exists to
    catch. This checker walks scripts/ and roles/*/files/*.py instead.

    The rules here are the Python-source half of the "a pattern that looks anchored and is not"
    family (REGEX-01, REGEX-02, the \\b trap) that check_silent_guards.py covers for YAML/Jinja.

  ICASE-01  an upper-case-only class ([A-Z]) doing boundary work in a pattern compiled with
            re.IGNORECASE. Under that flag [A-Z] matches lower case too, so a lookaround written
            as a camelCase boundary accepts ANY letter and bounds nothing.

            Example: `(pass|token|secret)(?=[A-Z])` under IGNORECASE flags `compass`,
            `passthrough` and `tokenizer` as credentials while `PrivateKey` slips through —
            simultaneously noisy and blind, in a checker that guards against committing secrets.

            Fix: keep a case-SENSITIVE branch for the camelCase boundary, and scope `(?i:...)` to
            the delimiter-bounded (snake_case) branch, where a `_`/`-` does the bounding and case
            cannot blur it.

SUPPRESSION
    `# regex-check: ignore ICASE-01 — <reason>` on the flagged line or the line above. A bare
    suppression with no reason does not suppress (same discipline as check_silent_guards).

Exit codes: 0 = clean, 1 = at least one finding, 2 = usage/internal error.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _devkit_config  # noqa: E402

# Per-repo data (devkit.toml [regex_anchors]): which Python trees to scan by default (required — a
# guessed default would scan nothing in a repo laid out differently, and report clean), and which
# repo-relative prefixes are never scanned (a second checkout, the venv).
try:
    _CFG = _devkit_config.load()
    REPO = _CFG.root
    DEFAULT_ROOTS = tuple(_CFG.str_list("regex_anchors.paths"))
    EXCLUDE_PREFIXES = tuple(
        _CFG.str_list("regex_anchors.exclude_prefixes", ["venv/", ".claude/worktrees/"])
    )
except _devkit_config.ConfigError as _exc:
    _devkit_config.fatal("check_regex_anchors", _exc)

# A class containing A-Z but no a-z: [A-Z], [A-Z0-9], [^A-Z] ...
UPPER_ONLY_CLASS_RE = re.compile(r"\[\^?[^\]]*A-Z[^\]]*\]")
LOWER_IN_CLASS_RE = re.compile(r"\[\^?[^\]]*a-z[^\]]*\]")
LOOKAROUND_RE = re.compile(r"\(\?=|\(\?!|\(\?<=|\(\?<!")
SUPPRESS_RE = re.compile(r"#\s*regex-check:\s*ignore\s+([A-Z]+-\d+)\s*[—-]\s*(\S.*)?$")


def _suppressed(lines: list[str], idx: int, rule: str) -> bool:
    """A suppression on the flagged line, or on the line directly above it, WITH a reason."""
    for probe in (idx, idx - 1):
        if 0 <= probe < len(lines):
            m = SUPPRESS_RE.search(lines[probe])
            if m and m.group(1) == rule and (m.group(2) or "").strip():
                return True
    return False


def _code_line_flags(text: str, lines: list[str]) -> list[bool]:
    """True for lines that are CODE, False for lines inside a string/docstring.

    Prose that *describes* this trap is not an instance of it. Both of this rule's first findings
    were docstrings explaining the bug (including in this very file), so without this the rule
    flags its own documentation — a check that cries wolf at the people trying to explain it.
    Uses tokenize, so it is exact rather than a guess at quote nesting.
    """
    import io
    import tokenize

    flags = [True] * (len(lines) + 1)
    try:
        toks = list(tokenize.generate_tokens(io.StringIO(text).readline))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        # An unparseable file is left fully scannable rather than silently skipped.
        return [True] * (len(lines) + 1)

    # Mark only DOCSTRINGS / bare string expressions, never a string passed as an argument.
    # A regex literal inside re.compile("...") is the very thing being checked, so blanking every
    # STRING token made the rule miss its own fixture. A docstring is a STRING that
    # stands alone as a statement: the preceding significant token is a NEWLINE/INDENT/DEDENT or
    # start-of-file, rather than an operator such as '(' or '='.
    prev_significant = None
    for tok in toks:
        if tok.type in (tokenize.NL, tokenize.COMMENT):
            continue
        if tok.type == tokenize.STRING:
            standalone = prev_significant in (
                None,
                tokenize.NEWLINE,
                tokenize.INDENT,
                tokenize.DEDENT,
            )
            if standalone:
                for ln in range(tok.start[0], tok.end[0] + 1):
                    if 1 <= ln <= len(lines):
                        flags[ln - 1] = False
        prev_significant = tok.type
    return flags


def _enclosing_call(lines: list[str], idx: int) -> str:
    """The text of the re.compile(...)/re.search(...) call containing line `idx`.

    Scoped by balancing parentheses from the call's opening paren, so the flags of a NEIGHBOURING
    pattern cannot be mistaken for this one's — the bug a fixed-size line window had.
    """
    start = idx
    while start >= 0 and "re." not in lines[start]:
        if idx - start > 4:
            break
        start -= 1
    if start < 0 or "re." not in lines[start]:
        return lines[idx]
    depth = 0
    out = []
    for ln in lines[start : start + 8]:
        out.append(ln)
        for ch in ln:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
        if depth <= 0 and len(out) > 0 and "(" in "".join(out):
            break
    return "\n".join(out)


def check_file(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    if "IGNORECASE" not in text and "re.I" not in text:
        return []
    lines = text.splitlines()
    code_lines = _code_line_flags(text, lines)
    problems = []
    for i, raw in enumerate(lines):
        if raw.lstrip().startswith("#") or not code_lines[i]:
            continue
        if "A-Z" not in raw or not LOOKAROUND_RE.search(raw):
            continue
        # The flag must apply to THIS pattern, so the search is scoped to this ONE re.compile(...)
        # call by balancing parentheses from the call onward. A fixed 3-line window bled into the
        # NEXT pattern's flags and flagged a correct case-sensitive branch;
        # and a file-level "does IGNORECASE appear anywhere" test is worse still, because a file
        # holding a case-sensitive camelCase branch ALONGSIDE an IGNORECASE one is precisely the
        # correct fix for this trap — so that test flags the fix itself.
        call = _enclosing_call(lines, i)
        if not re.search(r"re\.(?:IGNORECASE|I)\b", call) and "(?i)" not in call:
            continue
        m = UPPER_ONLY_CLASS_RE.search(raw)
        # A class that already spans both cases ([A-Za-z]) is deliberate, not a false anchor.
        if not m or "a-z" in m.group(0) or LOWER_IN_CLASS_RE.search(raw):
            continue
        if _suppressed(lines, i, "ICASE-01"):
            continue
        rel = path.relative_to(REPO) if path.is_relative_to(REPO) else path
        problems.append(
            f"{rel}:{i + 1}: [ICASE-01] upper-case-only class '{m.group(0)}' does boundary work in "
            "a lookaround, in a file compiled with re.IGNORECASE — under that flag it matches "
            "LOWER case too, so the lookaround bounds nothing and the pattern only looks anchored. "
            "(e.g. flagging 'compass'/'passthrough'/'tokenizer' while missing 'PrivateKey'). "
            "Fix: a case-SENSITIVE branch for the camelCase boundary, and "
            "(?i:...) scoped to the delimiter-bounded branch."
        )
    return problems


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("paths", nargs="*", default=list(DEFAULT_ROOTS))
    args = ap.parse_args()

    problems: list[str] = []
    scanned = 0
    for arg in args.paths:
        root = Path(arg)
        if not root.is_absolute():
            root = REPO / root
        targets = [root] if root.is_file() else sorted(root.rglob("*.py"))
        for p in targets:
            # Exclusions are judged RELATIVE to the repo root. An absolute-path check for
            # ".claude/worktrees" skips the entire tree when the checker itself runs from inside a
            # worktree (0 files scanned), which is a checker that silently checks nothing.
            #
            # The prefix must be the DOT path: `claude/worktrees/` matches nothing when worktrees
            # live at `.claude/worktrees/`, and the checker scans a full second copy of the repo.
            # A leading-dot difference is invisible in review and total in effect — the same
            # anchoring trap a slash in a .gitignore pattern sets.
            try:
                rel = p.relative_to(REPO).as_posix()
            except ValueError:
                rel = p.as_posix()
            if p.suffix != ".py" or rel.startswith(EXCLUDE_PREFIXES):
                continue
            scanned += 1
            problems.extend(check_file(p))

    for pr in problems:
        print(f"FAIL {pr}")
    print(f"\ncheck_regex_anchors: {len(problems)} FAIL across {scanned} file(s) scanned.")
    return 1 if problems else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # pragma: no cover
        print(f"check_regex_anchors: internal error: {exc}", file=sys.stderr)
        sys.exit(2)
