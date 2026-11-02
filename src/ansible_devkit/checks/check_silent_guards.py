#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""check_silent_guards — static checker for guards/gates/conditionals that look correct but can
never fire.

WHY THIS EXISTS
    A `when:`/`assert:` that reads as a real check but is structurally incapable of ever firing
    (or of ever being false) is worse than no check: it reports health. Typical consequences: a
    handler-set fact read before the handler runs makes a same-run reload guard act on a stale value;
    a wrong-index attribute test in front of an irreversible `lvremove -y` defeats half of the
    safety check while the other half still reads correctly.

    The shape is deliberate: a small, tested, line-oriented script that a hook AND a human AND CI
    can all run, printing exactly why and citing the source, with a paired test file. The document
    that explains the rule set is named per repo in devkit.toml `silent_guards.audit_doc`.

WHAT THIS DOES NOT DO (read before assuming coverage)
    Several patterns in this family are NOT checked here because they are not tractable as static,
    file-local analysis without an Ansible-aware fact/handler graph:
      - A handler-set fact read during the run (the archetype of this bug class) is only PARTIALLY
        covered: this script flags a `set_fact` that exists ONLY in
        handlers/main.yml with no inline counterpart in tasks/ for the same role (rule HANDLER-01).
        It CANNOT trace whether some *consumer* elsewhere in the repo actually reads that fact
        mid-run before flush_handlers — that requires cross-file dataflow this script doesn't build.
      - "A registered result that is never asserted on anywhere" is NOT checked at all:
        proving a register is *never* read requires knowing every possible consumer across the whole
        repo (other files, other roles via facts), which is a real static-analysis project, not a
        grep. A local, best-effort version of "register set, nothing in this file/role reads it" was
        considered and rejected — the false-positive rate against legitimate "register now, some
        other include reads it later" patterns was judged too high to ship as anything but noise.
      - Any dataflow that crosses role boundaries (a var set in role A, consumed in role B via
        facts) is out of scope everywhere in this file. Every rule below is file- or role-local.

    Where a rule's blast radius includes real ambiguity, it WARNs (exit 0, printed) rather than
    FAILs (exit 1) — see RULES below for the fail/warn split and why.

USAGE
    devkit check silent-guards [PATH ...]      # defaults to the configured ansible_roots
    devkit check silent-guards --fail-on-warn   # promote warnings to failures (CI-strict)
    devkit check silent-guards --list-rules

SUPPRESSION
    A single line immediately before (or trailing on) the flagged line:
        # guard-check: ignore RULE-ID — <reason, required, non-empty>
    A suppression comment with no reason after the em-dash/hyphen is itself flagged as invalid and
    does not suppress anything — a bare "ignore this" is exactly the kind of unreviewable escape
    hatch this tool exists to prevent.

Exit codes: 0 = clean (or only warnings, without --fail-on-warn), 1 = at least one FAIL finding
(or a WARN finding when --fail-on-warn is set), 2 = usage/internal error.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _devkit_config  # noqa: E402

try:
    import yaml
except ImportError:  # pragma: no cover - repo always has PyYAML via ansible-dev-tools
    yaml = None  # type: ignore[assignment]

# Per-repo data (devkit.toml). AUDIT_DOC is printed with every summary; VENDORED_COLLECTIONS is the
# directory MOLCOLL-01 requires in a scenario's ANSIBLE_COLLECTIONS_PATH (required: without it the
# rule could not tell a right path from a wrong one).
try:
    _CFG = _devkit_config.load()
    AUDIT_DOC = _CFG.string("silent_guards.audit_doc", "check_silent_guards.py --list-rules")
    VENDORED_COLLECTIONS = _CFG.string("silent_guards.vendored_collections_dir")
    OWN_COLLECTIONS = _CFG.string("silent_guards.own_collections", "its own collections")
    DEFAULT_ROOTS = tuple(_CFG.str_list("paths.ansible_roots", ["roles", "playbooks"]))
    EXEMPT_SUBSTR = (*_CFG.str_list("paths.vendored", []), "/.git/")
except _devkit_config.ConfigError as _exc:
    _devkit_config.fatal("check_silent_guards", _exc)

SUPPRESS_RE = re.compile(r"#\s*guard-check:\s*ignore\s+([A-Z]+-\d+)\s*(?:[-—]+\s*(\S.*))?$")

# Repo root, for the one rule that needs whole-repo context (TIMERUNIT-01).
REPO_ROOT = _CFG.root
SCAN_SUFFIXES = (".yml", ".yaml")


# --------------------------------------------------------------------------------------------
# Finding model
# --------------------------------------------------------------------------------------------


@dataclass
class Finding:
    rule: str
    level: str  # "FAIL" or "WARN"
    path: Path
    line: int
    message: str


@dataclass
class Suppression:
    rule: str
    reason: str | None
    line: int


def parse_suppressions(lines: list[str]) -> dict[int, list[Suppression]]:
    """Map 1-indexed line number -> suppressions that apply to THAT line.

    A suppression comment applies to:
      - its own line (a trailing '# guard-check: ignore ...' on the flagged line itself), and
      - the line immediately below it (comment on its own line, directly above what it covers),
        which also covers "comment right above the whole task's '- name:' line", and
      - every other line within the SAME enclosing task block (from its '- name:' boundary to the
        next one at the same or shallower indent) — because a finding is often reported on the
        task's header line (e.g. META-01 fires on the 'meta:' line) while the natural place for a
        human to write the suppression is next to the specific key it explains (e.g. next to
        'until:'), not necessarily on or directly above that exact line.
    """
    raw: list[Suppression] = []
    for i, line in enumerate(lines, 1):
        m = SUPPRESS_RE.search(line)
        if m:
            raw.append(Suppression(rule=m.group(1), reason=m.group(2), line=i))
    if not raw:
        return {}

    blocks = _extract_task_blocks(lines)  # (start_idx, end_idx, indent), 0-indexed half-open
    applies: dict[int, list[Suppression]] = {}
    for s in raw:
        targets = {s.line, s.line + 1}
        for start, end, _indent in blocks:
            if start < s.line <= end:  # s.line is 1-indexed; start/end are 0-indexed [start, end)
                targets.update(range(start + 1, end + 1))
                break
        for t in targets:
            applies.setdefault(t, []).append(s)
    return applies


def is_suppressed(sups_at_line: list[Suppression], rule: str) -> tuple[bool, str | None]:
    for s in sups_at_line:
        if s.rule == rule:
            if not s.reason or not s.reason.strip():
                return (False, "bare")  # present but invalid — caller reports SUPPRESS-01
            return (True, None)
    return (False, None)


# --------------------------------------------------------------------------------------------
# File discovery
# --------------------------------------------------------------------------------------------


def is_exempt(path: Path) -> bool:
    s = str(path)
    return any(x in s for x in EXEMPT_SUBSTR)


def iter_files(roots: list[Path]):
    for root in roots:
        if root.is_file():
            if root.suffix in SCAN_SUFFIXES and not is_exempt(root):
                yield root
            continue
        if not root.exists():
            continue
        for p in sorted(root.rglob("*")):
            if p.is_file() and p.suffix in SCAN_SUFFIXES and not is_exempt(p):
                yield p


def strip_comment(line: str) -> str:
    stripped = line.lstrip()
    if stripped.startswith("#"):
        return ""
    # crude but matches boundary_lint's convention
    hashpos = line.find(" #")
    return line[:hashpos] if hashpos != -1 else line


# --------------------------------------------------------------------------------------------
# Rule METACLASS-4 / SUPPRESS-01: bare suppression comments are themselves invalid
# --------------------------------------------------------------------------------------------


def check_bare_suppressions(path: Path, lines: list[str]) -> list[Finding]:
    out = []
    for i, line in enumerate(lines, 1):
        m = SUPPRESS_RE.search(line)
        if m and not (m.group(2) and m.group(2).strip()):
            out.append(
                Finding(
                    "SUPPRESS-01",
                    "FAIL",
                    path,
                    i,
                    "guard-check suppression with no reason. Format required: "
                    "'# guard-check: ignore <RULE-ID> — <one-line reason>'. A bare suppression is "
                    "an unreviewable escape hatch — exactly what this checker exists to prevent. "
                    f"See {AUDIT_DOC}.",
                )
            )
    return out


# --------------------------------------------------------------------------------------------
# Rule META-01: meta: action combined with until:/retries:/delay:.
# Deterministic: these keywords are silently ignored by the meta action, full stop. FAIL.
# --------------------------------------------------------------------------------------------

META_TASK_RE = re.compile(r"^(\s*)(?:ansible\.builtin\.)?meta\s*:\s*\S+\s*$")
RETRY_KEY_RE = re.compile(r"^(\s*)(until|retries|delay)\s*:")
TASK_BOUNDARY_RE = re.compile(r"^(\s*)-\s")


def check_meta_until(path: Path, lines: list[str]) -> list[Finding]:
    out: list[Finding] = []
    n = len(lines)
    for i, raw in enumerate(lines):
        line = strip_comment(raw)
        m = META_TASK_RE.match(line)
        if not m:
            continue
        indent = len(m.group(1))
        hit_keys: list[tuple[int, str]] = []
        # Scan sibling keys: same indent level, until we hit a new list-item boundary or dedent.
        j = i + 1
        while j < n:
            nxt_raw = lines[j]
            nxt = strip_comment(nxt_raw)
            if nxt.strip() == "":
                j += 1
                continue
            nxt_indent = len(nxt) - len(nxt.lstrip(" "))
            if nxt_indent < indent:
                break
            if TASK_BOUNDARY_RE.match(nxt) and nxt_indent <= indent:
                break
            rk = RETRY_KEY_RE.match(nxt)
            if rk and len(rk.group(1)) == indent:
                hit_keys.append((j + 1, rk.group(2)))
            j += 1
        if hit_keys:
            keys = ", ".join(k for _, k in hit_keys)
            out.append(
                Finding(
                    "META-01",
                    "FAIL",
                    path,
                    i + 1,
                    f"'meta:' task also sets {keys} — meta actions run synchronously in the "
                    "strategy plugin and ALWAYS ignore until:/retries:/delay:, silently executing "
                    "exactly once regardless of these keys (a meta task with an always-false "
                    f"until: still 'succeeds' immediately). See "
                    f"{AUDIT_DOC}. Fix: replace with a real retrying task "
                    "(e.g. wait_for_connection) after the meta, or drop the keys as dead weight.",
                )
            )
    return out


# --------------------------------------------------------------------------------------------
# Rule REGEX-01: POSIX bracket classes inside a Jinja search/match/regex_* argument. FAIL.
# Deterministic: Python's re module has no POSIX named classes; nested in a negated class the
# pattern matches nothing at all.
# --------------------------------------------------------------------------------------------

POSIX_CLASS_RE = re.compile(
    r"\[:(?:alnum|alpha|digit|space|punct|upper|lower|cntrl|print|graph|blank|xdigit):\]"
)
JINJA_REGEX_CONTEXT_RE = re.compile(
    r"(?:is\s+(?:not\s+)?(?:search|match)|regex_search|regex_replace|regex_findall)\s*\("
)


def check_posix_classes(path: Path, lines: list[str]) -> list[Finding]:
    out = []
    for i, raw in enumerate(lines, 1):
        if not POSIX_CLASS_RE.search(raw):
            continue
        if JINJA_REGEX_CONTEXT_RE.search(raw) or "search(" in raw or "match(" in raw:
            out.append(
                Finding(
                    "REGEX-01",
                    "FAIL",
                    path,
                    i,
                    "POSIX bracket class (e.g. [:alnum:]) inside a Jinja search/match/regex_* "
                    "pattern. Ansible's regex filters/tests use Python's re module, which has no "
                    "POSIX named classes: nested inside a class "
                    "like [^-[:alnum:]] it parses as a malformed class and matches NOTHING, ever, "
                    f"in either direction. See {AUDIT_DOC}. Fix: use \\w (or an explicit character "
                    "set) instead of the POSIX class name.",
                )
            )
    return out


# --------------------------------------------------------------------------------------------
# Rule BACKSLASH-01: \b (or other C-style escapes meaningful in a string but not in Jinja regex)
# in a non-raw Jinja/YAML plain-scalar regex argument. WARN — \b is sometimes genuinely meant as
# backspace in non-regex contexts, and telling "this string is meant as a regex" apart from
# "this string is meant as literal bytes" is not always certain from the line alone.
# --------------------------------------------------------------------------------------------

BACKSLASH_B_RE = re.compile(r"\\b")


def check_backslash_b_in_regex(path: Path, lines: list[str]) -> list[Finding]:
    out = []
    for i, raw in enumerate(lines, 1):
        # Strip comments first, like every other rule here. Without this the rule fired on prose
        # DESCRIBING the trap — `# an earlier draft used regex_search('\b'...)` in a comment that
        # exists precisely to record the fix — so documenting a trap tripped the checker for it.
        # A rule that punishes its own explanatory comment teaches people to delete the comment.
        line = strip_comment(raw)
        if not JINJA_REGEX_CONTEXT_RE.search(line):
            continue
        # only flag if \b appears inside what looks like a quoted pattern argument on this line
        if BACKSLASH_B_RE.search(line) and ("'" in line or '"' in line):
            out.append(
                Finding(
                    "REGEX-02",
                    "WARN",
                    path,
                    i,
                    "\\b used inside a regex-ish Jinja call on a plain (non-raw) string. In a "
                    "normal YAML/Jinja plain or single/double-quoted scalar, \\b is a BACKSPACE "
                    "character, not a word-boundary regex token — a guard built on it never "
                    "matches. If \\b here is meant as a word boundary, use a "
                    f"raw pattern or escape it as \\\\b. See {AUDIT_DOC}. "
                    "WARN not FAIL: \\b can legitimately appear in a non-regex string.",
                )
            )
    return out


# --------------------------------------------------------------------------------------------
# Rule ANCHOR-01: '$' anchor without (?m) against something that looks like multi-line .stdout.
# WARN — cannot statically know if the source is genuinely single-line.
# --------------------------------------------------------------------------------------------

DOLLAR_ANCHOR_RE = re.compile(r"(?:search|match)\(\s*['\"].*\$['\"]")
MULTILINE_FLAG_RE = re.compile(r"\(\?m\)")


def check_dollar_anchor(path: Path, lines: list[str]) -> list[Finding]:
    out = []
    for i, raw in enumerate(lines, 1):
        if not DOLLAR_ANCHOR_RE.search(raw):
            continue
        if MULTILINE_FLAG_RE.search(raw):
            continue
        if "stdout" in raw or "stdout_lines" in raw:
            out.append(
                Finding(
                    "ANCHOR-01",
                    "WARN",
                    path,
                    i,
                    "'$' anchor in a search()/match() pattern against something naming .stdout, "
                    "with no (?m) multiline flag. Without (?m), '$' anchors only the END OF THE "
                    "WHOLE STRING, not end-of-line — command output with multiple lines will not "
                    f"match as expected. See {AUDIT_DOC}. Fix: add (?m) to the pattern, "
                    "or extract exact lines/tokens instead of anchoring raw stdout. WARN not FAIL: "
                    "many .stdout values are genuinely single-line by construction.",
                )
            )
    return out


# --------------------------------------------------------------------------------------------
# Rule FAILED-01 / IGNORE-01: failed_when:false / ignore_errors:true on a task, then a later
# task in the same file branches on that register's .failed or bare truthiness. WARN — requires
# tracking register name across tasks in a file, which is doable, but "later task in reachable
# scope" is a real heuristic (doesn't model when: skip logic), so this stays WARN.
# --------------------------------------------------------------------------------------------

REGISTER_RE = re.compile(r"^\s*register\s*:\s*([A-Za-z_][A-Za-z0-9_]*)\s*$")
FAILED_WHEN_FALSE_RE = re.compile(r"^\s*failed_when\s*:\s*false\s*$", re.IGNORECASE)


NAME_LINE_RE = re.compile(r"^(\s*)-\s+name\s*:")
PLAY_KEY_RE = re.compile(r"^\s*(hosts|tasks|pre_tasks|post_tasks|handlers|roles)\s*:")


def _is_play_header(lines: list[str], start: int, indent: int) -> bool:
    """A '- name:' entry is a PLAY header (not a task) if a 'hosts:' sibling key appears before
    the next '-' list item at the SAME list-item indent. Plays have a hosts:/tasks:/roles: key;
    tasks never do. Without this check, a play's own '- name:' block swallows the ENTIRE rest of
    the file as its 'block', causing every rule that walks task blocks to double-count every task
    inside it (once for its real, task-scoped block, once again for the play-scoped block).

    Sibling keys of a '- name: ...' mapping item are indented two past the dash itself (YAML's
    block-sequence-of-mappings shorthand: '- name: x' opens the mapping right after the dash, so
    'hosts:' below it lines up two columns deeper than '-', not level with it)."""
    key_indent = indent + 2
    for j in range(start + 1, len(lines)):
        line = lines[j]
        if line.strip() == "":
            continue
        cur_indent = len(line) - len(line.lstrip(" "))
        if cur_indent < key_indent:
            break  # dedented past this item's own mapping — done
        if cur_indent == key_indent and line.lstrip().startswith("-"):
            break  # a nested list under some other key, not a sibling — stop looking
        if cur_indent == key_indent and PLAY_KEY_RE.match(line):
            return True
    return False


def _extract_task_blocks(lines: list[str]) -> list[tuple[int, int, int]]:
    """Return (start_line_idx, end_line_idx, indent) for each top-level-ish '- name:' task block,
    approximated by looking at '- name:' boundaries at the same indent. 0-indexed line numbers.
    Play headers (a '- name:' entry carrying hosts:/tasks:/roles:) are excluded — see
    _is_play_header — so a play's own name doesn't produce a block spanning its whole task list."""
    starts = []
    for i, raw in enumerate(lines):
        m = NAME_LINE_RE.match(raw)
        if m:
            indent = len(m.group(1))
            if _is_play_header(lines, i, indent):
                continue
            starts.append((i, indent))
    blocks = []
    for idx, (start, indent) in enumerate(starts):
        end = len(lines)
        for other_start, other_indent in starts[idx + 1 :]:
            if other_indent <= indent:
                end = other_start
                break
        blocks.append((start, end, indent))
    return blocks


def check_neutralized_failed_branch(path: Path, lines: list[str]) -> list[Finding]:
    out: list[Finding] = []
    blocks = _extract_task_blocks(lines)
    neutralized: dict[str, int] = {}  # register name -> line it was neutralized (1-indexed)

    for start, end, _indent in blocks:
        block = lines[start:end]
        reg_name = None
        neutralizing_line = None
        for j, raw in enumerate(block):
            line = strip_comment(raw)
            rm = REGISTER_RE.match(line)
            if rm:
                reg_name = rm.group(1)
            # `ignore_errors: true` is DELIBERATELY not treated as a neutralizer. Ansible's
            # behaviour, with /bin/false under each key:
            #     ignore_errors: true   -> registered .failed == True   (honest)
            #     failed_when: false    -> registered .failed == False  (defeated)
            # ignore_errors only stops the failure ENDING THE PLAY; the register keeps the truth,
            # so a later `when: r is failed` works exactly as written. Flagging it condemned the
            # one idiom that correctly probes every host before failing — and since the fix for a
            # real failed_when:false bug IS to switch to ignore_errors, the rule flagged its own
            # remedy. A check that does that gets ignored wholesale.
            if FAILED_WHEN_FALSE_RE.match(line):
                neutralizing_line = start + j + 1
        if reg_name and neutralizing_line:
            neutralized[reg_name] = neutralizing_line

    if not neutralized:
        return out

    # look for `<register>.failed` / `<register> is failed` / `<register> is succeeded` / bare
    # `when: <register>` anywhere AFTER the neutralizing task in the same file.
    for i, raw in enumerate(lines, 1):
        line = strip_comment(raw)
        for reg, neut_line in neutralized.items():
            if i <= neut_line:
                continue
            patterns = [
                (rf"\b{re.escape(reg)}\.failed\b", ".failed"),
                (rf"\b{re.escape(reg)}\s+is\s+failed\b", "is failed"),
                (rf"\b{re.escape(reg)}\s+is\s+succeeded\b", "is succeeded"),
                (rf"\b{re.escape(reg)}\s+is\s+not\s+failed\b", "is not failed"),
            ]
            for pat, tag in patterns:
                if re.search(pat, line):
                    out.append(
                        Finding(
                            "FAILED-01",
                            "WARN",
                            path,
                            i,
                            f"branches on '{reg} {tag}', but '{reg}' was registered by a task at "
                            f"line {neut_line} with failed_when: false — which forces .failed to "
                            "False UNCONDITIONALLY, even on genuine failure, so this branch (and "
                            "the Ansible 'is failed'/'is succeeded' tests, which read the same "
                            f".failed field) can never go the other way. See "
                            f"{AUDIT_DOC}. "
                            "Fix: gate on .rc/.status or an explicit "
                            "read-back — or, to keep probing every host before failing, use "
                            "ignore_errors: true, which stops the failure ending the play WITHOUT "
                            "falsifying .failed. WARN not FAIL: this is a same-file "
                            "textual scan, not real dataflow — a genuinely different variable "
                            "reusing the name, or an intervening reset, would be a false positive.",
                        )
                    )
    return out


# --------------------------------------------------------------------------------------------
# Rule UNTIL-01: until: with no assert/fail referencing the same register within the next N
# tasks in the same file. WARN — "no assert anywhere reachable" can't be proven for cross-file
# consumers, so this is necessarily an approximation limited to the current file.
# --------------------------------------------------------------------------------------------

UNTIL_RE = re.compile(r"^\s*until\s*:")
# A fact being defined under `set_fact:` — `    _cl_mine: "{{ ... }}"`. Used to follow a value
# one hop from the register into the fact an assert actually tests. Deliberately excludes the
# `set_fact:`/`ansible.builtin.set_fact:` keys themselves and any other task-level keyword.
# The value may be inline ("{{ ... }}") OR a block scalar (`>-` / `|`), which is the common shape
# for long Jinja expressions — a version that excludes `>`/`|` matches almost nothing.
SET_FACT_NAME_RE = re.compile(r"^\s{4,}([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(\S.*|[|>][-+]?)$")
ASSERT_TASK_RE = re.compile(r"(?:ansible\.builtin\.)?assert\s*:")
FAIL_TASK_RE = re.compile(r"(?:ansible\.builtin\.)?fail\s*:")
# A tight window misses real guards: the verify sequence after a retry loop is typically
# "recompute from a fresh read" → "report what is missing" → "assert", and those tasks can run
# 20-40 lines each (long Jinja expressions, fail_msg prose), so a genuine assert may sit a dozen
# or more tasks downstream. At 24 what remains is a loop with NO assert anywhere in the file,
# which is the defect.
LOOKAHEAD_TASKS = 24


def check_until_without_assert(path: Path, lines: list[str]) -> list[Finding]:
    out: list[Finding] = []
    blocks = _extract_task_blocks(lines)

    # An outer `block:` task CONTAINS its children, so a retry loop nested inside one was also
    # attributed to the enclosing task — whose lookahead window starts AFTER the whole block, i.e.
    # past the very assert that follows the loop. That reported correctly-guarded loops as
    # unguarded (a role that asserts on the very next task was still flagged).
    # Attribute each `until:` to the INNERMOST task that holds it: the most deeply indented block.
    owner_of: dict[int, int] = {}  # until-line -> index of the most deeply indented owning block
    for bidx, (start, end, indent) in enumerate(blocks):
        for j, raw in enumerate(lines[start:end]):
            if UNTIL_RE.match(strip_comment(raw)):
                uline = start + j + 1
                prev = owner_of.get(uline)
                if prev is None or indent > blocks[prev][2]:
                    owner_of[uline] = bidx

    for bidx, (start, end, _indent) in enumerate(blocks):
        block = lines[start:end]
        reg_name = None
        until_line = None
        suppresses_failure = False
        for j, raw in enumerate(block):
            line = strip_comment(raw)
            rm = REGISTER_RE.match(line)
            if rm:
                reg_name = rm.group(1)
            if UNTIL_RE.match(line):
                until_line = start + j + 1
            if FAILED_WHEN_FALSE_RE.match(line):
                suppresses_failure = True

        # A retry loop is only a SILENT guard if exhausting its retries goes unnoticed. Without
        # `failed_when: false`, a loop that never satisfies its condition FAILS the task and stops
        # the play — loud, not silent — so an assert afterwards is optional belt-and-braces, not a
        # missing safety check. The defect is the PAIR: `until:` + `failed_when: false` exhausts its
        # retries and then continues, so a failed wait exits green. Flagging honest loops as well
        # makes a third of the findings unfixable-by-design noise, which is how a WARN class stops
        # being read at all.
        if not suppresses_failure:
            continue
        if not (reg_name and until_line):
            continue
        # Only the innermost owning task judges this loop.
        if owner_of.get(until_line) != bidx:
            continue

        # meta: tasks are handled by META-01; skip to avoid double-reporting the same line.
        block_text = "\n".join(block)
        if META_TASK_RE.search(strip_comment(block_text.splitlines()[0]) if block else ""):
            continue

        window_end = min(len(blocks), bidx + 1 + LOOKAHEAD_TASKS)

        # Names that count as re-checking this loop: the register itself, plus any fact DERIVED
        # from it downstream. The house pattern is
        # "recompute from a fresh read" -> set_fact -> assert on that fact, e.g.
        #     register: _cl_components ... until: ...
        #     set_fact: _cl_mine: "{{ _cl_components.json | ... }}"
        #     assert:   that: "_cl_mine | rejectattr('health.state', ...) | length == 0"
        # Requiring the REGISTER itself to appear inside the assert task missed every one of
        # those — a correctly guarded loop read as unguarded, which is the worst kind of WARN
        # because the fix it demands is to duplicate an assert that already exists.
        checked_names = {reg_name}
        for s2, e2, _i2 in blocks[bidx + 1 : window_end]:
            seg = "\n".join(lines[s2:e2])
            if not any(re.search(rf"\b{re.escape(n)}\b", seg) for n in checked_names):
                continue
            for line in lines[s2:e2]:
                fm = SET_FACT_NAME_RE.match(strip_comment(line))
                if fm:
                    checked_names.add(fm.group(1))

        found_check = False
        for s3, e3, _i3 in blocks[bidx + 1 : window_end]:
            seg = "\n".join(lines[s3:e3])
            if not (ASSERT_TASK_RE.search(seg) or FAIL_TASK_RE.search(seg)):
                continue
            if any(re.search(rf"\b{re.escape(n)}\b", seg) for n in checked_names):
                found_check = True
                break
        if not found_check:
            out.append(
                Finding(
                    "UNTIL-01",
                    "WARN",
                    path,
                    until_line,
                    f"'until:' loop on register '{reg_name}' with no assert/fail in the next "
                    f"{LOOKAHEAD_TASKS} tasks of this file referencing '{reg_name}'. A retry loop "
                    "that exhausts its retries still reports the play as green unless something "
                    f"explicitly re-checks the condition afterward. See {AUDIT_DOC}. "
                    "Fix: add an ansible.builtin.assert immediately after the "
                    "loop re-checking the same condition. WARN not FAIL: the real consumer may be "
                    "in a later file (e.g. a downstream HARD GATE play) that this file-local scan "
                    "cannot see.",
                )
            )

    # One `until:` is ONE finding. _extract_task_blocks yields both an outer `block:` task and
    # the tasks nested inside it, so a retry loop inside a block was reported once per enclosing
    # level — the same lines counted twice, which inflates the
    # backlog and makes a fixed file look half-fixed.
    seen: set[int] = set()
    deduped: list[Finding] = []
    for finding in out:
        if finding.line in seen:
            continue
        seen.add(finding.line)
        deduped.append(finding)
    return deduped


# --------------------------------------------------------------------------------------------
# Rule MAPKEY-01: Jinja templating inside a YAML mapping KEY. FAIL — deterministic via YAML AST:
# a mapping key containing '{{' is never templated by Ansible; it ships literally.
# --------------------------------------------------------------------------------------------


def check_jinja_in_mapping_key(path: Path, text: str, lines: list[str]) -> list[Finding]:
    if yaml is None:
        return []

    findings_raw: list[tuple[int, str]] = []
    try:
        for doc_node in _compose_all(text):
            _scan_node(doc_node, findings_raw, is_set_fact_direct_args=False)
    except Exception:
        return []  # not our job to catch YAML syntax errors

    out: list[Finding] = []
    for line_no, key in findings_raw:
        out.append(
            Finding(
                "MAPKEY-01",
                "FAIL",
                path,
                line_no,
                f"Jinja expression in a YAML mapping KEY: '{key}'. Ansible templates mapping "
                "VALUES, never mapping KEYS — this key ships as the literal characters "
                f"'{key}', not its rendered value. See {AUDIT_DOC}; the symptom is an opaque HTTP "
                "400 from the API. Fix: build the dict with a "
                "'{{ {key_var: value} }}' expression instead of a literal templated key. (The one "
                "documented exception — a bare '\"{{ var }}\": value' as the DIRECT argument to "
                "set_fact/vars, Ansible's supported dynamic-variable-name idiom — is not flagged.)",
            )
        )
    return out


def _compose_all(text: str):
    if yaml is None:
        return []
    return list(yaml.compose_all(text, Loader=yaml.SafeLoader))


def _scan_node(node, out: list[tuple[int, str]], is_set_fact_direct_args: bool):
    if node is None:
        return
    if isinstance(node, yaml.MappingNode):
        # Detect whether THIS mapping is the direct args-mapping of a set_fact/vars task, by
        # checking if any sibling key at the parent level was literally 'set_fact'/'vars' —
        # handled by the caller passing is_set_fact_direct_args down; here we just decide per key.
        for k_node, v_node in node.value:
            key_is_dynamic = (
                isinstance(k_node, yaml.ScalarNode)
                and "{{" in (k_node.value or "")
                and "}}" in (k_node.value or "")
            )
            if key_is_dynamic and not is_set_fact_direct_args:
                out.append((k_node.start_mark.line + 1, k_node.value))
            # recurse into value; mark child as "direct set_fact args" only if this exact key is
            # set_fact/vars/ansible.builtin.set_fact and the value is itself a mapping
            child_is_set_fact_args = isinstance(k_node, yaml.ScalarNode) and k_node.value in (
                "set_fact",
                "vars",
                "ansible.builtin.set_fact",
            )
            _scan_node(v_node, out, is_set_fact_direct_args=child_is_set_fact_args)
    elif isinstance(node, yaml.SequenceNode):
        for item in node.value:
            _scan_node(item, out, is_set_fact_direct_args=False)
    # ScalarNode: nothing to recurse into


# --------------------------------------------------------------------------------------------
# Rule ASSERTKEY-01: comment lines that appear to break a YAML flow/plain-scalar continuation
# inside an assert.that: list. Hard to prove generically; we flag the specific
# shape: a '#' comment line sitting where it could be swallowed by YAML's plain-scalar folding
# inside a block sequence item that itself spans multiple physical lines without explicit quotes.
# WARN — legitimate '#'-prefixed comment lines between properly-terminated list items are common
# and safe; only the folding case is dangerous, and telling them apart from text alone is not
# 100% certain, and the shape is rare in practice.
# --------------------------------------------------------------------------------------------

ASSERT_THAT_RE = re.compile(r"^(\s*)that\s*:\s*$")
LIST_ITEM_RE = re.compile(r"^(\s*)-\s*(.*)$")
COMMENT_LINE_RE = re.compile(r"^(\s*)#")


def check_comment_in_assert_that(path: Path, lines: list[str]) -> list[Finding]:
    out: list[Finding] = []
    for i, raw in enumerate(lines):
        m = ASSERT_THAT_RE.match(raw)
        if not m:
            continue
        indent = len(m.group(1))
        j = i + 1
        # walk the that: list, watching for: list item line that does NOT end with a YAML-safe
        # terminator (i.e. looks like an unfinished/unquoted expression) immediately followed by
        # a '#' comment line at deeper-or-equal indent, immediately followed by another line that
        # is NOT a new '-' list item (i.e. looks like a continuation).
        prev_item_open = False
        while j < len(lines):
            line = lines[j]
            if line.strip() == "":
                j += 1
                continue
            cur_indent = len(line) - len(line.lstrip(" "))
            if cur_indent < indent and line.strip() != "":
                break
            li = LIST_ITEM_RE.match(line)
            cm = COMMENT_LINE_RE.match(line)
            if li:
                content = li.group(2).rstrip()
                # An "open" item: one that plausibly continues onto the next physical line as an
                # unquoted plain-scalar YAML fold. The dangerous shape is specifically a trailing
                # binary/boolean operator (and/or/not/+/etc.) or an unclosed bracket/quote — a
                # complete comparison ending in a digit, identifier, or closing punctuation is NOT
                # open, even though it doesn't end in a quote/brace/bracket (e.g. 'x.rc == 0' or
                # 'foo is defined' are complete conditions, not continuations).
                open_tail_re = re.compile(
                    r"(\band\b|\bor\b|\bnot\b|[+\-*/%|&^~]|,)\s*$", re.IGNORECASE
                )
                unclosed_bracket = content.count("(") > content.count(")") or content.count(
                    "["
                ) > content.count("]")
                prev_item_open = bool(content) and (
                    bool(open_tail_re.search(content)) or unclosed_bracket
                )
            elif cm and prev_item_open:
                # comment line right after an "open"-looking item — check what follows
                k = j + 1
                while k < len(lines) and lines[k].strip() == "":
                    k += 1
                if k < len(lines):
                    nxt = lines[k]
                    nxt_indent = len(nxt) - len(nxt.lstrip(" "))
                    if not LIST_ITEM_RE.match(nxt) and nxt_indent >= indent:
                        out.append(
                            Finding(
                                "ASSERTKEY-01",
                                "WARN",
                                path,
                                j + 1,
                                "comment line appears between an unterminated assert.that list "
                                "item and its apparent continuation. If the item above is an "
                                "unquoted multi-line plain scalar, YAML folds the comment's text "
                                "into the value and the following line parses as a second, "
                                "unrelated truthy string rather than the next boolean condition. "
                                f"See {AUDIT_DOC}. Fix: quote each condition fully on "
                                "one line, or move the comment above the whole 'that:' key. WARN "
                                "not FAIL: this is a textual heuristic and the shape is rare, so "
                                "treat any hit here as worth a careful look, not an automatic bug.",
                            )
                        )
                prev_item_open = False
            else:
                prev_item_open = False
            j += 1
    return out


# --------------------------------------------------------------------------------------------
# Rule JINJACOMMENT-01: a literal '#' inside a {{ ... }} expression (not {# ... #}). FAIL —
# '#' is not a comment marker inside a Jinja expression; Jinja2 raises a hard syntax error, so
# this is deterministic (a play carrying this literally cannot run at all — different symptom
# from most rules here, but same "looks-correct, silently-wrong" family, and the
# fastest possible feedback is a hard fail rather than a WARN nobody reads before the play blows
# up at runtime).
# --------------------------------------------------------------------------------------------

JINJA_EXPR_RE = re.compile(r"\{\{(.*?)\}\}")


def check_comment_in_jinja_expr(path: Path, lines: list[str]) -> list[Finding]:
    out = []
    for i, raw in enumerate(lines, 1):
        for m in JINJA_EXPR_RE.finditer(raw):
            expr = m.group(1)
            # ignore '#' that's inside a quoted string within the expression
            cleaned = re.sub(r"'[^']*'|\"[^\"]*\"", "", expr)
            if "#" in cleaned:
                out.append(
                    Finding(
                        "JINJACOMMENT-01",
                        "FAIL",
                        path,
                        i,
                        "'#' inside a {{ ... }} Jinja expression. '#' is not a comment marker "
                        "inside an expression (only {# ... #} is a Jinja comment) — this is a "
                        f"hard Jinja syntax error at render time. See {AUDIT_DOC}. "
                        "Fix: remove the '#' or move the explanatory text to a YAML '#' comment "
                        "outside the {{ }} braces.",
                    )
                )
    return out


# --------------------------------------------------------------------------------------------
# Rule STRINT-01: string-vs-int comparison in an assert/when, e.g. (x | length | string) == 5,
# or 'x' == 5 where one side is quoted and the other bare-numeric. WARN — Jinja/Python does do
# some implicit coercion in places, and telling a deliberate string comparison from a bug from
# text alone is not certain.
# --------------------------------------------------------------------------------------------

STRING_COERCED_EQ_INT_RE = re.compile(r"\|\s*string\s*\)?\s*(==|!=)\s*\d+\b")
QUOTED_EQ_BARE_INT_RE = re.compile(r"""(['"])\d+\1\s*(==|!=)\s*[A-Za-z_]""")
BARE_INT_EQ_QUOTED_RE = re.compile(r"""[A-Za-z_][A-Za-z0-9_.]*\s*(==|!=)\s*(['"])\d+\2""")


def check_string_int_compare(path: Path, lines: list[str]) -> list[Finding]:
    out = []
    for i, raw in enumerate(lines, 1):
        if not ("assert" in raw or "when" in raw or "==" in raw or "!=" in raw):
            pass  # cheap pre-filter avoided; keep simple, files are small
        if STRING_COERCED_EQ_INT_RE.search(raw):
            out.append(
                Finding(
                    "STRINT-01",
                    "WARN",
                    path,
                    i,
                    "value explicitly coerced with '| string' then compared against a bare "
                    "integer literal with ==/!=. A string will never equal an int in Jinja's "
                    f"comparison — this pattern is always False. See {AUDIT_DOC}. "
                    "Fix: drop the '| string' coercion, or compare against a quoted numeral "
                    "consistently. WARN not FAIL: cannot fully rule out a deliberate never-true "
                    "sentinel check from text alone.",
                )
            )
    return out


# --------------------------------------------------------------------------------------------
# Rule CHECKMODE-01: 'ansible_check_mode' set via -e / EXTRA= in play header docs/comments.
# FAIL — deterministic grep for the documented-but-broken idiom; false-positive risk is near
# zero (this string shape has no legitimate other meaning).
# --------------------------------------------------------------------------------------------

CHECKMODE_VIA_EXTRA_RE = re.compile(
    r"(EXTRA=['\"]?ansible_check_mode|-e\s+['\"]?ansible_check_mode)"
)


def check_checkmode_via_extra(path: Path, lines: list[str]) -> list[Finding]:
    out = []
    for i, raw in enumerate(lines, 1):
        if (
            CHECKMODE_VIA_EXTRA_RE.search(raw)
            and "does not work" not in raw.lower()
            and "does_not_work" not in raw.lower()
        ):
            out.append(
                Finding(
                    "CHECKMODE-01",
                    "FAIL",
                    path,
                    i,
                    "documents 'ansible_check_mode' as settable via -e/EXTRA=. It is a read-only "
                    "magic variable Ansible derives from the real --check CLI flag — setting it "
                    "via -e/EXTRA= is silently accepted and silently ignored, so documented dry-run "
                    f"instructions built on it give zero preview protection. See {AUDIT_DOC}. "
                    "Fix: use a real --check flag, or better, an explicit <name>_apply/_confirm var "
                    "(generate by default, apply behind the flag).",
                )
            )
    return out


# --------------------------------------------------------------------------------------------
# Rule CHECKMODE-02: `when: ... ansible_check_mode ...` inside a block that itself sets a
# block-level `check_mode:` key (rather than inheriting the real flag). WARN — needs to track
# block scope, which this line-oriented pass approximates via indentation; some risk of missing
# deeply nested or oddly formatted blocks, so this stays WARN rather than FAIL.
# --------------------------------------------------------------------------------------------

BLOCK_CHECKMODE_RE = re.compile(r"^(\s*)check_mode\s*:\s*(?:true|\"?\{\{.*\}\}\"?)")
WHEN_ANSIBLE_CHECKMODE_RE = re.compile(r"ansible_check_mode")


def check_block_checkmode_scope(path: Path, lines: list[str]) -> list[Finding]:
    out = []
    for i, raw in enumerate(lines):
        m = BLOCK_CHECKMODE_RE.match(strip_comment(raw))
        if not m:
            continue
        indent = len(m.group(1))
        # scan forward within this block's scope (deeper indent than the block: line, or same
        # indent as sibling tasks up to the next dedent past `indent`)
        j = i + 1
        while j < len(lines):
            nxt = lines[j]
            if nxt.strip() == "":
                j += 1
                continue
            nxt_indent = len(nxt) - len(nxt.lstrip(" "))
            if nxt_indent < indent:
                break
            line = strip_comment(nxt)
            if re.search(r"^\s*when\s*:", line) and WHEN_ANSIBLE_CHECKMODE_RE.search(line):
                out.append(
                    Finding(
                        "CHECKMODE-02",
                        "WARN",
                        path,
                        j + 1,
                        "'when:' references ansible_check_mode inside a block carrying its own "
                        "block-level 'check_mode:' key. A block-level check_mode does NOT set the "
                        "ansible_check_mode magic variable — it only changes whether tasks inside "
                        "the block actually run — so this when: condition sees the OUTER run's real "
                        f"--check state, not the block's, and can silently never fire as intended. "
                        f"See {AUDIT_DOC}. "
                        ""
                        "Fix: use an explicit var set alongside the block's own check_mode key, not "
                        "ansible_check_mode. WARN not FAIL: block-scope here is indentation-"
                        "approximated, not a real YAML AST walk.",
                    )
                )
                # also check further-nested when: referencing it — keep scanning within scope
            j += 1
    return out


# --------------------------------------------------------------------------------------------
# Rule INDEXGUARD-01: single-character string index compared to a literal single char, in the
# same task file as a destructive command (rm/lvremove/zfs destroy/pct destroy/qm destroy/
# docker rm/zpool destroy). WARN — heuristic; cannot verify the index is *wrong* without knowing
# the authoritative field layout, only that it's UNEXPLAINED (no citation comment nearby).
# --------------------------------------------------------------------------------------------

INDEX_COMPARE_RE = re.compile(r"\[(\d+)\]\s*\)*\s*(==|!=)\s*'(.)'")
DESTRUCTIVE_CMD_RE = re.compile(
    r"\b(lvremove|zfs\s+destroy|zpool\s+destroy|pct\s+destroy|qm\s+destroy|docker\s+rm|rm\s+-rf?)\b"
)
# A citation is either (a) a reference to an authoritative source (a man page section, or the
# tool's own documented output format), or (b) a worked example enumerating at least two distinct
# concrete index/field values side by side (e.g. "idx4='a' idx5='o'") — a decent proxy for someone
# having actually verified the layout against real output, as opposed to asserting a position in
# passing. Deliberately requires more than a bare mention of the word "index"/"position": a
# nearby-but-WRONG comment ("attr pos5") next to a buggy index is exactly the shape this rule
# exists for, which is why a loose word match must not count as a citation on its own.
FIELD_CITATION_SOURCE_RE = re.compile(
    r"(\w+\(\d\)|man\s+\w|lvs\s+(-o|--options)|--noheadings|reportformat\s+json)", re.IGNORECASE
)
FIELD_CITATION_WORKED_EXAMPLE_RE = re.compile(
    r"idx\d.{0,6}idx\d|index\s*\d.{0,10}index\s*\d", re.IGNORECASE
)
CITATION_LOOKBACK_LINES = 15


def check_unexplained_index_guard(path: Path, lines: list[str]) -> list[Finding]:
    has_destructive = any(DESTRUCTIVE_CMD_RE.search(strip_comment(l)) for l in lines)
    if not has_destructive:
        return []
    out = []
    for i, raw in enumerate(lines, 1):
        line = strip_comment(raw)
        if not INDEX_COMPARE_RE.search(line):
            continue
        # look further back for a citation: comments explaining a fixed-width field layout often
        # sit above the task's own 'name:' line, not just directly above the assert condition.
        window = "\n".join(lines[max(0, i - 1 - CITATION_LOOKBACK_LINES) : i])
        if FIELD_CITATION_SOURCE_RE.search(window) or FIELD_CITATION_WORKED_EXAMPLE_RE.search(
            window
        ):
            continue  # already documents the authoritative layout — not flagged
        out.append(
            Finding(
                "INDEXGUARD-01",
                "WARN",
                path,
                i,
                "single-character index compared against a literal char, in a file that also "
                "runs a destructive command (lvremove/zfs destroy/pct destroy/qm destroy/docker "
                "rm/rm -rf), with no nearby comment citing the authoritative field layout. The "
                "classic shape: lv_attr[4] used where the Open flag is actually at index 5, "
                f"silently defeating half of a pre-lvremove safety check. "
                f"See {AUDIT_DOC}. Fix: add a comment citing the source "
                "(e.g. 'lvm(8): state=idx4, open=idx5') next to the index, or prefer named-field "
                "extraction over positional slicing. WARN not FAIL: cannot verify the index itself "
                "is wrong without the authoritative field layout — only that it's undocumented.",
            )
        )
    return out


# --------------------------------------------------------------------------------------------
# Rule HANDLER-01: a set_fact name that exists ONLY inside a role's handlers/main.yml, with no
# matching inline set_fact of the same name anywhere in that role's tasks/. WARN — see module
# docstring: this cannot trace whether anything actually consumes the fact mid-run, only that
# the fact-defining shape matches the archetype bug. Still worth surfacing because it is exactly
# the shape of the archetype.
# --------------------------------------------------------------------------------------------


def _set_fact_name_counts(path: Path) -> dict[str, int]:
    """Count how many separate set_fact tasks assign each fact name in this file. Counting (not
    just presence) matters: a role that only ever sets a fact to a hardcoded init value ONCE
    (e.g. 'x: false' before any mutation) and then relies on a handler to flip it is exactly the
    archetype bug even though the name technically appears 'inline' once. The fixed pattern
    sets the name inline TWICE — once to initialise, once again
    after flush_handlers with a real read-back expression — so >=2 inline occurrences is the
    bar for 'looks fixed'."""
    if yaml is None:
        return {}
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
        docs = yaml.safe_load_all(text)
        counts: dict[str, int] = {}
        for doc in docs:
            _collect_set_fact_counts(doc, counts)
        return counts
    except Exception:
        return {}


def _collect_set_fact_counts(node, counts: dict[str, int]):
    if isinstance(node, dict):
        for key in ("set_fact", "ansible.builtin.set_fact"):
            if key in node and isinstance(node[key], dict):
                for name in node[key].keys():
                    if isinstance(name, str):
                        counts[name] = counts.get(name, 0) + 1
        for v in node.values():
            _collect_set_fact_counts(v, counts)
    elif isinstance(node, list):
        for item in node:
            _collect_set_fact_counts(item, counts)


def check_handler_only_fact(role_dir: Path) -> list[Finding]:
    handlers_file = role_dir / "handlers" / "main.yml"
    tasks_dir = role_dir / "tasks"
    if not handlers_file.exists() or not tasks_dir.exists():
        return []

    handler_counts = _set_fact_name_counts(handlers_file)
    if not handler_counts:
        return []

    inline_counts: dict[str, int] = {}
    for tf in tasks_dir.rglob("*.yml"):
        for name, n in _set_fact_name_counts(tf).items():
            inline_counts[name] = inline_counts.get(name, 0) + n

    # Flag names the handler sets that tasks/ sets FEWER THAN TWICE inline (zero = pure archetype
    # bug; exactly one = the "only an init-to-false, no post-handler re-set" variant — still
    # broken, since the sole inline occurrence never reflects the handler's own change).
    only_in_handler = {name for name in handler_counts if inline_counts.get(name, 0) < 2}
    if not only_in_handler:
        return []

    out = []
    try:
        text = handlers_file.read_text(encoding="utf-8", errors="ignore")
        lines = text.splitlines()
    except OSError:
        lines = []
    for name in sorted(only_in_handler):
        line_no = 1
        for i, l in enumerate(lines, 1):
            if re.search(rf"^\s*{re.escape(name)}\s*:", l):
                line_no = i
                break
        inline_n = inline_counts.get(name, 0)
        inline_desc = (
            "no inline set_fact of the same name exists anywhere"
            if inline_n == 0
            else f"only ONE inline set_fact of the same name exists (a static init, e.g. to "
            f"'false') with no post-handler re-set reflecting a real outcome"
        )
        out.append(
            Finding(
                "HANDLER-01",
                "WARN",
                handlers_file,
                line_no,
                f"'{name}' is set only by handlers/main.yml for any run-time-meaningful value — "
                f"{inline_desc} under {tasks_dir.relative_to(role_dir.parent)}/. "
                "Handlers run at PLAY END (or at an explicit meta: flush_handlers) — a same-run "
                "'reload if changed' guard reading this fact before that point always sees the "
                "pre-handler value. This is exactly the shape that puts an alert manager into a "
                f"false-alerting loop. See {AUDIT_DOC}. Fix: also set the fact "
                "inline (e.g. right after 'meta: flush_handlers', reading the mutating task's "
                ".changed). WARN not FAIL: this check cannot trace whether "
                "any consumer actually reads the fact mid-run — see this script's module docstring.",
            )
        )
    return out


# --------------------------------------------------------------------------------------------
# Rule MOLMIRROR-01: a molecule verify.yml/converge.yml that computes a selectattr/rejectattr/map
# filter chain over a hand-typed 'stub'/vars literal, with NO ansible.builtin.template,
# include_role, or import_role anywhere in the scenario directory. WARN — deliberately narrow
# (a blanket "no include_role" rule would flag the many scenarios that legitimately render
# templates directly, a house-wide, non-buggy pattern).
# --------------------------------------------------------------------------------------------

FILTER_CHAIN_RE = re.compile(r"\|\s*(selectattr|rejectattr|map)\s*\(")
STUB_VAR_RE = re.compile(r"^\s*stub\s*:\s*$")
TEMPLATE_OR_ROLE_RE = re.compile(r"(ansible\.builtin\.template|include_role|import_role)\s*:")


def check_molecule_mirror(scenario_dir: Path) -> list[Finding]:
    files = list(scenario_dir.glob("*.yml"))
    if not files:
        return []
    any_real_invocation = False
    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if TEMPLATE_OR_ROLE_RE.search(text):
            any_real_invocation = True
            break
    if any_real_invocation:
        return []  # legitimate render-the-template-directly pattern, or a real role invocation

    out = []
    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
            lines = text.splitlines()
        except OSError:
            continue
        has_stub = any(STUB_VAR_RE.match(l) for l in lines)
        filter_lines = [i for i, l in enumerate(lines, 1) if FILTER_CHAIN_RE.search(l)]
        if has_stub and filter_lines:
            out.append(
                Finding(
                    "MOLMIRROR-01",
                    "WARN",
                    f,
                    filter_lines[0],
                    "molecule scenario computes a selectattr/rejectattr/map filter chain over a "
                    "hand-typed 'stub:' literal, and NOTHING in this scenario directory calls "
                    "ansible.builtin.template, include_role, or import_role for the role under "
                    "test. This is the 'mirror the module' tautology: the test re-derives the "
                    "role's own decision expression and asserts the copy against itself, so a "
                    "regression in the REAL task file is invisible to this test. See "
                    f"{AUDIT_DOC}. "
                    "Fix: invoke the role/module for real (even "
                    "against a stubbed API response) instead of retyping its filter expression. "
                    "WARN not FAIL: rendering a role's templates directly with "
                    "ansible.builtin.template (checked separately, not flagged) is a legitimate, "
                    "house-wide pattern used by most molecule scenarios — this "
                    "rule is deliberately narrow to the stub+filter-chain-with-zero-invocation "
                    "shape to avoid flagging all of them.",
                )
            )
    return out


# --------------------------------------------------------------------------------------------
# Rule MOLMIRROR-02: a molecule scenario that hand-copies a role's `__default` resolution instead
# of including the role's own setup_vars.yml / _resolve_defaults.yml.
#
# Sibling of MOLMIRROR-01, not a widening of it. MOLMIRROR-01 exempts any scenario that renders a
# template or calls the role — correctly, because that is the house pattern. But a scenario can do
# BOTH: render the real template AND still hand-copy the variable resolution that feeds it. That
# copy is a second source of truth, and it drifts silently.
#
# The failure mode: a scenario's converge.yml mirrors its role's setup_vars.yml set_fact list; a
# commit adds one variable to the role and its template — a completely correct change — and the
# scenario dies with "'<var>' is undefined". The test blames the role for the test's own
# staleness, and the natural response is to patch the copy rather than delete it.
#
# The shape is precise and cheap to detect: the scenario assigns `<name>: "{{ <name>__default }}"`
# (with or without a `| default(...)`) while the role ships a resolver file the scenario never
# includes. WARN, because a scenario may legitimately pin one or two values by hand — the signal is
# a scenario doing the resolver's whole job in parallel with it.
# --------------------------------------------------------------------------------------------

MIRRORED_DEFAULT_RE = re.compile(
    r"^\s*(?P<name>[a-z_][a-z0-9_]*)\s*:\s*[\"']\{\{\s*(?P=name)__default\b"
)
RESOLVER_INCLUDE_RE = re.compile(r"include_tasks\s*:.*(setup_vars|_resolve_defaults)")


def check_molecule_default_mirror(scenario_dir: Path) -> list[Finding]:
    role_dir = scenario_dir.parent.parent
    resolvers = [
        role_dir / "tasks" / "setup_vars.yml",
        role_dir / "tasks" / "_resolve_defaults.yml",
    ]
    available = [r for r in resolvers if r.exists()]
    if not available:
        return []  # nothing to include; a hand-set value is the only option

    files = sorted(scenario_dir.glob("*.yml"))
    if any(
        RESOLVER_INCLUDE_RE.search(f.read_text(encoding="utf-8", errors="ignore"))
        for f in files
        if f.is_file()
    ):
        return []  # the scenario already defers to the role's own resolver

    out = []
    for f in files:
        try:
            lines = f.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        # Keep the match objects rather than re-running the regex on the same lines below: the
        # second pass returned Optional[Match] and had .group() called on it unguarded, which is
        # safe only because the line already matched once — a fact mypy cannot see and a future
        # edit could break.
        matches = [(i, m) for i, l in enumerate(lines, 1) if (m := MIRRORED_DEFAULT_RE.match(l))]
        hits = [i for i, _ in matches]
        # One or two pinned values is normal; doing the resolver's whole job is the smell.
        if len(hits) >= 2:
            names = ", ".join(sorted({m.group("name") for _, m in matches}))
            out.append(
                Finding(
                    "MOLMIRROR-02",
                    "WARN",
                    f,
                    hits[0],
                    f"molecule scenario hand-copies {len(hits)} of the role's `__default` "
                    f"resolutions ({names}) while the role ships "
                    f"{available[0].name}, which this scenario never includes. That copy is a "
                    "SECOND SOURCE OF TRUTH and it drifts: adding a variable to the role leaves "
                    "the scenario failing with \"'<var>' is undefined\", which reads as a broken "
                    "ROLE and is actually a stale TEST. Fix: "
                    f'`ansible.builtin.include_tasks: "{{{{ playbook_dir }}}}/../../tasks/{available[0].name}"` '
                    "and set only the values the scenario deliberately overrides. WARN because "
                    "pinning one or two values by hand is legitimate; this fires at two or more.",
                )
            )
    return out


# --------------------------------------------------------------------------------------------
# Rule MOLCOLL-01: a molecule scenario uses a `community.*` (or other non-builtin) collection
# plugin but its molecule.yml never sets ANSIBLE_COLLECTIONS_PATH.
#
# THIS CANNOT BE CAUGHT BY RUNNING THE SUITE LOCALLY, which is the whole reason it is a lint rule.
# A developer venv installed from the `ansible` package BUNDLES community.general inside
# site-packages/ansible_collections/, so the filter resolves locally no matter what any path is set
# to. CI installs collections via requirements.yml into a location molecule does not search, and
# ansible reads ansible.cfg from the CURRENT directory only — CI runs `( cd roles/<role> && ... )`,
# so the repo-root collections_path is not in effect either.
#
# Result: a role fails CI with "No filter named 'community.general.dict_kv'"
# while passing every local run, including one deliberately stripped of the fix. FAIL rather than
# WARN precisely because no local signal exists — the rule is the only thing standing between this
# and a red pipeline.
# --------------------------------------------------------------------------------------------

# A repo's OWN collection (devkit.toml `silent_guards.own_collections`, kept in-tree) is
# deliberately NOT listed: a scenario typically references it only in a comment or behind an
# apply gate it never sets. Add its prefix here if a scenario executes it.
#
# NOTE the two shapes. `community.general.dict_kv` is namespace.collection.plugin (three
# parts), while `ansible.posix.sysctl` is ALREADY namespace.collection in its first two —
# so a single "three dotted parts after the namespace" pattern matches the first and misses
# the second entirely. The original pattern did exactly that, and silently failed to catch
# the ansible.posix.sysctl case it was written in response to.
COLLECTION_PLUGIN_RE = re.compile(
    r"\b(?:community\.[a-z_]+\.[a-z_]+"
    r"|ansible\.(?:posix|utils|netcommon)\.[a-z_]+"
    r"|kubernetes\.core\.[a-z_]+)"
)
COLLECTIONS_PATH_RE = re.compile(r"ANSIBLE_COLLECTIONS_PATH\s*:")
INVOKES_ROLE_RE = re.compile(r"(include_role|import_role)\s*:")


def check_molecule_collections_path(scenario_dir: Path) -> list[Finding]:
    role_dir = scenario_dir.parent.parent

    scenario_files = sorted(scenario_dir.glob("*.yml"))

    # The role's own tasks count ONLY when the scenario actually invokes the role. A scenario that
    # calls include_role executes every collection module the role uses — a scenario can contain no
    # collection reference itself while its role's tasks/main.yml uses ansible.posix.sysctl, and CI
    # dies on exactly that.
    #
    # A scenario that only renders templates never runs those tasks, so a collection module in the
    # role is irrelevant to it. Scanning tasks unconditionally flags every such role — noise that
    # buries the real findings.
    invokes_role = any(
        INVOKES_ROLE_RE.search(f.read_text(encoding="utf-8", errors="ignore"))
        for f in scenario_files
        if f.name != "molecule.yml" and f.is_file()
    )
    search_files = scenario_files + (
        sorted((role_dir / "tasks").glob("*.yml")) if invokes_role else []
    )

    used: tuple[Path, int, str] | None = None
    for f in search_files:
        if f.name == "molecule.yml":
            continue
        try:
            lines = f.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for i, line in enumerate(lines, 1):
            if line.strip().startswith("#"):
                continue
            m = COLLECTION_PLUGIN_RE.search(line)
            if m:
                used = (f, i, m.group(0))
                break
        if used:
            break
    if not used:
        return []

    mol = scenario_dir / "molecule.yml"
    declared = ""
    if mol.exists():
        try:
            for line in mol.read_text(encoding="utf-8", errors="ignore").splitlines():
                if COLLECTIONS_PATH_RE.search(line):
                    declared = line
                    break
        except OSError:
            pass

    f, line_no, plugin = used
    # A path that omits collections.galaxy is WORSE than none: it looks deliberate and resolves
    # nothing vendored. Every vendored collection lives there; only the repo's own collection
    # lives in collections/.
    if declared and VENDORED_COLLECTIONS in declared:
        return []

    why = (
        "molecule.yml sets no ANSIBLE_COLLECTIONS_PATH"
        if not declared
        else f"molecule.yml's ANSIBLE_COLLECTIONS_PATH omits {VENDORED_COLLECTIONS}/, where every "
        f"vendored collection actually lives (only the repo's own {OWN_COLLECTIONS} is in "
        "collections/) — "
        "which looks deliberate and resolves nothing"
    )
    return [
        Finding(
            "MOLCOLL-01",
            "FAIL",
            f,
            line_no,
            f"the role or its scenario uses the collection plugin `{plugin}` but {why}. This "
            "PASSES LOCALLY AND FAILS ON CI, with no local signal available: a venv installed "
            "from the `ansible` package bundles the collections inside site-packages, so the "
            "plugin resolves here regardless, while CI installs them where molecule does not "
            "look — and `( cd roles/<role> && ... )` means the repo-root ansible.cfg and its "
            'collections_path are not read either. The symptom is "No filter named '
            "'community.general.dict_kv'\" or \"couldn't resolve module/action "
            "'ansible.posix.sysctl'\" on CI only. Fix: under provisioner: "
            "`env: {ANSIBLE_COLLECTIONS_PATH: "
            f'"${{MOLECULE_PROJECT_DIRECTORY}}/../../{VENDORED_COLLECTIONS}:'
            '${MOLECULE_PROJECT_DIRECTORY}/../../collections"}` — BOTH trees, mirroring '
            "ansible.cfg.",
        )
    ]


# --------------------------------------------------------------------------------------------
# Rule RESOLVE-01: a role's generated defaults resolver binds its options with
# `x | default(x__default)` and NOTHING guards against the role's own leftover facts.
#
# `set_fact` persists for the rest of the play. A role invoked TWICE in one play therefore sees
# its own facts from the first call on the second: a later caller that OMITS an option silently
# inherits the earlier caller's value instead of the declared default. The `| default(...)` reads
# as "fall back to the default" and, on a repeat call, can never do so — a guard that cannot fire.
#
# A role resolving state via `state | default('present')`, called with state=absent and then
# called again with nothing, resolves to `absent` both times.
#
# FAIL — deterministic. The fix is generated, not hand-written: regenerate with
#   argspec generate <role>
# which emits a first-call branch and a repeat-call branch keyed on `_<role>__argspec_resolved`.
# --------------------------------------------------------------------------------------------

RESOLVER_BIND_RE = re.compile(r'^\s{4}([a-z0-9_]+)\s*:\s*"\{\{\s*\1\s*\|\s*default\(\1__default\)')


def check_resolver_reentry(path: Path, lines: list[str]) -> list[Finding]:
    # Only ever applies to a generated resolver file.
    if path.name != "_resolve_defaults.yml":
        return []
    if any("__argspec_resolved" in ln for ln in lines):
        return []  # already guarded
    for i, raw in enumerate(lines, 1):
        m = RESOLVER_BIND_RE.match(raw.rstrip("\n"))
        if not m:
            continue
        return [
            Finding(
                "RESOLVE-01",
                "FAIL",
                path,
                i,
                f"resolver binds '{m.group(1)}' with | default({m.group(1)}__default) and has no "
                "re-entry guard. set_fact persists for the whole play, so if this role is included "
                "twice in one play the second call reads the FIRST call's leftover fact: a caller "
                "that omits this option silently inherits the earlier value instead of the declared "
                "default, and the `| default(...)` can never fire. Fix: regenerate "
                "with `argspec generate <role>`, which emits a "
                "first-call and a repeat-call branch keyed on `_<role>__argspec_resolved`. Do not "
                "hand-edit this file — it is overwritten on every generation.",
            )
        ]
    return []


# --------------------------------------------------------------------------------------------
# Rule YAMLESC-01: a backslash escape inside a Jinja expression that sits in a NON-double-quoted
# YAML scalar (folded >-, literal |, single-quoted or plain). FAIL.
#
# WHY THIS IS DETERMINISTIC, and why the direction is the opposite of the intuition:
#     Only YAML's DOUBLE-QUOTED style processes backslash escapes. Every other style passes the
#     backslash through literally. The instinct is therefore "the non-double-quoted style is the
#     safe one, because my regex survives intact" — and for a REGEX that is true. For an escape
#     that is meant to be a real character (\n, \t) it is exactly backwards, and it fails SILENTLY:
#
#       vars:
#         n_double: "{{ s.split('\n') | length }}"     -> 3   (correct)
#         n_folded: >-
#           {{ s.split('\n') | length }}               -> 1   (WRONG, and nothing warns)
#
#     Measured with ansible-core 2.21.4 (not bare Jinja2, which
#     behaves differently — bare Jinja2 processes \n itself and returns 3 for BOTH, which is
#     precisely why testing this outside Ansible "proves" the bug does not exist). Ansible's
#     templar does not apply Python string-literal unescaping to the expression it receives, so a
#     surviving backslash+n stays two characters and split() never finds a newline.
#
#     The asymmetry that makes this worth a FAIL rather than a WARN: the WRONG-but-safe direction
#     is LOUD and the wrong-and-dangerous direction is SILENT.
#       - \| \. \d \s \w \S \( in a DOUBLE-quoted scalar: YAML itself raises
#         "found unknown escape character" and the play refuses to load. Impossible to miss.
#       - \n \t in a NON-double-quoted scalar: loads fine, yamllint is clean,
#         ansible-lint is clean, and the expression quietly computes the wrong answer.
#     So this rule only ever fires on the silent direction. The loud direction needs no check.
#
#     The damage this does in practice: an "is X present" check built on `split('\n')` inside a
#       >- scalar reports False on a host where X IS present — a silent guard arriving through
#       the quoting style rather than the logic.
#
# SCOPE: only escapes that Python/Jinja WOULD have turned into a different character are flagged
# (\n \t \r \0 \a \b \f \v). A regex escape (\d \s \w \. \| ...) is CORRECT in a non-double-quoted
# scalar — that is the house pattern and flagging it would be pure noise, so it is excluded.
# --------------------------------------------------------------------------------------------

# Escapes where backslash+char and the real character differ, i.e. where surviving the YAML layer
# silently changes the meaning. Deliberately EXCLUDES regex escapes (\d \s \w \. \| \S \D \W \A \Z
# \+ \* \( \) \[ \]), which are meant to reach the regex engine as a backslash pair.
_YAMLESC_CHARS = "ntr0afv"
_YAMLESC_LITERAL_RE = re.compile(r"""(['"])((?:\\.|(?!\1).)*)\1""")
_YAMLESC_ESCAPE_RE = re.compile(r"\\([%s])" % _YAMLESC_CHARS)
# A Jinja span: {{ ... }} or {% ... %}. Escapes OUTSIDE these are shell/text, not Jinja.
_YAMLESC_JINJA_SPAN_RE = re.compile(r"\{\{.*?\}\}|\{%.*?%\}|\{\{[^}]*$|\{%[^%]*$")

# A value that opens a block scalar: `key: >-`, `key: |`, `- key: >`, with optional indicators.
_BLOCK_SCALAR_OPEN_RE = re.compile(r":\s*[>|][+-]?\d*\s*(?:#.*)?$")
# `key: "..."` — the only style that processes escapes.
_DQ_VALUE_RE = re.compile(r":\s*\"")


def _yamlesc_scalar_style_map(lines: list[str]) -> dict[int, str]:
    """Map 1-indexed line number -> enclosing YAML scalar style for lines inside a BLOCK scalar.

    Only block scalars (>- | etc.) span lines, so those are the ones that need tracking; a
    single-line flow scalar's style is readable from the line itself. Returns 'block' for every
    continuation line of a block scalar, so the caller can tell a folded continuation apart from
    an ordinary `key: "{{ ... }}"` line.
    """
    styles: dict[int, str] = {}
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        if _BLOCK_SCALAR_OPEN_RE.search(line.rstrip("\n")):
            open_indent = len(line) - len(line.lstrip())
            j = i + 1
            # Consume the block's body: every line more-indented than the opening key, plus blanks.
            while j < n:
                body = lines[j]
                if not body.strip():
                    styles[j + 1] = "block"
                    j += 1
                    continue
                body_indent = len(body) - len(body.lstrip())
                if body_indent <= open_indent:
                    break
                styles[j + 1] = "block"
                j += 1
            i = j
            continue
        i += 1
    return styles


def check_yaml_escape_in_jinja(path: Path, lines: list[str]) -> list[Finding]:
    out: list[Finding] = []
    styles = _yamlesc_scalar_style_map(lines)
    for i, raw in enumerate(lines, 1):
        if "{{" not in raw and "{%" not in raw:
            continue
        stripped = raw.rstrip("\n")
        in_block = styles.get(i) == "block"
        # A `key: "{{ ... }}"` line is the SAFE style — YAML unescapes it. Skip it.
        if not in_block and _DQ_VALUE_RE.search(stripped):
            continue
        # Single-quoted or plain flow scalar on its own line is also unsafe, but a bare plain
        # scalar containing {{ }} is rare and usually a template body; require either a block
        # continuation or an explicitly single-quoted value to keep this deterministic.
        if not in_block and not re.search(r":\s*'", stripped):
            continue
        # Only look INSIDE Jinja delimiters. A shell command in a block scalar legitimately
        # contains its own escapes (printf 'x=%s\n', tr '\n' ','), where the backslash MUST
        # survive YAML untouched — those are correct and must never be flagged. Restricting the
        # scan to {{ }} / {% %} spans is what separates the two.
        for span in _YAMLESC_JINJA_SPAN_RE.finditer(stripped):
            for lit in _YAMLESC_LITERAL_RE.finditer(span.group(0)):
                for m in _YAMLESC_ESCAPE_RE.finditer(lit.group(2)):
                    ch = m.group(1)
                    out.append(
                        Finding(
                            "YAMLESC-01",
                            "FAIL",
                            path,
                            i,
                            f"'\\{ch}' inside a Jinja expression in a NON-double-quoted YAML scalar "
                            f"(folded >-, literal |, or single-quoted). Only YAML's double-quoted "
                            f"style processes backslash escapes, so this reaches Ansible's templar as "
                            f"the two characters backslash + '{ch}' and NEVER as the real character. "
                            "With ansible-core 2.21.4, `split('\\n')` in a >- scalar "
                            'returns 1 where the same expression in a "..." scalar returns 3, and '
                            "both yamllint and ansible-lint are silent about it. Note bare Jinja2 "
                            "does unescape this, so testing outside Ansible will wrongly show it "
                            "working. Fix: put the expression in a double-quoted scalar "
                            '(key: "{{ ... }}"), doubling any REGEX backslashes (\\\\S) as you move '
                            "it; or split on an unambiguous literal instead of an escape.",
                        )
                    )
    return out


# --------------------------------------------------------------------------------------------
# Rule PIPEQ-01: `... | grep -q` inside a shell block that sets `pipefail`. FAIL.
#
# The mechanics, measured:
#     set -o pipefail; <50k lines> | grep -q match   -> rc=141 (SIGPIPE), i.e. "no match"
#     set -o pipefail; <1 line>    | grep -q match   -> rc=0    (correct)
#     no pipefail;     <50k lines> | grep -q match   -> rc=0    (correct)
# So it needs pipefail AND enough output that the writer is still writing when grep -q exits and
# closes the pipe. Two consequences that shape this rule:
#   - BOTH shapes break, not only `if ! ...`: the positive `if cmd | grep -q X; then` reports
#     NOT-matched on genuinely matching input too. So this rule does not try to distinguish them.
#   - It is output-size dependent, which is exactly why it survives review: it works on the host
#     with 3 units and fails on the one with 300. Static analysis cannot know the size, so any
#     `grep -q` on the right-hand side of a pipe under pipefail is reported.
# What it costs: a CI "docs-only change" detector built this way reports docs_only=true for a
# large YAML change, skips every test and scanner behind it, and the required check goes green
# in seconds — under a comment claiming it fails CLOSED.
# Fix: decide from a file with `grep -c` and compare the count, or
# drop -q and test the captured output, so a wrong verdict is visible rather than implicit.
# --------------------------------------------------------------------------------------------

# A single `|` (not `||`) immediately before grep: that grep is the pipe's READER and can
# take SIGPIPE. `[ -f x ] || grep -q p file` has no writer upstream and cannot invert, so the
# negative lookbehind for a second `|` keeps that out (it produced the one false positive).
_PIPEQ_RE = re.compile(r"(?<!\|)\|(?!\|)\s*grep\b(?![^|]*\s/)[^|]*(?:\s-\w*q|\s-q\w*)")
_PIPEFAIL_RE = re.compile(r"\bpipefail\b")


def check_grep_q_under_pipefail(path: Path, lines: list[str]) -> list[Finding]:
    """Report `| grep -q` anywhere in a file that also sets pipefail.

    Scoped per-file rather than per-shell-block: a `cmd:` block scalar's extent is not reliably
    recoverable line-by-line, and `pipefail` in an Ansible task is almost always in the same block
    as the pipeline it governs (the house pattern is `set -o pipefail` as the first line of the
    shell body). Over-reporting here is cheap — the fix is a better pattern either way.
    """
    if not any(_PIPEFAIL_RE.search(ln) for ln in lines):
        return []
    out = []
    for i, raw in enumerate(lines, 1):
        if raw.lstrip().startswith("#"):
            continue
        if _PIPEQ_RE.search(raw):
            out.append(
                Finding(
                    "PIPEQ-01",
                    "FAIL",
                    path,
                    i,
                    "`| grep -q` in a file that sets `pipefail`. grep -q exits on the FIRST match "
                    "and closes the pipe; the writer then takes SIGPIPE and pipefail reports the "
                    "whole pipeline failed. With pipefail, 50k lines piped "
                    "into `grep -q <match>` gives rc=141 — indistinguishable from 'no match' — "
                    "while the same pipeline on ONE line gives rc=0. So it works in testing and "
                    "fails on a bigger host, and BOTH `if cmd | grep -q` and `if ! cmd | grep -q` "
                    "invert. A CI docs-only detector built this way skips every suite on a large "
                    "change and goes green in seconds, under a comment claiming it fails CLOSED. "
                    "Fix: write the output to a "
                    "file and decide with `grep -c`, comparing (and printing) the count; or drop "
                    "-q and test the captured text.",
                )
            )
    return out


# --------------------------------------------------------------------------------------------
# Rule IPSUB-01: substring membership test against an IP address. FAIL.
#
# `'192.0.2.2' in stdout` is True for '192.0.2.255', '192.0.2.20' and '1192.0.2.2'. The test reads
# as "is this host present" and is really "does this text contain these characters", so it passes
# on a neighbour and can never be trusted for a presence/absence gate.
# Deterministic to spot: a dotted-quad literal on the left of `in`, against a scalar (not a list).
# Fix: extract addresses with a regex and compare exact list membership, e.g.
#   {{ (out | regex_findall('\\d+\\.\\d+\\.\\d+\\.\\d+')) is contains('192.0.2.2') }}
# --------------------------------------------------------------------------------------------

# '192.0.2.2' in something   /   "192.0.2.2" in something
_IPSUB_RE = re.compile(r"""(['"])(\d{1,3}(?:\.\d{1,3}){3})\1\s+in\s+(?!\[)([A-Za-z_][\w.\[\]']*)""")


def check_ip_substring_membership(path: Path, lines: list[str]) -> list[Finding]:
    out = []
    for i, raw in enumerate(lines, 1):
        # A YAML comment is not code. Four of this rule's first seven findings were comments
        # WARNING against this very trap ("'192.0.2.6' in stdout would also match ..."), i.e. the
        # rule flagged the documentation of the bug it hunts — the same false-positive class that
        # ICASE-01 hit in Python docstrings.
        if raw.lstrip().startswith("#"):
            continue
        # No same-line {{/when:/that: requirement: an assert's conditions sit on their OWN lines
        # under `that:`, so gating on that made the rule unable to fire on the commonest shape.
        # The quoted-dotted-quad-followed-by-`in` pattern is specific enough on its own.
        for m in _IPSUB_RE.finditer(raw):
            ip, target = m.group(2), m.group(3)
            # `in` against a *_lines register IS exact membership (each element is one address).
            # Match only the suffix — a substring test would also exempt e.g. `pipelines_out`.
            if target.endswith("_lines") or target.endswith("_lines | default([])"):
                continue
            out.append(
                Finding(
                    "IPSUB-01",
                    "FAIL",
                    path,
                    i,
                    f"substring test `'{ip}' in {target}` — this is text containment, not address "
                    f"membership. It is also True for '{ip}55'/'{ip}0' and for a longer prefix, so "
                    "a presence gate written this way passes on a NEIGHBOUR address. Fix: extract "
                    "addresses and compare exactly, e.g. "
                    f"`({target} | regex_findall('\\\\d+\\\\.\\\\d+\\\\.\\\\d+\\\\.\\\\d+')) is "
                    f"contains('{ip}')`, or test against the `*_lines` form where each element is "
                    "one address.",
                )
            )
    return out


# --------------------------------------------------------------------------------------------
# Rule IPADDRTEST-01: ansible.utils.ipaddr used as a TEST rather than a filter. FAIL.
#
# `ipaddr` is a filter; `selectattr`/`select` expect a TEST. Passing a filter name raises at
# render time ("Unable to look up a name or access an attribute"), so the whole task dies — loud,
# but only once the play reaches that line, which on a fleet-wide play can be minutes in and
# after earlier tasks have already written state. Deterministic and cheap to catch statically.
# Fix: `selectattr('addr', 'match', '...')`, or map through the filter and compare, or use
# `ansible.utils.ipaddr` in a `set_fact` before the select.
# --------------------------------------------------------------------------------------------

_IPADDR_TEST_RE = re.compile(r"\b(?:select|reject)(?:attr)?\s*\(\s*[^)]*['\"]ipaddr['\"]")


def check_ipaddr_as_test(path: Path, lines: list[str]) -> list[Finding]:
    out = []
    for i, raw in enumerate(lines, 1):
        if _IPADDR_TEST_RE.search(raw):
            out.append(
                Finding(
                    "IPADDRTEST-01",
                    "FAIL",
                    path,
                    i,
                    "`ipaddr` used as a TEST inside select/reject/selectattr/rejectattr. "
                    "ansible.utils.ipaddr is a FILTER, not a test — a select* expects a test name, "
                    "so this raises at render time and kills the task. Fix: resolve the value "
                    "through the filter first (`set_fact` / `map`) and select on the RESULT, or use "
                    "a real test such as 'match' against an address regex.",
                )
            )
    return out


# --------------------------------------------------------------------------------------------
# Rule DIGRC-01: a `dig` result judged by output emptiness rather than rc / a `^;;` reject. WARN.
#
# dig writes its DIAGNOSTICS to stdout, so "stdout is non-empty" is not "the lookup succeeded":
# a SERVFAIL still prints `;; communications error` and friends, and a `when: x.stdout | length > 0`
# gate therefore reads a failed resolution as a successful one. This is the same family as the
# `grep -q` inversion — a check whose happy and sad paths are indistinguishable at the point it is
# read.
# WARN, not FAIL: plenty of legitimate dig uses register output for a REPORT rather than a gate,
# and distinguishing "this register feeds a decision" from "this register feeds a debug message"
# needs dataflow this checker does not build. So it reports the pairing and leaves the judgement.
# Fix: check `rc == 0` AND reject `^;;` (`+short` still prints diagnostics on failure).
# --------------------------------------------------------------------------------------------

_DIG_CMD_RE = re.compile(r"\bdig\s+(?:@|\+|[A-Za-z0-9])")
_DIG_STDOUT_GATE_RE = re.compile(
    r"\.stdout\b[^\n]*(?:\|\s*length\s*[><=]|\|\s*trim\s*\)?\s*\|\s*length|is\s+truthy|!=\s*['\"]{2})"
)


def check_dig_judged_by_stdout(path: Path, lines: list[str]) -> list[Finding]:
    """Flag a file that runs `dig` AND gates on stdout emptiness, with no rc or ';;' reject."""
    if not any(_DIG_CMD_RE.search(ln) for ln in lines):
        return []
    text = "\n".join(lines)
    # An rc check or a ';;' reject anywhere in the file is taken as the author having handled it —
    # this rule is about the MISSING pairing, not about where it lives.
    if re.search(r"\.rc\s*(?:==|!=)|rejectattr|reject\(\s*['\"]match['\"]\s*,\s*['\"]\^;;", text):
        return []
    if ";;" in text:
        return []
    out = []
    for i, raw in enumerate(lines, 1):
        if _DIG_STDOUT_GATE_RE.search(raw):
            out.append(
                Finding(
                    "DIGRC-01",
                    "WARN",
                    path,
                    i,
                    "this file runs `dig` and judges the result by stdout emptiness, with no `rc` "
                    "check and no `^;;` reject anywhere in it. dig prints its DIAGNOSTICS to "
                    "stdout, so a SERVFAIL/timeout produces non-empty stdout and this gate reads a "
                    "FAILED lookup as a successful one (`+short` is not exempt). Fix: require "
                    "`rc == 0` and reject lines matching `^;;` before trusting the answer. "
                    "WARN not FAIL: a dig registered purely for a report, rather than for a "
                    "decision, is legitimate and cannot be told apart from this statically.",
                )
            )
    return out


# --------------------------------------------------------------------------------------------
# Rule TIMERUNIT-01: systemctl stop/disable on a unit that also has a `.timer` in the repo. WARN.
#
# `systemctl stop foo` resolves to `foo.service`. If the work is actually driven by `foo.timer`,
# the timer survives and re-triggers the service — so a "stop it" step reads as done and the thing
# keeps running, which is the shape that leaves an operator debugging a service they believe is off.
# Only fires when a `<name>.timer` is ACTUALLY present somewhere in the repo, so this cannot flag a
# unit that genuinely has no timer. That check is what makes it specific enough to be worth having.
# Fix: target the `.timer` explicitly (stop/disable both), or use `state: stopped` on both units.
# --------------------------------------------------------------------------------------------

_SYSTEMCTL_STOP_RE = re.compile(r"systemctl\s+(?:--user\s+)?(?:stop|disable)\s+([A-Za-z0-9@_.\-]+)")


def check_systemctl_stop_ignores_timer(
    path: Path, lines: list[str], timers: set[str]
) -> list[Finding]:
    out = []
    for i, raw in enumerate(lines, 1):
        for m in _SYSTEMCTL_STOP_RE.finditer(raw):
            unit = m.group(1)
            if unit.endswith(".timer"):
                continue
            base = unit[: -len(".service")] if unit.endswith(".service") else unit
            if base in timers and f"{base}.timer" not in raw:
                out.append(
                    Finding(
                        "TIMERUNIT-01",
                        "WARN",
                        path,
                        i,
                        f"`systemctl stop/disable {unit}` resolves to '{base}.service', but this "
                        f"repo also defines '{base}.timer' — the timer SURVIVES and re-triggers "
                        "the service, so a step that reads as 'stopped' leaves it running on the "
                        f"next tick. Fix: target '{base}.timer' explicitly as well (stop AND "
                        "disable), or converge both units with ansible.builtin.systemd_service. "
                        "WARN not FAIL: stopping only the service is occasionally what you mean.",
                    )
                )
    return out


# --------------------------------------------------------------------------------------------
# Rule PGREPMULTI-01: `pgrep`/`pkill` given MORE THAN ONE pattern. FAIL — procps accepts exactly
# one, exits 2 with "only one pattern can be provided" ON STDERR, and prints no PIDs. Paired with
# the near-universal `2>/dev/null` that silences it, the command returns EMPTY — which reads as
# "the process is not running" rather than "I asked wrongly".
#
# In a drift check, `pgrep -x compositor-wl compositor` returns nothing against a RUNNING
# compositor, so the check reports "no session found" and, by the same path, NO DRIFT — a guard
# that cannot see the thing it compares against.
#
# Deterministic: the arity is wrong regardless of context. Note macOS pgrep ACCEPTS multiple
# patterns, so this cannot be caught by running it on a macOS controller — it fails only on the
# Linux targets.
# --------------------------------------------------------------------------------------------

# `pgrep`/`pkill`, its flags, then TWO bare words. Stops at a redirect, pipe, separator or
# substitution so only real pattern arguments are counted.
PGREP_MULTI_RE = re.compile(
    r"\b(pgrep|pkill)\b"
    r"((?:\s+-[^\s]+)*)"  # flags — anything beginning with '-'
    # NEGATIVE LOOKAHEAD ON BOTH PATTERNS, and it is not decoration: `[-\w]+` for the flag group
    # is GREEDY-OPTIONAL, so on `pgrep -xc demo-daemon` the matcher happily skipped the flag group
    # entirely and read '-xc' as the first "pattern" and 'demo-daemon' as the second, firing on a
    # CORRECT single-pattern call — a rule that false-positives on valid input gets disabled,
    # which is worse than no rule.
    r"\s+(?!-)([A-Za-z0-9_.-]+)"  # first pattern (cannot start with '-')
    # The second pattern must NOT be a redirection's fd number. `pgrep -x demo-daemon 2>/dev/null`
    # is a very common form, and reading its `2` as a pattern makes the
    # rule fire on correct code everywhere. A bare digit
    # is never a sensible process name, and a trailing `>` or `&` confirms it is a redirect.
    r"\s+(?!-)(?![0-9]+[>&])([A-Za-z0-9_.-]+)"  # second pattern -> the defect
    r"(?!\s*[>&])"  # ...and it is not itself followed by a redirect
)


def check_pgrep_multiple_patterns(path: Path, lines: list[str]) -> list[Finding]:
    out = []
    for i, raw in enumerate(lines, 1):
        stripped = raw.strip()
        if stripped.startswith("#"):
            continue
        m = PGREP_MULTI_RE.search(raw)
        if not m:
            continue
        flags = m.group(2) or ""
        # Flags that legitimately take a VALUE consume the next word, so what looks like a
        # second pattern is that option's argument. Checked by name rather than guessed.
        if re.search(
            r"-(?:P|s|u|U|G|g|t|n|o|d|-parent|-session|-uid|-euid|-group|-delimiter)$",
            flags.strip(),
        ):
            continue
        out.append(
            Finding(
                "PGREPMULTI-01",
                "FAIL",
                path,
                i,
                f"`{m.group(1)}` given two patterns ('{m.group(3)}' and '{m.group(4)}'). procps "
                "accepts exactly ONE: it exits 2 with 'only one pattern can be provided' on "
                "STDERR and prints no PIDs, so with the usual `2>/dev/null` the command returns "
                "EMPTY and reads as 'not running' rather than 'asked wrongly', even against a "
                "RUNNING process. NOTE macOS pgrep accepts multiple patterns, so testing on a "
                "macOS controller will not reproduce it. Fix: one "
                f"`{m.group(1)}` call per pattern, or match the executable with -f.",
            )
        )
    return out


# --------------------------------------------------------------------------------------------
# Rule INSPECTENV-01: a task whose RESULT is a container's full inspect document, with no
# `no_log`. FAIL — the inspect document carries `Config.Env`, i.e. every environment variable the
# container was started with, VALUES INCLUDED, and a JSON run-log callback writes every task result
# verbatim.
#
# A `docker_container_info` read-back that only wants the image, the id and the health status
# logs the container's API key with them, and a health wait re-logs the whole Env on every retry.
# The same shape sits in front of every container that takes a credential through its
# environment.
#
# Flags, as a YAML-AST walk (so a task's own and its enclosing block/play's `no_log` both count):
#   - community.docker.docker_container_info               (returns `container` = full inspect)
#   - community.docker.docker_container, unless state: absent (returns the same document)
#   - command/shell/raw running `docker inspect` / `docker container inspect` with no
#     `--format`/`-f` and no pipe narrowing its output, in the same command segment.
# NOT flagged: `docker image inspect` (an image's Env is baked at build time, not a runtime secret),
# a narrow `--format`, and an inspect piped straight into a filter (the author chose the fields).
#
# Deterministic: the module returns Env whether or not anything reads it. Fix: `no_log: true` on the
# task and a `set_fact` of ONLY the fields needed (image, id, state, health), or `docker inspect
# --format` selecting just those fields.
# --------------------------------------------------------------------------------------------

_INSPECT_INFO_MODULES = {
    "community.docker.docker_container_info",
    "docker_container_info",
}
_CONTAINER_MODULES = {"community.docker.docker_container", "docker_container"}
_SHELL_MODULES = {
    "ansible.builtin.command",
    "command",
    "ansible.builtin.shell",
    "shell",
    "ansible.builtin.raw",
    "raw",
}
_DOCKER_INSPECT_RE = re.compile(r"\bdocker\s+(?:container\s+)?inspect\b")
# The rest of ONE shell command: up to a separator, a substitution close, or an unescaped newline.
_CMD_SEGMENT_END_RE = re.compile(r"\|\||&&|[|;)`]|(?<!\\)\n")
_FORMAT_FLAG_RE = re.compile(r"(?:^|\s)(?:--format\b|-f(?=\s|['\"{]|$))")
_NO_LOG_FALSE = {"false", "no", "off", "0", ""}


def _scalar(node) -> str | None:
    return node.value if isinstance(node, yaml.ScalarNode) else None


def _no_log_on(node) -> bool | None:
    """True/False if this mapping sets no_log, None if it does not mention it."""
    for k, v in node.value:
        if _scalar(k) == "no_log":
            val = (_scalar(v) or "").strip().lower()
            return val not in _NO_LOG_FALSE
    return None


def _command_text(v_node) -> str:
    """The command a command/shell/raw task runs, as one string (argv joined by spaces)."""
    if isinstance(v_node, yaml.ScalarNode):
        return v_node.value or ""
    if isinstance(v_node, yaml.MappingNode):
        for k, v in v_node.value:
            key = _scalar(k)
            if key in ("cmd", "_raw_params") and isinstance(v, yaml.ScalarNode):
                return v.value or ""
            if key == "argv" and isinstance(v, yaml.SequenceNode):
                return " ".join(_scalar(i) or "" for i in v.value)
    return ""


def _unbounded_inspect(cmd: str) -> bool:
    for m in _DOCKER_INSPECT_RE.finditer(cmd):
        rest = cmd[m.end() :]
        end = _CMD_SEGMENT_END_RE.search(rest)
        segment = rest[: end.start()] if end else rest
        if _FORMAT_FLAG_RE.search(segment):
            continue
        if end and end.group(0) == "|":
            continue  # piped straight into a filter: the author narrowed the output
        return True
    return False


def _inspect_env_hits(node, inherited_no_log: bool, out: list[tuple[int, str]]):
    if node is None:
        return
    if isinstance(node, yaml.SequenceNode):
        for item in node.value:
            _inspect_env_hits(item, inherited_no_log, out)
        return
    if not isinstance(node, yaml.MappingNode):
        return
    own = _no_log_on(node)
    no_log = inherited_no_log if own is None else own
    keys = {_scalar(k): v for k, v in node.value}
    if not no_log:
        for k_node, v_node in node.value:
            key = _scalar(k_node)
            line = k_node.start_mark.line + 1
            if key in _INSPECT_INFO_MODULES:
                out.append((line, f"`{key}` returns the container's full inspect document"))
            elif key in _CONTAINER_MODULES:
                state = ""
                if isinstance(v_node, yaml.MappingNode):
                    for sk, sv in v_node.value:
                        if _scalar(sk) == "state":
                            state = (_scalar(sv) or "").strip()
                if state != "absent":
                    out.append((line, f"`{key}` returns the container's full inspect document"))
            elif key in _SHELL_MODULES and _unbounded_inspect(_command_text(v_node)):
                out.append((line, f"`{key}` runs `docker inspect` with no --format"))
    # Recurse only through the keys that can hold tasks; module arguments are not tasks.
    for child in (
        "tasks",
        "pre_tasks",
        "post_tasks",
        "handlers",
        "block",
        "rescue",
        "always",
    ):
        if child in keys:
            _inspect_env_hits(keys[child], no_log, out)


def check_inspect_registers_env(path: Path, text: str, lines: list[str]) -> list[Finding]:
    if yaml is None:
        return []
    hits: list[tuple[int, str]] = []
    try:
        for doc_node in _compose_all(text):
            _inspect_env_hits(doc_node, False, hits)
    except Exception:
        return []
    return [
        Finding(
            "INSPECTENV-01",
            "FAIL",
            path,
            line,
            f"{what}, which includes Config.Env — every environment VALUE the container runs "
            "with — and this task has no `no_log: true`, so a run-log callback writes those values "
            "in clear text — a read-back that needs only image, id and health logs the API key "
            "with them. Fix: `no_log: true` "
            "on the task (or its block) and a set_fact of ONLY the fields you need, or "
            "`docker inspect --format` selecting just those fields.",
        )
        for line, what in hits
    ]


# --------------------------------------------------------------------------------------------
# Rule CONDMAP-01: a conditional that YAML parses as a MAPPING, not a string. FAIL.
#
# An unquoted colon-space inside a Jinja expression in a LIST ITEM — `- _body is
# search('auth: refused')` under `that:`, `when:` or `failed_when:` — makes YAML read the
# item as a one-key mapping (`{"_body is search('auth": "refused')"}`). (The inline form,
# `when: x is search('a: b')`, is a loud YAML syntax error that yamllint already catches; only the
# list-item form parses.) Every linter is happy; Ansible refuses it with
# "Conditional expressions must be strings" only when the task RUNS, which for a gate deep in a
# play is after everything before it has already acted.
#
# Deterministic: the YAML node type IS the defect. No conditional keyword accepts a mapping, so a
# mapping there is wrong whatever it contains.
# --------------------------------------------------------------------------------------------

_CONDMAP_KEYS = ("when", "failed_when", "changed_when", "until")
_ASSERT_MODULES = ("assert", "ansible.builtin.assert", "ansible.legacy.assert")


def _condmap_items(v_node):
    """The individual conditionals under a conditional key: the node itself, or a list's items."""
    if isinstance(v_node, yaml.SequenceNode):
        return list(v_node.value)
    return [v_node]


def _condmap_hits(node, out: list[tuple[int, str]]):
    if isinstance(node, yaml.SequenceNode):
        for item in node.value:
            _condmap_hits(item, out)
        return
    if not isinstance(node, yaml.MappingNode):
        return
    for k_node, v_node in node.value:
        key = _scalar(k_node)
        where: list[tuple[str, object]] = []
        if key in _CONDMAP_KEYS:
            where = [(f"{key}:", i) for i in _condmap_items(v_node)]
        elif key in _ASSERT_MODULES and isinstance(v_node, yaml.MappingNode):
            for ak, av in v_node.value:
                if _scalar(ak) == "that":
                    where = [(f"{key}: that:", i) for i in _condmap_items(av)]
        for label, item in where:
            if isinstance(item, yaml.MappingNode):
                out.append((item.start_mark.line + 1, label))
        _condmap_hits(v_node, out)


def check_conditional_is_mapping(path: Path, text: str, lines: list[str]) -> list[Finding]:
    if yaml is None:
        return []
    hits: list[tuple[int, str]] = []
    try:
        for doc_node in _compose_all(text):
            _condmap_hits(doc_node, hits)
    except Exception:
        return []
    return [
        Finding(
            "CONDMAP-01",
            "FAIL",
            path,
            line,
            f"a conditional under `{label}` parses as a YAML MAPPING, not a string — almost "
            "always an unquoted ': ' inside the expression (e.g. `- x is search('a: b')`). "
            "Ansible rejects it with 'Conditional expressions must be strings', but only when "
            "the task runs. Fix: quote the whole condition (`- \"x is search('a: b')\"`), or "
            "use a block scalar.",
        )
        for line, label in hits
    ]


# --------------------------------------------------------------------------------------------
# Runner
# --------------------------------------------------------------------------------------------

LINE_RULES = [
    check_resolver_reentry,
    check_meta_until,
    check_posix_classes,
    check_pgrep_multiple_patterns,
    check_backslash_b_in_regex,
    check_dollar_anchor,
    check_neutralized_failed_branch,
    check_until_without_assert,
    check_comment_in_assert_that,
    check_comment_in_jinja_expr,
    check_string_int_compare,
    check_checkmode_via_extra,
    check_block_checkmode_scope,
    check_unexplained_index_guard,
    check_yaml_escape_in_jinja,
    check_grep_q_under_pipefail,
    check_ip_substring_membership,
    check_ipaddr_as_test,
    check_dig_judged_by_stdout,
]

RULE_DOCS = {
    "META-01": ("FAIL", "meta: action combined with until:/retries:/delay: (always ignored)"),
    "REGEX-01": ("FAIL", "POSIX bracket class inside a Python/Jinja regex (matches nothing)"),
    "REGEX-02": ("WARN", "\\b inside a non-raw regex-ish string (backspace, not word boundary)"),
    "ANCHOR-01": ("WARN", "'$' anchor without (?m) against apparent multi-line stdout"),
    "FAILED-01": (
        "WARN",
        "branch on .failed/is failed/is succeeded after failed_when:false (not ignore_errors)",
    ),
    "UNTIL-01": (
        "WARN",
        "until: loop with no assert/fail re-checking the register afterward (file-local)",
    ),
    "ASSERTKEY-01": (
        "WARN",
        "comment inside an assert.that: list breaking a plain-scalar continuation",
    ),
    "JINJACOMMENT-01": ("FAIL", "'#' inside a {{ }} Jinja expression (hard syntax error)"),
    "STRINT-01": ("WARN", "string-coerced value compared against a bare int literal"),
    "CHECKMODE-01": ("FAIL", "docs claim ansible_check_mode is settable via -e/EXTRA= (it is not)"),
    "CHECKMODE-02": (
        "WARN",
        "when: ansible_check_mode inside a block with its own check_mode: key",
    ),
    "INDEXGUARD-01": (
        "WARN",
        "unexplained single-char index guard in front of a destructive command",
    ),
    "MAPKEY-01": ("FAIL", "Jinja expression inside a YAML mapping key (never templated)"),
    "PGREPMULTI-01": (
        "FAIL",
        "pgrep/pkill given more than one pattern (procps takes exactly one; fails silently)",
    ),
    "YAMLESC-01": (
        "FAIL",
        "\\n/\\t escape inside a Jinja expression in a non-double-quoted YAML scalar "
        "(survives as backslash+char; silently wrong)",
    ),
    "HANDLER-01": (
        "WARN",
        "set_fact exists only in handlers/main.yml, no inline counterpart in tasks/",
    ),
    "MOLMIRROR-01": (
        "WARN",
        "molecule verify/converge re-derives the role's own filter expression as its own test",
    ),
    "MOLMIRROR-02": (
        "WARN",
        "molecule scenario hand-copies the role's __default resolution instead of including its resolver",
    ),
    "MOLCOLL-01": (
        "FAIL",
        "molecule scenario uses a collection plugin without ANSIBLE_COLLECTIONS_PATH (passes locally, fails CI)",
    ),
    "SUPPRESS-01": ("FAIL", "guard-check suppression comment with no reason"),
    "PIPEQ-01": ("FAIL", "`| grep -q` under pipefail (SIGPIPE reads as 'no match' on big output)"),
    "IPSUB-01": ("FAIL", "substring test against an IP literal (matches neighbour addresses)"),
    "IPADDRTEST-01": ("FAIL", "ipaddr used as a test inside select*/reject* (it is a filter)"),
    "DIGRC-01": ("WARN", "dig result judged by stdout emptiness, with no rc check or '^;;' reject"),
    "TIMERUNIT-01": (
        "WARN",
        "systemctl stop/disable of a unit whose .timer also exists in the repo (timer survives)",
    ),
    "RESOLVE-01": (
        "FAIL",
        "generated defaults resolver has no re-entry guard (stale fact on a repeat in-play call)",
    ),
    "INSPECTENV-01": (
        "FAIL",
        "container inspect result (Config.Env, secrets included) logged without no_log",
    ),
    "CONDMAP-01": (
        "FAIL",
        "when:/until:/*_when:/assert that: item parses as a YAML mapping (unquoted ': ')",
    ),
}


def _repo_timer_basenames() -> set[str]:
    """Base names of every `<name>.timer` the repo defines or manages.

    TIMERUNIT-01 only fires when the timer ACTUALLY exists, so this is what keeps it from flagging
    every `systemctl stop`. Computed once per run rather than per file.
    """
    names: set[str] = set()
    for root in DEFAULT_ROOTS:
        base = REPO_ROOT / root
        if not base.is_dir():
            continue
        for p in base.rglob("*"):
            if p.is_dir():
                continue
            if p.suffix in (".j2", ".yml", ".yaml", ".timer") or p.name.endswith(".timer.j2"):
                try:
                    txt = p.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                names |= {m for m in re.findall(r"([A-Za-z0-9@_\-]+)\.timer\b", txt)}
            if p.name.endswith(".timer") or p.name.endswith(".timer.j2"):
                names.add(p.name.split(".timer")[0])
    return names


_TIMER_BASENAMES: set[str] | None = None


def scan_file(path: Path) -> list[Finding]:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    lines = text.splitlines()

    findings: list[Finding] = []
    findings += check_bare_suppressions(path, lines)
    for rule_fn in LINE_RULES:
        findings += rule_fn(path, lines)
    findings += check_jinja_in_mapping_key(path, text, lines)
    findings += check_inspect_registers_env(path, text, lines)
    findings += check_conditional_is_mapping(path, text, lines)

    global _TIMER_BASENAMES
    if _TIMER_BASENAMES is None:
        _TIMER_BASENAMES = _repo_timer_basenames()
    findings += check_systemctl_stop_ignores_timer(path, lines, _TIMER_BASENAMES)

    return findings


def apply_suppressions(
    findings: list[Finding], lines_by_file: dict[Path, list[str]]
) -> tuple[list[Finding], list[Finding]]:
    kept: list[Finding] = []
    suppressed: list[Finding] = []
    for f in findings:
        if f.rule == "SUPPRESS-01":
            kept.append(f)
            continue
        lines = lines_by_file.get(f.path)
        if lines is None:
            kept.append(f)
            continue
        applies = parse_suppressions(lines)
        sups_here = applies.get(f.line, [])
        ok, _ = is_suppressed(sups_here, f.rule)
        if ok:
            suppressed.append(f)
        else:
            kept.append(f)
    return kept, suppressed


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("paths", nargs="*", default=list(DEFAULT_ROOTS))
    ap.add_argument(
        "--fail-on-warn", action="store_true", help="treat WARN findings as failures too"
    )
    ap.add_argument("--list-rules", action="store_true", help="print the rule table and exit")
    ap.add_argument(
        "--quiet-suppressed",
        action="store_true",
        help="don't print a summary of suppressed findings",
    )
    args = ap.parse_args()

    if args.list_rules:
        print(f"{'RULE':16} {'LEVEL':6} DESCRIPTION")
        for rule, (level, desc) in sorted(RULE_DOCS.items()):
            print(f"{rule:16} {level:6} {desc}")
        return 0

    roots = [Path(p) for p in args.paths]
    all_findings: list[Finding] = []
    lines_by_file: dict[Path, list[str]] = {}

    for f in iter_files(roots):
        findings = scan_file(f)
        all_findings.extend(findings)
        try:
            lines_by_file[f] = f.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            lines_by_file[f] = []

    # role-level checks (need the whole role directory, not a single file). A "role dir" is any
    # directory that has a tasks/ and/or molecule/ subdirectory (tasks/ for HANDLER-01, molecule/
    # for MOLMIRROR-01 — a dir with only one of the two is still worth checking for that one rule).
    # We accept three shapes on the command line:
    #   - a roles/ container (e.g. `roles`)      -> every immediate child that looks like a role
    #   - a single role dir (e.g. `roles/foo`)    -> that dir itself, if it looks like a role
    #   - anything else                            -> walk looking for role-shaped dirs at any depth
    def _looks_like_role(p: Path) -> bool:
        return (p / "tasks").is_dir() or (p / "molecule").is_dir()

    role_dirs: list[Path] = []
    for root in roots:
        if not root.is_dir():
            continue
        if _looks_like_role(root):
            role_dirs.append(root)
        elif root.name == "roles":
            role_dirs.extend(p for p in root.iterdir() if p.is_dir() and _looks_like_role(p))
        else:
            role_dirs.extend(
                p
                for p in root.rglob("*")
                if p.is_dir() and _looks_like_role(p) and not is_exempt(p)
            )

    seen_roles = set()
    for rd in role_dirs:
        rd = rd.resolve()
        if rd in seen_roles or is_exempt(rd):
            continue
        seen_roles.add(rd)
        all_findings.extend(check_handler_only_fact(rd))
        mol_default = rd / "molecule" / "default"
        if mol_default.exists():
            all_findings.extend(check_molecule_mirror(mol_default))
            all_findings.extend(check_molecule_default_mirror(mol_default))
            all_findings.extend(check_molecule_collections_path(mol_default))

    kept, suppressed = apply_suppressions(all_findings, lines_by_file)

    fails = [f for f in kept if f.level == "FAIL"]
    warns = [f for f in kept if f.level == "WARN"]

    for f in sorted(kept, key=lambda x: (str(x.path), x.line)):
        print(f"{f.level:4} [{f.rule}] {f.path}:{f.line}: {f.message}")

    if suppressed and not args.quiet_suppressed:
        print(f"\n({len(suppressed)} finding(s) suppressed via guard-check: ignore comments)")

    print(
        f"\ncheck_silent_guards: {len(fails)} FAIL, {len(warns)} WARN across "
        f"{len(lines_by_file)} file(s) scanned. See {AUDIT_DOC}."
    )

    if fails:
        return 1
    if warns and args.fail_on_warn:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
