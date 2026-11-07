#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""check_workflow_fork_guard — a fork PR's code must never reach a self-hosted runner.

WHY THIS EXISTS
    A self-hosted runner is PERSISTENT: isolation between jobs is a cleanup hook, per-instance
    users and a verified shared environment, which is enough for the owner's own branches and not
    for a stranger's code. So every job a fork PR can trigger must either refuse the fork or run
    it on a GitHub-hosted runner.

    The shape this catches: a workflow whose light jobs select `vars.<RUNS_ON>`, a repository
    variable documented as "set to the self-hosted labels while hosted minutes are blocked". From
    the moment it is flipped, a fork PR's code runs on the persistent runner through every one of
    those jobs, and the only protection is a comment saying the variable "must stay hosted if fork
    PRs are ever accepted" — a rule held by memory, on a switch meant to be flipped in a hurry.

THE RULE (FORKGUARD-01)
    In a workflow triggered by `pull_request`, a job whose `runs-on` is
    not a literal GitHub-hosted label (`ubuntu-*`, `macos-*`, `windows-*`) must carry ONE of:

      A. an `if:` with the guard as a top-level conjunct (the heavy jobs' form):
             (github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository)
         It must be one TOP-LEVEL `&&` conjunct: inside an `||`, negated or compared, it
         guards nothing, and that is a finding.

      B. a `runs-on` that selects a hosted label FIRST for a fork PR, before any variable:
             ${{ fromJSON((github.event_name == 'pull_request' && github.event.pull_request.head.repo.full_name != github.repository) && '"ubuntu-latest"' || vars.X || '"ubuntu-latest"') }}

    Form B is for the jobs that are REQUIRED checks, and the difference from A is deliberate: a
    job skipped by `if:` reports SUCCESS to a required check, so guarding a required check with A
    would give a fork PR green required checks having run nothing. B keeps the fork PR checked,
    on a hosted runner.

    Both forms are matched as CANONICAL text (whitespace-normalised), not evaluated: a variant
    that means the same thing is a finding, and the fix is to write the canonical form. That is
    the price of a deterministic rule, and it keeps every guard greppable by one string.

UNDER pull_request_target, pull_request_review, pull_request_review_comment, issue_comment AND
workflow_run NO GUARD IS ACCEPTED
    Their event name is not 'pull_request', so form A's first disjunct is TRUE for a fork and form
    B falls through to the variable. Every job in such a workflow must be a literal hosted label.

REUSABLE WORKFLOWS (FORKGUARD-01 through the call, FORKGUARD-02 for a remote one)
    A job that `uses:` a reusable workflow has no `runs-on` of its own, and the callee is triggered
    only by `workflow_call`, so judging files one at a time never judges it at all — a fork PR's
    code reaching a self-hosted runner through `uses: ./.github/workflows/x.yml` was invisible
    (found 2026-11-06). So: a LOCAL call is followed, and the callee's jobs are judged under the
    CALLER's triggers (recursively, with a cycle guard); a `workflow_call`-only workflow that no
    scanned caller reaches is judged as fork-reachable anyway, because an unscanned caller may
    exist (fail closed); and a REMOTE call (`owner/repo/.github/workflows/x.yml@ref`) cannot be
    inspected here, so its ref must be a 40-hex commit SHA (FORKGUARD-02) and the callee must carry
    its own guard in its own repository. The one exception, as DEP-04's: ansible-devkit's own
    reusable workflows at a release tag — their jobs are judged in that repository and are hosted.

WHAT THIS DOES NOT COVER
    `workflow_run`, `issue_comment` and other triggers that can be made to run PR code are not
    judged here. A composite action (`uses: ./.github/actions/x` in a STEP) runs on the job's own
    runner and needs no judgement of its own.

USAGE
    devkit check workflow-fork-guard [WORKFLOW_DIR_OR_FILE ...]   (default .github/workflows)
    devkit check workflow-fork-guard --list-rules

Exit codes: 0 = clean, 1 = at least one finding, 2 = usage/parse error.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _devkit_config  # noqa: E402

RULES = {
    "FORKGUARD-01": "a job a fork PR can trigger may select a self-hosted runner "
    "(no canonical fork guard in its if: or runs-on:)",
    "FORKGUARD-02": "a fork-reachable job calls a remote reusable workflow that is not pinned to a "
    "commit SHA (its callee cannot be inspected here)",
}

# A remote reusable-workflow call: owner/repo/.github/workflows/<file>@<ref>.
REMOTE_USES = re.compile(
    r"^(?P<repo>[\w.-]+/[\w.-]+)/\.github/workflows/(?P<file>[^@]+)@(?P<ref>.+)$"
)
LOCAL_USES = re.compile(r"^\./\.github/workflows/(?P<file>[\w.-]+\.ya?ml)$")
COMMIT_SHA = re.compile(r"^[0-9a-f]{40}$")
# DEP-04's exception, for the same reason: ansible-devkit's own reusable workflows are judged in
# that repository (every job hosted) and are pinned by release tag by every repository built on it.
DEVKIT_REUSABLE = re.compile(
    r"^Richard-Lynch/ansible-devkit/\.github/workflows/reusable-[\w-]+\.ya?ml@v\d+\.\d+\.\d+$"
)

# The labels GitHub itself hosts (docs: "GitHub-hosted runners", standard and larger-runner images
# are the same label families). An ALLOWLIST, not a prefix pattern: `ubuntu-lab` is a self-hosted
# label someone chose to look familiar, and a pattern `^ubuntu-` accepted it (security review,
# 2026-11-06). A repository with its own larger-runner labels adds them in devkit.toml
# `[workflow_fork_guard] hosted_labels`; anything else is treated as possibly self-hosted.
DEFAULT_HOSTED_LABELS = frozenset(
    {
        "ubuntu-latest",
        "ubuntu-slim",
        "ubuntu-24.04",
        "ubuntu-22.04",
        "ubuntu-24.04-arm",
        "ubuntu-22.04-arm",
        "macos-latest",
        "macos-latest-large",
        "macos-latest-xlarge",
        "macos-15",
        "macos-15-large",
        "macos-15-xlarge",
        "macos-14",
        "macos-14-large",
        "macos-14-xlarge",
        "macos-13",
        "macos-13-large",
        "macos-13-xlarge",
        "windows-latest",
        "windows-2025",
        "windows-2022",
        "windows-11-arm",
    }
)
try:
    _CFG = _devkit_config.load()
    HOSTED_LABELS = DEFAULT_HOSTED_LABELS | frozenset(
        _CFG.str_list("workflow_fork_guard.hosted_labels", [])
    )
except _devkit_config.ConfigError as _exc:
    _devkit_config.fatal("check_workflow_fork_guard", _exc)

# Form A: the guard, as the heavy jobs write it.
GUARD_IF = (
    "(github.event_name != 'pull_request' || "
    "github.event.pull_request.head.repo.full_name == github.repository)"
)
# Form B: runs-on whose FIRST alternative is a hosted label, chosen for a fork PR.
# The WHOLE canonical form, fullmatched: `(fork) && '"hosted"' || vars.NAME || '"hosted"'` and
# nothing else. A prefix match let anything follow — `... || vars.X) && fromJSON(vars.Y)` makes
# the fork's hosted label a mere operand of a later `&&`, so a fork lands on vars.Y (found by
# security review, 2026-11-06).
# The two quoted labels are CAPTURED and each must be in HOSTED_LABELS — the same allowlist
# hosted_literal() uses; no prefix pattern anywhere in this module (security review, 2026-11-06).
GUARD_RUNS_ON = re.compile(
    r"^\$\{\{ fromJSON\(\(github\.event_name == 'pull_request' && "
    r"github\.event\.pull_request\.head\.repo\.full_name != github\.repository\) && "
    r"'\"(?P<fork>[^\"']+)\"' \|\| vars\.[A-Za-z_][A-Za-z0-9_]* \|\| "
    r"'\"(?P<fallback>[^\"']+)\"'\) \}\}$"
)

# Every trigger under which a job can run with a fork PR's code or in a fork PR's context. Only
# plain `pull_request` has the canonical guards: under every other one the event name differs, so
# form A's first disjunct is TRUE and form B falls through to the variable, and a hosted literal is
# the only accepted runs-on (security review, 2026-11-06: the set was pull_request and
# pull_request_target only, so a pull_request_review workflow with the canonical guard passed and
# would have run fork code on a self-hosted runner).
FORK_TRIGGERS = (
    "pull_request",
    "pull_request_target",
    "pull_request_review",
    "pull_request_review_comment",
    "issue_comment",
    "workflow_run",
)
STRICT_TRIGGERS = frozenset(FORK_TRIGGERS) - {"pull_request"}


def norm(text: str) -> str:
    """Collapse whitespace so a folded or re-wrapped expression compares equal."""
    return re.sub(r"\s+", " ", text).strip()


def strip_braces(expr: str) -> str:
    e = expr.strip()
    if e.startswith("${{") and e.endswith("}}"):
        e = e[3:-2].strip()
    return e


def split_top_level(expr: str, op: str) -> list[str]:
    """Split on `op` where it occurs outside every parenthesis and string literal."""
    parts: list[str] = []
    depth = 0
    in_str = False
    last = 0
    i = 0
    while i < len(expr):
        c = expr[i]
        if in_str:
            if c == "'":
                # '' is an escaped quote inside a GitHub expression string
                if i + 1 < len(expr) and expr[i + 1] == "'":
                    i += 2
                    continue
                in_str = False
        elif c == "'":
            in_str = True
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        elif depth == 0 and expr.startswith(op, i):
            parts.append(expr[last:i].strip())
            i += len(op)
            last = i
            continue
        i += 1
    parts.append(expr[last:].strip())
    return parts


def strip_parens(expr: str) -> str:
    """Remove parentheses that wrap the WHOLE expression (not `(a) || (b)`)."""
    e = expr.strip()
    while e.startswith("(") and e.endswith(")"):
        depth = 0
        wraps = True
        for i, c in enumerate(e):
            depth += c == "("
            depth -= c == ")"
            if depth == 0 and i < len(e) - 1:
                wraps = False
                break
        if not wraps:
            break
        e = e[1:-1].strip()
    return e


def if_guarded(job_if: object) -> bool:
    """The guard must be one TOP-LEVEL `&&` conjunct, so that it being false makes the whole
    `if:` false. Anywhere else (inside an `||`, negated, compared) it guards nothing."""
    if not isinstance(job_if, str):
        return False
    want = strip_parens(GUARD_IF)
    expr = norm(strip_braces(job_if))
    if "${{" in expr or "}}" in expr:
        # `${{ a }} || ${{ b }}`: GitHub evaluates each block separately and concatenates the TEXT,
        # so the string is not one expression and the guard cannot be a conjunct of it. Unguarded.
        return False
    if strip_parens(expr) == want:
        return True  # the guard IS the whole if (its own `||` is the guard's, not a defeat)
    # `||` binds looser than `&&`: `guard && x || true` is `(guard && x) || true`, which is true
    # for a fork whenever the right disjunct is. So the whole expression must be ONE disjunct;
    # splitting on `&&` alone accepted that shape (security review, 2026-11-06).
    if len(split_top_level(expr, "||")) != 1:
        return False
    conjuncts = split_top_level(expr, "&&")
    return any(strip_parens(c) == want for c in conjuncts)


def hosted_literal(runs_on: object) -> bool:
    if isinstance(runs_on, str):
        return runs_on.strip() in HOSTED_LABELS
    if isinstance(runs_on, list) and runs_on:
        return all(isinstance(x, str) and x.strip() in HOSTED_LABELS for x in runs_on)
    return (
        False  # a mapping (`group:`/`labels:`), an expression, an empty list: not provably hosted
    )


def runs_on_guarded(runs_on: object) -> bool:
    if not isinstance(runs_on, str):
        return False
    m = GUARD_RUNS_ON.fullmatch(norm(runs_on))
    return bool(m) and m.group("fork") in HOSTED_LABELS and m.group("fallback") in HOSTED_LABELS


def triggers(doc: dict) -> set[str]:
    # PyYAML (YAML 1.1) reads a bare `on:` key as the boolean True.
    on = doc.get("on", doc.get(True))
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return {str(x) for x in on}
    if isinstance(on, dict):
        return {str(k) for k in on}
    return set()


def load(path: Path) -> dict:
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ValueError(f"{path}: does not parse: {exc}") from exc
    return doc if isinstance(doc, dict) else {}


def judge_jobs(
    path: Path,
    docs: dict[Path, dict],
    *,
    target: bool,
    chain: tuple[Path, ...],
    reached: set[Path],
    via: str = "",
) -> tuple[list[str], int]:
    """Judge every job of `path` as fork-reachable; follow local reusable calls under the caller's
    triggers. Returns (findings, jobs judged)."""
    doc = docs[path]
    findings: list[str] = []
    judged = 0
    where = f"{path}{via}"
    jobs = doc.get("jobs")
    if not isinstance(jobs, dict):
        findings.append(f"{where}: [FORKGUARD-01] `jobs:` is not a mapping; nothing can be judged.")
        return findings, judged
    for name, job in jobs.items():
        if not isinstance(job, dict):
            findings.append(
                f"{where}: job '{name}': [FORKGUARD-01] the job is not a mapping; it cannot be judged."
            )
            continue
        uses = job.get("uses")
        if isinstance(uses, str) and "runs-on" not in job:
            u = uses.strip()
            m = LOCAL_USES.match(u)
            if m:
                # Relative to the CALLER's own workflow directory, never by basename across every
                # scanned file: a same-named file in another tree is a different workflow.
                callee = next((c for c in docs if c == path.parent / m.group("file")), None)
                if callee is None:
                    findings.append(
                        f"{where}: job '{name}': [FORKGUARD-01] calls local reusable workflow "
                        f"{u!r}, which is not among the scanned files, so its jobs cannot be "
                        "judged; scan the whole workflow directory."
                    )
                    continue
                if callee in chain:
                    continue  # a cycle: already being judged under these triggers
                reached.add(callee)
                sub, n = judge_jobs(
                    callee,
                    docs,
                    target=target,
                    chain=chain + (callee,),
                    reached=reached,
                    via=f" (called from {path.name} job '{name}')",
                )
                findings += sub
                judged += n
                continue
            m = REMOTE_USES.match(u)
            if m:
                judged += 1
                if COMMIT_SHA.match(m.group("ref")) or DEVKIT_REUSABLE.match(u):
                    continue
                findings.append(
                    f"{where}: job '{name}': [FORKGUARD-02] calls remote reusable workflow {u!r} "
                    "from a fork-reachable job; its callee cannot be inspected here, so the ref "
                    "must be a 40-hex commit SHA, and the callee must carry its own fork guard in "
                    "its own repository."
                )
                continue
            findings.append(
                f"{where}: job '{name}': [FORKGUARD-01] calls {u!r}, which is neither a local "
                "`./.github/workflows/<file>` nor a remote `owner/repo/.github/workflows/<file>@ref`;"
                " it cannot be judged."
            )
            continue
        if "runs-on" not in job:
            findings.append(
                f"{where}: job '{name}': [FORKGUARD-01] the job has neither runs-on nor uses; "
                "where it runs cannot be judged."
            )
            continue
        judged += 1
        runs_on = job["runs-on"]
        if hosted_literal(runs_on):
            continue
        if target:
            findings.append(
                f"{where}: job '{name}': [FORKGUARD-01] a workflow triggered by "
                "pull_request_target / pull_request_review(_comment) / issue_comment / "
                "workflow_run (or a reusable workflow whose caller's trigger is unknown) runs fork "
                f"code or runs in a fork PR's context; runs-on {norm(str(runs_on))!r} must be a "
                "literal hosted label (no fork guard is accepted under these triggers)."
            )
            continue
        if if_guarded(job.get("if")) or runs_on_guarded(runs_on):
            continue
        findings.append(
            f"{where}: job '{name}': [FORKGUARD-01] runs-on {norm(str(runs_on))!r} can select a "
            "self-hosted runner and nothing refuses a fork PR. Add the canonical guard to `if:`\n"
            f"      {GUARD_IF}\n"
            "    or, for a required check (a skipped job reports SUCCESS), pick hosted first in "
            "runs-on:\n"
            "      ${{ fromJSON((github.event_name == 'pull_request' && "
            "github.event.pull_request.head.repo.full_name != github.repository) && "
            "'\"ubuntu-latest\"' || vars.<RUNS_ON> || '\"ubuntu-latest\"') }}"
        )
    return findings, judged


def check_files(files: list[Path]) -> tuple[list[str], int]:
    """Judge a SET of workflow files together, so reusable calls between them can be followed."""
    docs = {f: load(f) for f in files}
    findings: list[str] = []
    judged = 0
    # Pass 0: which files are reached through a local reusable call from a fork-triggered file.
    # A file that offers `workflow_call` and is NOT reached by any scanned caller may be called
    # by a caller this scan cannot see, under a trigger it cannot know — so it is judged in the
    # strictest context whatever its OWN triggers say (security review, 2026-11-06).
    reached: set[Path] = set()
    for path, doc in docs.items():
        if set(FORK_TRIGGERS) & triggers(doc):
            judge_jobs(path, docs, target=False, chain=(path,), reached=reached)
    for path, doc in docs.items():
        trig = triggers(doc)
        if not set(FORK_TRIGGERS) & trig:
            continue
        # Under any trigger but plain pull_request the event name is not 'pull_request', so
        # neither canonical form refuses a fork there (form A's first disjunct is TRUE, form B
        # falls through to the variable). There is no accepted guard: such a workflow runs
        # hosted, full stop.
        unknown_caller = "workflow_call" in trig and path not in reached
        fs, n = judge_jobs(
            path,
            docs,
            target=bool(trig & STRICT_TRIGGERS) or unknown_caller,
            chain=(path,),
            reached=set(reached),
            via=(" (also workflow_call with no scanned caller)" if unknown_caller else ""),
        )
        findings += fs
        judged += n
    # A workflow_call-only workflow that no scanned caller reached: a caller this scan did not see
    # may still be fork-triggered — by pull_request_target, for all this scan knows — so it is
    # judged in the STRICTEST context: only a hosted literal passes. Fail closed.
    for path, doc in docs.items():
        trig = triggers(doc)
        if "workflow_call" in trig and not set(FORK_TRIGGERS) & trig and path not in reached:
            fs, n = judge_jobs(
                path,
                docs,
                target=True,
                chain=(path,),
                reached=reached,
                via=" (workflow_call with no scanned caller: judged as pull_request_target)",
            )
            findings += fs
            judged += n
    return findings, judged


def main(argv: list[str]) -> int:
    if "--list-rules" in argv:
        for rid, desc in RULES.items():
            print(f"{rid}  FAIL  {desc}")
        return 0
    targets = [Path(a) for a in argv] or [Path(".github/workflows")]
    files: list[Path] = []
    for t in targets:
        if t.is_dir():
            files += sorted(t.glob("*.yml")) + sorted(t.glob("*.yaml"))
        elif t.is_file():
            files.append(t)
        else:
            print(
                f"check_workflow_fork_guard: no such file or directory: {t}",
                file=sys.stderr,
            )
            return 2
    if not files:
        print("check_workflow_fork_guard: no workflow files found — refusing to report clean.")
        return 2
    try:
        findings, judged = check_files(files)
    except ValueError as exc:
        print(f"check_workflow_fork_guard: {exc}", file=sys.stderr)
        return 2
    for line in findings:
        print(line)
    print(
        f"check_workflow_fork_guard: {len(findings)} FAIL — {judged} fork-reachable job(s) in "
        f"{len(files)} workflow file(s) judged."
    )
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
