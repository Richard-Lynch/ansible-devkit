#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for check_workflow_fork_guard.py (FORKGUARD-01).

Run:  uv run tests/suites/test_check_workflow_fork_guard.py   (from the repo root)

Both directions: every MUST-FAIL fixture is a job a fork PR could push onto a self-hosted runner,
and every NEAR-MISS is one that looks similar and is safe. The first MUST-FAIL case is the exact
shape a light job has before this rule: a bare repository variable in runs-on.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

from _paths import CHECKS, ROOT  # tests/suites/_paths.py

SCRIPT = CHECKS / "check_workflow_fork_guard.py"
REPO = ROOT

LIGHT = """${{ fromJSON(vars.RUNS_ON || '"ubuntu-latest"') }}"""
LIGHT_PINNED = (
    "${{ fromJSON((github.event_name == 'pull_request' && "
    "github.event.pull_request.head.repo.full_name != github.repository) && "
    """'"ubuntu-latest"' || vars.RUNS_ON || '"ubuntu-latest"') }}"""
)
GUARD = (
    "(github.event_name != 'pull_request' || "
    "github.event.pull_request.head.repo.full_name == github.repository)"
)


def wf(job: str, on: str = "pull_request:\n    types: [opened]") -> str:
    return f"name: t\non:\n  {on}\njobs:\n{job}"


def job(runs_on: str, job_if: str | None = None) -> str:
    out = "  j:\n"
    if job_if is not None:
        out += f'    if: "{job_if}"\n'
    out += f"    runs-on: {runs_on}\n    steps:\n      - run: true\n"
    return out


MUST_FAIL = {
    "guard inside an || under a top-level &&": wf(
        job(
            "[self-hosted, isolated]",
            f"always() && (github.event.pull_request.draft == true || {GUARD})",
        )
    ),
    "guard negated": wf(job("[self-hosted, isolated]", f"!{GUARD}")),
    "guard compared to false": wf(job("[self-hosted, isolated]", f"{GUARD} == false")),
    "pull_request_target with the canonical if: guard": wf(
        job("[self-hosted, isolated]", GUARD), on="pull_request_target:"
    ),
    "pull_request_target with the canonical runs-on pin": wf(
        job(LIGHT_PINNED), on="pull_request_target:"
    ),
    "light job with no guard (the pre-rule shape)": wf(job(LIGHT)),
    "literal self-hosted list, no guard": wf(job("[self-hosted, isolated]")),
    "guard defeated by a top-level ||": wf(job("[self-hosted, isolated]", f"always() || {GUARD}")),
    "guard negated by a different comparison (!= repository)": wf(
        job(
            "[self-hosted, isolated]",
            "(github.event_name != 'pull_request' || "
            "github.event.pull_request.head.repo.full_name != github.repository)",
        )
    ),
    "runs-on with the variable FIRST and hosted last": wf(
        job(
            "${{ fromJSON(vars.RUNS_ON || (github.event_name == 'pull_request' && "
            "github.event.pull_request.head.repo.full_name != github.repository) && "
            """'"ubuntu-latest"') }}"""
        )
    ),
    "guard as a conjunct of the LEFT disjunct of a top-level || (guard && x || true)": wf(
        job("[self-hosted, isolated]", f"{GUARD} && always() || true")
    ),
    "canonical runs-on prefix with junk after it (the hosted label becomes an operand)": wf(
        job(
            "${{ fromJSON((github.event_name == 'pull_request' && "
            "github.event.pull_request.head.repo.full_name != github.repository) && "
            """'"ubuntu-latest"' || vars.RUNS_ON) && fromJSON(vars.OTHER) }}"""
        )
    ),
    "canonical runs-on whose LAST alternative is a variable, not a hosted label": wf(
        job(
            "${{ fromJSON((github.event_name == 'pull_request' && "
            "github.event.pull_request.head.repo.full_name != github.repository) && "
            """'"ubuntu-latest"' || vars.RUNS_ON || vars.OTHER) }}"""
        )
    ),
    "pull_request_review with the canonical if: guard (HIGH: the guard cannot hold there)": wf(
        job("[self-hosted, isolated]", GUARD), on="pull_request_review:"
    ),
    "pull_request_review_comment with the canonical runs-on pin": wf(
        job(LIGHT_PINNED), on="pull_request_review_comment:"
    ),
    "issue_comment on a self-hosted list": wf(job("[self-hosted, lab]"), on="issue_comment:"),
    "workflow_run with the canonical if: guard": wf(
        job("[self-hosted, lab]", GUARD), on="workflow_run:\n    workflows: [ci]"
    ),
    "a self-hosted label that merely LOOKS hosted (ubuntu-lab)": wf(job("ubuntu-lab")),
    "a list mixing a hosted label with a lookalike": wf(job("[ubuntu-latest, ubuntu-lab]")),
    "runs-on in the group/labels mapping form": wf(
        "  j:\n    runs-on:\n      group: big\n      labels: [ubuntu-latest]\n    steps:\n      - run: true\n"
    ),
    "runs-on from a strategy matrix": wf(
        "  j:\n    strategy:\n      matrix:\n        os: [ubuntu-latest, self-hosted]\n"
        "    runs-on: ${{ matrix.os }}\n    steps:\n      - run: true\n"
    ),
    "if: that is not a string (a YAML boolean) guards nothing": wf(
        "  j:\n    if: true\n    runs-on: [self-hosted, lab]\n    steps:\n      - run: true\n"
    ),
    "canonical runs-on form whose labels merely LOOK hosted (ubuntu-lab)": wf(
        job(
            "${{ fromJSON((github.event_name == 'pull_request' && "
            "github.event.pull_request.head.repo.full_name != github.repository) && "
            """'"ubuntu-lab"' || vars.RUNS_ON || '"ubuntu-lab"') }}"""
        )
    ),
    "canonical runs-on form with a hosted fork label but a lookalike fallback": wf(
        job(
            "${{ fromJSON((github.event_name == 'pull_request' && "
            "github.event.pull_request.head.repo.full_name != github.repository) && "
            """'"ubuntu-latest"' || vars.RUNS_ON || '"ubuntu-lab"') }}"""
        )
    ),
    "if: made of two ${{ }} blocks (text concatenation, not one expression)": wf(
        job(
            "[self-hosted, lab]",
            "${{ github.event_name != 'pull_request' }} || "
            "${{ github.event.pull_request.head.repo.full_name == github.repository }}",
        )
    ),
    "if: with a ${{ }} block embedded inside the guard text": wf(
        job("[self-hosted, lab]", f"${{{{ true }}}} && {GUARD}")
    ),
    "a job that is not a mapping cannot be judged": wf("  j: just-a-string\n"),
    "a job with neither runs-on nor uses cannot be judged": wf(
        "  j:\n    steps:\n      - run: true\n"
    ),
    "jobs: that is not a mapping": "name: t\non:\n  pull_request:\njobs: [a, b]\n",
    "pull_request_target trigger counts too": wf(
        job("[self-hosted, lab]"), on="pull_request_target:"
    ),
    "list-form on: [pull_request]": "name: t\non: [pull_request, push]\njobs:\n"
    + job("[self-hosted, lab]"),
}

NEAR_MISS = {
    "a list of hosted labels needs no guard": wf(job("[ubuntu-latest]")),
    "an arm hosted label from the allowlist": wf(job("ubuntu-24.04-arm")),
    "canonical runs-on form with arm labels from the allowlist": wf(
        job(
            "${{ fromJSON((github.event_name == 'pull_request' && "
            "github.event.pull_request.head.repo.full_name != github.repository) && "
            """'"ubuntu-24.04-arm"' || vars.RUNS_ON || '"ubuntu-24.04-arm"') }}"""
        )
    ),
    "if: wrapped ONCE in ${{ }} around the whole guard": wf(
        job("[self-hosted, lab]", f"${{{{ {GUARD} }}}}")
    ),
    "a larger-runner macos label from the allowlist": wf(job("macos-14-xlarge")),
    "pull_request_review on a hosted literal is fine": wf(
        job("ubuntu-latest"), on="pull_request_review:"
    ),
    "issue_comment on a hosted literal is fine": wf(job("ubuntu-24.04"), on="issue_comment:"),
    "pull_request_target on a hosted literal is fine": wf(
        job("ubuntu-latest"), on="pull_request_target:"
    ),
    "hosted literal needs no guard": wf(job("ubuntu-latest")),
    "light job pinned to hosted for forks (form B)": wf(job(LIGHT_PINNED)),
    "guard with a parenthesised || in ANOTHER conjunct (one top-level disjunct)": wf(
        job(
            "[self-hosted, isolated]",
            f"{GUARD} && (github.event.pull_request.draft != true || always())",
        )
    ),
    "canonical runs-on with another variable name and macos (form B, fullmatch)": wf(
        job(
            "${{ fromJSON((github.event_name == 'pull_request' && "
            "github.event.pull_request.head.repo.full_name != github.repository) && "
            """'"macos-latest"' || vars.RUNNERS || '"macos-latest"') }}"""
        )
    ),
    "heavy guard as a conjunct (form A)": wf(
        job(
            "[self-hosted, isolated]",
            f"github.event.pull_request.draft != true && {GUARD}",
        )
    ),
    "guard as the whole if, without its outer parentheses": wf(
        job("[self-hosted, isolated]", GUARD[1:-1])
    ),
    "a quoted || inside a string literal is not an operator": wf(
        job("[self-hosted, isolated]", f"contains(github.ref, '||') && {GUARD}")
    ),
    "no PR trigger at all (schedule only)": wf(
        job("[self-hosted, lab]"), on="schedule:\n    - cron: '0 6 * * *'"
    ),
    "a reusable-workflow call pinned to a commit SHA has no runs-on to judge": wf(
        "  j:\n    uses: o/r/.github/workflows/x.yml@" + "b" * 40 + "\n"
    ),
}


# Reusable-workflow cases are DIRECTORIES: a caller plus its callee, judged together.
CALLER = wf("  j:\n    uses: ./.github/workflows/callee.yml\n")
CALLEE_UNGUARDED = "name: c\non:\n  workflow_call:\njobs:\n" + job("[self-hosted, lab]")
CALLEE_GUARDED = "name: c\non:\n  workflow_call:\njobs:\n" + job("[self-hosted, lab]", GUARD)
CALLEE_HOSTED = "name: c\non:\n  workflow_call:\njobs:\n" + job("ubuntu-latest")

DIR_MUST_FAIL: dict[str, tuple[dict[str, str], str]] = {
    "a PR workflow calls a local reusable workflow whose job selects the lab runner unguarded": (
        {"caller.yml": CALLER, "callee.yml": CALLEE_UNGUARDED},
        "FORKGUARD-01",
    ),
    "a workflow_call-only file with no caller is judged as fork-reachable": (
        {"callee.yml": CALLEE_UNGUARDED},
        "FORKGUARD-01",
    ),
    "a local call to a callee that is not among the scanned files": (
        {"caller.yml": CALLER},
        "FORKGUARD-01",
    ),
    "a remote reusable workflow at a tag ref": (
        {"caller.yml": wf("  j:\n    uses: o/r/.github/workflows/x.yml@v1\n")},
        "FORKGUARD-02",
    ),
    "a remote reusable workflow at a branch ref": (
        {"caller.yml": wf("  j:\n    uses: o/r/.github/workflows/x.yml@main\n")},
        "FORKGUARD-02",
    ),
    "a workflow_call-only file with no caller: even the canonical if: guard is not enough": (
        {"callee.yml": CALLEE_GUARDED},
        "FORKGUARD-01",
    ),
    "pull_request AND workflow_call with the canonical guard, no scanned caller": (
        {
            "both.yml": "name: b\non:\n  pull_request:\n  workflow_call:\njobs:\n"
            + job("[self-hosted, lab]", GUARD)
        },
        "FORKGUARD-01",
    ),
    "a chain: PR -> local a -> local b, b unguarded": (
        {
            "caller.yml": wf("  j:\n    uses: ./.github/workflows/a.yml\n"),
            "a.yml": "name: a\non:\n  workflow_call:\njobs:\n  k:\n    uses: ./.github/workflows/b.yml\n",
            "b.yml": CALLEE_UNGUARDED,
        },
        "FORKGUARD-01",
    ),
}
DIR_NEAR_MISS: dict[str, dict[str, str]] = {
    "the same callee with the guard passes": {"caller.yml": CALLER, "callee.yml": CALLEE_GUARDED},
    "a callee on a hosted literal passes": {"caller.yml": CALLER, "callee.yml": CALLEE_HOSTED},
    "a remote reusable workflow at a 40-hex SHA passes": {
        "caller.yml": wf("  j:\n    uses: o/r/.github/workflows/x.yml@" + "a" * 40 + "\n")
    },
    "ansible-devkit's own reusable workflow at a release tag passes (DEP-04's exception)": {
        "caller.yml": wf(
            "  j:\n    uses: Richard-Lynch/ansible-devkit/.github/workflows/reusable-ci.yml@v0.5.0\n"
        )
    },
    "a self-call cycle terminates and judges once": {
        "caller.yml": wf("  j:\n    uses: ./.github/workflows/caller.yml\n"),
    },
    "pull_request AND workflow_call with the canonical guard, reached by a scanned PR caller": {
        "caller.yml": wf("  j:\n    uses: ./.github/workflows/both.yml\n"),
        "both.yml": "name: b\non:\n  pull_request:\n  workflow_call:\njobs:\n"
        + job("[self-hosted, lab]", GUARD),
    },
    "the guarded callee passes when a scanned PR caller reaches it": {
        "caller.yml": CALLER,
        "callee.yml": CALLEE_GUARDED,
    },
    "a workflow_call-only callee on a hosted literal with no caller passes": {
        "callee.yml": CALLEE_HOSTED
    },
}


def run(path: Path) -> tuple[int, str]:
    p = subprocess.run(
        [sys.executable, str(SCRIPT), str(path)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    return p.returncode, p.stdout + p.stderr


def main() -> int:
    failures: list[str] = []
    rc, out = run(REPO / ".github" / "workflows")
    print(f"  {'PASS' if rc == 0 else 'FAIL'}  the real workflows are clean")
    if rc != 0:
        failures.append(f"real workflows:\n{out}")

    with tempfile.TemporaryDirectory(prefix="forkguard_") as td:
        for i, (label, text) in enumerate(MUST_FAIL.items()):
            f = Path(td) / f"fail{i}.yml"
            f.write_text(text)
            rc, out = run(f)
            ok = rc == 1 and "FORKGUARD-01" in out
            print(f"  {'PASS' if ok else 'FAIL'}  must fail: {label}")
            if not ok:
                failures.append(f"{label} (rc={rc}):\n{text}\n{out}")
        for i, (label, text) in enumerate(NEAR_MISS.items()):
            f = Path(td) / f"pass{i}.yml"
            f.write_text(text)
            rc, out = run(f)
            ok = rc == 0 and "FORKGUARD-01" not in out
            print(f"  {'PASS' if ok else 'FAIL'}  near-miss passes: {label}")
            if not ok:
                failures.append(f"{label} (rc={rc}):\n{text}\n{out}")

        for i, (label, (files, rule)) in enumerate(DIR_MUST_FAIL.items()):
            d = Path(td) / f"dfail{i}"
            d.mkdir()
            for fname, text in files.items():
                (d / fname).write_text(text)
            rc, out = run(d)
            ok = rc == 1 and rule in out
            print(f"  {'PASS' if ok else 'FAIL'}  must fail ({rule}): {label}")
            if not ok:
                failures.append(f"{label} (rc={rc}):\n{out}")
        for i, (label, files) in enumerate(DIR_NEAR_MISS.items()):
            d = Path(td) / f"dpass{i}"
            d.mkdir()
            for fname, text in files.items():
                (d / fname).write_text(text)
            rc, out = run(d)
            ok = rc == 0 and "FORKGUARD" not in out
            print(f"  {'PASS' if ok else 'FAIL'}  near-miss passes: {label}")
            if not ok:
                failures.append(f"{label} (rc={rc}):\n{out}")

        # A local callee is resolved RELATIVE TO THE CALLER, not by basename across every scanned
        # file: tree A's caller must be judged against tree A's callee (unguarded), not tree B's.
        a = Path(td) / "treeA"
        b = Path(td) / "treeB"
        a.mkdir()
        b.mkdir()
        (a / "caller.yml").write_text(CALLER)
        (a / "callee.yml").write_text(CALLEE_UNGUARDED)
        (b / "callee.yml").write_text(CALLEE_HOSTED)
        p = subprocess.run(
            [sys.executable, str(SCRIPT), str(a), str(b)],
            capture_output=True,
            text=True,
            timeout=60,
        )
        out = p.stdout + p.stderr
        ok = p.returncode == 1 and "treeA" in out and "FORKGUARD-01" in out
        print(
            f"  {'PASS' if ok else 'FAIL'}  must fail: the callee is the caller's own tree's, not a same-named one"
        )
        if not ok:
            failures.append(f"callee resolution (rc={p.returncode}):\n{out}")

        # devkit.toml [workflow_fork_guard] hosted_labels extends the allowlist for a repository
        # with its own larger-runner labels; without the entry the same label is a finding.
        cfgdir = Path(td) / "cfgrepo"
        (cfgdir / ".github" / "workflows").mkdir(parents=True)
        (cfgdir / ".github" / "workflows" / "w.yml").write_text(wf(job("ubuntu-8core-large")))
        import os as _os

        env = {k: v for k, v in _os.environ.items() if k != "DEVKIT_ROOT"}
        env["DEVKIT_ROOT"] = str(cfgdir)
        p = subprocess.run(
            [sys.executable, str(SCRIPT), str(cfgdir / ".github" / "workflows")],
            capture_output=True,
            text=True,
            timeout=60,
            env=env,
        )
        ok = p.returncode == 1 and "FORKGUARD-01" in p.stdout
        print(
            f"  {'PASS' if ok else 'FAIL'}  must fail: an unlisted larger-runner label is possibly self-hosted"
        )
        if not ok:
            failures.append(f"unlisted label rc={p.returncode}:\n{p.stdout}{p.stderr}")
        (cfgdir / "devkit.toml").write_text(
            '[workflow_fork_guard]\nhosted_labels = ["ubuntu-8core-large"]\n'
        )
        p = subprocess.run(
            [sys.executable, str(SCRIPT), str(cfgdir / ".github" / "workflows")],
            capture_output=True,
            text=True,
            timeout=60,
            env=env,
        )
        ok = p.returncode == 0
        print(
            f"  {'PASS' if ok else 'FAIL'}  near-miss passes: the same label listed in devkit.toml hosted_labels"
        )
        if not ok:
            failures.append(f"listed label rc={p.returncode}:\n{p.stdout}{p.stderr}")

        # Loud, never clean, on nothing to read or an unparseable file.
        empty = Path(td) / "empty"
        empty.mkdir()
        rc, out = run(empty)
        ok = rc == 2
        print(f"  {'PASS' if ok else 'FAIL'}  an empty directory exits 2, not clean")
        if not ok:
            failures.append(f"empty dir rc={rc}:\n{out}")
        bad = Path(td) / "bad.yml"
        bad.write_text("on: [pull_request\njobs: {")
        rc, out = run(bad)
        ok = rc == 2
        print(f"  {'PASS' if ok else 'FAIL'}  an unparseable workflow exits 2")
        if not ok:
            failures.append(f"bad yaml rc={rc}:\n{out}")

    lr = subprocess.run(
        [sys.executable, str(SCRIPT), "--list-rules"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    ok = lr.returncode == 0 and lr.stdout.startswith("FORKGUARD-01") and "FORKGUARD-02" in lr.stdout
    print(
        f"  {'PASS' if ok else 'FAIL'}  --list-rules names FORKGUARD-01 and -02 (DOCRULE-01 reads it)"
    )
    if not ok:
        failures.append(f"--list-rules: rc={lr.returncode} {lr.stdout!r}")
    if failures:
        print(f"\n{len(failures)} FAILURE(S):", file=sys.stderr)
        for msg in failures:
            print(f"--- {msg}", file=sys.stderr)
        return 1
    print("\ntest_check_workflow_fork_guard: all passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
