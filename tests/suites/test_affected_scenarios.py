#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Cases for affected-scenarios.sh — the molecule scenario selector — against a fixture repo.

WHY THESE CASES. Running every molecule scenario on every change is slow, and selecting a subset is
exactly where a gate quietly stops covering things. So the property under test is not "does it
select correctly" but "does it ever select TOO LITTLE": the selector picks the right scenario when
it can be certain and falls back to ALL whenever it cannot (an empty diff, a git error, a shared
path, a role path it cannot parse). A green check is indistinguishable from a check that ran, so
every case asserts in both directions.

The fixture is built here: three roles (two with a default scenario, one without), two
playbook-level scenarios (one `# ci-exempt: <reason>`, which CI skips on purpose), and a
devkit.toml adding `lib/` to the global prefixes. The selector is told where the repo is through
DEVKIT_ROOT, as check_molecule_verify.py tells it.

Run: uv run tests/suites/test_affected_scenarios.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from _paths import SELECTOR  # tests/suites/_paths.py

FAILURES = 0
CASES = 0

MOLECULE = (
    "driver: {name: default}\nplatforms: [{name: localhost}]\n"
    "provisioner: {name: ansible, playbooks: {converge: converge.yml, verify: verify.yml}}\n"
    "verifier: {name: ansible}\n"
)


def check(label: str, got, want) -> None:
    global FAILURES, CASES
    CASES += 1
    if got == want:
        print(f"  PASS  {label}")
    else:
        FAILURES += 1
        print(f"  FAIL  {label}\n          got  {got!r}\n          want {want!r}")


def write(root: Path, rel: str, text: str = "") -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def build(root: Path) -> None:
    for role in ("alpha", "beta"):
        write(root, f"roles/{role}/molecule/default/molecule.yml", MOLECULE)
        write(root, f"roles/{role}/tasks/main.yml", "---\n")
    write(root, "roles/noscenario/tasks/main.yml", "---\n")
    write(root, "playbooks/site/molecule/smoke/molecule.yml", MOLECULE)
    write(
        root,
        "playbooks/tools/molecule/mac/molecule.yml",
        "# ci-exempt: needs a macOS-only tool\n" + MOLECULE,
    )
    write(root, "devkit.toml", '[molecule]\nselector_global_prefixes = ["lib/"]\n')
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)


def run(root: Path, changed: str | None = None, argv: list[str] | None = None) -> dict:
    env = dict(os.environ)
    env["DEVKIT_ROOT"] = str(root)
    if changed is not None:
        env["CHANGED_FILES"] = changed
    else:
        env.pop("CHANGED_FILES", None)
    p = subprocess.run(
        ["bash", str(SELECTOR), *(argv or [])],
        capture_output=True,
        text=True,
        env=env,
        cwd=root,
        timeout=60,
    )
    assert p.returncode == 0, f"selector exited {p.returncode}: {p.stderr[-400:]}"
    return json.loads(p.stdout)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="affected_") as td:
        root = Path(td)
        build(root)
        every = ["alpha", "beta"]
        pbs = ["playbooks/site/molecule/smoke"]
        all_count = len(every) + len(pbs)

        # --- it SELECTS when it can be certain -----------------------------------------------
        r = run(root, "roles/alpha/tasks/main.yml")
        check(
            "one role -> exactly that scenario",
            (r["all"], r["roles"]),
            (False, ["alpha"]),
        )
        r = run(root, "roles/alpha/tasks/main.yml\nroles/beta/tasks/main.yml")
        check("two roles -> both", (r["all"], r["roles"]), (False, ["alpha", "beta"]))
        r = run(root, "roles/alpha/a.yml\nroles/alpha/b.yml")
        check("same role twice -> selected once", r["roles"], ["alpha"])

        # --- it selects NOTHING only when nothing can be affected ---------------------------
        r = run(root, "README.md\ndocs/x.md")
        check("docs-only -> no scenarios", (r["all"], r["count"]), (False, 0))
        r = run(root, "playbooks/site/main.yml")
        check("playbook-only -> no ROLE scenario", (r["all"], r["roles"]), (False, []))
        check("playbook-only -> every playbook scenario", r["playbook_scenarios"], pbs)
        check("playbook-only -> count is the playbook scenarios", r["count"], len(pbs))
        r = run(root, "roles/alpha/tasks/main.yml")
        check("role change -> playbook scenarios too", r["playbook_scenarios"], pbs)
        r = run(root, "README.md\nplaybooks/site/README.md")
        check(
            "docs under playbooks/ -> still nothing",
            (r["count"], r["playbook_scenarios"]),
            (0, []),
        )

        # A role with no scenario has nothing to run, but must be REPORTED, not silently dropped.
        r = run(root, "roles/noscenario/tasks/main.yml")
        check(
            "role without a scenario -> no role selected",
            (r["all"], r["roles"]),
            (False, []),
        )
        check(
            "role without a scenario -> but it is NAMED",
            "noscenario" in r["reason"],
            True,
        )

        # --- it FAILS OPEN to everything ---------------------------------------------------
        for label, changed in [
            ("Makefile", "Makefile"),
            ("ci/", "ci/affected-scenarios.sh"),
            (".github/", ".github/workflows/ci.yml"),
            ("collections/", "collections/ansible_collections/x/y/plugins/a.py"),
            ("inventories/", "inventories/hosts/a.yml"),
            ("group_vars/", "group_vars/all.yml"),
            ("lib/ (from devkit.toml)", "lib/models.py"),
            (".ansible-lint.yml", ".ansible-lint.yml"),
            (".yamllint", ".yamllint"),
            ("requirements.yml", "requirements.yml"),
            ("pyproject.toml", "pyproject.toml"),
            ("ansible.cfg", "ansible.cfg"),
            (".python-version", ".python-version"),
        ]:
            r = run(root, changed)
            check(
                f"global path -> ALL: {label}",
                (r["all"], r["count"]),
                (True, all_count),
            )

        r = run(root, "roles/alpha/x.yml\nMakefile")
        check(
            "role + global -> ALL (global wins)",
            (r["all"], r["count"]),
            (True, all_count),
        )
        r = run(root, "roles/")
        check("unparseable role path -> ALL", r["all"], True)
        r = run(root, "")
        check("empty changed list -> ALL", r["all"], True)
        check("empty changed list -> says why", "resolved" in r["reason"], True)
        r = run(root, None, ["nonexistent-ref-aaa", "nonexistent-ref-bbb"])
        check("git diff failure -> ALL", r["all"], True)

        # An unreadable devkit.toml selects ALL, with the reason on record — never fewer.
        (root / "devkit.toml").write_text("[molecule\nselector_global_prefixes = 3\n")
        r = run(root, "README.md")
        check(
            "broken devkit.toml -> ALL",
            (r["all"], "devkit.toml" in r["reason"]),
            (True, True),
        )
        (root / "devkit.toml").write_text('[molecule]\nselector_global_prefixes = ["lib/"]\n')

        # --- the selected names are REAL scenario directories -------------------------------
        r = run(root, "Makefile")
        check("ALL lists only real scenarios", sorted(r["roles"]), every)
        check("ALL lists every playbook scenario", r["playbook_scenarios"], pbs)
        check(
            "ALL leaves out the ci-exempt scenario",
            "playbooks/tools/molecule/mac" in r["playbook_scenarios"],
            False,
        )

    print(f"\n{CASES - FAILURES}/{CASES} passed")
    print("ALL PASS" if not FAILURES else f"{FAILURES} FAILED")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
