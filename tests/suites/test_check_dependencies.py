#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Cases for check_dependencies.py (DEP-02..05, baseline-FAIL): every rule FAILS on its fixture
and PASSES on a near-miss, and the baseline tolerates, refuses stale entries and refuses an entry
with no reason.

Each case builds a throwaway git repository (the check scans TRACKED files) with a devkit.toml,
writes the fixture, and runs the check as `devkit check dependencies` would: a subprocess with
DEVKIT_ROOT pointing at the repository.

Run: uv run tests/suites/test_check_dependencies.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from _paths import CHECKS

CHECK = CHECKS / "check_dependencies.py"
SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"
DIGEST = "sha256:" + "ab" * 32
TOML = '[dependencies]\nrequirement_files = ["requirements.txt"]\n'
GALAXY = (
    'namespace: acme\nname: demo\nversion: 1.0.0\ndependencies:\n  community.general: ">=10.0.0"\n'
)

results: list[tuple[str, bool, str]] = []


def run(files: dict[str, str], baseline: dict | None = None) -> tuple[int, str]:
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        files = {"devkit.toml": TOML, **files}
        for rel, text in files.items():
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)
        if baseline is not None:
            (root / "deps-baseline.json").write_text(json.dumps(baseline))
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
        env = {**os.environ, "DEVKIT_ROOT": str(root)}
        p = subprocess.run(
            [sys.executable, str(CHECK)],
            cwd=root,
            env=env,
            capture_output=True,
            text=True,
        )
        return p.returncode, p.stdout + p.stderr


def case(name: str, files: dict[str, str], want_rc: int, want: str = "", **kw) -> None:
    rc, out = run(files, **kw)
    ok = rc == want_rc and (want in out)
    results.append((name, ok, out))


def wf(run_line: str) -> dict[str, str]:
    return {
        ".github/workflows/x.yml": "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
        f"    steps:\n      - run: |\n          {run_line}\n"
    }


def task(body: str, name: str = "roles/r/tasks/main.yml") -> dict[str, str]:
    return {"galaxy.yml": GALAXY, name: body}


# ---- DEP-02 ------------------------------------------------------------------------------------
case("DEP-02 FAIL pip install <pkg>", wf("pip install requests"), 1, "DEP-02")
case(
    "DEP-02 near-miss -r of a declared requirements file",
    wf("pip install -r requirements.txt"),
    0,
)
case("DEP-02 FAIL -r of an undeclared file", wf("pip install -r other.txt"), 1, "DEP-02")
case(
    "DEP-02 FAIL python3.12 -m pip with a global option",
    wf("python3.12 -m pip -q install x"),
    1,
    "DEP-02",
)
case(
    "DEP-02 FAIL a backslash continuation",
    wf("pip \\\n          install requests"),
    1,
    "DEP-02",
)
case("DEP-02 near-miss a commented command", wf("echo hi  # pip install requests"), 0)
case(
    "DEP-02 near-miss '#' inside quotes is not a comment",
    wf("echo 'a #b' && echo ok"),
    0,
)
case(
    "DEP-02 FAIL an index override",
    wf("pip install -r requirements.txt --index-url https://x"),
    1,
    "--index-url",
)
case(
    "DEP-02 FAIL a VCS requirement",
    wf("pip install git+https://example.com/x.git"),
    1,
    "DEP-02",
)
case("DEP-02 near-miss -e .", wf("pip install -e ."), 0)
case("DEP-02 FAIL -e of anything but .", wf("pip install -e ../x"), 1, "DEP-02")
case("DEP-02 FAIL uvx tool", wf("uvx ruff check"), 1, "ruff")
case(
    "DEP-02 near-miss uvx's arguments are not packages",
    wf("uvx ruff==0.6.0 check all"),
    1,
    "ruff",
)
case("DEP-02 FAIL uv tool install", wf("uv tool install black"), 1, "black")
case("DEP-02 FAIL pipx run", wf("pipx run cowsay"), 1, "cowsay")
case(
    "DEP-02 FAIL pip module, free-form, unpinned",
    task("- name: x\n  ansible.builtin.pip: name=requests\n"),
    1,
    "DEP-02",
)
case(
    "DEP-02 FAIL ansible.legacy.pip dict, unpinned",
    task("- name: x\n  ansible.legacy.pip:\n    name: requests\n"),
    1,
    "DEP-02",
)
case(
    "DEP-02 near-miss pip module with an exact pin",
    task("- name: x\n  ansible.builtin.pip:\n    name: requests==2.32.0\n"),
    0,
)
case(
    "DEP-02 FAIL a pip module of an unreadable shape",
    task("- name: x\n  ansible.builtin.pip: [1, 2]\n"),
    1,
    "cannot read",
)
case(
    "DEP-02 FAIL a file using pip that does not parse",
    task("- name: x\n  ansible.builtin.pip:\n    name: [unclosed\n"),
    1,
    "does not parse",
)

# ---- DEP-03 ------------------------------------------------------------------------------------
case(
    "DEP-03 FAIL :latest",
    task("- x:\n    image: nginx:latest\n", "roles/r/defaults/main.yml"),
    1,
    "DEP-03",
)
case(
    "DEP-03 FAIL untagged",
    task("- x:\n    image: nginx\n", "roles/r/defaults/main.yml"),
    1,
    "untagged",
)
case(
    "DEP-03 near-miss a tag",
    task("- x:\n    image: nginx:1.27\n", "roles/r/defaults/main.yml"),
    0,
)
case(
    "DEP-03 near-miss a Jinja image",
    task('- x:\n    image: "{{ img }}"\n', "roles/r/defaults/main.yml"),
    0,
)
case(
    "DEP-03 FAIL FROM python AS python",
    {"Dockerfile": "FROM python AS python\nRUN true\n"},
    1,
    "DEP-03",
)
case(
    "DEP-03 near-miss FROM a stage defined earlier",
    {"Dockerfile": "FROM python:3.12 AS b\nFROM b\n"},
    0,
)
case("DEP-03 FAIL a Containerfile", {"Containerfile": "FROM x:latest\n"}, 1, "DEP-03")
case(
    "DEP-03 FAIL a templated dockerfile",
    {"roles/r/templates/app.Dockerfile.j2": "FROM x\n"},
    1,
    "DEP-03",
)

# ---- DEP-04 ------------------------------------------------------------------------------------
STEP = "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: {u}\n"
JOB = "on: push\njobs:\n  ci:\n    uses: {u}\n"
case(
    "DEP-04 FAIL an action by tag",
    {".github/workflows/a.yml": STEP.format(u="actions/checkout@v4")},
    1,
    "DEP-04",
)
case(
    "DEP-04 near-miss an action by SHA",
    {".github/workflows/a.yml": STEP.format(u=f"actions/checkout@{SHA}")},
    0,
)
case(
    "DEP-04 near-miss a local action",
    {".github/workflows/a.yml": STEP.format(u="./.github/actions/x")},
    0,
)
case(
    "DEP-04 FAIL docker://x:latest",
    {".github/workflows/a.yml": STEP.format(u="docker://x:latest")},
    1,
    "docker://",
)
case(
    "DEP-04 near-miss docker:// by digest",
    {".github/workflows/a.yml": STEP.format(u=f"docker://x@{DIGEST}")},
    0,
)
case(
    "DEP-04 near-miss devkit's reusable workflow at a release tag (CONFORM-04)",
    {
        ".github/workflows/ci.yml": JOB.format(
            u="Richard-Lynch/ansible-devkit/.github/workflows/reusable-ci.yml@v1.2.3"
        )
    },
    0,
)
case(
    "DEP-04 FAIL devkit's reusable workflow at a branch",
    {
        ".github/workflows/ci.yml": JOB.format(
            u="Richard-Lynch/ansible-devkit/.github/workflows/reusable-ci.yml@main"
        )
    },
    1,
    "DEP-04",
)
case(
    "DEP-04 FAIL another reusable workflow by tag",
    {".github/workflows/ci.yml": JOB.format(u="other/repo/.github/workflows/x.yml@v1.0.0")},
    1,
    "DEP-04",
)
case(
    "DEP-04 FAIL a workflow that does not parse",
    {".github/workflows/a.yml": "jobs: [\n"},
    1,
    "does not parse",
)
case(
    "DEP-04 FAIL found in a non-ASCII workflow name (git ls-files -z)",
    {".github/workflows/ünicode.yml": STEP.format(u="actions/checkout@v4")},
    1,
    "DEP-04",
)

# ---- DEP-05 ------------------------------------------------------------------------------------
G = "namespace: acme\nname: demo\nversion: 1.0.0\ndependencies:\n  community.general: {v}\n"
case(
    "DEP-05 FAIL a '*' dependency",
    {"galaxy.yml": G.format(v='"*"')},
    1,
    "is not a range",
)
case("DEP-05 FAIL an exact pin", {"galaxy.yml": G.format(v='"==10.0.0"')}, 1, "DEP-05")
case("DEP-05 near-miss a lower bound", {"galaxy.yml": G.format(v='">=10.0.0"')}, 0)
case(
    "DEP-05 near-miss a bounded range",
    {"galaxy.yml": G.format(v='">=10.0.0,<11.0.0"')},
    0,
)
case(
    "DEP-05 FAIL a role using an undeclared collection",
    task("- name: x\n  community.docker.docker_container:\n    name: x\n"),
    1,
    "community.docker",
)
case(
    "DEP-05 near-miss declared, builtin and itself",
    task(
        "- name: a\n  community.general.ini_file:\n    path: x\n"
        "- name: b\n  ansible.builtin.debug:\n    msg: x\n"
        "- name: c\n  ansible.builtin.include_role:\n    name: acme.demo.other\n"
    ),
    0,
)
case(
    "DEP-05 FAIL a plugin importing an undeclared collection",
    {
        "galaxy.yml": GALAXY,
        "plugins/filter/f.py": "from ansible_collections.ansible.utils.plugins.x import y\n",
    },
    1,
    "ansible.utils",
)

# ---- baseline ----------------------------------------------------------------------------------
KEY = "DEP-02|.github/workflows/x.yml|requests"
case(
    "baseline tolerates a recorded finding",
    wf("pip install requests"),
    0,
    baseline={"entries": {KEY: 1}, "reasons": {KEY: "a recorded and reviewed reason"}},
)
case(
    "baseline FAIL a stale entry",
    wf("echo nothing"),
    1,
    "STALE",
    baseline={"entries": {KEY: 1}, "reasons": {KEY: "a recorded and reviewed reason"}},
)
case(
    "baseline exit 2 on an entry with no reason",
    wf("pip install requests"),
    2,
    "no reason",
    baseline={"entries": {KEY: 1}, "reasons": {KEY: "UNREVIEWED"}},
)
case(
    "baseline FAIL a second occurrence beyond the count",
    wf("pip install requests && pip install requests"),
    1,
    "DEP-02",
    baseline={"entries": {KEY: 1}, "reasons": {KEY: "a recorded and reviewed reason"}},
)

failed = 0
for name, ok, out in results:
    print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    if not ok:
        failed += 1
        print("        " + out.strip().replace("\n", "\n        ")[:1200])
print(f"\n{len(results) - failed}/{len(results)} passed")
sys.exit(1 if failed else 0)
