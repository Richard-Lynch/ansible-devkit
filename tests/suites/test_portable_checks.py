#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""The generic checks run against a repo that is NOT this one, configured only by devkit.toml.

WHY THIS EXISTS. A generic check must not know where any one repository keeps things — a tree
root named after a service, a trap log under logs/, the rulebook's file name, a repo root derived
from the script's own location. That every such fact comes from devkit.toml is only proven by
running the checks somewhere those facts are false. So this suite builds a throwaway git repo with an unrelated layout
and its own devkit.toml, then asserts three things:

  1. CLEAN: every check exits 0 on it. A check that still needed an estate path would fail here or,
     worse, pass by scanning nothing — so the clean run also asserts each check SAW the fixture.
  2. CATCH: one injected violation per rule makes the owning check exit non-zero naming the rule.
     A rule that can only fire against one repository's layout is not portable.
  3. NEAR-MISS: values from ANOTHER repo's devkit.toml (agent_config_dir, collections.galaxy, an
     unrelated domain, scripts/) do NOT fire in the fixture. A hidden constant would fire on them.
     And a devkit.toml missing a REQUIRED key makes its check exit 2 naming the key, never 0.

The checkers are run from this package as subprocesses with cwd=<fixture> — exactly how
`devkit check` runs them against a consuming repo.

Run: uv run tests/suites/test_portable_checks.py   (from the repo root)
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

from _paths import CHECKS, ROOT  # noqa: F401 — tests/suites/_paths.py

from _paths import CHECKS as HOOKS  # noqa: E402
from _paths import SELECTOR  # noqa: E402
from test_check_silent_guards import FILE_CASES  # noqa: E402

# Variables that would redirect a check away from the fixture; scrubbed from every run.
SCRUB_ENV = ("DEVKIT_ROOT", "DEVKIT_TRAP_LOG_DIR", "DEVKIT_TRAP_LOG_DIR")

RULE_SOURCES = [
    "check_silent_guards.py",
    "check_agent_tree_writes.py",
    "check_molecule_verify.py",
]

DEVKIT_TOML = """\
[paths]
vendored = ["third_party/"]
ansible_roots = ["roles", "playbooks"]

[docs]
rulebook = "RULES.md"
rule_sources = {rule_sources}
trap_section = "## Pitfalls"

[ci_coverage]
suite_dirs = ["tests"]
primary_workflow = ".github/workflows/checks.yml"

[silent_guards]
audit_doc = "RULES.md"
vendored_collections_dir = "third_party/collections"

[regex_anchors]
paths = ["tools"]

[agent_tree]
tree_roots = ['\\{{\\{{app_state_dir\\}}\\}}']
concat_roots = ['app_state_dir\\s*~']
config_dir_aliases = {{ app_home = "/state" }}

[ha_restart]
supervisor_modules = ["acme.home.supervisor"]

[molecule]
selector = "{selector}"

[trap_hits]
log_dir = "var/trap-log"

[boundary]
patterns = [{{ regex = '\\bexample-estate\\.test\\b', label = "fixture estate domain" }}]
"""

GOOD_MOLECULE = """\
driver: {name: default}
platforms: [{name: localhost}]
provisioner:
  name: ansible
  playbooks: {converge: converge.yml, verify: verify.yml}
verifier: {name: ansible}
"""
GOOD_VERIFY = """\
---
- name: Verify
  hosts: localhost
  gather_facts: false
  tasks:
    - name: Probe
      ansible.builtin.assert:
        that: [true]
"""
USES_COLLECTION = (
    "---\n- name: Converge\n  hosts: localhost\n  tasks:\n    - ansible.builtin.set_fact:\n"
    "        x: \"{{ ['a'] | map('community.general.dict_kv', 'k') | list }}\"\n"
)


def collections_path(vendored: str) -> str:
    """GOOD_MOLECULE with provisioner.env.ANSIBLE_COLLECTIONS_PATH naming `vendored`."""
    env = (
        "  name: ansible\n  env:\n    ANSIBLE_COLLECTIONS_PATH: "
        f'"${{MOLECULE_PROJECT_DIRECTORY}}/../../{vendored}"\n'
    )
    return GOOD_MOLECULE.replace("  name: ansible\n", env)


# regex-check: ignore ICASE-01 — fixture DATA injected into the fixture repo, not a pattern used here
ICASE_BAD = 'import re\nP = re.compile(r"(pass|token)(?=[A-Z])", re.IGNORECASE)\n'
NOOP_TASKS = "---\n- name: Say hello\n  ansible.builtin.debug:\n    msg: hello\n"

CLEAN_FILES: dict[str, str] = {
    "roles/web/tasks/main.yml": NOOP_TASKS,
    "roles/web/defaults/main.yml": "---\nweb_port: 8080\n",
    "roles/web/files/app.conf": "listen = 8080\n",
    "roles/web/molecule/default/molecule.yml": GOOD_MOLECULE,
    "roles/web/molecule/default/converge.yml": GOOD_VERIFY,
    "roles/web/molecule/default/verify.yml": GOOD_VERIFY,
    "playbooks/site.yml": "---\n- name: Site\n  hosts: all\n  roles: [web]\n",
    "playbooks/demo/molecule/default/molecule.yml": GOOD_MOLECULE,
    "playbooks/demo/molecule/default/converge.yml": GOOD_VERIFY,
    "playbooks/demo/molecule/default/verify.yml": GOOD_VERIFY,
    "tools/helper.py": "import re\n\nNAME = re.compile(r'[a-z]+')\n",
    "tests/test_web.py": "print('ok')\n",
    ".github/workflows/checks.yml": "on: [pull_request]\njobs:\n  t:\n    runs-on: x\n"
    "    steps:\n      - run: python3 tests/test_web.py\n",
    ".gitignore": "var/\n",
}


def run(fixture: Path, script: str, *args: str, stdin: str | None = None) -> tuple[int, str]:
    exe = HOOKS / script
    env = {k: v for k, v in os.environ.items() if k not in SCRUB_ENV}
    cp = subprocess.run(
        [sys.executable, str(exe), *args],
        cwd=fixture,
        env=env,
        input=stdin,
        capture_output=True,
        text=True,
        timeout=120,
    )
    return cp.returncode, cp.stdout + cp.stderr


def git(fixture: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=fixture, capture_output=True, text=True, check=True)


def write(fixture: Path, rel: str, text: str) -> None:
    p = fixture / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def build(root: Path) -> Path:
    fx = root / "fixture"
    fx.mkdir()
    sources = json.dumps([str(HOOKS / s) for s in RULE_SOURCES])
    write(fx, "devkit.toml", DEVKIT_TOML.format(rule_sources=sources, selector=SELECTOR))
    for rel, text in CLEAN_FILES.items():
        write(fx, rel, text)
    # The rulebook documents exactly the rules the sources enforce, read from them (DOCRULE-01).
    ids: list[str] = []
    for s in RULE_SOURCES:
        rc, out = run(fx, s, "--list-rules")
        assert rc == 0, f"{s} --list-rules failed in the fixture: {out}"
        ids += [ln.split()[0] for ln in out.splitlines() if ln[:1].isupper() and "-" in ln[:20]]
    bullets = "".join(f"- **[FAIL {i}]** fixture rule.\n" for i in ids if i != "RULE")
    write(fx, "RULES.md", "# Rules\n\n## Pitfalls\n\n" + bullets + "\n## After\n")
    git(fx, "init", "-q")
    git(fx, "config", "user.email", "t@example.com")
    git(fx, "config", "user.name", "t")
    git(fx, "add", "-A")
    git(fx, "commit", "-q", "-m", "fixture")
    return fx


# (script, args) per check. The clean run requires exit 0 AND the "seen" fragment, so a check that
# scanned nothing cannot pass here.
CHECKS: dict[str, tuple[str, list[str], str]] = {
    "silent_guards": (
        "check_silent_guards.py",
        ["--fail-on-warn"],
        "0 FAIL, 0 WARN across",
    ),
    "rootfs_seal": ("check_rootfs_seal.py", [], "0 FAIL across"),
    "vendored_secrets": ("check_vendored_secrets.py", [], "0 FAIL across 1 vendored"),
    "agent_tree": ("check_agent_tree_writes.py", [], "0 FAIL across"),
    "ha_restart": ("check_ha_restart_validated.py", [], "0 FAIL across"),
    "molecule_verify": ("check_molecule_verify.py", [], "0 FAIL across 2 scenario(s)"),
    "tracked_ignored": ("check_no_tracked_ignored.py", [], "0 FAIL across"),
    "defaults_resolved": ("check_defaults_resolved.py", [], "0 FAIL across 1 role(s)"),
    "regex_anchors": ("check_regex_anchors.py", [], "0 FAIL across 1 file(s)"),
    "traps_checked": ("check_traps_are_checked.py", [], "0 FAIL across 1 doc(s)"),
    "ci_coverage": ("check_ci_covers_hook_tests.py", [], "all 1 hook test suite(s)"),
    "docs_drift": ("check_docs_drift.py", [], "0 FAIL across 1 doc(s)"),
    "boundary": ("boundary_lint.py", ["--enforce"], "0 estate-fact leak(s)"),
}

Mutation = Callable[[Path], None]


def files(mapping: dict[str, str]) -> Mutation:
    def apply(fx: Path) -> None:
        for rel, text in mapping.items():
            write(fx, rel, text)

    return apply


def task(text: str, rel: str = "roles/web/tasks/extra.yml") -> Mutation:
    return files({rel: text})


def sg_file(name: str, content: str) -> Mutation:
    return task(content, f"roles/web/tasks/{name}")


SG_ROLE_CASES: dict[str, Mutation] = {
    "DIGRC-01": task(
        "---\n- name: Resolve\n  ansible.builtin.command: dig @192.0.2.1 example.com +short\n"
        "  register: _d\n- name: Check\n  ansible.builtin.assert:\n    that:\n"
        "      - _d.stdout | trim | length > 0\n"
    ),
    "IPSUB-01": task(
        "---\n- name: Check\n  ansible.builtin.assert:\n    that:\n"
        "      - \"'192.0.2.2' in _r.stdout\"\n"
    ),
    "IPADDRTEST-01": task(
        "---\n- name: Pick\n  ansible.builtin.set_fact:\n"
        "    v: \"{{ h | selectattr('addr', 'ipaddr') | list }}\"\n"
    ),
    "PIPEQ-01": task(
        "---\n- name: Probe\n  ansible.builtin.shell:\n    cmd: |\n      set -o pipefail\n"
        "      if systemctl list-units | grep -q foo; then echo y; fi\n"
    ),
    "PGREPMULTI-01": task(
        "---\n- name: Probe\n  ansible.builtin.shell: pgrep -x webd web 2>/dev/null\n"
    ),
    "INSPECTENV-01": task(
        "---\n- name: Read it\n  community.docker.docker_container_info:\n    name: web\n"
        "  register: _ci\n"
    ),
    "YAMLESC-01": task(
        "---\n- name: Count\n  ansible.builtin.set_fact:\n    n: >-\n"
        "      {{ s.split('\\n') | length }}\n"
    ),
    "RESOLVE-01": task(
        "---\n- name: Resolve declared options over their generated defaults\n"
        "  ansible.builtin.set_fact:\n"
        '    web_port: "{{ web_port | default(web_port__default) }}"\n',
        "roles/web/tasks/_resolve_defaults.yml",
    ),
    # TIMERUNIT-01 needs the timer to exist in THIS repo: the rule reads the configured roots
    # below the configured repo root, so it fires only if both resolve to the fixture.
    "TIMERUNIT-01": files(
        {
            "roles/web/templates/sync.timer.j2": "[Timer]\nOnCalendar=daily\n",
            "roles/web/tasks/extra.yml": "---\n- name: Stop\n  ansible.builtin.command: "
            "systemctl stop sync\n",
        }
    ),
    "HANDLER-01": files(
        {
            "roles/web/tasks/extra.yml": "---\n- name: Init\n  ansible.builtin.set_fact:\n"
            '    web_changed: "{{ false }}"\n- name: Flush\n  ansible.builtin.meta: '
            "flush_handlers\n",
            "roles/web/handlers/main.yml": "---\n- name: Mark\n  ansible.builtin.set_fact:\n"
            "    web_changed: true\n",
        }
    ),
    "MOLMIRROR-01": files(
        {
            "roles/web/molecule/default/verify.yml": "---\n- name: Verify\n  hosts: localhost\n"
            "  tasks:\n    - name: Case\n      vars:\n        stub:\n"
            '          - {id: "a", comment: "other"}\n'
            '          - {id: "b", comment: "managed-nightly"}\n'
            "      block:\n        - ansible.builtin.set_fact:\n"
            "            our: \"{{ stub | selectattr('comment','search','managed') | list | first }}\"\n"
            "        - ansible.builtin.assert:\n            that:\n"
            "              - our.id == 'b'\n",
        }
    ),
    "MOLMIRROR-02": files(
        {
            "roles/web/tasks/setup_vars.yml": "---\n- name: Resolve\n  ansible.builtin.set_fact:\n"
            '    web_port: "{{ web_port | default(web_port__default) }}"\n',
            "roles/web/molecule/default/converge.yml": "---\n- name: Converge\n  hosts: localhost\n"
            "  tasks:\n    - ansible.builtin.set_fact:\n"
            '        web_port: "{{ web_port__default }}"\n'
            '        web_name: "{{ web_name__default }}"\n'
            '        web_net: "{{ web_net__default }}"\n',
        }
    ),
    # MOLCOLL-01 against another repo's directory name: the fixture vendors into
    # third_party/collections, so a path naming collections.galaxy is the wrong one HERE.
    "MOLCOLL-01": files(
        {
            "roles/web/molecule/default/molecule.yml": collections_path("collections.galaxy"),
            "roles/web/molecule/default/converge.yml": USES_COLLECTION,
        }
    ),
}

AGENT_WRITE = "---\n- name: Write it\n  ansible.builtin.copy:\n    content: x\n    dest: {dest}\n"

# (rule or fragment, check, mutation). Every rule each check can emit, one injection each.
CATCH: list[tuple[str, str, Mutation]] = [
    *[
        (rule, "silent_guards", sg_file(name, content))
        for rule, must, name, content in FILE_CASES
        if must
    ],
    (
        "SUPPRESS-01",
        "silent_guards",
        task("---\n- name: X  # guard-check: ignore META-01\n  ansible.builtin.debug: {msg: x}\n"),
    ),
    *[(rule, "silent_guards", m) for rule, m in SG_ROLE_CASES.items()],
    (
        "unseals the rootfs OUTSIDE a block",
        "rootfs_seal",
        task("---\n- name: Unseal\n  ansible.builtin.command: steamos-readonly disable\n"),
    ),
    (
        "looks like a credential",
        "vendored_secrets",
        files({"roles/web/files/settings.json": '{"db": {"password": "hunter2-real"}}\n'}),
    ),
    (
        "AGENTTREE-01",
        "agent_tree",
        task(AGENT_WRITE.format(dest='"{{ app_state_dir }}/cache/sub/x"')),
    ),
    (
        "AGENTTREE-01",  # the alias form, through config_dir_aliases' suffix
        "agent_tree",
        files(
            {
                "roles/web/vars/main.yml": "---\n_home: \"{{ app_home | default('/srv') }}\"\n",
                "roles/web/tasks/extra.yml": AGENT_WRITE.format(dest='"{{ _home }}/state/a/b"'),
            }
        ),
    ),
    (
        "core_restart",
        "ha_restart",
        task(
            "---\n- name: Play\n  hosts: home\n  tasks:\n    - name: Restart\n"
            "      acme.home.supervisor:\n        action: core_restart\n",
            "playbooks/home.yml",
        ),
    ),
    (
        "MOLVERIFY-01",
        "molecule_verify",
        files(
            {
                "roles/web/molecule/default/molecule.yml": GOOD_MOLECULE
                + "scenario:\n  test_sequence: [syntax, converge]\n"
            }
        ),
    ),
    (
        "MOLVERIFY-02",
        "molecule_verify",
        files(
            {
                "roles/web/molecule/default/molecule.yml": GOOD_MOLECULE.replace(
                    "verifier: {name: ansible}",
                    "verifier: {name: ansible, enabled: false}",
                )
            }
        ),
    ),
    (
        "MOLVERIFY-03",
        "molecule_verify",
        files(
            {
                "roles/web/molecule/default/molecule.yml": GOOD_MOLECULE.replace(
                    "verify: verify.yml", "verify: verfy.yml"
                )
            }
        ),
    ),
    (
        "MOLVERIFY-04",
        "molecule_verify",
        files(
            {
                "roles/web/molecule/default/verify.yml": GOOD_VERIFY.replace(
                    "hosts: localhost", "hosts: instance"
                )
            }
        ),
    ),
    (
        "MOLVERIFY-05",
        "molecule_verify",
        files(
            {
                "roles/web/molecule/extra/molecule.yml": GOOD_MOLECULE,
                "roles/web/molecule/extra/verify.yml": GOOD_VERIFY,
            }
        ),
    ),
    (
        "MOLVERIFY-06",
        "molecule_verify",
        files(
            {
                "roles/web/molecule/default/molecule.yml": GOOD_MOLECULE
                + "scenario:\n  test_sequence: [prepare, converge, verify]\n"
            }
        ),
    ),
    ("TRACKIGNORE-01", "tracked_ignored", lambda fx: _force_add(fx, "var/kept.txt")),
    ("SELFLINK-01", "tracked_ignored", lambda fx: _abs_link(fx)),
    (
        "RESOLVE-02",
        "defaults_resolved",
        files({"roles/web/defaults/main.yml": "---\nweb_port__default: 8080\n"}),
    ),
    (
        "ICASE-01",
        "regex_anchors",
        files(
            {
                "tools/bad.py": ICASE_BAD,
            }
        ),
    ),
    ("TRAPTAG-01", "traps_checked", lambda fx: _rulebook(fx, "- **[you]** bare.\n")),
    (
        "test_forgotten.py",
        "ci_coverage",
        files({"tests/test_forgotten.py": "print(1)\n"}),
    ),
    ("DOCRULE-01", "docs_drift", lambda fx: _drop_rule(fx, "META-01")),
    (
        "fixture estate domain",
        "boundary",
        task(
            "---\n- name: Hit\n  ansible.builtin.uri:\n    url: https://web.example-estate.test/\n"
        ),
    ),
]

# Another repo's values, in the fixture: a check that still carried a hidden constant would fire.
NEAR_MISS: list[tuple[str, str, Mutation]] = [
    (
        "another repo's tree root (agent_config_dir/data) is not a root here",
        "agent_tree",
        task(AGENT_WRITE.format(dest='"{{ agent_config_dir }}/data/a/b"')),
    ),
    (
        "collections.galaxy is not this repo's vendored dir; third_party/collections is",
        "silent_guards",
        files(
            {
                "roles/web/molecule/default/molecule.yml": collections_path(
                    "third_party/collections"
                ),
                "roles/web/molecule/default/converge.yml": USES_COLLECTION,
            }
        ),
    ),
    (
        "another repo's HA module name is not this repo's",
        "ha_restart",
        task(
            "---\n- name: Play\n  hosts: home\n  tasks:\n    - name: Restart\n"
            "      other.ns.homeassistant_supervisor:\n        action: core_restart\n",
            "playbooks/home.yml",
        ),
    ),
    (
        "another repo's domain is not an estate fact here",
        "boundary",
        task(
            "---\n- name: Hit\n  ansible.builtin.uri:\n    url: https://web.other-estate.example.com/\n"
        ),
    ),
    (
        "scripts/ is another repo's scan root, not this repo's",
        "regex_anchors",
        files(
            {
                "scripts/bad.py": ICASE_BAD,
            }
        ),
    ),
    (
        "a vendored tree from this repo's [paths] vendored is skipped",
        "agent_tree",
        task(
            AGENT_WRITE.format(dest='"{{ app_state_dir }}/cache/sub/x"'),
            "third_party/roles/x/tasks/main.yml",
        ),
    ),
]

# A REQUIRED key removed: the check must exit 2 and name it — never 0.
REQUIRED: list[tuple[str, str]] = [
    ("agent_tree", "agent_tree.tree_roots"),
    ("silent_guards", "silent_guards.vendored_collections_dir"),
    ("ha_restart", "ha_restart.supervisor_modules"),
    ("molecule_verify", "molecule.selector"),
    ("regex_anchors", "regex_anchors.paths"),
    ("traps_checked", "docs.trap_section"),
    ("ci_coverage", "ci_coverage.suite_dirs"),
    ("docs_drift", "docs.rule_sources"),
    ("boundary", "boundary.patterns"),
]


def _force_add(fx: Path, rel: str) -> None:
    write(fx, rel, "data\n")
    git(fx, "add", "-f", rel)


def _abs_link(fx: Path) -> None:
    (fx / "link").symlink_to(fx / "tools" / "helper.py")
    git(fx, "add", "link")


def _rulebook(fx: Path, extra: str) -> None:
    p = fx / "RULES.md"
    p.write_text(p.read_text().replace("\n## After\n", extra + "\n## After\n"))


def _drop_rule(fx: Path, rule: str) -> None:
    p = fx / "RULES.md"
    p.write_text(p.read_text().replace(f"- **[FAIL {rule}]** fixture rule.\n", ""))


def _drop_key(fx: Path, dotted: str) -> None:
    section, key = dotted.split(".")
    p = fx / "devkit.toml"
    out, cur = [], ""
    for ln in p.read_text().splitlines(keepends=True):
        if ln.startswith("["):
            cur = ln.strip()[1:-1]
        if cur == section and ln.split("=")[0].strip() == key:
            continue
        out.append(ln)
    p.write_text("".join(out))


def check(fx: Path, name: str) -> tuple[int, str]:
    script, args, _ = CHECKS[name]
    return run(fx, script, *args)


def copy_of(base: Path, td: Path, tag: str) -> Path:
    dst = td / tag
    shutil.copytree(base, dst, symlinks=True)
    return dst


def main() -> int:
    failures: list[str] = []
    cases = 0

    def record(ok: bool, label: str, detail: str) -> None:
        nonlocal cases
        cases += 1
        print(f"  {'PASS' if ok else 'FAIL'}  {label}")
        if not ok:
            failures.append(f"{label}\n{detail[-3000:]}")

    with tempfile.TemporaryDirectory(prefix="portable_checks_") as tdname:
        td = Path(tdname)
        base = build(td)

        print("CLEAN — every check exits 0 on the fixture, having seen it:")
        for name, (_, _, seen) in CHECKS.items():
            rc, out = check(base, name)
            record(rc == 0 and seen in out, f"clean  {name}", out)

        rc1, out1 = run(base, "trap_report.py")
        record(
            rc1 == 0 and "var/trap-log" in out1,
            "clean  trap_report reads var/trap-log",
            out1,
        )

        print("CATCH — one injected violation per rule:")
        for i, (rule, name, mutate) in enumerate(CATCH):
            fx = copy_of(base, td, f"catch{i}")
            mutate(fx)
            rc, out = check(fx, name)
            record(rc != 0 and rule in out, f"catch  {name:<17} {rule}", out)
            shutil.rmtree(fx)

        # The trap-hit recorder: a hit lands in THIS repo's configured log, and the report reads it.
        fx = copy_of(base, td, "traps")
        bad = fx / "roles" / "web" / "tasks" / "esc.yml"
        bad.write_text(
            "---\n- name: Count\n  ansible.builtin.set_fact:\n    n: >-\n"
            "      {{ s.split('\\n') | length }}\n"
        )
        payload = json.dumps(
            {
                "tool_name": "Edit",
                "session_id": "t",
                "tool_input": {"file_path": str(bad)},
            }
        )
        rc, out = run(fx, "record_trap_hits.py", stdin=payload)
        logged = list((fx / "var" / "trap-log").glob("*.jsonl"))
        record(rc == 0 and len(logged) == 1, "catch  record_trap_hits -> var/trap-log", out)
        rc, out = run(fx, "trap_report.py")
        record(rc == 0 and "YAMLESC-01" in out, "catch  trap_report ranks YAMLESC-01", out)

        print("NEAR-MISS — another repo's values do not fire here:")
        for i, (label, name, mutate) in enumerate(NEAR_MISS):
            fx = copy_of(base, td, f"near{i}")
            mutate(fx)
            rc, out = check(fx, name)
            record(rc == 0, f"near   {name:<17} {label}", out)
            shutil.rmtree(fx)

        print("REQUIRED — a missing key exits 2 naming it:")
        for i, (name, key) in enumerate(REQUIRED):
            fx = copy_of(base, td, f"req{i}")
            _drop_key(fx, key)
            rc, out = check(fx, name)
            record(rc == 2 and key in out, f"loud   {name:<17} {key}", out)
            shutil.rmtree(fx)

    print(f"\n{cases - len(failures)}/{cases} passed")
    for f in failures:
        print(f"  FAILED: {f}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
