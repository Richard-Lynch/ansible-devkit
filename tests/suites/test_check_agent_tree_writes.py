#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for check_agent_tree_writes.py (AGENTTREE-01).

Every FAIL fixture is paired with a near-miss that must PASS. Three groups:

  * Fixtures: one shape each of what the rule must catch, and what it must leave alone.
  * Realistic: two full-length shapes (a root-owned script delivery into the agent's tree, and
    a dotenv lineinfile), which must be caught.
  * MutationProof: copies of the checker with one protection removed must turn the fixture that
    depends on it green-when-it-should-be-red. A check that cannot see its own protection go
    missing proves nothing about it.

Run: uv run tests/suites/test_check_agent_tree_writes.py   (from the repo root)
"""

from __future__ import annotations

import importlib.util
import tempfile
import textwrap
import unittest
from pathlib import Path

from _paths import CHECKS, ROOT  # noqa: F401 — tests/suites/_paths.py
import _paths

_paths.use_fixture_config()

HERE = CHECKS
SRC = HERE / "check_agent_tree_writes.py"


def load(path: Path, name: str = "check_agent_tree_writes"):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None, path
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


C = load(SRC)

GATE = """
- name: Stat it
  ansible.builtin.stat:
    path: "{{ agent_config_dir }}/data/config.yaml"
    follow: false
  register: st
- name: HARD GATE - not a link
  ansible.builtin.assert:
    that: ["not (st.stat.islnk | default(false))"]
"""


class Base(unittest.TestCase):
    C = C  # the checker under test; MutationProof swaps it

    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.addCleanup(self._t.cleanup)
        self.t = Path(self._t.name)

    def write(self, rel: str, text: str) -> Path:
        p = self.t / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(text).lstrip("\n"))
        return p

    def findings(self) -> list[str]:
        return self.C.scan(self.C.iter_files([str(self.t / "roles"), str(self.t / "playbooks")]))

    def task(self, body: str, rel="roles/r/tasks/main.yml", pre: str = ""):
        self.write(rel, pre + textwrap.dedent(body))
        return self.findings()

    def assertFails(self, found, fragment=""):
        self.assertEqual(len(found), 1, found)
        self.assertIn("[AGENTTREE-01]", found[0])
        self.assertIn(fragment, found[0])

    def assertPasses(self, found):
        self.assertEqual(found, [])


class Fixtures(Base):
    # ---- the guarded form, and each piece of it missing -----------------------------------------
    def test_pass_copy_follow_false_behind_a_preceding_islnk_gate(self):
        self.assertPasses(
            self.task(
                """
                - name: Write it
                  ansible.builtin.copy:
                    content: x
                    dest: "{{ agent_config_dir }}/data/config.yaml"
                    follow: false
                """,
                pre=GATE,
            )
        )

    def test_fail_copy_without_follow_false(self):
        self.assertFails(
            self.task(
                """
                - name: Write it
                  ansible.builtin.copy: {content: x, dest: "{{ agent_config_dir }}/data/config.yaml"}
                """,
                pre=GATE,
            ),
            "`follow: false`",
        )

    def test_fail_copy_follow_false_without_a_gate(self):
        self.assertFails(
            self.task("""
                - name: Write it
                  ansible.builtin.copy:
                    content: x
                    dest: "{{ agent_config_dir }}/data/config.yaml"
                    follow: false
                """),
            "islnk",
        )

    def test_fail_gate_after_the_write_is_not_preceding(self):
        write = textwrap.dedent("""
            - name: Write it
              ansible.builtin.copy:
                content: x
                dest: "{{ agent_config_dir }}/data/config.yaml"
                follow: false
            """)
        self.write("roles/r/tasks/main.yml", write + GATE)
        self.assertFails(self.findings(), "islnk")

    def test_pass_gate_inside_an_earlier_block(self):
        self.assertPasses(self.task("""
                - name: Guarded
                  block:
                    - name: Gate
                      ansible.builtin.assert: {that: ["not s.stat.islnk"]}
                    - name: Write it
                      ansible.builtin.template:
                        src: c.j2
                        dest: "{{ agent_config_dir }}/data/config.yaml"
                        follow: no
                """))

    # ---- lineinfile and friends: no gate makes them safe ----------------------------------------
    def test_fail_lineinfile_even_behind_a_gate(self):
        self.assertFails(
            self.task(
                """
                - name: Key line
                  ansible.builtin.lineinfile:
                    path: "{{ agent_config_dir }}/data/.env"
                    line: K=v
                    follow: false
                """,
                pre=GATE,
            ),
            "realpath()",
        )

    def test_fail_blockinfile_and_replace(self):
        for mod in ("blockinfile", "ansible.builtin.replace"):
            with self.subTest(mod=mod):
                self.assertFails(
                    self.task(f"""
                        - name: Edit
                          {mod}:
                            path: "{{{{ agent_config_dir }}}}/data/.env"
                            regexp: x
                        """),
                    "realpath()",
                )

    def test_pass_lineinfile_as_the_agent(self):
        self.assertPasses(self.task("""
                - name: Key line
                  ansible.builtin.lineinfile: {path: "{{ agent_config_dir }}/data/.env", line: K=v}
                  become_user: appsvc
                """))

    def test_pass_become_user_inherited_from_a_block_and_fail_explicit_root(self):
        self.assertPasses(self.task("""
                - name: As the agent
                  become_user: "{{ agent_user }}"
                  block:
                    - name: Key line
                      ansible.builtin.lineinfile: {path: "{{ agent_config_dir }}/data/.env", line: K=v}
                """))
        self.assertFails(self.task("""
                - name: Key line
                  ansible.builtin.lineinfile: {path: "{{ agent_config_dir }}/data/.env", line: K=v}
                  become_user: root
                """))

    # ---- depth: follow: false only covers the last component ------------------------------------
    def test_fail_two_components_below_the_root_even_guarded(self):
        self.assertFails(
            self.task(
                """
                - name: Shared scripts dir
                  ansible.builtin.file:
                    path: "{{ agent_config_dir }}/data/scripts/shared"
                    state: directory
                    follow: false
                """,
                pre=GATE,
            ),
            "LAST component",
        )

    def test_fail_static_dir_then_jinja_name_is_deep(self):
        self.assertFails(
            self.task(
                """
                - name: Mirror file
                  ansible.builtin.copy:
                    content: x
                    dest: "{{ agent_state_root }}/learning/{{ name }}"
                    follow: false
                """,
                pre=GATE,
            ),
            "LAST component",
        )

    # ---- what is and is not under a tree root ---------------------------------------------------
    def test_pass_the_tree_root_itself_and_its_root_owned_siblings(self):
        self.assertPasses(self.task("""
                - name: The state dir itself (its parent is root-owned)
                  ansible.builtin.file: {path: "{{ agent_config_dir }}/data", state: directory}
                - name: A root-owned sibling
                  ansible.builtin.copy: {content: x, dest: "{{ agent_config_dir }}/policy/hook.py"}
                - name: Not data/ at all
                  ansible.builtin.copy: {content: x, dest: "{{ agent_config_dir }}/database/x"}
                - name: Reads are not writes
                  ansible.builtin.slurp: {src: "{{ agent_config_dir }}/data/config.yaml"}
                """))

    def test_fail_every_known_root(self):
        for dest in (
            "/opt/agent/data/x.json",
            "{{ agent_state_root }}/x.json",
            "{{ agent_learning_home }}/x.json",
            "{{ worker_state_dir }}/cards/{{ card }}/data/servers.json",
            "{{ worker_state_dir }}/homes/{{ card }}/.gitconfig",
        ):
            with self.subTest(dest=dest):
                self.assertFails(self.task(f"""
                        - name: Write
                          ansible.builtin.copy: {{content: x, dest: "{dest}"}}
                        """))

    def test_fail_free_form_file_args(self):
        self.assertFails(self.task("""
                - name: Touch
                  file: path={{ agent_config_dir }}/data/x state=touch
                """))

    # ---- variables: aliases of the config dir, and values under a root ---------------------------
    def test_fail_alias_of_the_config_dir_in_a_play(self):
        self.write(
            "playbooks/svc/maintenance/p.yml",
            """
            - name: P
              hosts: appsvc
              vars:
                _cfg: "{{ agent_config_dir | default('/opt/agent') }}"
              tasks:
                - name: Restore
                  ansible.builtin.copy: {src: /root/bk, dest: "{{ _cfg }}/data/config.yaml", remote_src: true}
            """,
        )
        self.assertFails(self.findings())

    def test_alias_is_followed_into_an_included_tasks_file_of_the_same_service(self):
        self.write(
            "playbooks/svc/maintenance/p.yml",
            """
            - name: P
              hosts: appsvc
              vars: {_cfg: "{{ agent_config_dir }}"}
              tasks:
                - name: Case
                  ansible.builtin.include_tasks: ../tasks/case.yml
            """,
        )
        self.write(
            "playbooks/svc/tasks/case.yml",
            """
            - name: Plant
              ansible.builtin.lineinfile: {path: "{{ _cfg }}/data/.env", line: K=v}
            """,
        )
        self.assertFails(self.findings(), "case.yml")

    def test_pass_same_name_in_another_service_is_not_an_alias(self):
        self.write(
            "playbooks/a/p.yml",
            """
            - name: A
              hosts: appsvc
              vars: {_cfg: "{{ agent_config_dir }}"}
              tasks: []
            """,
        )
        self.write(
            "playbooks/b/p.yml",
            """
            - name: B
              hosts: other
              vars: {_cfg: /srv/thing}
              tasks:
                - name: Write
                  ansible.builtin.copy: {content: x, dest: "{{ _cfg }}/data/x"}
            """,
        )
        self.assertPasses(self.findings())

    def test_fail_loop_over_a_role_var_under_a_root(self):
        self.write(
            "roles/r/vars/main.yml",
            """
            _dirs:
              - "{{ agent_learning_home }}/learning"
              - "{{ agent_learning_home }}/learning/ledger"
            """,
        )
        self.assertFails(self.task("""
                - name: Dirs
                  ansible.builtin.file: {path: "{{ item }}", state: directory}
                  loop: "{{ _dirs }}"
                """))

    def test_fail_set_fact_concatenation_onto_a_root(self):
        self.assertFails(self.task("""
                - name: Choose
                  ansible.builtin.set_fact:
                    p: "{{ agent_config_dir ~ ('/subs' if ro else '/data') ~ '/s.json' }}"
                - name: Write
                  ansible.builtin.copy: {content: x, dest: "{{ p }}"}
                """))

    def test_loop_items_only_the_key_the_path_uses(self):
        body = """
            - name: Copy
              ansible.builtin.copy:
                src: "{{{{ item.src }}}}"
                dest: "{dest}"
                remote_src: true
              loop:
                - {{src: "{{{{ agent_config_dir }}}}/data/.env", name: data.env,
                   dest: "{{{{ agent_config_dir }}}}/data/.env"}}
            """
        # backup: reads FROM the tree into /root; the dest is not in it
        self.assertPasses(self.task(body.format(dest="/root/bk/{{ item.name }}")))
        # restore: writes INTO the tree
        self.assertFails(self.task(body.format(dest="{{ item.dest }}")))

    # ---- suppressions and exemptions ------------------------------------------------------------
    def test_suppression_needs_a_reason(self):
        body = """
            - name: Write  # guard-check: ignore AGENTTREE-01{reason}
              ansible.builtin.copy: {{content: x, dest: "{{{{ agent_config_dir }}}}/data/x"}}
            """
        self.assertPasses(
            self.task(body.format(reason=" — the stack is stopped and data/ is root's here"))
        )
        self.assertFails(self.task(body.format(reason="")), "must say why")

    def test_pass_molecule_is_exempt(self):
        self.write(
            "roles/r/molecule/default/converge.yml",
            """
            - name: Fixture
              ansible.builtin.lineinfile: {path: "{{ agent_config_dir }}/data/.env", line: K=v}
            """,
        )
        self.assertPasses(self.findings())


class Realistic(Base):
    def test_root_owned_script_delivery_into_agent_tree(self):
        self.task("""
            - name: Ensure the agent's scripts directory exists (agent-owned)
              ansible.builtin.file:
                path: "{{ agent_config_dir }}/data/scripts"
                state: directory
                owner: "{{ agent_state_uid }}"
            - name: Ensure the shared scripts directory exists (root-owned)
              ansible.builtin.file:
                path: "{{ agent_config_dir }}/data/scripts/shared"
                state: directory
                owner: root
            - name: Copy each shared script, root-owned 0644
              ansible.builtin.copy:
                src: "{{ item.path }}"
                dest: "{{ agent_config_dir }}/data/scripts/shared/{{ item.path | basename }}"
              loop: "{{ agent__cron_src.files }}"
            """)
        found = self.findings()
        self.assertEqual(len(found), 3, found)

    def test_dotenv_lineinfile_into_agent_tree(self):
        self.assertFails(
            self.task("""
                - name: Put the app.env SERVICE_API_KEY in data/.env too
                  ansible.builtin.lineinfile:
                    path: "{{ agent_config_dir }}/data/.env"
                    regexp: "^SERVICE_API_KEY="
                    line: "SERVICE_API_KEY={{ agent_service_api_key }}"
                    create: true
                    owner: "{{ agent_state_uid }}"
                    mode: "0600"
                  no_log: true
                """),
            "lineinfile",
        )


class CLI(unittest.TestCase):
    def test_list_rules_names_the_rule(self):
        import contextlib
        import io

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(C.main(["x", "--list-rules"]), 0)
        self.assertTrue(buf.getvalue().startswith("AGENTTREE-01"))


# Each protection, the source text that implements it, its removal, and a fixture that must go red.
MUTATIONS = (
    (
        'and state["gate"] and not deep',
        "and not deep",
        "Fixtures.test_fail_copy_follow_false_without_a_gate",
    ),
    (
        'and state["gate"] and not deep',
        'and state["gate"]',
        "Fixtures.test_fail_two_components_below_the_root_even_guarded",
    ),
    (
        'FOLLOW_GUARDABLE = {"file", "copy", "template"}',
        'FOLLOW_GUARDABLE = {"file", "copy", "template", "lineinfile"}',
        "Fixtures.test_fail_lineinfile_even_behind_a_gate",
    ),
    (
        'if below_root(" ".join(values), tainted, aliases)[0]:',
        "if False:",
        "Fixtures.test_fail_loop_over_a_role_var_under_a_root",
    ),
    (
        'rf"\\{{\\{{{re.escape(a)}\\}}\\}}{re.escape(s)}" for a, s in aliases.items()',
        'rf"\\{{\\{{{re.escape(a)}\\}}\\}}{re.escape(s)}" for a, s in {}.items()',
        "Fixtures.test_fail_alias_of_the_config_dir_in_a_play",
    ),
    (
        "            if ok:\n                continue\n",
        "            if ok or bare:\n                continue\n",
        "Fixtures.test_suppression_needs_a_reason",
    ),
)


class MutationProof(unittest.TestCase):
    def test_each_mutation_turns_its_fixture_red(self):
        src = SRC.read_text()
        for needle, replacement, case in MUTATIONS:
            with self.subTest(case=case, needle=needle):
                self.assertIn(needle, src, "mutation anchor gone: update MUTATIONS")
                with tempfile.TemporaryDirectory() as td:
                    broken = Path(td) / "check_agent_tree_writes.py"
                    broken.write_text(src.replace(needle, replacement, 1))
                    mutant = load(broken, "check_agent_tree_writes_mutant")
                    cls_name, meth = case.split(".")
                    cls = type(cls_name, (globals()[cls_name],), {"C": mutant})
                    result = unittest.TestResult()
                    cls(meth).run(result)
                    self.assertFalse(
                        result.wasSuccessful(),
                        f"{case} still passes with the protection removed: it cannot see it",
                    )


if __name__ == "__main__":
    unittest.main(verbosity=1)
