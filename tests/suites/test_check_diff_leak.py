#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Cases for check_diff_leak.py (DIFFLEAK-01) — every shape that must FAIL, and its near-miss.

WHY THIS EXISTS. A `--check --diff` run prints credentials into the run log when a template task
renders a secret and has no `no_log`, because `--diff` prints the whole rendered file. The rule
is only as good as its two halves — finding the file a task really renders, and telling a
credential from a name that is merely ABOUT one — so both are tested in both directions.

Each case builds a throwaway role/playbook tree and runs the checker over it. Values are never
real: the checker reads NAMES, so a fixture needs no secret at all.

Run: uv run tests/suites/test_check_diff_leak.py   (from the repo root)
"""

from __future__ import annotations

import contextlib
import io
import os
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

import _paths
from _paths import CHECKS  # tests/suites/_paths.py

_paths.use_fixture_config()
sys.path.insert(0, str(CHECKS))
import check_diff_leak as c  # noqa: E402


def _tree(root: Path, files: dict[str, str]) -> None:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(text))


def _scan(files: dict[str, str]) -> tuple[int, str]:
    with tempfile.TemporaryDirectory() as td:
        old = os.getcwd()
        os.chdir(td)
        try:
            _tree(Path(td), files)
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = c.main(["check_diff_leak.py", "roles", "playbooks"])
            return rc, out.getvalue()
        finally:
            os.chdir(old)


def _role(tasks: str, **extra: str) -> dict[str, str]:
    files = {"roles/r/tasks/main.yml": tasks}
    files.update({f"roles/r/{k}": v for k, v in extra.items()})
    return files


TPL_SECRET = "DB_PASSWORD={{ r_db_password }}\n"

# A vault/hash filter exempts only the value it is APPLIED to, at the top level of the expression.
TPL_VAULT_NESTED = "p: {{ r_secret_a ~ (r_x | vault(r_vault_pw)) }}\n"
TPL_VAULT_THEN_DEFAULT = "p: {{ r_x | vault(r_vault_pw) | default(r_other_secret) }}\n"
TPL_VAULT_THEN_YAML = "p: {{ r_password | vault(r_vault_pw) | to_yaml }}\n"
TPL_HASHED_CONCAT = "p: {{ (r_salt ~ r_password) | hash('sha256') }}\n"
TPL_VAULT_THEN_CONCAT = "p: {{ r_x | vault(r_vault_pw) ~ r_secret_b }}\n"
TPL_VAULT_TWO_ARGS = "p: {{ r_password | vault(r_vault_pw, 'prod') }}\n"

# name -> tree. Each must exit 1 and name DIFFLEAK-01.
_SECURITY_REVIEW_FAIL = {
    "vault filter nested inside a sub-expression does not exempt the rest": _role(
        """
        - name: render
          ansible.builtin.template:
            src: v.j2
            dest: /etc/x
        """,
        **{"templates/v.j2": TPL_VAULT_NESTED},
    ),
    "a filter after the vault that re-introduces a credential": _role(
        """
        - name: render
          ansible.builtin.template:
            src: v.j2
            dest: /etc/x
        """,
        **{"templates/v.j2": TPL_VAULT_THEN_DEFAULT},
    ),
    "text after the vault call's closing paren is still rendered (vault(pw) ~ secret)": _role(
        """
        - name: render
          ansible.builtin.template:
            src: v.j2
            dest: /etc/x
        """,
        **{"templates/v.j2": TPL_VAULT_THEN_CONCAT},
    ),
    "a suppression on the NEXT task does not cover this one": _role(
        """
        - name: render
          ansible.builtin.template:
            src: c.j2
            dest: /etc/x
        # guard-check: ignore DIFFLEAK-01 — this comment belongs to the task below
        - name: other
          ansible.builtin.debug:
            msg: hi
        """,
        **{"templates/c.j2": TPL_SECRET},
    ),
    "a suppression two lines above (not directly above) does not count": _role(
        """
        # guard-check: ignore DIFFLEAK-01 — too far away
        - name: other
          ansible.builtin.debug:
            msg: hi
        - name: render
          ansible.builtin.template:
            src: c.j2
            dest: /etc/x
        """,
        **{"templates/c.j2": TPL_SECRET},
    ),
    "a task-level args: mapping carries the src": _role(
        """
        - name: render
          ansible.builtin.template:
          args:
            src: c.j2
            dest: /etc/x
        """,
        **{"templates/c.j2": TPL_SECRET},
    ),
    "the action: string form": _role(
        """
        - name: render
          action: template src=c.j2 dest=/etc/x
        """,
        **{"templates/c.j2": TPL_SECRET},
    ),
    "the action: mapping form with args": _role(
        """
        - name: render
          action:
            module: ansible.builtin.template
            args:
              src: c.j2
              dest: /etc/x
        """,
        **{"templates/c.j2": TPL_SECRET},
    ),
    "local_action: with inline mapping args": _role(
        """
        - name: render
          local_action:
            module: template
            src: c.j2
            dest: /etc/x
        """,
        **{"templates/c.j2": TPL_SECRET},
    ),
    "the secret sits in an INCLUDED partial": _role(
        """
        - name: render
          ansible.builtin.template:
            src: outer.j2
            dest: /etc/x
        """,
        **{
            "templates/outer.j2": "a: 1\n{% include 'partial.j2' %}\n",
            "templates/partial.j2": TPL_SECRET,
        },
    ),
    "the secret sits in a template the rendered one EXTENDS": _role(
        """
        - name: render
          ansible.builtin.template:
            src: child.j2
            dest: /etc/x
        """,
        **{"templates/child.j2": "{% extends 'base.j2' %}\n", "templates/base.j2": TPL_SECRET},
    ),
    "the secret sits two includes deep (with a cycle back)": _role(
        """
        - name: render
          ansible.builtin.template:
            src: a.j2
            dest: /etc/x
        """,
        **{
            "templates/a.j2": "{% include 'b.j2' %}\n",
            "templates/b.j2": "{% include 'a.j2' %}\n{% from 'c.j2' import m %}\n",
            "templates/c.j2": TPL_SECRET,
        },
    ),
    "copy content: renders lookup('template', ...) of a template holding the secret": _role(
        """
        - name: render
          ansible.builtin.copy:
            content: "{{ lookup('template', 'c.j2') }}"
            dest: /etc/x
        """,
        **{"templates/c.j2": TPL_SECRET},
    ),
    "query('ansible.builtin.template', ...) likewise": _role(
        """
        - name: render
          ansible.builtin.copy:
            content: "{{ query('ansible.builtin.template', 'c.j2') | first }}"
            dest: /etc/x
        """,
        **{"templates/c.j2": TPL_SECRET},
    ),
    "a template whose body renders another template through lookup('template')": _role(
        """
        - name: render
          ansible.builtin.template:
            src: outer.j2
            dest: /etc/x
        """,
        **{
            "templates/outer.j2": "{{ lookup('template', 'c.j2') }}\n",
            "templates/c.j2": TPL_SECRET,
        },
    ),
    "a secret inside a {% macro %} body, called in the output": _role(
        """
        - name: render
          ansible.builtin.template:
            src: m.j2
            dest: /etc/x
        """,
        **{"templates/m.j2": "{% macro m() %}{{ r_db_password }}{% endmacro %}{{ m() }}\n"},
    ),
    "a secret inside a {% filter upper %} block": _role(
        """
        - name: render
          ansible.builtin.template:
            src: f.j2
            dest: /etc/x
        """,
        **{"templates/f.j2": "{% filter upper %}{{ r_db_password }}{% endfilter %}\n"},
    ),
    "lookup('vars', <secret name>) renders the named variable": _role("""
        - name: render
          ansible.builtin.copy:
            content: "{{ lookup('vars', 'r_db_password') }}"
            dest: /etc/x
        """),
    "lookup('env', <secret-named env var>)": _role("""
        - name: render
          ansible.builtin.copy:
            content: "{{ lookup('ansible.builtin.env', 'DB_PASSWORD') }}"
            dest: /etc/x
        """),
    "win_template renders a secret": _role(
        """
        - name: render
          ansible.windows.win_template:
            src: c.j2
            dest: C:\\x.conf
        """,
        **{"templates/c.j2": TPL_SECRET},
    ),
    "win_copy content: renders a secret": _role("""
        - name: render
          ansible.windows.win_copy:
            content: "pw={{ r_db_password }}"
            dest: C:\\x.conf
        """),
    "ansible.legacy.template lookup renders a template holding the secret": _role(
        """
        - name: render
          ansible.builtin.copy:
            content: "{{ lookup('ansible.legacy.template', 'c.j2') }}"
            dest: /etc/x
        """,
        **{"templates/c.j2": TPL_SECRET},
    ),
    "a third-party template-reading lookup is content this check cannot see (no no_log)": _role(
        """
        - name: render
          ansible.builtin.copy:
            content: "{{ lookup('acme.tools.template', 'c.j2') }}"
            dest: /etc/x
        """,
        **{"templates/c.j2": "a: 1\n"},
    ),
    "a file lookup whose path names a credential": _role("""
        - name: render
          ansible.builtin.copy:
            content: "{{ lookup('file', '/etc/keys/db_password') }}"
            dest: /etc/x
        """),
    "an unresolved source WITHOUT no_log is a finding (fail closed)": _role("""
        - name: render
          ansible.builtin.template:
            src: "{{ r_which_template }}"
            dest: /etc/x
        """),
    "a third-party module named template renders too (short-name rule)": _role(
        """
        - name: render
          acme.tools.template:
            src: c.j2
            dest: /etc/x
        """,
        **{"templates/c.j2": TPL_SECRET},
    ),
    "a secret in a {% with %} binding": _role(
        """
        - name: render
          ansible.builtin.template:
            src: w.j2
            dest: /etc/x
        """,
        **{"templates/w.j2": "{% with k = r_db_password %}{{ k }}{% endwith %}\n"},
    ),
    "a macro parameter whose default is a secret": _role(
        """
        - name: render
          ansible.builtin.template:
            src: m.j2
            dest: /etc/x
        """,
        **{"templates/m.j2": "{% macro m(x=r_db_password) %}{{ x }}{% endmacro %}{{ m() }}\n"},
    ),
    "a secret in a {% call %} block's arguments": _role(
        """
        - name: render
          ansible.builtin.template:
            src: c.j2
            dest: /etc/x
        """,
        **{
            "templates/c.j2": "{% macro m(x) %}{{ caller() }}{% endmacro %}"
            "{% call m(r_db_password) %}y{% endcall %}\n"
        },
    ),
    "with_fileglob whose pattern is not static": _role("""
        - name: render many
          ansible.builtin.template:
            src: "{{ item }}"
            dest: "/etc/{{ item | basename }}"
          with_fileglob: "{{ r_pattern }}"
        """),
    "with_fileglob that matches no file": _role("""
        - name: render many
          ansible.builtin.template:
            src: "{{ item }}"
            dest: "/etc/{{ item | basename }}"
          with_fileglob: "nothing-here/*.j2"
        """),
    "include_role free-form naming deployment_config with a secret template swept": _role(
        """
        - name: sweep
          ansible.builtin.include_role: name=richard_lynch.common.deployment_config
          vars:
            deployment_config_source: "{{ role_path }}/files"
        """,
        **{"files/app.env.j2": TPL_SECRET},
    ),
    "include_role free-form that cannot be parsed": _role("""
        - name: sweep
          ansible.builtin.include_role: name="unterminated
        """),
    "copy content: whose Jinja does not parse (no no_log)": _role("""
        - name: render
          ansible.builtin.copy:
            content: "{{ r_x | }}"
            dest: /etc/x
        """),
    "a {% set %} block whose body is a lookup taints the variable": _role(
        """
        - name: render
          ansible.builtin.template:
            src: s.j2
            dest: /etc/x
        """,
        **{"templates/s.j2": "{% set blob %}{{ lookup('pipe', 'cat x') }}{% endset %}{{ blob }}\n"},
    ),
    "an attribute named like a secret on a non-name base": _role("""
        - name: render
          ansible.builtin.copy:
            content: "{{ (r_rows | first).password }}"
            dest: /etc/x
        """),
    "a literal subscript named like a secret on a call result": _role("""
        - name: render
          ansible.builtin.copy:
            content: "{{ r_rows[0]['api_token'] }}"
            dest: /etc/x
        """),
    ".get('<secret key>') on an expression": _role("""
        - name: render
          ansible.builtin.copy:
            content: "{{ (r_cfg | from_yaml).get('db_password') }}"
            dest: /etc/x
        """),
    "json_query of a secret path": _role("""
        - name: render
          ansible.builtin.copy:
            content: "{{ r_doc | json_query('db.password') }}"
            dest: /etc/x
        """),
    "a task file that does not parse as YAML": _role(
        """
        - name: render
          ansible.builtin.template:
            src: c.j2
            dest: /etc/x
          mode: [unterminated
        """,
        **{"templates/c.j2": TPL_SECRET},
    ),
    "a play file beside data that does not parse as YAML": {
        "playbooks/p/play.yml": "- hosts: all\n  tasks:\n    - name: x\n      ansible.builtin.template: {src: c.j2, dest: /x\n",
        "playbooks/p/vars.yml": "p_user: bob\n",
    },
    "a task file whose top level is a mapping, not a list": _role(
        """
        name: render
        ansible.builtin.template:
          src: c.j2
          dest: /etc/x
        """,
        **{"templates/c.j2": TPL_SECRET},
    ),
    "a template with a #jinja2: delimiter header is not judged (no no_log)": _role(
        """
        - name: render
          ansible.builtin.template:
            src: d.j2
            dest: /etc/x
        """,
        **{
            "templates/d.j2": "#jinja2: variable_start_string:'[%', variable_end_string:'%]'\n[% r_x %]\n"
        },
    ),
    "a template task with custom delimiter options is not judged (no no_log)": _role(
        """
        - name: render
          ansible.builtin.template:
            src: plain.j2
            dest: /etc/x
            variable_start_string: "[%"
            variable_end_string: "%]"
        """,
        **{"templates/plain.j2": "a: 1\n"},
    ),
    "a vars file two levels deep (vars/main/x.yml) defining a secret-named value": {
        "roles/r/tasks/main.yml": """
        - name: render
          ansible.builtin.copy:
            content: "{{ r_conn }}"
            dest: /etc/x
        """,
        "roles/r/vars/main/db.yml": 'r_conn: "{{ r_db_password }}"\n',
    },
    "a task var with a not-a-secret suffix DEFINED from a credential is tainted": _role("""
        - name: render
          vars:
            r_token_file: "{{ r_api_token }}"
          ansible.builtin.copy:
            content: "{{ r_token_file }}"
            dest: /etc/x
        """),
    "a defaults name with a not-a-secret suffix DEFINED from a credential is tainted": {
        "roles/r/tasks/main.yml": """
        - name: render
          ansible.builtin.copy:
            content: "{{ r_password_file }}"
            dest: /etc/x
        """,
        "roles/r/defaults/main.yml": 'r_password_file: "{{ r_db_password }}"\n',
    },
    "lineinfile alias value:": _role("""
        - name: line
          ansible.builtin.lineinfile:
            path: /etc/x
            value: "pw={{ r_db_password }}"
        """),
    "blockinfile alias content:": _role("""
        - name: block
          ansible.builtin.blockinfile:
            path: /etc/x
            content: |
              pw={{ r_db_password }}
        """),
    "ini_file values: list": _role("""
        - name: ini
          community.general.ini_file:
            path: /etc/x
            section: s
            option: pw
            values: ["{{ r_db_password }}", "b"]
        """),
    "precedence: secret ~ x | vault(pw) vaults only x": _role(
        """
        - name: render
          ansible.builtin.template:
            src: v.j2
            dest: /etc/x
        """,
        **{"templates/v.j2": "p: {{ r_secret ~ r_x | vault(r_vault_pw) }}\n"},
    ),
    "precedence: an if/else whose other branch is the secret": _role(
        """
        - name: render
          ansible.builtin.template:
            src: v.j2
            dest: /etc/x
        """,
        **{"templates/v.j2": "p: {{ r_x | vault(r_vault_pw) if r_flag else r_secret }}\n"},
    ),
    "free-form k=v with a quoted dest containing a space still resolves the src": _role(
        """
        - name: render
          ansible.builtin.template: src=c.j2 dest="/etc/x y.conf" mode=0600
        """,
        **{"templates/c.j2": TPL_SECRET},
    ),
    "free-form k=v with Jinja containing spaces still resolves the src": _role(
        """
        - name: render
          ansible.builtin.template: src=c.j2 dest={{ r_dir | default('/etc/x') }}/x.conf
        """,
        **{"templates/c.j2": TPL_SECRET},
    ),
}
MUST_FAIL: dict[str, dict[str, str]] = {
    "template_bare_src_in_templates": _role(
        """
        - name: Render
          ansible.builtin.template: {src: app.env.j2, dest: /x/app.env, mode: "0600"}
        """,
        **{"templates/app.env.j2": TPL_SECRET},
    ),
    "template_jinja_prefixed_src_in_files": _role(
        """
        - name: Render (the stack_arr_jellystat shape)
          ansible.builtin.template:
            src: "{{ r__files }}/docker-compose.yml.j2"
            dest: /x/docker-compose.yml
            mode: "0600"
        """,
        **{"files/docker-compose.yml.j2": 'JWT_SECRET: "{{ r_jwt_secret }}"\n'},
    ),
    "copy_content": _role("""
        - name: Write
          ansible.builtin.copy: {content: "TOKEN={{ r_api_token }}\\n", dest: /x, mode: "0600"}
        """),
    "lineinfile_with_secret_lookup": _role("""
        - name: Line
          ansible.builtin.lineinfile:
            path: /x
            line: "K={{ lookup('my.utils.onepassword_cached', 'item') }}"
        """),
    "alias_defined_from_a_lookup_in_vars": _role(
        """
        - name: Render
          ansible.builtin.template: {src: c.j2, dest: /x}
        """,
        **{"vars/main.yml": "_r_pw: \"{{ lookup('my.utils.onepassword_cached', 'x') }}\"\n"},
        **{"templates/c.j2": "pw={{ _r_pw }}\n"},
    ),
    "set_in_template_carries_the_credential": _role(
        """
        - name: Render
          ansible.builtin.template: {src: c.j2, dest: /x}
        """,
        **{"templates/c.j2": "{% set p = r_jwt_secret %}value={{ p }}\n"},
    ),
    "diff_false_alone_is_not_enough": _role(
        """
        - name: Render
          ansible.builtin.template: {src: app.env.j2, dest: /x}
          diff: false
        """,
        **{"templates/app.env.j2": TPL_SECRET},
    ),
    "templated_no_log_is_not_accepted": _role(
        """
        - name: Render
          ansible.builtin.template: {src: app.env.j2, dest: /x}
          no_log: "{{ quiet | default(false) }}"
        """,
        **{"templates/app.env.j2": TPL_SECRET},
    ),
    "deployment_config_sweep_of_a_secret_template": _role(
        """
        - name: Deploy
          ansible.builtin.include_role:
            name: richard_lynch.common.deployment_config
          vars:
            deployment_config_source: "{{ r_files }}"
            deployment_config_destination: /x
        """,
        **{"files/app.env.j2": TPL_SECRET},
    ),
    "with_fileglob_item_src": _role(
        """
        - name: Render dynamic
          ansible.builtin.template:
            src: "{{ item }}"
            dest: "/x/{{ item | basename }}"
          with_fileglob: ["{{ role_path }}/templates/dyn/*.j2"]
        """,
        **{"templates/dyn/a.yml.j2": "secret: {{ r_forward_auth_secret }}\n"},
    ),
    "playbook_relative_src": {
        "playbooks/p/maint/fix.yml": """
            - hosts: all
              tasks:
                - name: Render via the role's template
                  ansible.builtin.template:
                    src: "{{ playbook_dir }}/../../../roles/r/templates/k.j2"
                    dest: /x
            """,
        "roles/r/templates/k.j2": 'secret "{{ tsig_key_secret }}";\n',
    },
    "suppression_without_a_reason": _role(
        """
        # guard-check: ignore DIFFLEAK-01
        - name: Render
          ansible.builtin.template: {src: app.env.j2, dest: /x}
        """,
        **{"templates/app.env.j2": TPL_SECRET},
    ),
}

# name -> tree. Each must exit 0.
MUST_FAIL.update(_SECURITY_REVIEW_FAIL)

MUST_PASS: dict[str, dict[str, str]] = {
    "vault applied to the whole expression, then a formatting filter on the ciphertext": _role(
        """
        - name: render
          ansible.builtin.template:
            src: v.j2
            dest: /etc/x
        """,
        **{"templates/v.j2": TPL_VAULT_THEN_YAML},
    ),
    "a vault call with two arguments and nothing after it": _role(
        """
        - name: render
          ansible.builtin.template:
            src: v.j2
            dest: /etc/x
        """,
        **{"templates/v.j2": TPL_VAULT_TWO_ARGS},
    ),
    "a suppression comment directly above the task counts": _role(
        """
        - name: other
          ansible.builtin.debug:
            msg: hi
        # guard-check: ignore DIFFLEAK-01 — fixture: deliberately exempt
        - name: render
          ansible.builtin.template:
            src: c.j2
            dest: /etc/x
        """,
        **{"templates/c.j2": TPL_SECRET},
    ),
    "a suppression on the task's own last line counts": _role(
        """
        - name: render
          ansible.builtin.template:
            src: c.j2
            dest: /etc/x  # guard-check: ignore DIFFLEAK-01 — fixture: deliberately exempt
        - name: other
          ansible.builtin.debug:
            msg: hi
        """,
        **{"templates/c.j2": TPL_SECRET},
    ),
    "an included partial with no secret is fine": _role(
        """
        - name: render
          ansible.builtin.template:
            src: outer.j2
            dest: /etc/x
        """,
        **{"templates/outer.j2": "{% include 'partial.j2' %}\n", "templates/partial.j2": "a: 1\n"},
    ),
    "action: mapping form WITH no_log": _role(
        """
        - name: render
          action:
            module: template
            args:
              src: c.j2
              dest: /etc/x
          no_log: true
        """,
        **{"templates/c.j2": TPL_SECRET},
    ),
    "with_fileglob whose pattern is not static, WITH no_log": _role("""
        - name: render many
          ansible.builtin.template:
            src: "{{ item }}"
            dest: "/etc/{{ item | basename }}"
          with_fileglob: "{{ r_pattern }}"
          no_log: true
        """),
    "with_fileglob over static non-secret templates": _role(
        """
        - name: render many
          ansible.builtin.template:
            src: "{{ item }}"
            dest: "/etc/{{ item | basename }}"
          with_fileglob: "{{ role_path }}/files/*.j2"
        """,
        **{"files/plain.j2": "a: 1\n"},
    ),
    "include_role free-form naming deployment_config, covered by apply no_log": _role(
        """
        - name: sweep
          ansible.builtin.include_role:
            name: richard_lynch.common.deployment_config
            apply:
              no_log: true
          vars:
            deployment_config_source: "{{ role_path }}/files"
        """,
        **{"files/app.env.j2": TPL_SECRET},
    ),
    "a {% set %} block of plain text": _role(
        """
        - name: render
          ansible.builtin.template:
            src: s.j2
            dest: /etc/x
        """,
        **{"templates/s.j2": "{% set blob %}hello {{ r_user }}{% endset %}{{ blob }}\n"},
    ),
    "an attribute that is not secret-named on a non-name base": _role("""
        - name: render
          ansible.builtin.copy:
            content: "{{ (r_rows | first).name }}"
            dest: /etc/x
        """),
    ".get('<plain key>') on an expression": _role("""
        - name: render
          ansible.builtin.copy:
            content: "{{ (r_cfg | from_yaml).get('hostname') }}"
            dest: /etc/x
        """),
    "a mapping data file beside a play, and HA config with !include under files/, are data": {
        "playbooks/p/play.yml": """
        - hosts: all
          tasks:
            - name: fine
              ansible.builtin.debug:
                msg: hi
        """,
        "playbooks/p/vars.yml": "p_user: bob\n",
        "playbooks/p/files/config/configuration.yaml": "automation: !include automations.yaml\n",
    },
    "a mapping at the top of a vars file is data, not a task file": {
        "roles/r/tasks/main.yml": """
        - name: fine
          ansible.builtin.debug:
            msg: hi
        """,
        "roles/r/vars/main.yml": "r_user: bob\n",
        "roles/r/defaults/main.yml": "r_db_password: changeme\n",
    },
    "an empty task file renders nothing": {
        "roles/r/tasks/main.yml": "---\n",
    },
    "a template with a #jinja2: delimiter header, WITH no_log": _role(
        """
        - name: render
          ansible.builtin.template:
            src: d.j2
            dest: /etc/x
          no_log: true
        """,
        **{
            "templates/d.j2": "#jinja2: variable_start_string:'[%', variable_end_string:'%]'\n[% r_x %]\n"
        },
    ),
    "a not-a-secret-suffixed name defined from a PATH is not tainted": _role("""
        - name: render
          vars:
            r_token_file: "/etc/app/token"
          ansible.builtin.copy:
            content: "{{ r_token_file }}"
            dest: /etc/x
        """),
    "group_vars two levels deep are data, not a task file": {
        "playbooks/p/play.yml": """
        - hosts: all
          tasks:
            - name: fine
              ansible.builtin.debug:
                msg: hi
        """,
        "playbooks/p/group_vars/all/main.yml": "p_user: bob\n",
    },
    "lookup('vars', <plain name>) is not a credential": _role("""
        - name: render
          ansible.builtin.copy:
            content: "{{ lookup('vars', 'r_user_name') }}"
            dest: /etc/x
        """),
    "an unresolved source WITH no_log is counted, not a finding": _role("""
        - name: render
          ansible.builtin.template:
            src: "{{ r_which_template }}"
            dest: /etc/x
          no_log: true
        """),
    "an unresolved source suppressed with a reason": _role("""
        - name: render  # guard-check: ignore DIFFLEAK-01 — fixture: the source is chosen at run time from a vetted list
          ansible.builtin.template:
            src: "{{ r_which_template }}"
            dest: /etc/x
        """),
    "a {% filter vault(pw) %} block protects its whole body": _role(
        """
        - name: render
          ansible.builtin.template:
            src: v.j2
            dest: /etc/x
        """,
        **{"templates/v.j2": "{% filter vault(r_vault_pw) %}{{ r_db_password }}{% endfilter %}\n"},
    ),
    "a {% with %} binding of a non-secret": _role(
        """
        - name: render
          ansible.builtin.template:
            src: w.j2
            dest: /etc/x
        """,
        **{"templates/w.j2": "{% with k = r_user %}{{ k }}{% endwith %}\n"},
    ),
    "copy content: renders lookup('template', ...) of a template with no secret": _role(
        """
        - name: render
          ansible.builtin.copy:
            content: "{{ lookup('template', 'plain.j2') }}"
            dest: /etc/x
        """,
        **{"templates/plain.j2": "a: 1\n"},
    ),
    "precedence: the parenthesised concatenation IS vaulted": _role(
        """
        - name: render
          ansible.builtin.template:
            src: v.j2
            dest: /etc/x
        """,
        **{"templates/v.j2": "p: {{ (r_secret ~ r_x) | vault(r_vault_pw) }}\n"},
    ),
    "lineinfile line: with no credential": _role("""
        - name: line
          ansible.builtin.lineinfile:
            path: /etc/x
            line: "user={{ r_user }}"
        """),
    "a hash applied to the whole (parenthesised) expression": _role(
        """
        - name: render
          ansible.builtin.template:
            src: v.j2
            dest: /etc/x
        """,
        **{"templates/v.j2": TPL_HASHED_CONCAT},
    ),
    "free-form k=v rendering a secret WITH no_log": _role(
        """
        - name: render
          ansible.builtin.template: src=c.j2 dest="/etc/x y.conf"
          no_log: true
        """,
        **{"templates/c.j2": TPL_SECRET},
    ),
    "no_log_on_the_task": _role(
        """
        - name: Render
          ansible.builtin.template: {src: app.env.j2, dest: /x, mode: "0600"}
          no_log: true
        """,
        **{"templates/app.env.j2": TPL_SECRET},
    ),
    "no_log_inherited_from_block": _role(
        """
        - name: Block
          no_log: true
          block:
            - name: Render
              ansible.builtin.template: {src: app.env.j2, dest: /x}
        """,
        **{"templates/app.env.j2": TPL_SECRET},
    ),
    "names_about_a_credential": _role(
        """
        - name: Render
          ansible.builtin.template: {src: c.j2, dest: /x}
        """,
        **{
            "templates/c.j2": (
                "file={{ r_password_file }} ttl={{ r_token_ttl }} on={{ r_api_key_enabled }}\n"
                "item={{ r_jwt_secret_op_item }} env={{ ex.api_key_env_var }} tok={{ tokenizer }}\n"
                "c={{ compass }} p={{ passthrough }}\n"
            )
        },
    ),
    "credential_only_TESTED_never_rendered": _role(
        """
        - name: Render
          ansible.builtin.template: {src: c.j2, dest: /x}
        """,
        **{
            "templates/c.j2": (
                "{% if r_api_key | default('') | length > 0 %}\n"
                "  api_key: os.environ/R_API_KEY\n{% endif %}\n"
            )
        },
    ),
    "vaulted_or_hashed_output": _role(
        """
        - name: Render
          ansible.builtin.template: {src: c.j2, dest: /x}
        - name: Record the digest
          ansible.builtin.copy:
            content: "{{ r_doc_with_token | to_nice_yaml | hash('sha256') }}  f\\n"
            dest: /y
        """,
        **{"templates/c.j2": "p: {{ r_password | vault(ansible_vault_password) | to_yaml }}\n"},
    ),
    "copy_src_is_not_rendered": _role(
        """
        - name: Copy
          ansible.builtin.copy: {src: app.env.j2, dest: /x}
        """,
        **{"files/app.env.j2": TPL_SECRET},
    ),
    "deployment_config_with_apply_no_log": _role(
        """
        - name: Deploy
          ansible.builtin.include_role:
            name: richard_lynch.common.deployment_config
            apply:
              no_log: true
          vars:
            deployment_config_source: "{{ r_files }}"
        """,
        **{"files/app.env.j2": TPL_SECRET},
    ),
    "deployment_config_sweep_with_no_secret_template": _role(
        """
        - name: Deploy
          ansible.builtin.include_role:
            name: richard_lynch.common.deployment_config
          vars:
            deployment_config_source: "{{ r_files }}"
        """,
        **{"files/compose.yml.j2": "image: {{ r_image }}\n"},
    ),
    "suppressed_with_a_reason": _role(
        """
        # guard-check: ignore DIFFLEAK-01 — the doc is built by a filter that refuses secrets
        - name: Render
          ansible.builtin.template: {src: app.env.j2, dest: /x}
        """,
        **{"templates/app.env.j2": TPL_SECRET},
    ),
    "molecule_scenarios_are_not_the_estate": {
        "roles/r/molecule/default/converge.yml": """
            - hosts: all
              tasks:
                - name: Render
                  ansible.builtin.copy: {content: "{{ fake_password }}", dest: /x}
            """,
    },
}


class Names(unittest.TestCase):
    def test_credential_names(self):
        for n in (
            "password",
            "r_db_password",
            "sudoPassword",
            "jellystat_jwt_secret",
            "cloudflared_tunnel_token",
            "gateway_openai_api_key",
            "ci_ssh_privkey",
            "private_key",
            "db_pw",
            "apikey",
        ):
            with self.subTest(n):
                self.assertTrue(c.is_secret_name(n), n)

    def test_near_miss_names(self):
        for n in (
            "password_file",
            "token_ttl",
            "api_key_enabled",
            "secret_name",
            "api_token_id",
            "jwt_secret_op_item",
            "api_key_env_var",
            "tokenizer",
            "compass",
            "passthrough",
            "hostname",
            "password_hash",
        ):
            with self.subTest(n):
                self.assertFalse(c.is_secret_name(n), n)

    def test_filter_and_test_names_are_not_data(self):
        self.assertEqual(c.credential_refs("{{ 'x' | password_hash('sha512') }}"), set())
        self.assertEqual(c.credential_refs("{% if a is token %}{% endif %}"), set())
        self.assertEqual(c.credential_refs("{{ ['token'] | join }}"), set())

    def test_subscript_key_counts(self):
        self.assertEqual(c.credential_refs("{{ cfg['api_token'] }}"), {"cfg.api_token"})


class Trees(unittest.TestCase):
    def test_every_must_fail_tree_fails(self):
        for name, tree in MUST_FAIL.items():
            with self.subTest(name):
                rc, out = _scan(tree)
                self.assertEqual(rc, 1, out)
                self.assertIn("[DIFFLEAK-01]", out)
                self.assertIn("1 FAIL", out)

    def test_every_near_miss_passes(self):
        for name, tree in MUST_PASS.items():
            with self.subTest(name):
                rc, out = _scan(tree)
                self.assertEqual(rc, 0, out)
                self.assertIn("0 FAIL", out)

    def test_bare_suppression_says_why_it_failed(self):
        _rc, out = _scan(MUST_FAIL["suppression_without_a_reason"])
        self.assertIn("must say why", out)

    def test_unresolvable_src_is_counted_never_silent(self):
        rc, out = _scan(_role("""
                - name: Render whatever
                  ansible.builtin.template: {src: "{{ item }}", dest: /x}
                  loop: "{{ things }}"
                """))
        # Fail closed (security review, 2026-11-06): an unresolved source without no_log is a
        # FINDING as well as a counted unresolved item; the near-miss (with no_log) is in MUST_PASS.
        self.assertEqual(rc, 1, out)
        self.assertIn("<unresolved>", out)
        self.assertIn("1 source(s) could not be resolved", out)

    def test_non_literal_include_and_missing_include_are_unresolved(self):
        rc, out = _scan(
            _role(
                """
                - name: render
                  ansible.builtin.template:
                    src: outer.j2
                    dest: /etc/x
                """,
                **{"templates/outer.j2": "{% include r_partial %}\n{% include 'gone.j2' %}\n"},
            )
        )
        self.assertIn("2 source(s) could not be resolved", out, out)

    def test_unparseable_args_mapping_is_unresolved(self):
        rc, out = _scan(
            _role(
                """
                - name: render
                  ansible.builtin.template: src=c.j2 dest=/etc/x
                  args: not-a-mapping
                """,
                **{"templates/c.j2": TPL_SECRET},
            )
        )
        self.assertIn("1 source(s) could not be resolved", out, out)

    def test_lookup_render_paths_that_cannot_be_judged_are_unresolved(self):
        rc, out = _scan(_role("""
                - name: non-literal template lookup
                  ansible.builtin.copy:
                    content: "{{ lookup('template', r_which) }}"
                    dest: /etc/a
                - name: file lookup copies unrendered content
                  ansible.builtin.copy:
                    content: "{{ lookup('file', 'creds.txt') }}"
                    dest: /etc/b
                - name: template lookup of a file no search path holds
                  ansible.builtin.copy:
                    content: "{{ lookup('template', 'gone.j2') }}"
                    dest: /etc/c
                - name: a command's output is content this check cannot see
                  ansible.builtin.copy:
                    content: "{{ lookup('pipe', 'cat /etc/creds') }}"
                    dest: /etc/d
                """))
        self.assertIn("4 source(s) could not be resolved", out, out)

    def test_unparseable_free_form_is_unresolved_never_passed(self):
        rc, out = _scan(
            _role(
                """
                - name: render
                  ansible.builtin.template: src=c.j2 dest="/etc/unterminated
                """,
                **{"templates/c.j2": TPL_SECRET},
            )
        )
        self.assertIn("1 source(s) could not be resolved", out, out)

    def test_ast_precedence_and_protection(self):
        cr = c.credential_refs
        # the filter binds tighter than ~ / + / and / or / if: only its operand is protected
        self.assertIn("r_secret", cr("{{ r_secret ~ r_x | vault(r_pw) }}"))
        self.assertEqual(cr("{{ (r_secret ~ r_x) | vault(r_pw) }}"), set())
        self.assertIn("r_secret", cr("{{ r_secret + r_x | hash('sha256') }}"))
        self.assertIn("r_secret", cr("{{ r_x | vault(r_pw) if r_flag else r_secret }}"))
        self.assertIn("r_secret", cr("{{ r_secret if r_flag else r_x | vault(r_pw) }}"))
        self.assertEqual(cr("{{ (r_secret or r_x) | vault(r_pw) }}"), set())
        self.assertIn("r_secret", cr("{{ r_secret and r_x | vault(r_pw) }}"))
        self.assertIn("r_secret", cr("{{ r_secret or (r_x | vault(r_pw)) }}"))
        # nested / chained
        self.assertIn("r_secret_a", cr("{{ r_secret_a ~ (r_x | vault(r_pw)) }}"))
        self.assertEqual(
            cr("{{ r_x | vault(r_pw) | default(r_other_secret) }}"), {"r_other_secret"}
        )
        self.assertEqual(cr("{{ r_password | vault(r_pw) | to_yaml }}"), set())
        self.assertEqual(cr("{{ r_password | ansible.builtin.vault(r_pw) }}"), set())
        self.assertIn("r_password", cr("{{ r_password | vaulted }}"))
        self.assertIn("r_password", cr("{{ r_password | hash_name }}"))
        # a test or comparison emits a boolean, a conditional's test renders nothing
        self.assertEqual(cr("{{ r_password is defined }}"), set())
        self.assertEqual(cr("{{ 'x' if r_password else 'y' }}"), set())
        self.assertEqual(cr("{% if r_password %}a{% endif %}"), set())
        # statements: set / for taint, include targets
        self.assertEqual(cr("{% set k = r_password %}{{ k }}"), {"k"})
        self.assertEqual(cr("{% set k = r_password | vault(r_pw) %}{{ k }}"), set())
        self.assertEqual(cr("{% for s in r_secret_values %}{{ s }}{% endfor %}"), {"s"})
        self.assertEqual(
            cr("{{ lookup('community.general.onepassword', 'item') }}"),
            {"lookup('community.general.onepassword')"},
        )
        self.assertEqual(cr("{{ cfg['api_token'] }}"), {"cfg.api_token"})
        self.assertEqual(cr("{{ d[r_secret_key] }}"), {"r_secret_key"})

    def test_unparseable_jinja_is_an_error_for_files_and_taint_for_vars(self):
        with self.assertRaises(c.TemplateParseError):
            c.credential_refs("{{ r_x | }}")
        self.assertEqual(c.credential_refs_or_tainted("{{ r_x | }}", set()), {"<unparseable>"})
        rc, out = _scan(
            _role(
                """
                - name: render
                  ansible.builtin.template:
                    src: bad.j2
                    dest: /etc/x
                """,
                **{"templates/bad.j2": "x: {{ r_x | \n"},
            )
        )
        self.assertIn("1 source(s) could not be resolved", out, out)
        rc, out = _scan(_role("""
                - name: render
                  vars:
                    r_dyn: "{{ r_x | }}"
                  ansible.builtin.copy:
                    content: "{{ r_dyn }}"
                    dest: /etc/x
                """))
        self.assertEqual(rc, 1, out)

    def test_render_args_match_the_installed_ansible_core(self):
        """Every rendering argument and alias in RENDER_ARGS exists in the module's real spec,
        and every alias of a rendering option is listed (ansible-doc is the source of truth)."""
        import json
        import shutil
        import subprocess

        if shutil.which("ansible-doc") is None:
            self.skipTest("ansible-doc not on PATH")
        fq = {
            "ini_file": "community.general.ini_file",
            "win_template": "ansible.windows.win_template",
            "win_copy": "ansible.windows.win_copy",
            "win_lineinfile": "ansible.windows.win_lineinfile",
        }
        for module, args in c.RENDER_ARGS.items():
            if not args:
                continue
            name = fq.get(module, f"ansible.builtin.{module}")
            run = subprocess.run(
                ["ansible-doc", "-t", "module", "-j", name], capture_output=True, text=True
            )
            doc = json.loads(run.stdout) if run.returncode == 0 else {}
            if name not in doc:
                self.assertIn(module, fq, f"{name}: ansible-doc has no entry ({run.stderr[:200]})")
                continue  # a collection module whose collection is not installed here
            options = doc[name]["doc"]["options"]
            names = {o: set(v.get("aliases") or []) for o, v in options.items()}
            for a in args:
                self.assertTrue(
                    a in names or any(a in al for al in names.values()),
                    f"{module}: {a} is not an option",
                )
                if a in names:
                    for alias in names[a]:
                        self.assertIn(alias, args, f"{module}: alias {alias} of {a} is missing")

    def test_render_tasks_are_seen(self):
        """A clean result over a tree with render tasks must have SEEN them (not scanned nothing)."""
        _rc, out = _scan(MUST_PASS["no_log_on_the_task"])
        self.assertIn("across 1 render task(s)", out)

    def test_list_rules(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(c.main(["x", "--list-rules"]), 0)
        self.assertTrue(out.getvalue().startswith("DIFFLEAK-01  FAIL"))


if __name__ == "__main__":
    unittest.main(verbosity=1)
