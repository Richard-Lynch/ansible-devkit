#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for check_silent_guards.py — the static checker for guards/gates/conditionals that look
correct but can never fire (see the checker's docstring).

Run:  uv run tests/suites/test_check_silent_guards.py
      (exit 0 = all pass, 1 = failures; prints a per-case report)

WHY THESE CASES: every BUGGY fixture below is a minimal reproduction of the shape its rule
catches, and every FIXED fixture is the corresponding correct rewrite of the same shape, to prove
the rule does not cry wolf on the pattern it exists to allow.

Each case is (expected, fixture content or path, label), run through the real script as a
subprocess, and the goal is that reading the case list is itself a readable spec of the ruleset.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

from _paths import CHECKS, ROOT  # noqa: F401 — tests/suites/_paths.py
import _paths

_paths.use_fixture_config()

SCRIPT = CHECKS / "check_silent_guards.py"

CLEAN = "clean"  # exit 0, no findings of the rule under test
CATCH = "catch"  # exit 0 or 1, but the rule under test DOES fire


def run(paths: list[str], extra_args: list[str] | None = None) -> tuple[int, str]:
    cmd = [sys.executable, str(SCRIPT), *(extra_args or []), *paths]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    return proc.returncode, proc.stdout + proc.stderr


def write(tmpdir: Path, name: str, content: str) -> Path:
    p = tmpdir / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    return p


# --------------------------------------------------------------------------------------------
# Fixture content — single-file cases: (rule_id, expect_catch: bool, filename, yaml content)
# --------------------------------------------------------------------------------------------

FILE_CASES: list[tuple[str, bool, str, str]] = [
    # ---- META-01: meta: + until:/retries:/delay: ----
    (
        "META-01",
        True,
        "meta_until_buggy.yml",
        """\
- name: Wait for the IP to appear in the dynamic inventory for
  delegate_to: localhost
  ansible.builtin.meta: refresh_inventory
  retries: "{{ wait_retries }}"
  delay: "{{ wait_delay }}"
  until: hostvars[new_container.hostname] != null
  changed_when: false
""",
    ),
    (
        "META-01",
        False,
        "meta_until_fixed.yml",
        """\
- name: Flush handlers
  ansible.builtin.meta: flush_handlers

- name: Now really wait for connectivity
  ansible.builtin.wait_for_connection:
    timeout: 60
""",
    ),
    # ---- REGEX-01: POSIX bracket class in a Python/Jinja regex ----
    (
        "REGEX-01",
        True,
        "posix_buggy.yml",
        """\
- name: HARD GATE — /etc/hosts must no longer mention the old name
  ansible.builtin.assert:
    that:
      - _hosts_after.rc == 0
      - target_name in _hosts_after.stdout
      - _hosts_after.stdout is not search('(^|[^-[:alnum:]])' + source_name + '([^-[:alnum:]]|$)')
""",
    ),
    (
        "REGEX-01",
        False,
        "posix_fixed.yml",
        """\
- name: HARD GATE — /etc/hosts must no longer mention the old name
  ansible.builtin.assert:
    that:
      - _hosts_after.rc == 0
      - target_name in _hosts_after.stdout
      - _hosts_after.stdout is not search('(^|[^-\\w])' + source_name + '([^-\\w]|$)')
""",
    ),
    # ---- CHECKMODE-01: ansible_check_mode documented as settable via -e/EXTRA= ----
    (
        "CHECKMODE-01",
        True,
        "checkmode_extra_buggy.yml",
        """\
# │   make converge PLAYBOOK=.../main.yml EXTRA='ansible_check_mode=true'  (or --check)  │
- name: dummy
  ansible.builtin.debug:
    msg: hi
""",
    ),
    (
        "CHECKMODE-01",
        False,
        "checkmode_extra_fixed.yml",
        """\
# NB `EXTRA='ansible_check_mode=true'` DOES NOT WORK and was documented here until today.
- name: dummy
  ansible.builtin.debug:
    msg: hi
""",
    ),
    # ---- MAPKEY-01: Jinja in a YAML mapping key (an opaque HTTP 400 from an API) ----
    (
        "MAPKEY-01",
        True,
        "mapkey_buggy.yml",
        """\
- name: Bad — Jinja in a mapping key
  ansible.builtin.uri:
    url: https://api.example.com/v4/zones
    body:
      "prefix.{{ my_var }}": "*"
    method: POST
""",
    ),
    (
        "MAPKEY-01",
        False,
        "mapkey_fixed.yml",
        """\
- name: OK — build the dict dynamically instead of a templated literal key
  ansible.builtin.uri:
    url: https://api.example.com/v4/zones
    body: "{{ {'prefix.' + my_var: '*'} }}"
    method: POST

- name: OK — dynamic set_fact key is the documented-supported idiom
  ansible.builtin.set_fact:
    "{{ dynamic_name }}": "value"
""",
    ),
    # ---- JINJACOMMENT-01: '#' inside a {{ }} expression ----
    (
        "JINJACOMMENT-01",
        True,
        "jinjacomment_buggy.yml",
        """\
- name: Bad — comment inside a Jinja expression
  ansible.builtin.debug:
    msg: "{{ some_var # this breaks }}"
""",
    ),
    (
        "JINJACOMMENT-01",
        False,
        "jinjacomment_fixed.yml",
        """\
- name: OK — comment outside the expression
  ansible.builtin.debug:
    msg: "{{ some_var }}"  # a normal YAML comment, fine
""",
    ),
    # ---- FAILED-01: branch on .failed/is failed after failed_when:false ----
    (
        "FAILED-01",
        True,
        "failed_when_buggy.yml",
        """\
- name: Test SSH port accessibility
  ansible.builtin.wait_for:
    host: "{{ ansible_host }}"
    port: "{{ ssh_port }}"
  register: ssh_port_result
  failed_when: false

- name: Display SSH port failures
  ansible.builtin.debug:
    msg: bad
  failed_when: true
  when: ssh_port_result is failed
""",
    ),
    (
        "FAILED-01",
        False,
        "failed_when_fixed.yml",
        """\
- name: Test SSH port accessibility
  ansible.builtin.wait_for:
    host: "{{ ansible_host }}"
    port: "{{ ssh_port }}"
  register: ssh_port_result

- name: Display SSH port failures
  ansible.builtin.debug:
    msg: bad
  when: ssh_port_result.rc != 0
""",
    ),
    # ---- UNTIL-01: a loop inside a block:, asserted on the NEXT task, is correctly guarded ----
    # The enclosing block task contains the loop, so attributing the loop to the OUTER task put the
    # lookahead window after the whole block — past the very assert that guards it, flagging
    # correctly-written guards like this one.
    (
        "UNTIL-01",
        False,
        "until_in_block_with_assert.yml",
        """\
- name: Confirm the reload landed
  when: reload | bool
  block:
    - name: Ask the metrics server which rule groups it has loaded
      ansible.builtin.uri:
        url: "http://localhost:9090/api/v1/rules"
      register: _loaded
      until: (_loaded.json.data.groups | default([]) | length) > 0
      retries: 6
      delay: 2
      failed_when: false

    - name: Assert the rules are live
      ansible.builtin.assert:
        that:
          - (_loaded.json.data.groups | default([]) | length) > 0
""",
    ),
    # ---- UNTIL-01: assert on a fact DERIVED from the register still counts as a re-check ----
    # The house pattern is recompute-from-a-fresh-read -> set_fact -> assert on that fact.
    # Requiring the register name inside the assert task itself misses every one of those:
    # correctly guarded loops whose only "fix" would be to duplicate an assert that already exists.
    (
        "UNTIL-01",
        False,
        "until_assert_on_derived_fact.yml",
        """\
- name: Ask the log shipper which components it is running
  ansible.builtin.uri:
    url: "http://127.0.0.1:12345/api/v0/web/components"
  register: _cl_components
  until: (_cl_components.json | default([]) | length) > 0
  retries: 12
  delay: 5
  failed_when: false

- name: Work out which components are live
  ansible.builtin.set_fact:
    _cl_mine: >-
      {{ _cl_components.json | default([]) | selectattr('health', 'defined') | list }}

- name: Assert every source is loaded and healthy
  ansible.builtin.assert:
    that:
      - (_cl_mine | length) > 0
""",
    ),
    # ---- UNTIL-01: an HONEST retry loop (no failed_when:false) is not a silent guard ----
    # Exhausting the retries fails the task and stops the play, which is loud, not silent. The
    # defect is specifically until: PAIRED WITH failed_when:false. Flagging honest loops makes
    # findings unfixable by design.
    (
        "UNTIL-01",
        False,
        "until_without_suppression.yml",
        """\
- name: Wait for Postgres to accept connections
  ansible.builtin.command: pg_isready -U postgres
  register: _pg_ready
  retries: 15
  delay: 3
  until: _pg_ready.rc == 0
  changed_when: false
""",
    ),
    # ---- REGEX-02: a comment DESCRIBING the \b trap is not the trap ----
    (
        "REGEX-02",
        False,
        "backslash_b_in_comment.yml",
        """\
- name: HARD GATE — read back rather than trusting a regex
  # An earlier draft derived `changed` from a Jinja regex_search('\b'...) on the controller;
  # in a non-raw Python string \b is a BACKSPACE, not a word boundary, so it never matched.
  ansible.builtin.assert:
    that:
      - _hosts_after.rc == 0
      - target_name in _hosts_after.stdout
""",
    ),
    (
        "REGEX-02",
        True,
        "backslash_b_live_pattern.yml",
        """\
- name: A \b in a live pattern must still be caught
  ansible.builtin.assert:
    that:
      - _out.stdout is search('\\bhostname\\b')
""",
    ),
    # ---- FAILED-01: ignore_errors is HONEST and must NOT be flagged ----
    # Ansible's behaviour (task running /bin/false under each key):
    #   ignore_errors: true -> .failed == True   |   failed_when: false -> .failed == False
    # This is the fix the rule's own message now recommends, so flagging it would condemn the
    # remedy. The buggy/fixed pair above proves the rule still catches the real defect.
    (
        "FAILED-01",
        False,
        "ignore_errors_is_honest.yml",
        """\
- name: Probe every host before failing the play
  ansible.builtin.wait_for:
    host: "{{ ansible_host }}"
    port: 22
  register: ssh_port_result
  ignore_errors: true

- name: Report the ones that failed
  ansible.builtin.debug:
    msg: "port unreachable"
  failed_when: true
  when: ssh_port_result is failed
""",
    ),
    # ---- UNTIL-01: until: with no assert/fail re-checking the register ----
    (
        "UNTIL-01",
        True,
        "until_no_assert_buggy.yml",
        """\
- name: Wait for the service to be healthy
  ansible.builtin.command:
    cmd: "docker inspect appdb"
  register: _health
  until: _health.stdout == "healthy"
  retries: 20
  delay: 5
  failed_when: false

- name: Report import
  ansible.builtin.debug:
    msg: "health={{ _health.stdout | default('?') }}"
""",
    ),
    (
        "UNTIL-01",
        False,
        "until_with_assert_fixed.yml",
        """\
- name: Wait for the service to be healthy
  ansible.builtin.command:
    cmd: "docker inspect appdb"
  register: _health
  until: _health.stdout == "healthy"
  retries: 20
  delay: 5
  failed_when: false

- name: HARD GATE — the service must be healthy
  ansible.builtin.assert:
    that:
      - _health.stdout == "healthy"
""",
    ),
    # ---- STRINT-01: string-coerced value compared to a bare int literal ----
    (
        "STRINT-01",
        True,
        "strint_buggy.yml",
        """\
- name: Bad — string coerced then compared to int literal
  ansible.builtin.assert:
    that:
      - (some_list | length | string) == 5
""",
    ),
    (
        "STRINT-01",
        False,
        "strint_fixed.yml",
        """\
- name: OK — compare without the coercion
  ansible.builtin.assert:
    that:
      - (some_list | length) == 5
""",
    ),
    # ---- CHECKMODE-02: when: ansible_check_mode inside a block-level check_mode: block ----
    (
        "CHECKMODE-02",
        True,
        "checkmode02_buggy.yml",
        """\
- name: Preview block
  check_mode: "{{ not apply }}"
  block:
    - name: something guarded wrongly
      ansible.builtin.debug:
        msg: preview
      when: not ansible_check_mode
""",
    ),
    (
        "CHECKMODE-02",
        False,
        "checkmode02_fixed.yml",
        """\
- name: Preview block
  check_mode: "{{ not apply }}"
  block:
    - name: something guarded correctly with a dedicated var
      ansible.builtin.debug:
        msg: preview
      when: apply
""",
    ),
    # ---- INDEXGUARD-01: unexplained single-char index guard before a destructive cmd ----
    (
        "INDEXGUARD-01",
        True,
        "indexguard_buggy.yml",
        """\
- name: Assert every candidate is unreferenced + not open (attr pos5 must be '-')
  ansible.builtin.assert:
    that:
      - (_refs.results[idx].stdout | int) == 0
      - (item.split('|')[1][4]) != 'o'
    fail_msg: "referenced or open — NOT removing."
  loop: "{{ _orphan_snaps }}"

- name: Remove each orphaned backup snapshot
  ansible.builtin.command:
    cmd: "lvremove -y {{ vg }}/{{ item.split('|')[0] }}"
""",
    ),
    (
        "INDEXGUARD-01",
        False,
        "indexguard_fixed.yml",
        """\
# The Open flag is at INDEX 5 of lv_attr, not index 4. Index 4 is State, which is 'a' on every
# active LV. Per lvs(8), worked example:
#     data  twi-aotz--   idx4='a'  idx5='o'   <-- open
#     base  Vri-a-tz-k   idx4='a'  idx5='-'   <-- not open
- name: Assert every candidate is unreferenced + not open (attr index 5 must not be 'o')
  ansible.builtin.assert:
    that:
      - (_refs.results[idx].stdout | int) == 0
      - (item.split('|')[1][5]) != 'o'
    fail_msg: "referenced or open — NOT removing."
  loop: "{{ _orphan_snaps }}"

- name: Remove each orphaned backup snapshot
  ansible.builtin.command:
    cmd: "lvremove -y {{ vg }}/{{ item.split('|')[0] }}"
""",
    ),
    # ---- ANCHOR-01: '$' anchor without (?m) against multi-line stdout ----
    (
        "ANCHOR-01",
        True,
        "anchor_buggy.yml",
        """\
- name: Bad — $ without (?m) against multi-line stdout
  ansible.builtin.assert:
    that:
      - _dig_result.stdout is search('other-estate.example.com$')
""",
    ),
    (
        "ANCHOR-01",
        False,
        "anchor_fixed.yml",
        """\
- name: OK — (?m) present
  ansible.builtin.assert:
    that:
      - _dig_result.stdout is search('(?m)other-estate.example.com$')
""",
    ),
    # ---- REGEX-02: \\b as backspace, not word boundary, in a non-raw string (Known trap) ----
    (
        "REGEX-02",
        True,
        "backslashb_buggy.yml",
        """\
- name: Bad — \\b as word boundary in a non-raw string
  ansible.builtin.assert:
    that:
      - _hosts_after.stdout is not search('\\b' + source_name + '\\b')
""",
    ),
    (
        "REGEX-02",
        False,
        "backslashb_fixed.yml",
        """\
- name: OK — \\w-based boundary instead of \\b
  ansible.builtin.assert:
    that:
      - _hosts_after.stdout is not search('(^|[^-\\w])' + source_name + '([^-\\w]|$)')
""",
    ),
    # ---- ASSERTKEY-01: comment breaking a plain-scalar continuation in assert.that ----
    (
        "ASSERTKEY-01",
        True,
        "assertkey_buggy.yml",
        """\
- name: Bad — comment breaks a folded continuation inside assert.that
  ansible.builtin.assert:
    that:
      - some_condition == true or
        # this comment explains the fallback
        other_condition == true
      - final_condition == true
""",
    ),
    (
        "ASSERTKEY-01",
        False,
        "assertkey_fixed.yml",
        """\
- name: OK — each condition self-contained, comment sits above a complete item
  ansible.builtin.assert:
    that:
      - _old_addrs.rc == 0
      # exact list membership, NOT a substring search: the broadcast address would false-trigger.
      - cutover_service_ip not in _old_ips
""",
    ),
    # ---- SUPPRESS-01: bare suppression comment (no reason) is itself invalid ----
    (
        "SUPPRESS-01",
        True,
        "suppress_bare.yml",
        """\
- name: task
  ansible.builtin.meta: refresh_inventory
  # guard-check: ignore META-01
  retries: 3
  delay: 1
  until: 1 == 2
""",
    ),
    (
        "SUPPRESS-01",
        False,
        "suppress_valid.yml",
        """\
- name: task
  ansible.builtin.meta: refresh_inventory
  # guard-check: ignore META-01 — intentional no-op poll, real retry happens in the next task
  retries: 3
  delay: 1
  until: 1 == 2
""",
    ),
    # ---- CONDMAP-01: a conditional list item that YAML parses as a mapping ----
    (
        "CONDMAP-01",
        True,
        "condmap_assert_buggy.yml",
        """\
- name: Gate — the unquoted colon-space makes this item a mapping
  ansible.builtin.assert:
    that:
      - _body.status == 401
      - _body is search('auth: refused')
""",
    ),
    (
        "CONDMAP-01",
        True,
        "condmap_when_buggy.yml",
        """\
- name: when list item with an unquoted colon-space
  ansible.builtin.debug:
    msg: hi
  when:
    - _r.stdout is search('state: running')
""",
    ),
    (
        "CONDMAP-01",
        True,
        "condmap_failed_when_buggy.yml",
        """\
- name: failed_when list item with an unquoted colon-space
  ansible.builtin.command:
    cmd: /bin/true
  register: _r
  changed_when: false
  failed_when:
    - _r.rc != 0
    - _r.stderr is search('error: denied')
""",
    ),
    (
        "CONDMAP-01",
        False,
        "condmap_quoted_fixed.yml",
        """\
- name: OK — the same conditions, quoted, are strings
  ansible.builtin.assert:
    that:
      - "_body is search('auth: refused')"
      - >-
        _body is search('state: running')
- name: OK — a mapping under a NON-conditional key is ordinary data
  ansible.builtin.debug:
    msg: "{{ item.a }}"
  loop:
    - {a: b}
  when:
    - "'k: v' in _r.stdout"
  until: "_r.stdout is search('ready: yes')"
""",
    ),
]


def test_file_cases(tmpdir: Path) -> list[str]:
    failures = []
    for rule, expect_catch, filename, content in FILE_CASES:
        path = write(tmpdir, filename, content)
        rc, out = run([str(path)])
        caught = rule in out and f"[{rule}]" in out
        ok = caught == expect_catch
        status = "PASS" if ok else "FAIL"
        print(f"  {status}  {rule:16} {'catch' if expect_catch else 'clean':5}  {filename}")
        if not ok:
            failures.append(
                f"{rule}/{filename}: expected {'a catch' if expect_catch else 'no finding'}, "
                f"{'got none' if expect_catch else 'got one'}\n---\n{out}\n---"
            )
    return failures


def test_suppress_valid_does_not_ALSO_suppress_bare(tmpdir: Path) -> list[str]:
    """The bare-suppression fixture's META-01 finding must NOT be suppressed (only SUPPRESS-01
    fires for it) — a bare comment must not accidentally still work as a suppression."""
    failures = []
    path = write(
        tmpdir,
        "suppress_bare_meta_check.yml",
        FILE_CASES[[c[2] for c in FILE_CASES].index("suppress_bare.yml")][3],
    )
    rc, out = run([str(path)])
    ok = "[META-01]" in out and "[SUPPRESS-01]" in out
    print(f"  {'PASS' if ok else 'FAIL'}  META-01+SUPPRESS-01 both fire on a bare suppression")
    if not ok:
        failures.append(f"bare suppression did not leave META-01 active:\n{out}")
    return failures


def test_handler_only_fact(tmpdir: Path) -> list[str]:
    """HANDLER-01: fact set only by a handler vs. the fixed shape (a role that re-sets the fact
    inline a second time after flush_handlers)."""
    failures = []

    buggy_role = tmpdir / "roles" / "buggy_role"
    write(
        buggy_role,
        "tasks/main.yml",
        """\
- name: Initialise changed status
  ansible.builtin.set_fact:
    buggy_role_changed: "{{ false }}"

- name: Copy the docker-compose file
  ansible.builtin.template:
    src: "docker-compose.yml.j2"
    dest: "docker-compose.yml"

- name: Flush handlers
  ansible.builtin.meta: flush_handlers
""",
    )
    write(
        buggy_role,
        "handlers/main.yml",
        """\
- name: Update changed status
  ansible.builtin.set_fact:
    buggy_role_changed: true
""",
    )

    fixed_role = tmpdir / "roles" / "fixed_role"
    write(
        fixed_role,
        "tasks/main.yml",
        """\
- name: Initialise changed status
  ansible.builtin.set_fact:
    fixed_role_changed: "{{ false }}"

- name: Ensure directories exists
  notify: Update changed status
  ansible.builtin.file:
    path: "{{ dest }}"
    state: directory

- name: Flush handlers
  ansible.builtin.meta: flush_handlers

- name: Re-set changed status inline too (the actual fix)
  ansible.builtin.set_fact:
    fixed_role_changed: true
  when: some_register.changed | default(false)
""",
    )
    write(
        fixed_role,
        "handlers/main.yml",
        """\
- name: Update changed status
  ansible.builtin.set_fact:
    fixed_role_changed: true
""",
    )

    rc, out = run([str(buggy_role)])
    ok1 = "[HANDLER-01]" in out
    print(f"  {'PASS' if ok1 else 'FAIL'}  HANDLER-01 catch    buggy_role (handler-only fact)")
    if not ok1:
        failures.append(f"HANDLER-01 did not fire on buggy_role:\n{out}")

    rc, out = run([str(fixed_role)])
    ok2 = "[HANDLER-01]" not in out
    print(f"  {'PASS' if ok2 else 'FAIL'}  HANDLER-01 clean    fixed_role (inline re-set present)")
    if not ok2:
        failures.append(f"HANDLER-01 false-fired on fixed_role:\n{out}")

    return failures


def test_molecule_mirror(tmpdir: Path) -> list[str]:
    """MOLMIRROR-01: a molecule verify.yml that computes the role's own filter expression over a
    hand-typed stub and never calls the role vs.
    the legitimate house-wide pattern of rendering templates directly with ansible.builtin.template
    (used by most molecule scenarios — must NOT be flagged)."""
    failures = []

    mirror_role = tmpdir / "roles" / "mirror_role"
    write(mirror_role, "tasks/main.yml", "- name: noop\n  ansible.builtin.debug: {msg: hi}\n")
    write(
        mirror_role,
        "molecule/default/verify.yml",
        """\
- name: Verify
  hosts: localhost
  tasks:
    - name: Case A
      vars:
        stub:
          - {id: "backup-aaa", comment: "someone elses job"}
          - {id: "backup-bbb", comment: "ansible-managed-nightly"}
      block:
        - set_fact:
            our: "{{ stub | selectattr('comment','search','ansible-managed') | list | first }}"
        - assert:
            that:
              - our.id == 'backup-bbb'
""",
    )

    template_role = tmpdir / "roles" / "template_role"
    write(template_role, "tasks/main.yml", "- name: noop\n  ansible.builtin.debug: {msg: hi}\n")
    write(
        template_role,
        "molecule/default/converge.yml",
        """\
- name: Converge — render + assert template
  hosts: localhost
  tasks:
    - ansible.builtin.template:
        src: "{{ playbook_dir }}/../../files/config/x.yml.j2"
        dest: /tmp/x.yml
""",
    )

    rc, out = run([str(mirror_role)])
    ok1 = "[MOLMIRROR-01]" in out
    print(
        f"  {'PASS' if ok1 else 'FAIL'}  MOLMIRROR-01 catch  mirror_role (stub + filter chain, no role call)"
    )
    if not ok1:
        failures.append(f"MOLMIRROR-01 did not fire on mirror_role:\n{out}")

    rc, out = run([str(template_role)])
    ok2 = "[MOLMIRROR-01]" not in out
    print(
        f"  {'PASS' if ok2 else 'FAIL'}  MOLMIRROR-01 clean  template_role (renders template directly — house pattern)"
    )
    if not ok2:
        failures.append(
            f"MOLMIRROR-01 false-fired on template_role (legitimate house pattern):\n{out}"
        )

    return failures


def test_molecule_default_mirror(tmpdir: Path) -> list[str]:
    """MOLMIRROR-02: a molecule scenario that hand-copies the role's `__default` resolution instead
    of including the role's own resolver — the shape that breaks when a variable is added to the
    role and the stale copy fails with "'<var>' is undefined", blaming the ROLE for the TEST's
    staleness."""
    failures = []

    # CATCH: hand-copies several __default resolutions, never includes the resolver.
    mirror = tmpdir / "roles" / "mirror_defaults"
    write(mirror, "tasks/main.yml", "- name: noop\n  ansible.builtin.debug: {msg: hi}\n")
    write(
        mirror,
        "tasks/setup_vars.yml",
        '- set_fact:\n    foo_image: "{{ foo_image | default(foo_image__default) }}"\n',
    )
    write(
        mirror,
        "molecule/default/converge.yml",
        """\
- name: Converge
  hosts: localhost
  tasks:
    - ansible.builtin.set_fact:
        foo_image: "{{ foo_image__default }}"
        foo_port: "{{ foo_port__default }}"
        foo_network: "{{ foo_network__default }}"
    - ansible.builtin.template:
        src: "{{ playbook_dir }}/../../templates/x.j2"
        dest: /tmp/x
""",
    )

    # EXEMPT 1: includes the role's own resolver — the correct pattern.
    good = tmpdir / "roles" / "good_defaults"
    write(good, "tasks/main.yml", "- name: noop\n  ansible.builtin.debug: {msg: hi}\n")
    write(
        good,
        "tasks/setup_vars.yml",
        '- set_fact:\n    foo_image: "{{ foo_image | default(foo_image__default) }}"\n',
    )
    write(
        good,
        "molecule/default/converge.yml",
        """\
- name: Converge
  hosts: localhost
  tasks:
    - ansible.builtin.include_tasks: "{{ playbook_dir }}/../../tasks/setup_vars.yml"
    - ansible.builtin.set_fact:
        foo_render_dir: /tmp/render
""",
    )

    # EXEMPT 2: below the threshold — pinning a single value by hand is legitimate.
    one = tmpdir / "roles" / "one_default"
    write(one, "tasks/main.yml", "- name: noop\n  ansible.builtin.debug: {msg: hi}\n")
    write(
        one,
        "tasks/setup_vars.yml",
        '- set_fact:\n    foo_image: "{{ foo_image | default(foo_image__default) }}"\n',
    )
    write(
        one,
        "molecule/default/converge.yml",
        """\
- name: Converge
  hosts: localhost
  tasks:
    - ansible.builtin.set_fact:
        foo_image: "{{ foo_image__default }}"
""",
    )

    # EXEMPT 3: the role ships no resolver at all, so there is nothing to include.
    noresolver = tmpdir / "roles" / "no_resolver"
    write(noresolver, "tasks/main.yml", "- name: noop\n  ansible.builtin.debug: {msg: hi}\n")
    write(
        noresolver,
        "molecule/default/converge.yml",
        """\
- name: Converge
  hosts: localhost
  tasks:
    - ansible.builtin.set_fact:
        foo_image: "{{ foo_image__default }}"
        foo_port: "{{ foo_port__default }}"
""",
    )

    for role, want, label in [
        (mirror, True, "mirror_defaults (3 hand-copied, no resolver include)"),
        (good, False, "good_defaults (includes the role's setup_vars.yml)"),
        (one, False, "one_default (single pinned value, below threshold)"),
        (noresolver, False, "no_resolver (role ships no resolver to include)"),
    ]:
        rc, out = run([str(role)])
        fired = "[MOLMIRROR-02]" in out
        ok = fired is want
        verb = "catch" if want else "exempt"
        print(f"  {'PASS' if ok else 'FAIL'}  MOLMIRROR-02 {verb}  {label}")
        if not ok:
            failures.append(
                f"MOLMIRROR-02 {'did not fire' if want else 'false-positived'} on {label}:\n{out}"
            )

    return failures


def test_molecule_collections_path(tmpdir: Path) -> list[str]:
    """MOLCOLL-01: a scenario using a community.* plugin without ANSIBLE_COLLECTIONS_PATH. This is
    the one failure mode with NO local signal — a dev venv bundles community.general inside
    site-packages, so it resolves locally however the paths are set, and only CI fails."""
    failures = []

    bad = tmpdir / "roles" / "coll_bad"
    write(bad, "tasks/main.yml", "- name: noop\n  ansible.builtin.debug: {msg: hi}\n")
    write(bad, "molecule/default/molecule.yml", "provisioner:\n  name: ansible\n")
    write(
        bad,
        "molecule/default/converge.yml",
        """\
- name: Converge
  hosts: localhost
  tasks:
    - ansible.builtin.set_fact:
        x: "{{ ['a'] | map('community.general.dict_kv', 'k') | list }}"
""",
    )

    good = tmpdir / "roles" / "coll_good"
    write(good, "tasks/main.yml", "- name: noop\n  ansible.builtin.debug: {msg: hi}\n")
    write(
        good,
        "molecule/default/molecule.yml",
        "provisioner:\n  name: ansible\n  env:\n"
        '    ANSIBLE_COLLECTIONS_PATH: "${MOLECULE_PROJECT_DIRECTORY}/../../collections.galaxy"\n',
    )
    write(
        good,
        "molecule/default/converge.yml",
        """\
- name: Converge
  hosts: localhost
  tasks:
    - ansible.builtin.set_fact:
        x: "{{ ['a'] | map('community.general.dict_kv', 'k') | list }}"
""",
    )

    builtin_only = tmpdir / "roles" / "coll_builtin"
    write(builtin_only, "tasks/main.yml", "- name: noop\n  ansible.builtin.debug: {msg: hi}\n")
    write(builtin_only, "molecule/default/molecule.yml", "provisioner:\n  name: ansible\n")
    write(
        builtin_only,
        "molecule/default/converge.yml",
        """\
- name: Converge
  hosts: localhost
  tasks:
    - ansible.builtin.set_fact:
        x: "{{ ['a'] | map('upper') | list }}"
""",
    )

    # A path that OMITS collections.galaxy is worse than none — it looks deliberate and resolves
    # nothing vendored, so CI fails on the first collection module the role uses.
    partial = tmpdir / "roles" / "coll_partial"
    write(
        partial,
        "tasks/main.yml",
        "- name: s\n  ansible.posix.sysctl: {name: net.ipv4.ip_forward, value: '1'}\n",
    )
    write(
        partial,
        "molecule/default/molecule.yml",
        "provisioner:\n  name: ansible\n  env:\n"
        '    ANSIBLE_COLLECTIONS_PATH: "${MOLECULE_PROJECT_DIRECTORY}/../../collections"\n',
    )
    write(
        partial,
        "molecule/default/converge.yml",
        """\
- name: Converge
  hosts: localhost
  tasks:
    - ansible.builtin.include_role:
        name: coll_partial
""",
    )

    # The role uses a collection module, but the scenario only RENDERS TEMPLATES — it never runs
    # those tasks, so the collection is irrelevant to it. Scanning role tasks unconditionally
    # flagged 15 such roles; that noise would have buried the two real findings.
    render_only = tmpdir / "roles" / "coll_render_only"
    write(
        render_only, "tasks/main.yml", "- name: s\n  ansible.posix.sysctl: {name: x, value: '1'}\n"
    )
    write(render_only, "molecule/default/molecule.yml", "provisioner:\n  name: ansible\n")
    write(
        render_only,
        "molecule/default/converge.yml",
        """\
- name: Converge
  hosts: localhost
  tasks:
    - ansible.builtin.template:
        src: "{{ playbook_dir }}/../../templates/x.j2"
        dest: /tmp/x
""",
    )

    for role, want, label in [
        (bad, True, "coll_bad (community.* plugin, no ANSIBLE_COLLECTIONS_PATH)"),
        (good, False, "coll_good (path declared)"),
        (builtin_only, False, "coll_builtin (builtin filters only)"),
        (partial, True, "coll_partial (path omits collections.galaxy)"),
        (render_only, False, "coll_render_only (role uses a collection; scenario only renders)"),
    ]:
        rc, out = run([str(role)])
        fired = "[MOLCOLL-01]" in out
        ok = fired is want
        verb = "catch" if want else "exempt"
        print(f"  {'PASS' if ok else 'FAIL'}  MOLCOLL-01 {verb}  {label}")
        if not ok:
            failures.append(
                f"MOLCOLL-01 {'did not fire' if want else 'false-positived'} on {label}:\n{out}"
            )

    return failures


def test_no_duplicate_findings_on_a_play(tmpdir: Path) -> list[str]:
    """Regression test: a play's own top-level '- name:' entry (carrying hosts:/tasks:) must not
    be treated as a task block — otherwise every rule that walks task blocks double-counts every
    task inside the play."""
    failures = []
    path = write(
        tmpdir,
        "play_dup_check.yml",
        """\
- name: A whole play
  hosts: localhost
  gather_facts: false
  tasks:
    - name: HTTP health probe
      ansible.builtin.uri:
        url: "http://example/"
      register: _http
      retries: 6
      delay: 5
      until: _http is success
      failed_when: false   # required for UNTIL-01 to apply: without it the loop fails loudly
""",
    )
    rc, out = run([str(path)])
    count = out.count("[UNTIL-01]")
    ok = count == 1
    print(f"  {'PASS' if ok else 'FAIL'}  no duplicate UNTIL-01 finding on a play (got {count})")
    if not ok:
        failures.append(f"expected exactly 1 UNTIL-01 finding, got {count}:\n{out}")

    # The same defect one level down: a retry loop nested inside a `block:` is contained by BOTH
    # the outer block task and its own task, so it would be reported once per enclosing level —
    # the same lines counted twice, which inflates the backlog and makes a half-fixed file look
    # untouched.
    nested = write(
        tmpdir,
        "block_dup_check.yml",
        """\
- name: Outer block task
  when: some_flag | bool
  block:
    - name: Ask the service which components it loaded
      ansible.builtin.uri:
        url: "http://127.0.0.1:12345/api/v0/web/components"
      register: _components
      until: (_components.json | default([]) | length) > 0
      retries: 12
      delay: 5
      failed_when: false
""",
    )
    rc, out = run([str(nested)])
    count = out.count("[UNTIL-01]")
    ok = count == 1
    print(f"  {'PASS' if ok else 'FAIL'}  no duplicate UNTIL-01 inside a block: (got {count})")
    if not ok:
        failures.append(f"expected exactly 1 UNTIL-01 finding inside a block, got {count}:\n{out}")
    return failures


def test_cli_basics() -> list[str]:
    failures = []

    rc, out = run([], ["--list-rules"])
    ok = rc == 0 and "META-01" in out and "MOLMIRROR-01" in out
    print(f"  {'PASS' if ok else 'FAIL'}  --list-rules exits 0 and lists known rules")
    if not ok:
        failures.append(f"--list-rules broken:\n{out}")

    rc, out = run(["/nonexistent/path/should/not/crash.yml"])
    ok = rc == 0
    print(f"  {'PASS' if ok else 'FAIL'}  nonexistent path does not crash the harness")
    if not ok:
        failures.append(f"nonexistent path crashed or exited nonzero: rc={rc}\n{out}")

    return failures


def test_resolver_reentry(tmpdir: Path) -> list[str]:
    """RESOLVE-01: a generated defaults resolver that binds `x | default(x__default)` with no
    re-entry guard. set_fact persists for the whole play, so a role included twice in one play
    reads its OWN leftover fact on the second call and a caller omitting the option silently
    inherits the earlier value."""
    failures = []

    unguarded = tmpdir / "unguarded" / "tasks"
    unguarded.mkdir(parents=True)
    (unguarded / "_resolve_defaults.yml").write_text(
        "---\n"
        "- name: Resolve declared options over their generated defaults\n"
        "  ansible.builtin.set_fact:\n"
        '    baseline_apply: "{{ baseline_apply | default(baseline_apply__default) }}"\n'
    )

    guarded = tmpdir / "guarded" / "tasks"
    guarded.mkdir(parents=True)
    (guarded / "_resolve_defaults.yml").write_text(
        "---\n"
        "- name: Resolve declared options over their generated defaults\n"
        "  ansible.builtin.set_fact:\n"
        '    baseline_apply: "{{ baseline_apply | default(baseline_apply__default) }}"\n'
        "  when: not (_example_role__argspec_resolved | default(false))\n"
        "\n"
        "- name: Rebind the defaults on a repeat call\n"
        "  ansible.builtin.set_fact:\n"
        '    baseline_apply: "{{ baseline_apply__default }}"\n'
        "  when: _example_role__argspec_resolved | default(false)\n"
        "\n"
        "- name: Record that this role has resolved its options in this play\n"
        "  ansible.builtin.set_fact:\n"
        "    _example_role__argspec_resolved: true\n"
    )

    # An ordinary task file with the same binding shape must NOT fire — the rule is scoped to
    # generated resolvers, where the two-branch fix is what applies.
    ordinary = tmpdir / "ordinary"
    ordinary.mkdir(parents=True)
    (ordinary / "setup_vars.yml").write_text(
        "---\n"
        "- name: Set up\n"
        "  ansible.builtin.set_fact:\n"
        '    baseline_apply: "{{ baseline_apply | default(baseline_apply__default) }}"\n'
    )

    for target, want, label in [
        (unguarded / "_resolve_defaults.yml", True, "unguarded resolver"),
        (guarded / "_resolve_defaults.yml", False, "guarded resolver (two branches)"),
        (ordinary / "setup_vars.yml", False, "non-resolver task file"),
    ]:
        rc, out = run([str(target)])
        fired = "[RESOLVE-01]" in out
        ok = fired is want
        verb = "catch" if want else "exempt"
        print(f"  {'PASS' if ok else 'FAIL'}  RESOLVE-01 {verb}  {label}")
        if not ok:
            failures.append(
                f"RESOLVE-01 {'did not fire' if want else 'false-positived'} on {label}:\n{out}"
            )

    return failures


def test_yaml_escape_in_jinja(tmpdir: Path) -> list[str]:
    """YAMLESC-01: a \\n / \\t escape inside a Jinja expression in a NON-double-quoted YAML scalar.

    Only YAML's double-quoted style processes backslash escapes, so in a folded (>-), literal (|)
    or single-quoted scalar the backslash survives and Ansible's templar receives two characters
    instead of a newline. With ansible-core 2.21.4, `s.split('\\n') | length` returns 1 in a >-
    scalar and 3 in a "..." scalar, for the same s.

    The three exempt fixtures are the ones that make this rule safe to ship as FAIL:
      - the double-quoted form is the CORRECT fix and must never fire;
      - a regex escape (\\S, \\d) in a folded scalar is the deliberate house pattern — the
        backslash is MEANT to reach the regex engine;
      - a shell command in a block scalar (printf '...\\n', tr '\\n' ',') needs its own
        backslashes intact. That last class produced 41 false positives on the first repo-wide run
        and is why the rule only inspects text inside {{ }} / {% %}.
    """
    failures = []

    cases = [
        (
            "folded_newline.yml",
            "---\n- hosts: localhost\n  tasks:\n    - ansible.builtin.set_fact:\n"
            "        n: >-\n          {{ s.split('\\n') | length }}\n",
            True,
            "folded >- with \\n (the reported bug)",
        ),
        (
            "literal_tab.yml",
            "---\n- hosts: localhost\n  tasks:\n    - ansible.builtin.set_fact:\n"
            "        t: |\n          {{ s.split('\\t') | first }}\n",
            True,
            "literal | with \\t",
        ),
        (
            "folded_join.yml",
            "---\n- hosts: localhost\n  tasks:\n    - ansible.builtin.set_fact:\n"
            "        j: >-\n          {{ items | join('\\n') }}\n",
            True,
            "folded >- with join('\\n') (the common case)",
        ),
        (
            "double_quoted.yml",
            "---\n- hosts: localhost\n  tasks:\n    - ansible.builtin.set_fact:\n"
            "        n: \"{{ s.split('\\n') | length }}\"\n",
            False,
            'double-quoted "..." (the correct fix)',
        ),
        (
            "folded_regex.yml",
            "---\n- hosts: localhost\n  tasks:\n    - ansible.builtin.set_fact:\n"
            "        r: >-\n          {{ s | regex_replace('^(\\S+).*$', '\\1') }}\n",
            False,
            "folded >- with a REGEX escape (house pattern)",
        ),
        (
            "folded_shell.yml",
            "---\n- hosts: localhost\n  tasks:\n    - ansible.builtin.shell:\n"
            "        cmd: >-\n          L=$(dig {{ item }} +short | tr '\\n' ',');\n"
            "          printf 'done=%s\\n' \"$L\"\n",
            False,
            "shell escapes in a folded scalar (must stay intact)",
        ),
    ]

    for name, content, want, label in cases:
        target = write(tmpdir / "yamlesc", name, content)
        rc, out = run([str(target)])
        fired = "[YAMLESC-01]" in out
        ok = fired is want
        verb = "catch" if want else "exempt"
        print(f"  {'PASS' if ok else 'FAIL'}  YAMLESC-01 {verb}  {label}")
        if not ok:
            failures.append(
                f"YAMLESC-01 {'did not fire' if want else 'false-positived'} on {label}:\n{out}"
            )

    return failures


def test_new_trap_rules(tmpdir: Path) -> list[str]:
    """PIPEQ-01 / IPSUB-01 / IPADDRTEST-01 / DIGRC-01 — traps that were once left to vigilance.

    The near-miss fixtures matter more than the catch fixtures here, because each rule's obvious
    first form false-positives and the exemption is what makes it shippable:
      - PIPEQ-01 on `grep -qa pattern /proc/1/environ` — a grep reading a FILE has no upstream
        writer and cannot take SIGPIPE, so only a grep that reads a single `|` is a finding.
      - IPSUB-01 on a COMMENT warning against this very trap, i.e. flagging the documentation of
        the bug it hunts.
    """
    failures = []

    cases = [
        # ---- PIPEQ-01 ----
        (
            "pipeq_bad.yml",
            "---\n- hosts: localhost\n  tasks:\n    - ansible.builtin.shell:\n        cmd: |\n"
            "          set -o pipefail\n"
            "          if systemctl list-units | grep -q foo; then echo y; fi\n",
            "PIPEQ-01",
            True,
            "| grep -q under pipefail",
        ),
        (
            "pipeq_count.yml",
            "---\n- hosts: localhost\n  tasks:\n    - ansible.builtin.shell:\n        cmd: |\n"
            "          set -o pipefail\n"
            "          _u=$(systemctl list-units)\n"
            '          if [ "$(printf \'%s\' "$_u" | grep -c foo)" -gt 0 ]; then echo y; fi\n',
            "PIPEQ-01",
            False,
            "captured then grep -c (the fix)",
        ),
        (
            "pipeq_file.yml",
            "---\n- hosts: localhost\n  tasks:\n    - ansible.builtin.shell:\n        cmd: |\n"
            "          set -o pipefail\n"
            "          if [ -f /run/x ] || grep -qa container=lxc /proc/1/environ; then echo y; fi\n",
            "PIPEQ-01",
            False,
            "grep -q reading a FILE (no writer to SIGPIPE)",
        ),
        (
            "pipeq_nopipefail.yml",
            "---\n- hosts: localhost\n  tasks:\n    - ansible.builtin.shell:\n        cmd: |\n"
            "          if systemctl list-units | grep -q foo; then echo y; fi\n",
            "PIPEQ-01",
            False,
            "no pipefail in the file",
        ),
        # ---- IPSUB-01 ----
        (
            "ipsub_bad.yml",
            "---\n- hosts: localhost\n  tasks:\n    - ansible.builtin.assert:\n        that:\n"
            "          - \"'192.0.2.2' in _r.stdout\"\n",
            "IPSUB-01",
            True,
            "substring test against an IP literal",
        ),
        (
            "ipsub_exact.yml",
            "---\n- hosts: localhost\n  tasks:\n    - ansible.builtin.assert:\n        that:\n"
            "          - \"(_r.stdout | regex_findall('x')) is contains('192.0.2.2')\"\n",
            "IPSUB-01",
            False,
            "exact membership over extracted addresses (the fix)",
        ),
        (
            "ipsub_lines.yml",
            "---\n- hosts: localhost\n  tasks:\n    - ansible.builtin.assert:\n        that:\n"
            "          - \"'192.0.2.2' in _r.stdout_lines\"\n",
            "IPSUB-01",
            False,
            "in against *_lines IS exact membership",
        ),
        (
            "ipsub_comment.yml",
            "---\n- hosts: localhost\n  tasks:\n"
            "    # '192.0.2.2' in stdout would also match 192.0.2.255 (the IPSUB-01 trap).\n"
            "    - ansible.builtin.debug: {msg: ok}\n",
            "IPSUB-01",
            False,
            "a COMMENT warning about the trap is not the trap",
        ),
        # ---- IPADDRTEST-01 ----
        (
            "ipaddr_bad.yml",
            "---\n- hosts: localhost\n  tasks:\n    - ansible.builtin.set_fact:\n"
            "        v: \"{{ h | selectattr('addr', 'ipaddr') | list }}\"\n",
            "IPADDRTEST-01",
            True,
            "ipaddr as a test inside selectattr",
        ),
        (
            "ipaddr_ok.yml",
            "---\n- hosts: localhost\n  tasks:\n    - ansible.builtin.set_fact:\n"
            "        v: \"{{ h | map('ansible.utils.ipaddr') | select | list }}\"\n",
            "IPADDRTEST-01",
            False,
            "ipaddr used as a FILTER (correct)",
        ),
        # ---- DIGRC-01 ----
        (
            "dig_bad.yml",
            "---\n- hosts: localhost\n  tasks:\n"
            "    - ansible.builtin.command: dig @192.0.2.1 example.com +short\n"
            "      register: _d\n"
            "    - ansible.builtin.assert:\n        that:\n"
            "          - _d.stdout | trim | length > 0\n",
            "DIGRC-01",
            True,
            "dig judged by stdout emptiness only",
        ),
        (
            "dig_ok.yml",
            "---\n- hosts: localhost\n  tasks:\n"
            "    - ansible.builtin.command: dig @192.0.2.1 example.com +short\n"
            "      register: _d\n"
            "    - ansible.builtin.assert:\n        that:\n"
            "          - _d.rc == 0\n"
            "          - _d.stdout_lines | reject('match', '^;;') | list | length > 0\n",
            "DIGRC-01",
            False,
            "rc checked AND ^;; rejected (the fix)",
        ),
    ]

    for name, content, rule, want, label in cases:
        target = write(tmpdir / "newtraps", name, content)
        rc, out = run([str(target)])
        fired = f"[{rule}]" in out
        ok = fired is want
        verb = "catch " if want else "exempt"
        print(f"  {'PASS' if ok else 'FAIL'}  {rule} {verb} {label}")
        if not ok:
            failures.append(
                f"{rule} {'did not fire' if want else 'false-positived'} on {label}:\n{out}"
            )

    return failures


def test_pgrep_multiple_patterns(tmpdir: Path) -> list[str]:
    """PGREPMULTI-01: pgrep/pkill given more than one pattern.

    procps accepts exactly ONE pattern. Given two it exits 2 with "only one pattern can be
    provided" on STDERR and prints no PIDs — so with the near-universal `2>/dev/null` the command
    returns EMPTY, which reads as "the process is not running" rather than "I asked wrongly".
    On a Linux target, `pgrep -x compositor-wl compositor` -> rc=2, no output, against a RUNNING
    compositor.

    IT CANNOT BE REPRODUCED ON THE CONTROLLER. macOS pgrep ACCEPTS multiple patterns and returns
    matches for both, so a developer testing the command locally sees it work. That asymmetry is
    the whole reason this is a static rule rather than something a run would reveal.

    The near-miss fixtures are what make it safe to ship as FAIL, and each one is a shape the
    obvious regex gets wrong:
      - `pgrep -x name` / `pgrep -xc name`: the greedy-optional flag group let the matcher skip
        the flags and read '-xc' as a pattern — 2 false positives on the fixtures themselves;
      - `pgrep -x name 2>/dev/null`: the redirect's fd number read as a second pattern, a false
        positive on correct code;
      - `pgrep -u user name` / `pgrep -P 1 name`: flags that take a VALUE, where the word after
        the flag is that value and not a pattern.
    """
    failures = []

    cases = [
        # (filename, content, must_fire)
        (
            "two_patterns.yml",
            "---\n- hosts: localhost\n  tasks:\n"
            "    - ansible.builtin.shell: pgrep -x compositor-wl compositor 2>/dev/null\n",
            True,
        ),
        (
            "two_patterns_pkill.yml",
            "---\n- hosts: localhost\n  tasks:\n" "    - ansible.builtin.shell: pkill -x foo bar\n",
            True,
        ),
        (
            "single_pattern.yml",
            "---\n- hosts: localhost\n  tasks:\n"
            "    - ansible.builtin.shell: pgrep -x compositor-wl\n",
            False,
        ),
        (
            "single_with_redirect.yml",
            "---\n- hosts: localhost\n  tasks:\n"
            "    - ansible.builtin.shell: pgrep -x demo-daemon 2>/dev/null\n",
            False,
        ),
        (
            "count_flag.yml",
            "---\n- hosts: localhost\n  tasks:\n"
            "    - ansible.builtin.shell: pgrep -xc demo-daemon\n",
            False,
        ),
        (
            "value_flag_user.yml",
            "---\n- hosts: localhost\n  tasks:\n"
            "    - ansible.builtin.shell: pgrep -u appuser demo-daemon\n",
            False,
        ),
        (
            "value_flag_parent.yml",
            "---\n- hosts: localhost\n  tasks:\n"
            "    - ansible.builtin.shell: pgrep -P 1 systemd\n",
            False,
        ),
        (
            "dash_f_quoted.yml",
            "---\n- hosts: localhost\n  tasks:\n"
            "    - ansible.builtin.shell: pgrep -f '/usr/bin/compositor ' >/dev/null\n",
            False,
        ),
    ]

    for name, content, must_fire in cases:
        path = write(tmpdir, name, content)
        _, out = run([str(path)])
        fired = "PGREPMULTI-01" in out
        if must_fire and not fired:
            failures.append(f"{name}: PGREPMULTI-01 should have fired")
        if not must_fire and fired:
            failures.append(f"{name}: PGREPMULTI-01 FALSE POSITIVE on correct code")

    return failures


def test_inspect_registers_env(tmpdir: Path) -> list[str]:
    """INSPECTENV-01: a container's full inspect document logged without no_log.

    The inspect document carries Config.Env, every environment VALUE the container runs with, and
    a run-log callback writes each task result verbatim — so a docker_container_info read-back
    that needs only image, id and health logs the service's API key with them.

    The near-misses are the shapes that read the SAME container safely: a narrow --format, an
    inspect piped into a filter, `docker image inspect` (build-time env, not a runtime secret),
    no_log on the task or inherited from its block, and docker_container with state: absent (which
    returns no document).
    """
    failures = []
    head = "---\n- hosts: appsvc\n  tasks:\n"
    cases = [
        # (filename, content, must_fire)
        (
            "info_no_nolog.yml",
            head + "    - name: Read the running container (image ref, image id, health)\n"
            "      community.docker.docker_container_info:\n"
            "        name: appsvc\n"
            "      register: _rb_ci\n",
            True,
        ),
        (
            "info_short_name.yml",
            head + "    - docker_container_info:\n        name: appsvc\n      register: _ci\n",
            True,
        ),
        (
            "info_in_block_no_nolog.yml",
            head + "    - block:\n"
            "        - name: Wait for the container healthcheck\n"
            "          community.docker.docker_container_info:\n"
            "            name: appsvc\n"
            "          register: _h\n"
            "          until: _h.container.State.Health.Status == 'healthy'\n",
            True,
        ),
        (
            "command_inspect_bare.yml",
            head + "    - name: Inspect the container\n"
            "      ansible.builtin.command: docker inspect appsvc\n"
            "      register: _raw\n",
            True,
        ),
        (
            "argv_inspect_bare.yml",
            head + "    - name: Inspect the container\n"
            "      ansible.builtin.command:\n"
            "        argv: [docker, container, inspect, appsvc]\n"
            "      register: _raw\n",
            True,
        ),
        (
            "container_started.yml",
            head + "    - community.docker.docker_container:\n"
            "        name: appsvc\n        state: started\n        restart: true\n",
            True,
        ),
        (
            "nolog_false_explicit.yml",
            head + "    - community.docker.docker_container_info:\n"
            "        name: appsvc\n      register: _ci\n      no_log: false\n",
            True,
        ),
        # ---- near-misses: must NOT fire ----
        (
            "info_with_nolog.yml",
            head + "    - name: Read the running container\n"
            "      community.docker.docker_container_info:\n"
            "        name: appsvc\n"
            "      register: _rb_ci\n"
            "      no_log: true\n",
            False,
        ),
        (
            "info_nolog_from_block.yml",
            head + "    - no_log: true\n      block:\n"
            "        - community.docker.docker_container_info:\n"
            "            name: appsvc\n"
            "          register: _h\n",
            False,
        ),
        (
            "inspect_narrow_format.yml",
            head + "    - name: Read the start time\n"
            "      ansible.builtin.command:\n"
            "        argv: [docker, inspect, --format, \"{{ '{{' }}.State.StartedAt{{ '}}' }}\", appsvc]\n"
            "      register: _st\n",
            False,
        ),
        (
            "inspect_dash_f.yml",
            head + "    - ansible.builtin.shell: >-\n"
            "        docker inspect -f '{% raw %}{{.State.Health.Status}}{% endraw %}' appsvc\n"
            "      register: _st\n",
            False,
        ),
        (
            "inspect_format_on_continuation.yml",
            head + "    - ansible.builtin.shell: |\n"
            "        img=$(pct exec 9999 -- docker inspect appsvc \\\n"
            "          --format '{% raw %}{{.Image}}{% endraw %}')\n"
            "      register: _img\n",
            False,
        ),
        (
            "inspect_piped_filter.yml",
            head
            + '    - ansible.builtin.shell: docker inspect $ids | grep -oE \'"Source": "[^"]*"\'\n'
            "      register: _m\n",
            False,
        ),
        (
            "image_inspect.yml",
            head + "    - ansible.builtin.command:\n"
            "        argv: [docker, image, inspect, example/agent-image]\n"
            "      register: _ii\n",
            False,
        ),
        (
            "container_absent.yml",
            head + "    - community.docker.docker_container:\n"
            "        name: appsvc-probe\n        state: absent\n",
            False,
        ),
        (
            "module_arg_named_block.yml",
            head + "    - name: A module argument that merely mentions inspect\n"
            "      ansible.builtin.debug:\n"
            "        msg: run docker inspect by hand to see the Env\n",
            False,
        ),
    ]

    for name, content, must_fire in cases:
        path = write(tmpdir, name, content)
        _, out = run([str(path)])
        fired = "INSPECTENV-01" in out
        if must_fire and not fired:
            failures.append(f"{name}: INSPECTENV-01 should have fired")
        if not must_fire and fired:
            failures.append(f"{name}: INSPECTENV-01 FALSE POSITIVE on correct code")

    return failures


def main() -> int:
    failures: list[str] = []
    with tempfile.TemporaryDirectory(prefix="check_silent_guards_test_") as td:
        tmpdir = Path(td)
        failures += test_file_cases(tmpdir)
        failures += test_suppress_valid_does_not_ALSO_suppress_bare(tmpdir)
        failures += test_handler_only_fact(tmpdir)
        failures += test_molecule_mirror(tmpdir)
        failures += test_molecule_default_mirror(tmpdir)
        failures += test_molecule_collections_path(tmpdir)
        failures += test_no_duplicate_findings_on_a_play(tmpdir)
        failures += test_resolver_reentry(tmpdir)
        failures += test_yaml_escape_in_jinja(tmpdir)
        failures += test_new_trap_rules(tmpdir)
        failures += test_pgrep_multiple_patterns(tmpdir)
        failures += test_inspect_registers_env(tmpdir)
    failures += test_cli_basics()

    total_cases = (
        len(FILE_CASES) + 2 + 2 + 2 + 1 + 2 + 4 + 5 + 3 + 6 + 12 + 8 + 16
    )  # file cases + each helper's sub-checks (dup-check adds 2, MOLMIRROR-02 adds 4, MOLCOLL-01 adds 5, RESOLVE-01 adds 3, YAMLESC-01 adds 6, new trap rules add 12, PGREPMULTI-01 adds 8, INSPECTENV-01 adds 16)
    print(f"\n{total_cases - len(failures)}/{total_cases} passed")
    for f in failures:
        print(f"  FAILED: {f}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
