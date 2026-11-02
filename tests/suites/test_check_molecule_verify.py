#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for check_molecule_verify.py.

BOTH DIRECTIONS: a fixture that must FAIL and a
near-miss that must PASS. Every FAIL fixture here is a shape that makes `molecule test` exit
0 over a verify.yml whose last task is `assert: {that: [false]}` (see the checker's docstring).

The near-misses are the shapes real repos use: the scaffold with no test_sequence, an
explicit sequence that includes verify, `hosts: all`, and an add_host alias.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from _paths import CHECKS, ROOT  # noqa: F401 — tests/suites/_paths.py
import _paths

_paths.use_fixture_config()

sys.path.insert(0, str(CHECKS))

from check_molecule_verify import RULES_TABLE, main, scan  # noqa: E402

GOOD_MOLECULE = """\
driver: { name: default }
platforms: [{ name: localhost }]
provisioner:
  name: ansible
  playbooks: { converge: converge.yml, verify: verify.yml }
verifier: { name: ansible }
"""

GOOD_VERIFY = """\
- name: Verify
  hosts: localhost
  gather_facts: false
  tasks:
    - name: Probe
      ansible.builtin.assert: {that: [true]}
"""

# A stand-in for ci/affected-scenarios.sh: the checker asks it for its full-run selection.
SELECTOR = """#!/usr/bin/env bash
[ "$CHANGED_FILES" = Makefile ] || exit 1
echo '{"all": true, "roles": [], "playbook_scenarios": %s}'
"""


def _scan(
    molecule: str = GOOD_MOLECULE,
    verify: str | None = GOOD_VERIFY,
    *,
    where: str = "roles/r/molecule/default",
    selected: list[str] | None = None,
    extra: dict[str, str] | None = None,
) -> list[str]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        scen = root / where
        scen.mkdir(parents=True)
        (scen / "molecule.yml").write_text(molecule, encoding="utf-8")
        (scen / "converge.yml").write_text(GOOD_VERIFY, encoding="utf-8")
        if verify is not None:
            (scen / "verify.yml").write_text(verify, encoding="utf-8")
        for name, body in (extra or {}).items():
            (scen / name).write_text(body, encoding="utf-8")
        (root / "ci").mkdir()
        listed = [where] if selected is None else selected
        sel = SELECTOR % str(listed).replace("'", '"')
        (root / "ci" / "affected-scenarios.sh").write_text(sel, encoding="utf-8")
        return scan(root)


def _rules(findings: list[str]) -> set[str]:
    return {f.split("[", 1)[1].split("]", 1)[0] for f in findings}


# ---------------------------------------------------------------- must FAIL


def test_sequence_without_verify() -> None:
    m = GOOD_MOLECULE + "scenario:\n  test_sequence: [syntax, converge, idempotence]\n"
    assert _rules(_scan(m)) == {"MOLVERIFY-01"}


def test_verifier_disabled() -> None:
    m = GOOD_MOLECULE.replace(
        "verifier: { name: ansible }", "verifier: {name: ansible, enabled: false}"
    )
    assert _rules(_scan(m)) == {"MOLVERIFY-02"}


def test_verifier_not_ansible() -> None:
    m = GOOD_MOLECULE.replace("verifier: { name: ansible }", "verifier: { name: testinfra }")
    assert _rules(_scan(m)) == {"MOLVERIFY-02"}


def test_verify_playbook_typo() -> None:
    """`verify: verfy.yml` -> molecule says 'Missing playbook' and exits 0."""
    m = GOOD_MOLECULE.replace("verify: verify.yml", "verify: verfy.yml")
    assert _rules(_scan(m)) == {"MOLVERIFY-03"}


def test_verify_playbook_points_elsewhere() -> None:
    m = GOOD_MOLECULE.replace("verify: verify.yml", "verify: other.yml")
    assert _rules(_scan(m, extra={"other.yml": GOOD_VERIFY})) == {"MOLVERIFY-03"}


def test_configured_verify_missing_with_no_verify_yml() -> None:
    """No verify.yml on disk, but molecule.yml says there is one: still a silent skip."""
    assert _rules(_scan(verify=None)) == {"MOLVERIFY-03"}


def test_verify_hosts_match_no_platform() -> None:
    """`hosts: instance` -> 'skipping: no hosts matched' and exit 0."""
    v = GOOD_VERIFY.replace("hosts: localhost", "hosts: instance")
    assert _rules(_scan(verify=v)) == {"MOLVERIFY-04"}


def test_add_host_in_a_LATER_play_does_not_count() -> None:
    """The alias exists only for plays AFTER the one that adds it."""
    v = (
        GOOD_VERIFY.replace("hosts: localhost", "hosts: verify-local")
        + "- name: Add\n  hosts: localhost\n  tasks:\n"
        + "    - ansible.builtin.add_host: {name: verify-local}\n"
    )
    assert _rules(_scan(verify=v)) == {"MOLVERIFY-04"}


def test_role_scenario_not_default() -> None:
    assert _rules(_scan(where="roles/r/molecule/extra")) == {"MOLVERIFY-05"}


def test_playbook_scenario_the_selector_omits() -> None:
    """The state before the selector learned about playbook scenarios: it listed none at all."""
    found = _scan(where="playbooks/helpers/molecule/thing", selected=[])
    assert _rules(found) == {"MOLVERIFY-05"}


def test_ci_exempt_without_a_reason() -> None:
    m = "# ci-exempt:\n" + GOOD_MOLECULE
    found = _scan(m, where="playbooks/helpers/molecule/thing", selected=[])
    assert _rules(found) == {"MOLVERIFY-05"}


def test_playbook_scenario_selector_lists_a_different_one() -> None:
    found = _scan(
        where="playbooks/helpers/molecule/thing",
        selected=["playbooks/helpers/molecule/other"],
    )
    assert _rules(found) == {"MOLVERIFY-05"}


def test_main_exits_nonzero_on_a_finding() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        scen = Path(tmp) / "roles/r/molecule/default"
        scen.mkdir(parents=True)
        (scen / "molecule.yml").write_text(
            GOOD_MOLECULE + "scenario: {test_sequence: [converge]}\n", encoding="utf-8"
        )
        (scen / "verify.yml").write_text(GOOD_VERIFY, encoding="utf-8")
        assert main(["x", tmp]) == 1


def test_prepare_without_destroy_before_it() -> None:
    """prepare without destroy: a passing run leaves prepared: true, the next
    run logs 'Skipping, instances already prepared.' and tests the previous run's leftovers."""
    m = (
        GOOD_MOLECULE
        + "scenario:\n  test_sequence: [syntax, prepare, converge, idempotence, verify]\n"
    )
    assert _rules(_scan(m)) == {"MOLVERIFY-06"}


def test_destroy_only_AFTER_prepare_does_not_count() -> None:
    """A trailing destroy resets the flag only when the run gets that far; a failed run does not."""
    m = GOOD_MOLECULE + "scenario:\n  test_sequence: [syntax, prepare, converge, verify, destroy]\n"
    assert _rules(_scan(m)) == {"MOLVERIFY-06"}


def test_prepare_without_destroy_is_flagged_even_with_no_verify() -> None:
    m = "platforms: [{ name: localhost }]\nprovisioner: { name: ansible }\n"
    m += "scenario: {test_sequence: [prepare, converge]}\n"
    assert _rules(_scan(m, verify=None)) == {"MOLVERIFY-06"}


# ---------------------------------------------------------------- near-misses must PASS


def test_destroy_before_prepare() -> None:
    """The fixed shape: destroy first, so prepare always starts from empty."""
    m = GOOD_MOLECULE + (
        "scenario:\n  test_sequence: [destroy, syntax, create, cleanup, prepare, converge,"
        " idempotence, verify, cleanup, destroy]\n"
    )
    assert _scan(m) == []


def test_sequence_without_prepare_needs_no_destroy() -> None:
    """Nothing to skip: only the prepare step consults the `prepared` flag."""
    m = GOOD_MOLECULE + "scenario:\n  test_sequence: [syntax, converge, idempotence, verify]\n"
    assert _scan(m) == []


def test_scaffold_default_sequence() -> None:
    assert _scan() == []


def test_explicit_sequence_with_verify() -> None:
    m = GOOD_MOLECULE + "scenario:\n  test_sequence: [syntax, converge, verify]\n"
    assert _scan(m) == []


def test_default_playbook_names_without_playbooks_key() -> None:
    """A scenario that omits `playbooks:`; molecule then looks for verify.yml by default."""
    m = "platforms: [{ name: localhost }]\nprovisioner: { name: ansible }\n"
    assert _scan(m) == []


def test_hosts_all_and_group() -> None:
    m = GOOD_MOLECULE.replace("[{ name: localhost }]", "[{ name: box, groups: [demo] }]")
    v = GOOD_VERIFY + GOOD_VERIFY.replace("hosts: localhost", "hosts: demo")
    v = v.replace("hosts: localhost", "hosts: all")
    assert _scan(m, v) == []


def test_add_host_in_an_EARLIER_play() -> None:
    """A fact-free alias added by an earlier play, then verified against."""
    v = (
        "- name: Add\n  hosts: localhost\n  tasks:\n"
        + "    - ansible.builtin.add_host: {name: verify-local, ansible_connection: local}\n"
        + GOOD_VERIFY.replace("hosts: localhost", "hosts: verify-local")
    )
    assert _scan(verify=v) == []


def test_templated_hosts_not_judged() -> None:
    v = GOOD_VERIFY.replace("hosts: localhost", 'hosts: "{{ target }}"')
    assert _scan(verify=v) == []


def test_scenario_without_any_verify_is_not_checked() -> None:
    m = "platforms: [{ name: localhost }]\nprovisioner: { name: ansible }\n"
    m += "scenario: {test_sequence: [converge]}\n"
    assert _scan(m, verify=None) == []


def test_playbook_scenario_the_selector_lists() -> None:
    assert _scan(where="playbooks/helpers/molecule/thing") == []


def test_ci_exempt_with_a_reason() -> None:
    """A macOS-only scenario (hdiutil), out of CI on purpose and saying why."""
    m = "# ci-exempt: needs macOS hdiutil\n" + GOOD_MOLECULE
    assert _scan(m, where="playbooks/helpers/molecule/thing", selected=[]) == []


def test_list_rules_names_every_rule() -> None:
    for n in range(1, 7):
        assert f"MOLVERIFY-0{n}" in RULES_TABLE


def _run() -> int:
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
        except AssertionError as exc:
            failed += 1
            print(f"FAIL {name}: {exc}")
    print(f"test_check_molecule_verify: {len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_run())
