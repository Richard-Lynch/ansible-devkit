#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for check_ha_restart_validated.py.

BOTH DIRECTIONS: a fixture that must FAIL and a near-miss that must PASS. A hook can ship with a
pattern that can never fire and
each reported a clean scan over the whole repo -- only a test proves a guard can catch anything.

The near-misses matter most here. A check that fires on a correct play gets suppressed, and a
suppressed check guards nothing.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from _paths import CHECKS, ROOT  # noqa: F401 — tests/suites/_paths.py
import _paths

_paths.use_fixture_config()

sys.path.insert(0, str(CHECKS))

from check_ha_restart_validated import check_file, main  # noqa: E402


def _check(content: str) -> list[str]:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "play.yml"
        path.write_text(content, encoding="utf-8")
        return check_file(path)


# ---------------------------------------------------------------- must FAIL


def test_restart_with_no_check_at_all() -> None:
    assert _check("""
- name: Play
  hosts: ha_core
  tasks:
    - name: Restart
      acme.home.homeassistant_supervisor:
        action: core_restart
        apply: true
"""), "a restart with no core_check must be reported"


def test_check_placed_AFTER_the_restart() -> None:
    """The ordering bug. Reads almost identically in a diff and validates nothing useful."""
    problems = _check("""
- name: Play
  hosts: ha_core
  tasks:
    - name: Restart
      acme.home.homeassistant_supervisor:
        action: core_restart
        apply: true
    - name: Validate
      acme.home.homeassistant_supervisor:
        action: core_check
        apply: true
""")
    assert problems, "a core_check AFTER the restart must not satisfy the rule"


def test_check_gated_more_tightly_than_the_restart() -> None:
    """A check the real run can skip.

    Gated on `apply`, restart not -- so the run that actually restarts skips validation. This is
    the subtle one: both tasks are present and in the right order.
    """
    problems = _check("""
- name: Play
  hosts: ha_core
  tasks:
    - name: Validate
      acme.home.homeassistant_supervisor:
        action: core_check
        apply: true
      when: _apply
    - name: Restart
      acme.home.homeassistant_supervisor:
        action: core_restart
        apply: true
""")
    assert problems, "a check gated more tightly than its restart must be reported"


def test_core_stop_counts_as_a_restart() -> None:
    """A stop plus a later start is a restart spelled differently."""
    assert _check("""
- name: Play
  hosts: ha_core
  tasks:
    - name: Stop
      acme.home.homeassistant_supervisor:
        action: core_stop
        apply: true
"""), "core_stop must be treated as a restart"


def test_bare_suppression_is_itself_a_violation() -> None:
    assert _check("""
- name: Play
  hosts: ha_core
  tasks:
    # ha-restart-check: ignore
    - name: Restart
      acme.home.homeassistant_supervisor:
        action: core_restart
        apply: true
"""), "a suppression with no reason must be reported"


def test_restart_inside_a_block_is_still_found() -> None:
    """A restart nested in a block must not escape the walk."""
    assert _check("""
- name: Play
  hosts: ha_core
  tasks:
    - name: Wrapper
      block:
        - name: Restart
          acme.home.homeassistant_supervisor:
            action: core_restart
            apply: true
"""), "a restart inside a block must still be checked"


def test_short_module_name_is_not_a_loophole() -> None:
    """A check that only knew the FQCN would silently pass this."""
    assert _check("""
- name: Play
  hosts: ha_core
  tasks:
    - name: Restart
      homeassistant_supervisor:
        action: core_restart
        apply: true
"""), "the short module name must be recognised"


# ---------------------------------------------------------------- must PASS


def test_correct_order_and_matching_gates() -> None:
    """The correct shape: validate, then restart. Must NOT be reported."""
    assert not _check("""
- name: Play
  hosts: ha_core
  tasks:
    - name: Validate
      acme.home.homeassistant_supervisor:
        action: core_check
        apply: true
      when: _apply
    - name: Restart
      acme.home.homeassistant_supervisor:
        action: core_restart
        apply: true
      when: _apply
""")


def test_restart_gated_more_tightly_than_the_check_is_fine() -> None:
    """Check on `apply`, restart on `apply` AND `restart`.

    A restart guarded by MORE conditions than the check is safe -- every run that restarts also
    validated. Reporting this would be a false positive on correct code.
    """
    assert not _check("""
- name: Play
  hosts: ha_core
  tasks:
    - name: Validate
      acme.home.homeassistant_supervisor:
        action: core_check
        apply: true
      when: _ha_cfg_apply
    - name: Restart
      acme.home.homeassistant_supervisor:
        action: core_restart
        apply: true
      when:
        - _ha_cfg_apply
        - _ha_cfg_restart
""")


def test_a_file_with_no_restart_is_not_reported() -> None:
    """A config check with no restart after it. Nothing to guard."""
    assert not _check("""
- name: Play
  hosts: ha_core
  tasks:
    - name: Validate
      acme.home.homeassistant_supervisor:
        action: core_check
        apply: true
""")


def test_suppression_with_a_reason_is_accepted() -> None:
    assert not _check("""
- name: Play
  hosts: ha_core
  tasks:
    # ha-restart-check: ignore — recovery play, the config is known bad and that is the point
    - name: Restart
      acme.home.homeassistant_supervisor:
        action: core_restart
        apply: true
""")


def test_an_unrelated_play_mentioning_restart_is_not_reported() -> None:
    """The word appears; no Supervisor action does. Must not fire."""
    assert not _check("""
- name: Play
  hosts: localhost
  tasks:
    - name: Talk about core_restart in a name
      ansible.builtin.debug:
        msg: "core_restart is how HA reloads"
""")


# ------------------------------------------------- the check's own plumbing


def test_a_directory_argument_is_expanded_not_skipped() -> None:
    """DIRECTORY ARGUMENTS MUST BE WALKED.

    `check.py roles playbooks` -- the form a task runner and CI use -- could skip directories and
    scanned ZERO files, exiting 0. A check that always passes is a silent guard in CI clothing.
    """
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "plays"
        root.mkdir()
        (root / "bad.yml").write_text(
            """
- name: Play
  hosts: ha_core
  tasks:
    - name: Restart
      acme.home.homeassistant_supervisor:
        action: core_restart
        apply: true
""",
            encoding="utf-8",
        )
        assert main(["check", str(root)]) == 1, "a directory argument must be walked"


def test_scanning_nothing_is_a_failure_not_a_pass() -> None:
    """An empty scan must never exit 0 -- it is indistinguishable from a real pass."""
    with tempfile.TemporaryDirectory() as tmp:
        assert main(["check", str(Path(tmp))]) == 1, "an empty scan must fail loudly"


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if not name.startswith("test_") or not callable(fn):
            continue
        try:
            fn()
            print(f"  PASS {name}")
        except AssertionError as exc:
            failures += 1
            print(f"  FAIL {name}: {exc}")
    print(f"\n{failures} failure(s)")
    raise SystemExit(1 if failures else 0)
