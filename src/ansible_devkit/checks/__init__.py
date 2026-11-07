# SPDX-License-Identifier: GPL-3.0-or-later
"""The static checks, and the registry `devkit check` dispatches through.

Every check is a stand-alone script in this directory, run as a SUBPROCESS with the caller's
working directory: each one resolves the repository it checks from `$DEVKIT_ROOT`, else the git
toplevel of the working directory (see `_devkit_config.py`), and reads that repository's
`devkit.toml`. Running them as scripts rather than importing them is deliberate — it is how a
pre-commit hook, a task runner and CI all invoke them, so the CLI exercises the same code path.

A check is a GATE when it belongs in `devkit check all`: it exits 0 clean, 1 on findings, 2 when it
could not run (a required devkit.toml key missing, a config error). The two non-gate entries are
telemetry (the trap-hit recorder reads a Claude Code PostToolUse payload on stdin; the report
ranks what it recorded) and are reachable by name only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent


@dataclass(frozen=True)
class Check:
    name: str
    script: str
    summary: str
    gate: bool = True
    default_args: tuple[str, ...] = field(default_factory=tuple)

    @property
    def path(self) -> Path:
        return HERE / self.script


CHECKS: tuple[Check, ...] = (
    Check(
        "inventory-strict",
        "check_inventory_strict.py",
        "inventory plugin expressions require strict evaluation (INVSTRICT-01)",
    ),
    Check(
        "silent-guards",
        "check_silent_guards.py",
        "guards, gates and conditionals in Ansible YAML that cannot fire or test the wrong thing",
    ),
    Check(
        "rootfs-seal",
        "check_rootfs_seal.py",
        "an immutable rootfs unsealed outside a block whose always: re-seals it",
    ),
    Check(
        "vendored-secrets",
        "check_vendored_secrets.py",
        "credential-shaped keys in files vendored under roles/*/files/",
    ),
    Check(
        "agent-tree-writes",
        "check_agent_tree_writes.py",
        "a root-run write by name under a tree an unprivileged agent can write (AGENTTREE-01)",
    ),
    Check(
        "ha-restart-validated",
        "check_ha_restart_validated.py",
        "a Home Assistant core restart with no core_check before it in the same file",
    ),
    Check(
        "molecule-verify",
        "check_molecule_verify.py",
        "a molecule scenario whose verify.yml can never run (MOLVERIFY-01..06)",
    ),
    Check(
        "no-tracked-ignored",
        "check_no_tracked_ignored.py",
        "a tracked path that .gitignore lists, or a tracked symlink that is absolute or self-resolving",
    ),
    Check(
        "defaults-resolved",
        "check_defaults_resolved.py",
        "a generated <name>__default that nothing in the role reads (RESOLVE-02)",
    ),
    Check(
        "regex-anchors",
        "check_regex_anchors.py",
        "Python regexes that look anchored and are not (ICASE-01)",
    ),
    Check(
        "traps-are-checked",
        "check_traps_are_checked.py",
        "every trap in the rulebook names a rule, or says why it cannot (TRAPTAG-01)",
    ),
    Check(
        "ci-covers-hook-tests",
        "check_ci_covers_hook_tests.py",
        "every test_*.py suite in the configured directories is run by some workflow",
    ),
    Check(
        "docs-drift",
        "check_docs_drift.py",
        "every rule a checker enforces is documented in the rulebook (DOCRULE-01)",
    ),
    Check(
        "dependencies",
        "check_dependencies.py",
        "dependencies pinned the standard's way: no ad-hoc installs, images and actions pinned, "
        "collection dependencies declared as ranges (DEP-02..05, baseline-FAIL)",
    ),
    Check(
        "boundary-lint",
        "boundary_lint.py",
        "estate facts (the configured patterns) hard-coded in engine paths (--warn to report only)",
        default_args=("--enforce",),
    ),
    Check(
        "diff-leak",
        "check_diff_leak.py",
        "a task rendering a credential into a file without no_log (--diff prints it; DIFFLEAK-01)",
    ),
    Check(
        "workflow-fork-guard",
        "check_workflow_fork_guard.py",
        "a job a fork PR can trigger that may select a self-hosted runner (FORKGUARD-01)",
    ),
    Check(
        "trap-report",
        "trap_report.py",
        "rank recorded trap hits by frequency (reads the trap-hit log)",
        gate=False,
    ),
    Check(
        "record-trap-hits",
        "record_trap_hits.py",
        "PostToolUse recorder: append a trap-hit record for the edited YAML file (stdin payload)",
        gate=False,
    ),
)

BY_NAME: dict[str, Check] = {c.name: c for c in CHECKS}
