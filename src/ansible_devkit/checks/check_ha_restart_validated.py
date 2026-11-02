#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Fail if a play restarts Home Assistant without validating the config first.

THE BUG THIS CATCHES. A restart loads whatever config is on disk. If that config is broken, HA
does not come back -- and whatever the home runs through it stops with it. The validation
(`core_check`, which is HA's OWN Supervisor rendering the whole config exactly as a start would)
must therefore run BEFORE every restart, in the same file, under a gate no weaker than the
restart's own.

Ordering is the entire point and it is invisible to review: a `core_check` sitting AFTER the
restart reads almost identically in a diff, and validates a config that has already been loaded
or failed to load. Likewise a check gated on `apply` while the restart is not -- that is a check
that can be skipped by the run that most needs it.

Rule, per file that contains a restart action:
  1. a `core_check` task must appear BEFORE the first restart task, and
  2. the restart must not be reachable under conditions the check is not -- i.e. every `when:`
     condition guarding the check must also guard the restart.

Exit 1 on any violation. Suppress a specific finding with a comment containing
`ha-restart-check: ignore <reason>` on the restarting task, which is recorded and reviewable --
a bare suppression with no reason is itself a violation.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _devkit_config  # noqa: E402

# The Supervisor module, in every spelling plays use (devkit.toml [ha_restart]). REQUIRED: a check
# that knew no module name would find no restarts anywhere and pass.
try:
    _CFG = _devkit_config.load()
    SUPERVISOR_MODULES = tuple(_CFG.str_list("ha_restart.supervisor_modules"))
    ANSIBLE_ROOTS = sorted(_CFG.str_list("paths.ansible_roots", ["roles", "playbooks"]))
except _devkit_config.ConfigError as _exc:
    _devkit_config.fatal("check_ha_restart_validated", _exc)

# The Supervisor actions that stop or restart Core. `core_stop` counts: a stop followed by a start
# is a restart spelled differently, and the config is loaded on the way back up either way.
RESTART_ACTIONS = ("core_restart", "core_start", "core_stop")
CHECK_ACTION = "core_check"

SUPPRESS = "ha-restart-check: ignore"


class _LineLoader(yaml.SafeLoader):
    """SafeLoader that records the source line of every mapping.

    The line number is what makes a finding actionable, and it is also how ORDER is determined --
    comparing positions in a walked structure would depend on walk order rather than on the order
    the tasks actually run in.
    """


def _mapping_with_line(loader: _LineLoader, node: yaml.MappingNode) -> dict:
    mapping = loader.construct_mapping(node, deep=True)
    mapping["__line__"] = node.start_mark.line + 1
    return mapping


_LineLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping_with_line)

# HA's own config uses these tags; a play never does, but the loader is shared so it must not
# explode on one. Returning None is fine -- nothing here inspects their values.
for _tag in (
    "!include",
    "!include_dir_merge_named",
    "!include_dir_merge_list",
    "!include_dir_list",
    "!include_dir_named",
    "!secret",
    "!env_var",
):
    _LineLoader.add_constructor(_tag, lambda _l, _n: None)


def _walk_tasks(node: Any) -> list[dict]:
    """Every task-shaped mapping in a play, in SOURCE ORDER.

    Recurses through blocks, rescue/always, and nested includes, because a restart inside a
    `block:` is still a restart. Sorted by line at the end so the caller can reason about order
    without depending on how this walk happens to recurse.
    """
    found: list[dict] = []
    if isinstance(node, dict):
        if "__line__" in node:
            found.append(node)
        for value in node.values():
            found.extend(_walk_tasks(value))
    elif isinstance(node, list):
        for item in node:
            found.extend(_walk_tasks(item))
    return found


def _supervisor_action(task: dict) -> str | None:
    """The Supervisor action a task invokes, or None.

    Both module spellings are accepted: a check that only knew the FQCN would silently pass a play
    using the short name, which is the failure mode this file exists to prevent.
    """
    for key in SUPERVISOR_MODULES:
        args = task.get(key)
        if isinstance(args, dict):
            action = args.get("action")
            return action if isinstance(action, str) else None
    return None


def _conditions(task: dict) -> set[str]:
    """A task's `when:` conditions, normalised to a set of strings."""
    when = task.get("when")
    if when is None:
        return set()
    if isinstance(when, str):
        return {when.strip()}
    if isinstance(when, list):
        return {str(item).strip() for item in when}
    return {str(when).strip()}


def check_file(path: Path) -> list[str]:
    """Return a list of problems found in one YAML file."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []

    # Cheap reject before parsing. Reading every YAML file in the repo to find the handful that
    # mention a restart would make this check slow enough that someone turns it off.
    if not any(action in text for action in RESTART_ACTIONS):
        return []

    try:
        docs = list(yaml.load_all(text, Loader=_LineLoader))
    except yaml.YAMLError:
        # Malformed YAML is yamllint's job to report, not this check's to guess at.
        return []

    lines = text.splitlines()
    tasks = sorted(_walk_tasks(docs), key=lambda t: t["__line__"])

    checks = [t for t in tasks if _supervisor_action(t) == CHECK_ACTION]
    restarts = [t for t in tasks if _supervisor_action(t) in RESTART_ACTIONS]
    if not restarts:
        return []

    problems: list[str] = []
    for restart in restarts:
        line = restart["__line__"]

        # A suppression has to carry a reason. The comment is looked for on the lines immediately
        # above the task, which is where a reviewer would write it.
        window = lines[max(0, line - 6) : line]
        suppression = next((ln for ln in window if SUPPRESS in ln), None)
        if suppression is not None:
            reason = suppression.split(SUPPRESS, 1)[1].lstrip("-—: ").strip()
            if reason:
                continue
            problems.append(
                f"{path}:{line}: bare `{SUPPRESS}` with no reason — say why this restart is safe"
            )
            continue

        earlier = [c for c in checks if c["__line__"] < line]
        if not earlier:
            problems.append(
                f"{path}:{line}: restarts Home Assistant "
                f"({_supervisor_action(restart)}) with no `{CHECK_ACTION}` before it. "
                f"A restart loads whatever is on disk; validate it first."
            )
            continue

        # The check must not be skippable by a run that performs the restart. Every condition on
        # the check has to also appear on the restart -- a check gated on `apply` while the
        # restart is not is a check the real run can skip.
        restart_conditions = _conditions(restart)
        for candidate in earlier:
            missing = _conditions(candidate) - restart_conditions
            if not missing:
                break
        else:
            problems.append(
                f"{path}:{line}: every `{CHECK_ACTION}` before this restart is guarded by a "
                f"condition the restart is not ({sorted(missing)}), so the restart can run "
                f"un-validated."
            )

    return problems


def main(argv: list[str]) -> int:
    paths = [Path(a) for a in argv[1:]]
    if not paths:
        root = _CFG.root
        paths = [p for d in ANSIBLE_ROOTS for p in (root / d).rglob("*.yml")]

    files: list[Path] = []
    for path in paths:
        if path.is_dir():
            files.extend(sorted(path.rglob("*.yml")))
            files.extend(sorted(path.rglob("*.yaml")))
        else:
            files.append(path)

    problems: list[str] = []
    for path in files:
        problems.extend(check_file(path))
    scanned = len(files)

    for problem in problems:
        print(problem)

    # The count is printed on success too. A check that prints nothing when it passes is
    # indistinguishable from one that scanned nothing.
    print(
        f"check_ha_restart_validated: {len(problems)} FAIL across {scanned} file(s) scanned.",
        file=sys.stderr,
    )
    if scanned == 0:
        # Never exit 0 having examined nothing. A green tick over an empty scan is worse than a
        # failure: it is indistinguishable from a real pass and nobody looks again.
        print(
            "check_ha_restart_validated: scanned NO files — check the paths given.",
            file=sys.stderr,
        )
        return 1
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
