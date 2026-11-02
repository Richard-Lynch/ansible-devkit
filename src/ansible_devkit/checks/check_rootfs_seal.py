#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Fail if a play unseals an immutable rootfs without guaranteeing the re-seal.

THE BUG THIS CATCHES. `steamos-readonly disable` placed BEFORE a block looks equivalent to
placing it inside one — the re-seal is right there in the `always:`. It is not equivalent: if the
unseal succeeds and the play is then interrupted (a failed task, a dropped connection, Ctrl-C),
the filesystem is left writable and nothing re-seals it. Nothing warns afterwards, and the next
atomic update silently discards whatever was written into it.

Rule: every task running an unseal must sit inside a `block:` whose `always:` runs the re-seal.
"""

from __future__ import annotations

import sys
from pathlib import Path

import re

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _devkit_config  # noqa: E402

# REGEXES, not substrings. Remount patterns force this: `"mount -o remount,rw /"` as a substring
# also matches `mount -o remount,rw /mnt/data`, which is an innocent task — and a check that fires
# on innocent tasks gets suppressed, which is how a guard quietly stops guarding. The root
# filesystem has to be matched as `/` *followed by nothing*, which a substring cannot express.
#
# The mount point must be `/` and NOT the start of a longer path: `/` then anything that cannot
# continue a path. Whitespace and end-of-string are the obvious cases; the quote characters matter
# because _commands() flattens a task dict with repr(), so `{cmd: mount -o remount,rw /}` arrives
# as the literal text `{'cmd': 'mount -o remount,rw /'}` and the `/` is followed by an apostrophe.
# Missing that is why the first version of this pattern silently matched NOTHING — the exact class
# of bug this hook exists to catch, in the hook itself. The fixtures in test_check_rootfs_seal.py
# cover both quoted and unquoted forms so it cannot regress.
_ROOT = r"""/(?=["'\s;&|]|$)"""

UNSEAL = (
    r"steamos-readonly\s+disable",
    r"btrfs\s+property\s+set\s+/\s+ro\s+false",
    # An image whose root is sealed by overlayfs plus an `ro` fstab entry: the unseal is a remount
    # of `/` (or raspi-config's overlay toggle). Both option orders, because `remount,rw` and
    # `rw,remount` are equally common and mean the same thing.
    rf"mount\s+-o\s+remount,rw\s+{_ROOT}",
    rf"mount\s+-o\s+rw,remount\s+{_ROOT}",
    r"raspi-config\s+nonint\s+disable_overlayfs",
)
RESEAL = (
    r"steamos-readonly\s+enable",
    r"btrfs\s+property\s+set\s+/\s+ro\s+true",
    rf"mount\s+-o\s+remount,ro\s+{_ROOT}",
    rf"mount\s+-o\s+ro,remount\s+{_ROOT}",
    r"raspi-config\s+nonint\s+enable_overlayfs",
)


def _commands(task: dict) -> str:
    """Every string a task might run, flattened, so the match does not depend on module form."""
    parts = []
    for key, value in task.items():
        if key.startswith("ansible.builtin.") or key in ("command", "shell", "raw"):
            parts.append(str(value))
    return " ".join(parts)


def check(path: Path) -> list[str]:
    try:
        doc = yaml.safe_load(path.read_text())
    except yaml.YAMLError:
        return []
    if not isinstance(doc, list):
        return []

    problems = []
    for task in doc:
        if not isinstance(task, dict):
            continue
        name = task.get("name", "(unnamed)")

        if "block" in task:
            block = task.get("block") or []
            always = task.get("always") or []
            unseals = any(
                any(re.search(u, _commands(t)) for u in UNSEAL)
                for t in block
                if isinstance(t, dict)
            )
            reseals = any(
                any(re.search(r, _commands(t)) for r in RESEAL)
                for t in always
                if isinstance(t, dict)
            )
            if unseals and not reseals:
                problems.append(
                    f"{path}: block '{name}' unseals the rootfs but its `always:` does not "
                    f"re-seal it"
                )
            continue

        if any(re.search(u, _commands(task)) for u in UNSEAL):
            problems.append(
                f"{path}: task '{name}' unseals the rootfs OUTSIDE a block — an interrupted run "
                f"leaves the filesystem writable with nothing to re-seal it"
            )
    return problems


def main(argv: list[str]) -> int:
    # Accept files OR directories, so `check_rootfs_seal.py roles playbooks` scans everything
    # beneath them rather than silently checking two paths that are not files.
    try:
        roots = _devkit_config.load().str_list("paths.ansible_roots", ["roles", "playbooks"])
    except _devkit_config.ConfigError as exc:
        _devkit_config.fatal("check_rootfs_seal", exc)
    args = [Path(a) for a in argv[1:]] or [Path(r) for r in roots]
    targets: list[Path] = []
    for arg in args:
        if arg.is_dir():
            targets.extend(sorted(arg.rglob("*.yml")))
        elif arg.is_file():
            targets.append(arg)

    problems: list[str] = []
    for path in targets:
        problems.extend(check(path))

    for p in problems:
        print(f"FAIL {p}")
    print(f"\ncheck_rootfs_seal: {len(problems)} FAIL across {len(targets)} file(s) scanned.")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
