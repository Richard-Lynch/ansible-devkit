#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Cases for check_rootfs_seal.py — including that every pattern can actually FIRE.

WHY THIS EXISTS. The remount patterns were added as regexes, and the first version of `_ROOT` used a
`(?=\\s|$)` lookahead. That matched NOTHING, because `_commands()` flattens a task dict with
repr() — so `{cmd: mount -o remount,rw /}` arrives as `{'cmd': 'mount -o remount,rw /'}` and the
`/` is followed by an apostrophe, not whitespace. The hook reported a clean scan over the whole
repo and would have kept reporting one forever.

That is precisely the failure mode this hook was written to catch, reproduced inside the hook
itself. So every pattern here is tested in BOTH directions: a fixture that must FAIL, and a
near-miss that must PASS. A guard nobody proved can fire is decoration.

Run: uv run tests/suites/test_check_rootfs_seal.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from _paths import CHECKS, ROOT  # noqa: F401 — tests/suites/_paths.py

sys.path.insert(0, str(CHECKS))

from check_rootfs_seal import check  # noqa: E402

FAIL, OK = "fail", "ok"

# (expected, yaml, label)
CASES: list[tuple[str, str, str]] = [
    # ---- the original SteamOS shape, which must keep working ----
    (
        FAIL,
        """
- name: Unseal outside a block
  ansible.builtin.command: {cmd: steamos-readonly disable}
""",
        "steamos: unseal outside a block",
    ),
    (
        FAIL,
        """
- name: Unsealed block with no re-seal
  block:
    - name: Unseal
      ansible.builtin.command: {cmd: steamos-readonly disable}
  always:
    - name: Not a re-seal
      ansible.builtin.debug: {msg: done}
""",
        "steamos: block without re-seal in always",
    ),
    (
        OK,
        """
- name: Correctly sealed
  block:
    - name: Unseal
      ansible.builtin.command: {cmd: steamos-readonly disable}
  always:
    - name: Re-seal
      ansible.builtin.command: {cmd: steamos-readonly enable}
""",
        "steamos: unseal in block, re-seal in always",
    ),
    # ---- an image whose root is sealed by overlayfs plus an `ro` fstab entry ----
    (
        FAIL,
        """
- name: Remount the root rw outside a block
  ansible.builtin.command: {cmd: "mount -o remount,rw /"}
""",
        "overlay: remount,rw / outside a block",
    ),
    (
        FAIL,
        """
- name: Other option order
  ansible.builtin.command: {cmd: "mount -o rw,remount /"}
""",
        "overlay: rw,remount / outside a block",
    ),
    (
        FAIL,
        """
- name: Unsealed block with no re-seal
  block:
    - name: Unseal
      ansible.builtin.shell: mount -o remount,rw /
  always:
    - name: Not a re-seal
      ansible.builtin.debug: {msg: done}
""",
        "overlay: block without re-seal",
    ),
    (
        OK,
        """
- name: Correctly sealed
  block:
    - name: Unseal
      ansible.builtin.shell: mount -o remount,rw /
  always:
    - name: Re-seal
      ansible.builtin.shell: mount -o remount,ro /
""",
        "overlay: unseal in block, re-seal in always",
    ),
    (
        FAIL,
        """
- name: Disable the overlay outside a block
  ansible.builtin.command: {cmd: raspi-config nonint disable_overlayfs}
""",
        "overlay: raspi-config disable_overlayfs outside a block",
    ),
    (
        OK,
        """
- name: Overlay toggled with a re-enable
  block:
    - name: Disable
      ansible.builtin.command: {cmd: raspi-config nonint disable_overlayfs}
  always:
    - name: Re-enable
      ansible.builtin.command: {cmd: raspi-config nonint enable_overlayfs}
""",
        "overlay: overlay disable/enable pair",
    ),
    # ---- NEAR MISSES: a hook that fires on innocent tasks gets suppressed ----
    (
        OK,
        """
- name: Remount an unrelated mountpoint
  ansible.builtin.command: {cmd: "mount -o remount,rw /mnt/data"}
""",
        "near-miss: /mnt/data is not the rootfs",
    ),
    (
        OK,
        """
- name: Remount the boot partition
  ansible.builtin.shell: mount -o remount,rw /boot/firmware
""",
        "near-miss: /boot/firmware is not the rootfs",
    ),
    (
        OK,
        """
- name: Read the overlay state
  ansible.builtin.command: {cmd: raspi-config nonint get_overlay_now}
""",
        "near-miss: reading overlay state is not an unseal",
    ),
]


def main() -> int:
    passed = failed = 0
    for expected, doc, label in CASES:
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as fh:
            fh.write(doc)
            path = Path(fh.name)
        try:
            got = FAIL if check(path) else OK
        finally:
            path.unlink(missing_ok=True)

        if got == expected:
            passed += 1
            print(f"  PASS  {expected:<4}  {label}")
        else:
            failed += 1
            print(f"  FAIL  want {expected}, got {got}  {label}")

    total = passed + failed
    print(f"\n{passed}/{total} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
