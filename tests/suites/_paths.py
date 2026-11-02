# SPDX-License-Identifier: GPL-3.0-or-later
"""Where the suites find the code under test, and the fixture config most of them assume.

The suites were written beside the checkers (one directory, `Path(__file__).with_name(...)`). In
the package the checkers live in src/ansible_devkit/checks/ and the suites here, so every locator
goes through CHECKS. ROOT is the repository root (the suites that exercise "the real repo" — the
CI-coverage check, the worktree skip — mean THIS repo).

use_fixture_config() points `_devkit_config` at tests/suites/fixture_repo/devkit.toml via
DEVKIT_ROOT, unless a caller already set it. The fixtures in several suites assume that file's
values (an agent-writable tree named `agent_config_dir`, a supervisor module `acme.home.*`, a
vendored collections dir `collections.galaxy`): without it a suite run from the repo root would
read THIS repo's devkit.toml, whose values are the package's own, and every such fixture would
fail for a reason that is not the checker's.
"""

from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CHECKS = ROOT / "src" / "ansible_devkit" / "checks"
DISCLOSE = ROOT / "src" / "ansible_devkit" / "disclose" / "disclose.py"
SELECTOR = ROOT / "src" / "ansible_devkit" / "scripts" / "affected-scenarios.sh"
FIXTURE_REPO = Path(__file__).resolve().parent / "fixture_repo"


def use_fixture_config() -> None:
    os.environ.setdefault("DEVKIT_ROOT", str(FIXTURE_REPO))
