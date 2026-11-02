#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Shared loader for `devkit.toml`: the per-repo data the GENERIC checks read.

WHY THIS EXISTS. The checks in this package (silent guards, rootfs seal, vendored secrets, regex
anchors, ...) must not know where any particular repository keeps things: which
directories hold the agent-writable trees, where the trap log lives, which file is the rulebook,
which workflow directory CI reads. Every such fact is a key in `devkit.toml` at the repo root, and
this module is the only thing that reads it.

THE CONTRACT, and why each clause is there:

  * The repo root is `$DEVKIT_ROOT`, else the git toplevel of the working directory, else the
    working directory. Never derived from this file's location: once installed as a package the
    checks live in site-packages, and a root derived from `__file__` would scan the package.
    Never found by walking UP looking for a devkit.toml either: a worktree whose branch predates
    the file sits inside the main checkout, and a walk-up would silently make the MAIN checkout the
    repo being checked.
  * `get(key)` with no default is a REQUIRED key. A repo that runs a check needing it and does not
    set it gets `ConfigError`, which every check turns into exit 2 with the key's name. A missing
    required key must never read as "nothing to check" — that is a silent guard in the checker.
  * `get(key, default)` is for values that are right for ANY repo (the Ansible `roles`/`playbooks`
    layout, `.github/workflows`). An estate fact never gets a default.
  * No devkit.toml at all is the same as an empty one: checks with no required keys still run,
    and any check that needs a key says which.

Stdlib only (tomllib, 3.11+), because the stdlib-only CI group imports it on docs-only changes.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any, NoReturn

FILENAME = "devkit.toml"
ROOT_ENV = "DEVKIT_ROOT"

_REQUIRED = object()


class ConfigError(Exception):
    """A required devkit.toml key is absent, or a key has the wrong type."""


def find_root(start: Path | None = None) -> Path:
    env = os.environ.get(ROOT_ENV)
    if env:
        return Path(env).resolve()
    here = (start or Path.cwd()).resolve()
    try:
        cp = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=here,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if cp.returncode == 0 and cp.stdout.strip():
            return Path(cp.stdout.strip()).resolve()
    except (OSError, subprocess.SubprocessError):
        pass
    return here


class Config:
    def __init__(self, root: Path, data: dict[str, Any], source: Path | None) -> None:
        self.root = root
        self.data = data
        self.source = source

    def _where(self) -> str:
        return str(self.source) if self.source else f"{self.root / FILENAME} (absent)"

    def get(self, key: str, default: Any = _REQUIRED) -> Any:
        node: Any = self.data
        for part in key.split("."):
            if not isinstance(node, dict) or part not in node:
                if default is _REQUIRED:
                    raise ConfigError(
                        f"{self._where()}: required key `{key}` is not set. This check refuses to "
                        "run without it rather than silently checking nothing — set it to the "
                        "value for this repo (an empty list is an explicit 'none')."
                    )
                return default
            node = node[part]
        return node

    def str_list(self, key: str, default: Any = _REQUIRED) -> list[str]:
        value = self.get(key, default)
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise ConfigError(f"{self._where()}: `{key}` must be a list of strings")
        return list(value)

    def string(self, key: str, default: Any = _REQUIRED) -> str:
        value = self.get(key, default)
        if not isinstance(value, str):
            raise ConfigError(f"{self._where()}: `{key}` must be a string")
        return value


_CACHE: dict[Path, Config] = {}


def load(start: Path | None = None) -> Config:
    root = find_root(start)
    if root in _CACHE:
        return _CACHE[root]
    path = root / FILENAME
    data: dict[str, Any] = {}
    source: Path | None = None
    if path.is_file():
        try:
            with path.open("rb") as fh:
                data = tomllib.load(fh)
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(f"{path}: not valid TOML ({exc})") from exc
        source = path
    cfg = Config(root, data, source)
    _CACHE[root] = cfg
    return cfg


def fatal(tool: str, exc: Exception) -> NoReturn:
    """Exit 2 naming the problem: a config error is a broken checker, never a pass."""
    print(f"{tool}: config error: {exc}", file=sys.stderr)
    raise SystemExit(2)
