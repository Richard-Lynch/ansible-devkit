# SPDX-License-Identifier: GPL-3.0-or-later
"""A non-editable, read-only devkit toolchain outside each consumer work tree."""

from __future__ import annotations

import os
import shutil
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest


@pytest.fixture
def installed_devkit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    prefix = tmp_path / "toolchain"
    python_directory = f"python{sys.version_info.major}.{sys.version_info.minor}"
    packages = prefix / "lib" / python_directory / "site-packages"
    package = packages / "ansible_devkit"
    shutil.copytree(
        Path(__file__).resolve().parents[1] / "src" / "ansible_devkit",
        package,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    binary = prefix / "bin" / "devkit"
    binary.parent.mkdir()
    binary.write_text(
        f"#!{sys.executable} -B\n"
        "import sys\n"
        f"sys.path.insert(0, {str(packages)!r})\n"
        "from ansible_devkit.cli import main\n"
        "main()\n"
    )
    binary.chmod(0o555)
    for path in package.rglob("*"):
        path.chmod(0o555 if path.is_dir() or path.name in ("pre-commit", "pre-push") else 0o444)
    package.chmod(0o555)
    monkeypatch.setenv(
        "PATH",
        os.pathsep.join([str(binary.parent), str(Path(sys.executable).parent), os.environ["PATH"]]),
    )
    monkeypatch.setenv("PYTHONDONTWRITEBYTECODE", "1")
    monkeypatch.setenv("UV_OFFLINE", "1")
    monkeypatch.setenv("UV_NO_SYNC", "1")
    monkeypatch.setenv("PIP_NO_INDEX", "1")
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("DEVKIT_ROOT", raising=False)
    yield binary
    package.chmod(0o755)
    for path in package.rglob("*"):
        if path.is_dir():
            path.chmod(0o755)
