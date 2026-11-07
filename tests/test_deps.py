# SPDX-License-Identifier: GPL-3.0-or-later
"""Dependency stamp and installation failure contracts."""

import json
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from ansible_devkit.cli import devkit
from ansible_devkit.deps import stamp_data


def test_stamps(tmp_path: Path) -> None:
    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=tmp_path):
        Path("requirements.yml").write_text("collections: []\nroles: []\n")
        message = "installed collections do not match requirements.yml - run make deps-install\n"
        result = runner.invoke(devkit, ["deps", "check"])
        assert result.exit_code == 1 and result.output == message
        Path("collections.galaxy").mkdir()
        stamp = Path("collections.galaxy/.requirements.sha256")
        stamp.write_text("stale")
        assert runner.invoke(devkit, ["deps", "check"]).output == message
        stamp.write_text(
            json.dumps(
                stamp_data(
                    Path("requirements.yml"),
                    Path("collections.galaxy"),
                    Path("roles.galaxy"),
                )
            )
        )
        assert runner.invoke(devkit, ["deps", "check"]).exit_code == 0


def test_failed_install_removes_stamp(tmp_path: Path) -> None:
    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=tmp_path):
        Path("requirements.yml").write_text("collections: [ns.name]\n")
        Path("collections.galaxy").mkdir()
        stamp = Path("collections.galaxy/.requirements.sha256")
        stamp.write_text("old")
        with patch("ansible_devkit.deps.subprocess.run", side_effect=OSError("failed")):
            assert runner.invoke(devkit, ["deps", "install"]).exit_code == 1
        assert not stamp.exists()
        with patch("ansible_devkit.deps.subprocess.run"):
            assert runner.invoke(devkit, ["deps", "install"]).exit_code == 1
            Path("collections.galaxy/ansible_collections/ns/name").mkdir(parents=True)
            assert runner.invoke(devkit, ["deps", "install"]).exit_code == 0
            assert runner.invoke(devkit, ["deps", "check"]).exit_code == 0


def test_git_collection_marker_and_role_verification(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    Path("requirements.yml").write_text(
        "roles:\n  - name: example.role\ncollections:\n"
        "  - name: https://example.invalid/repo.git # collection: ns.name\n    type: git\n"
    )
    Path("collections.galaxy/ansible_collections/ns/name").mkdir(parents=True)
    Path("roles.galaxy/example.role").mkdir(parents=True)
    with patch("ansible_devkit.deps.subprocess.run") as galaxy:
        assert CliRunner().invoke(devkit, ["deps", "install"]).exit_code == 0
        assert galaxy.call_count == 2
        Path("roles.galaxy/example.role").rmdir()
        assert CliRunner().invoke(devkit, ["deps", "install"]).exit_code == 1
        assert not Path("collections.galaxy/.requirements.sha256").exists()


def test_check_binds_paths_and_checks_directories(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    Path("requirements.yml").write_text("roles: [example.role]\ncollections: [ns.name]\n")
    role = Path("roles.galaxy/example.role")
    role.mkdir(parents=True)
    collection = Path("collections.galaxy/ansible_collections/ns/name")
    collection.mkdir(parents=True)
    runner = CliRunner()
    with patch("ansible_devkit.deps.subprocess.run"):
        assert runner.invoke(devkit, ["deps", "install"]).exit_code == 0
    assert runner.invoke(devkit, ["deps", "check"]).exit_code == 0
    assert runner.invoke(devkit, ["deps", "check", "--roles-path", "other"]).exit_code == 1
    role.rmdir()
    assert runner.invoke(devkit, ["deps", "check"]).exit_code == 1
    role.mkdir()
    collection.rmdir()
    assert runner.invoke(devkit, ["deps", "check"]).exit_code == 1


def test_src_only_roles_are_verified(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    Path("requirements.yml").write_text(
        "roles:\n  - src: geerlingguy.java\n" "  - src: https://example.com/role.git,main\n"
    )
    for name in ("geerlingguy.java", "role"):
        Path("roles.galaxy", name).mkdir(parents=True)
    runner = CliRunner()
    with patch("ansible_devkit.deps.subprocess.run"):
        assert runner.invoke(devkit, ["deps", "install"]).exit_code == 0
    assert runner.invoke(devkit, ["deps", "check"]).exit_code == 0
    Path("roles.galaxy/role").rmdir()
    assert runner.invoke(devkit, ["deps", "check"]).exit_code == 1
