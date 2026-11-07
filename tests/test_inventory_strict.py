# SPDX-License-Identifier: GPL-3.0-or-later
"""Inventory strictness catches silent expression failures."""

import subprocess
from pathlib import Path

import yaml

from ansible_devkit.checks.check_inventory_strict import main, scan


def test_inventory_expressions(tmp_path: Path) -> None:
    source = tmp_path / "inventory.yml"
    source.write_text("plugin: constructed\ngroups: {web: inventory_hostname}\n")
    assert len(scan(tmp_path)[0]) == 1
    source.write_text("plugin: constructed\nstrict: true\ngroups: {web: \"'true'\"}\n")
    assert len(scan(tmp_path)[0]) == 1
    source.write_text("plugin: constructed\nstrict: true\ngroups: {web: inventory_hostname}\n")
    assert scan(tmp_path) == ([], 1)
    source.unlink()
    assert scan(tmp_path) == ([], 0)


def test_compose_and_keyed_groups_require_strict(tmp_path: Path) -> None:
    source = tmp_path / "source.yaml"
    for key, value in [("compose", "{}"), ("keyed_groups", "[]")]:
        source.write_text(f"plugin: constructed\n{key}: {value}\n")
        assert len(scan(tmp_path)[0]) == 1
        source.write_text(f"plugin: constructed\nstrict: true\n{key}: {value}\n")
        assert scan(tmp_path) == ([], 1)


def test_only_whole_string_literals_are_rejected(tmp_path: Path) -> None:
    source = tmp_path / "inventory.yml"
    for expression in ("'true'", '"yes"'):
        source.write_text(
            yaml.safe_dump({"plugin": "constructed", "strict": True, "groups": {"x": expression}})
        )
        assert len(scan(tmp_path)[0]) == 1
    source.write_text(
        yaml.safe_dump(
            {
                "plugin": "constructed",
                "strict": True,
                "groups": {"x": "'prod' in tags and 'active' in status"},
            }
        )
    )
    assert scan(tmp_path)[0] == []


def test_main_finds_git_root_from_subdirectory(tmp_path: Path, monkeypatch) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "inventory.yml").write_text("plugin: constructed\ngroups: {x: hostname}\n")
    subdir = tmp_path / "subdir"
    subdir.mkdir()
    monkeypatch.delenv("DEVKIT_ROOT", raising=False)
    monkeypatch.chdir(subdir)
    assert main(["check_inventory_strict"]) == 1


def test_vault_values_do_not_hide_inventory_findings(tmp_path: Path) -> None:
    source = tmp_path / "inventory.yml"
    source.write_text(
        "plugin: constructed\npassword: !vault |\n  encrypted\ngroups: {web: hostname}\n"
    )
    findings, count = scan(tmp_path)
    assert count == 1
    assert len(findings) == 1 and "strict: true" in findings[0]


def test_invalid_inventory_yaml_is_reported(tmp_path: Path) -> None:
    source = tmp_path / "inventories" / "bad.yml"
    source.parent.mkdir()
    source.write_text("plugin: [invalid\n")
    findings, _ = scan(tmp_path)
    assert len(findings) == 1 and "inventories/bad.yml" in findings[0]
