# SPDX-License-Identifier: GPL-3.0-or-later
"""The copier template (copier.yml, template/) generates a repository that meets the standard.

The template is copied to a temporary NON-git directory before `copier copy`: copier reads a git
template at its latest tag, so copying from this checkout directly would test the last release's
template rather than the one in the working tree.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import copier
import pytest
import yaml

from ansible_devkit import __version__, conform

ROOT = Path(__file__).resolve().parents[1]

ANSWERS = {
    "namespace": "example_ns",
    "name": "demo",
    "description": "A demonstration collection.",
    "author": "Example Author",
    "github_owner": "example-owner",
    "release_date": "2026-01-02",
}


def generate(tmp_path: Path, **overrides: object) -> Path:
    src = tmp_path / "src"
    src.mkdir()
    shutil.copy(ROOT / "copier.yml", src / "copier.yml")
    shutil.copytree(ROOT / "template", src / "template")
    dst = tmp_path / "out"
    copier.run_copy(
        str(src), str(dst), data={**ANSWERS, **overrides}, defaults=True, quiet=True
    )
    subprocess.run(["git", "init", "-q", str(dst)], check=True)
    subprocess.run(["git", "-C", str(dst), "add", "-A"], check=True)
    return dst


def test_generated_repository_conforms(tmp_path: Path) -> None:
    out = generate(tmp_path)
    assert conform.conform(out) == []


def test_generated_repository_passes_devkit_check_all(tmp_path: Path) -> None:
    out = generate(tmp_path)
    p = subprocess.run(
        [sys.executable, "-m", "ansible_devkit.cli", "check", "all"],
        cwd=out,
        capture_output=True,
        text=True,
        timeout=600,
    )
    assert p.returncode == 0, p.stdout[-3000:] + p.stderr[-3000:]


def test_answers_reach_the_files(tmp_path: Path) -> None:
    out = generate(
        tmp_path, version="2.3.4", devkit_ref="v9.8.7", ansible_core=["2.21"]
    )
    galaxy = yaml.safe_load((out / "galaxy.yml").read_text())
    assert (galaxy["namespace"], galaxy["name"], galaxy["version"]) == (
        "example_ns",
        "demo",
        "2.3.4",
    )
    assert galaxy["license"] == ["GPL-3.0-or-later"]
    assert (
        galaxy["repository"]
        == "https://github.com/example-owner/ansible-collection-demo"
    )
    assert "## [2.3.4] — 2026-01-02" in (out / "CHANGELOG.md").read_text()
    ci = yaml.safe_load((out / ".github/workflows/ci.yml").read_text())
    assert ci["jobs"]["ci"]["uses"].endswith("reusable-ci.yml@v9.8.7")
    assert ci["jobs"]["ci"]["with"] == {
        "kind": "collection",
        "ansible_core": '["2.21"]',
    }
    runtime = yaml.safe_load((out / "meta/runtime.yml").read_text())
    assert runtime == {"requires_ansible": ">=2.19.0"}
    assert conform.conform(out) == []


def test_template_license_is_this_repositorys() -> None:
    assert (ROOT / "template/LICENSE").read_bytes() == (ROOT / "LICENSE").read_bytes()


def test_default_devkit_ref_is_this_release() -> None:
    questions = yaml.safe_load((ROOT / "copier.yml").read_text())
    assert questions["devkit_ref"]["default"] == f"v{__version__}"


@pytest.mark.parametrize(
    "answer",
    [
        {"devkit_ref": "main"},
        {"namespace": "Bad-Name"},
        {"version": "1.0"},
        {"ansible_core": [2.20]},
    ],
)
def test_invalid_answers_are_refused(tmp_path: Path, answer: dict) -> None:
    with pytest.raises(ValueError, match="Validation error for question"):
        generate(tmp_path, **answer)


def test_python_defaults_are_this_repositorys() -> None:
    """The template's default .python-version and the reusable workflows' fallback for a caller
    without one are both devkit's own .python-version, so they cannot drift apart."""
    want = (ROOT / ".python-version").read_text().strip()
    questions = yaml.safe_load((ROOT / "copier.yml").read_text())
    assert questions["python_version"]["default"] == want
    for wf in ("reusable-ci.yml", "reusable-release.yml"):
        doc = yaml.safe_load((ROOT / ".github/workflows" / wf).read_text())
        assert doc["env"]["PYTHON_FALLBACK"] == want, wf


def test_generated_repository_has_python_version_and_renovate(tmp_path: Path) -> None:
    out = generate(tmp_path, python_version="3.13")
    assert (out / ".python-version").read_text().strip() == "3.13"
    import json

    cfg = json.loads((out / "renovate.json").read_text())
    assert cfg["extends"] == [
        f"github>Richard-Lynch/ansible-devkit//renovate/default#v{__version__}"
    ]
    # The repository's own rules come AFTER the preset: everything off, then actions/* patches.
    rules = cfg["packageRules"]
    assert rules[0] == {**rules[0], "matchPackageNames": ["/.*/"], "automerge": False}
    assert any(
        r.get("matchDatasources") == ["galaxy-collection", "galaxy"]
        and r["automerge"] is False
        for r in rules
    )
    ok = [r for r in rules if r.get("automerge")]
    assert len(ok) == 1 and ok[0]["matchPackageNames"] == ["actions/**"]
    assert ok[0]["matchUpdateTypes"] == ["patch"] and ok[0]["minimumReleaseAge"]


def test_preset_never_turns_automerge_on() -> None:
    import json

    preset = json.loads((ROOT / "renovate/default.json").read_text())
    assert preset.get("automerge") is False
    assert preset["lockFileMaintenance"]["automerge"] is False
    assert not [r for r in preset["packageRules"] if r.get("automerge")]
    own = json.loads((ROOT / "renovate.json").read_text())
    assert own["extends"] == [
        f"github>Richard-Lynch/ansible-devkit//renovate/default#v{__version__}"
    ]


def test_generated_uv_lock_is_current(tmp_path: Path) -> None:
    out = generate(tmp_path, name="my_collection", version="2.3.4")
    result = subprocess.run(
        ["uv", "lock", "--check", "--offline"], cwd=out, capture_output=True, text=True
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_generated_repository_ignores_galaxy_dependencies(tmp_path: Path) -> None:
    out = generate(tmp_path)
    for directory in ("collections.galaxy", "roles.galaxy"):
        result = subprocess.run(
            ["git", "-C", str(out), "check-ignore", f"{directory}/example/file"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0, directory
