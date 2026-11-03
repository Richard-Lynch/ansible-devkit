# SPDX-License-Identifier: GPL-3.0-or-later
"""`devkit conform`: each rule, with a fixture that must FAIL it and a near-miss that must PASS.

The fixture is a conforming collection repository written here from strings (not generated from the
template, so a broken template cannot hide a broken rule; tests/test_template.py covers the template
against these same rules). Every case mutates one thing and asserts on the rule id it expects, so a
rule that fires on the wrong problem, or never fires, fails here.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from ansible_devkit import conform

ROOT = Path(__file__).resolve().parents[1]

CI = """\
name: ci
on:
  push:
    branches: [main]
  pull_request:
jobs:
  ci:
    uses: Richard-Lynch/ansible-devkit/.github/workflows/reusable-ci.yml@v0.2.0
    with:
      kind: collection
      ansible_core: '["2.20", "2.21"]'
"""

DISCLOSE = """\
name: disclose
on:
  pull_request:
    types: [opened, synchronize, reopened, edited]
jobs:
  disclose:
    uses: Richard-Lynch/ansible-devkit/.github/workflows/reusable-disclose.yml@v0.2.0
    secrets:
      DISCLOSE_PATTERNS: ${{ secrets.DISCLOSE_PATTERNS }}
      DISCLOSE_ALLOW: ${{ secrets.DISCLOSE_ALLOW }}
"""

RELEASE = """\
name: release
on:
  push:
    branches: [main]
jobs:
  release:
    uses: Richard-Lynch/ansible-devkit/.github/workflows/reusable-release.yml@v0.2.0
    with:
      kind: collection
    secrets: inherit
"""

CHANGELOG = """\
# Changelog

## [1.2.0] — 2026-01-02

### Added

- something
"""


def write(root: Path, rel: str, text: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def stage(root: Path) -> None:
    """Rewrite export.manifest from the tree, then `git add -A` so ls-files lists the tree."""
    files = sorted(
        str(p.relative_to(root))
        for p in root.rglob("*")
        if p.is_file() and ".git" not in p.relative_to(root).parts
    )
    if "export.manifest" not in files:
        files = sorted([*files, "export.manifest"])
    write(root, "export.manifest", "# every path\n" + "\n".join(files) + "\n")
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    write(tmp_path, ".github/workflows/ci.yml", CI)
    write(tmp_path, ".github/workflows/disclose.yml", DISCLOSE)
    write(tmp_path, ".github/workflows/release.yml", RELEASE)
    write(tmp_path, ".github/actionlint.yaml", "# no ignores\n")
    write(tmp_path, "galaxy.yml", "---\nnamespace: ex\nname: demo\nversion: 1.2.0\n")
    write(tmp_path, "CHANGELOG.md", CHANGELOG)
    write(
        tmp_path,
        "plugins/module_utils/x.py",
        "# SPDX-License-Identifier: GPL-3.0-or-later\n",
    )
    shutil.copy(ROOT / "LICENSE", tmp_path / "LICENSE")
    stage(tmp_path)
    return tmp_path


def rules(root: Path) -> list[str]:
    return [p.rule for p in conform.conform(root)]


def test_fixture_conforms(repo: Path) -> None:
    assert conform.conform(repo) == []


# CONFORM-01 — the three callers exist and parse


def test_01_missing_caller_fails(repo: Path) -> None:
    (repo / ".github/workflows/release.yml").unlink()
    assert rules(repo) == ["CONFORM-01"]


def test_01_not_a_mapping_fails(repo: Path) -> None:
    write(repo, ".github/workflows/ci.yml", "- a list\n")
    assert rules(repo) == ["CONFORM-01"]


def test_01_document_marker_and_comments_pass(repo: Path) -> None:
    write(repo, ".github/workflows/ci.yml", "# a caller\n---\n" + CI)
    assert rules(repo) == []


# CONFORM-02 — the job id names the required check


def test_02_wrong_job_id_fails(repo: Path) -> None:
    write(repo, ".github/workflows/ci.yml", CI.replace("  ci:\n", "  build:\n"))
    got = rules(repo)
    assert got.count("CONFORM-02") == 2  # no `ci`, and an extra job `build`
    assert set(got) == {"CONFORM-02"}


def test_02_extra_job_fails(repo: Path) -> None:
    write(repo, ".github/workflows/ci.yml", CI + "  lint:\n    runs-on: ubuntu-latest\n")
    assert rules(repo) == ["CONFORM-02"]


def test_02_display_name_differs_passes(repo: Path) -> None:
    write(
        repo,
        ".github/workflows/ci.yml",
        CI.replace("  ci:\n", "  ci:\n    name: shared\n"),
    )
    assert rules(repo) == []


# CONFORM-03 — the job calls the matching ansible-devkit reusable workflow


def test_03_another_repository_fails(repo: Path) -> None:
    write(
        repo,
        ".github/workflows/ci.yml",
        CI.replace("Richard-Lynch/ansible-devkit", "x/y"),
    )
    assert rules(repo) == ["CONFORM-03"]


def test_03_wrong_reusable_fails(repo: Path) -> None:
    text = RELEASE.replace("reusable-release.yml", "reusable-ci.yml")
    write(repo, ".github/workflows/release.yml", text)
    assert rules(repo) == ["CONFORM-03"]


def test_03_local_reusable_without_the_file_fails(repo: Path) -> None:
    text = CI.replace(
        "Richard-Lynch/ansible-devkit/.github/workflows/reusable-ci.yml@v0.2.0",
        "./.github/workflows/reusable-ci.yml",
    )
    write(repo, ".github/workflows/ci.yml", text)
    assert rules(repo) == ["CONFORM-03"]


def test_03_local_reusable_with_the_file_passes(repo: Path) -> None:
    text = CI.replace(
        "Richard-Lynch/ansible-devkit/.github/workflows/reusable-ci.yml@v0.2.0",
        "./.github/workflows/reusable-ci.yml",
    )
    write(repo, ".github/workflows/ci.yml", text)
    write(repo, ".github/workflows/reusable-ci.yml", "name: reusable-ci\n")
    stage(repo)
    assert rules(repo) == []


# CONFORM-04 — the ref is a release tag


@pytest.mark.parametrize("ref", ["@main", "@v1", "@v0.2", "@v0.2.0-rc1", ""])
def test_04_not_a_release_tag_fails(repo: Path, ref: str) -> None:
    write(repo, ".github/workflows/disclose.yml", DISCLOSE.replace("@v0.2.0", ref))
    assert rules(repo) == ["CONFORM-04"]


def test_04_multi_digit_tag_passes(repo: Path) -> None:
    write(
        repo,
        ".github/workflows/disclose.yml",
        DISCLOSE.replace("@v0.2.0", "@v10.20.300"),
    )
    assert rules(repo) == []


# CONFORM-05 — kind matches the repository; ansible_core is a JSON list of "X.Y"


def test_05_kind_mismatch_fails(repo: Path) -> None:
    write(
        repo,
        ".github/workflows/release.yml",
        RELEASE.replace("kind: collection", "kind: python"),
    )
    assert rules(repo) == ["CONFORM-05"]


def test_05_kind_missing_fails(repo: Path) -> None:
    write(repo, ".github/workflows/ci.yml", CI.replace("      kind: collection\n", ""))
    assert rules(repo) == ["CONFORM-05"]


@pytest.mark.parametrize("cores", ["'[2.20, 2.21]'", "'2.21'", "'[]'", "'[\"2.21.1\"]'"])
def test_05_bad_ansible_core_fails(repo: Path, cores: str) -> None:
    text = CI.replace('\'["2.20", "2.21"]\'', cores)
    write(repo, ".github/workflows/ci.yml", text)
    assert rules(repo) == ["CONFORM-05"]


def test_05_ansible_core_omitted_passes(repo: Path) -> None:
    text = CI.replace('      ansible_core: \'["2.20", "2.21"]\'\n', "")
    write(repo, ".github/workflows/ci.yml", text)
    assert rules(repo) == []


def test_05_python_repository_passes(repo: Path) -> None:
    (repo / "galaxy.yml").unlink()
    write(repo, "pyproject.toml", '[project]\nname = "x"\nversion = "1.2.0"\n')
    for name, text in (("ci", CI), ("release", RELEASE)):
        text = text.replace("kind: collection", "kind: python")
        text = text.replace('      ansible_core: \'["2.20", "2.21"]\'\n', "")
        write(repo, f".github/workflows/{name}.yml", text)
    stage(repo)
    assert rules(repo) == []


# CONFORM-06 — secrets


def test_06_release_without_inherit_fails(repo: Path) -> None:
    write(
        repo,
        ".github/workflows/release.yml",
        RELEASE.replace("    secrets: inherit\n", ""),
    )
    assert rules(repo) == ["CONFORM-06"]


def test_06_disclose_missing_allow_fails(repo: Path) -> None:
    text = DISCLOSE.replace("      DISCLOSE_ALLOW: ${{ secrets.DISCLOSE_ALLOW }}\n", "")
    write(repo, ".github/workflows/disclose.yml", text)
    assert rules(repo) == ["CONFORM-06"]


def test_06_disclose_wrong_source_fails(repo: Path) -> None:
    text = DISCLOSE.replace("secrets.DISCLOSE_PATTERNS }}", "vars.DISCLOSE_PATTERNS }}")
    write(repo, ".github/workflows/disclose.yml", text)
    assert rules(repo) == ["CONFORM-06"]


def test_06_disclose_unspaced_expression_passes(repo: Path) -> None:
    text = DISCLOSE.replace("${{ secrets.DISCLOSE_PATTERNS }}", "${{secrets.DISCLOSE_PATTERNS}}")
    write(repo, ".github/workflows/disclose.yml", text)
    assert rules(repo) == []


# CONFORM-07 — triggers


def test_07_disclose_without_edited_fails(repo: Path) -> None:
    text = DISCLOSE.replace(", edited]", "]")
    write(repo, ".github/workflows/disclose.yml", text)
    assert rules(repo) == ["CONFORM-07"]


def test_07_disclose_default_types_fail(repo: Path) -> None:
    text = DISCLOSE.replace("    types: [opened, synchronize, reopened, edited]\n", "")
    write(repo, ".github/workflows/disclose.yml", text)
    assert rules(repo) == ["CONFORM-07"]


def test_07_ci_without_pull_request_fails(repo: Path) -> None:
    write(repo, ".github/workflows/ci.yml", CI.replace("  pull_request:\n", ""))
    assert rules(repo) == ["CONFORM-07"]


def test_07_release_on_another_branch_fails(repo: Path) -> None:
    write(repo, ".github/workflows/release.yml", RELEASE.replace("[main]", "[develop]"))
    assert rules(repo) == ["CONFORM-07"]


def test_07_reordered_extra_types_and_scalar_branch_pass(repo: Path) -> None:
    text = DISCLOSE.replace(
        "[opened, synchronize, reopened, edited]",
        "[edited, ready_for_review, reopened, synchronize, opened]",
    )
    write(repo, ".github/workflows/disclose.yml", text)
    write(repo, ".github/workflows/release.yml", RELEASE.replace("[main]", "main"))
    assert rules(repo) == []


# CONFORM-08 — LICENSE is GPL-3.0


def test_08_other_licence_fails(repo: Path) -> None:
    write(
        repo,
        "LICENSE",
        "MIT License\n\nPermission is hereby granted, free of charge...\n",
    )
    assert rules(repo) == ["CONFORM-08"]


def test_08_edited_gpl_fails(repo: Path) -> None:
    text = (ROOT / "LICENSE").read_text(encoding="utf-8").replace("Version 3", "Version 2", 1)
    write(repo, "LICENSE", text)
    assert rules(repo) == ["CONFORM-08"]


def test_08_rewrapped_crlf_gpl_passes(repo: Path) -> None:
    words = (ROOT / "LICENSE").read_text(encoding="utf-8").split()
    lines = [" ".join(words[i : i + 9]) for i in range(0, len(words), 9)]
    (repo / "LICENSE").write_bytes("\r\n".join(lines).encode())
    assert rules(repo) == []


# CONFORM-09 — a CHANGELOG section for the declared version


def test_09_no_section_for_version_fails(repo: Path) -> None:
    write(repo, "galaxy.yml", "---\nnamespace: ex\nname: demo\nversion: 1.3.0\n")
    assert rules(repo) == ["CONFORM-09"]


def test_09_empty_section_fails(repo: Path) -> None:
    write(
        repo,
        "CHANGELOG.md",
        "# Changelog\n\n## [1.2.0] — 2026-01-02\n\n## [1.1.0]\n\n- x\n",
    )
    assert rules(repo) == ["CONFORM-09"]


def test_09_prefix_version_is_not_a_match(repo: Path) -> None:
    write(repo, "CHANGELOG.md", CHANGELOG.replace("[1.2.0]", "[1.2.0.1]"))
    assert rules(repo) == ["CONFORM-09"]


def test_09_section_among_others_passes(repo: Path) -> None:
    text = "# Changelog\n\n## [Unreleased]\n\n- next\n\n" + CHANGELOG[len("# Changelog\n\n") :]
    write(repo, "CHANGELOG.md", text + "\n## [1.1.0] — 2025-01-01\n\n- old\n")
    assert rules(repo) == []


# CONFORM-10 — export.manifest equals git ls-files


def test_10_unlisted_tracked_file_fails(repo: Path) -> None:
    write(repo, "README.md", "# demo\n")
    subprocess.run(["git", "-C", str(repo), "add", "README.md"], check=True)
    got = conform.conform(repo)
    assert [p.rule for p in got] == ["CONFORM-10"] and "README.md" in got[0].message


def test_10_listed_untracked_file_fails(repo: Path) -> None:
    with (repo / "export.manifest").open("a", encoding="utf-8") as fh:
        fh.write("docs/gone.md\n")
    subprocess.run(["git", "-C", str(repo), "add", "export.manifest"], check=True)
    got = conform.conform(repo)
    assert [p.rule for p in got] == ["CONFORM-10"] and "docs/gone.md" in got[0].message


def test_10_untracked_file_on_disk_is_not_a_problem(repo: Path) -> None:
    write(repo, "scratch.txt", "not tracked, not listed\n")
    assert rules(repo) == []


def test_10_unordered_manifest_with_comments_passes(repo: Path) -> None:
    lines = (repo / "export.manifest").read_text(encoding="utf-8").splitlines()
    write(repo, "export.manifest", "\n".join(["# head", "", *reversed(lines[1:]), ""]))
    subprocess.run(["git", "-C", str(repo), "add", "export.manifest"], check=True)
    assert rules(repo) == []


def test_10_and_11_not_a_git_repository_cannot_run(repo: Path) -> None:
    shutil.rmtree(repo / ".git")
    got = conform.conform(repo)
    assert {p.rule for p in got if p.unchecked} == {"CONFORM-10", "CONFORM-11"}
    assert conform.exit_code(got) == 2


# CONFORM-11 — SPDX headers on Python source


def test_11_missing_header_fails(repo: Path) -> None:
    write(repo, "plugins/filter/f.py", '"""no header"""\n')
    stage(repo)
    assert rules(repo) == ["CONFORM-11"]


def test_11_header_too_late_fails(repo: Path) -> None:
    write(
        repo,
        "plugins/filter/f.py",
        "\n" * 6 + "# SPDX-License-Identifier: GPL-3.0-or-later\n",
    )
    stage(repo)
    assert rules(repo) == ["CONFORM-11"]


def test_11_other_licence_header_fails(repo: Path) -> None:
    write(repo, "plugins/filter/f.py", "# SPDX-License-Identifier: MIT\n")
    stage(repo)
    assert rules(repo) == ["CONFORM-11"]


def test_11_header_after_shebang_and_copyright_passes(repo: Path) -> None:
    text = (
        "#!/usr/bin/python\n# Copyright: (c) 2026, Someone\n"
        "# GNU General Public License v3.0+\n# SPDX-License-Identifier: GPL-3.0-or-later\n"
    )
    write(repo, "plugins/filter/f.py", text)
    write(repo, "notes.txt", "a non-Python file needs no header\n")
    stage(repo)
    assert rules(repo) == []


# CONFORM-12 — .github/actionlint.yaml


def test_12_missing_fails(repo: Path) -> None:
    (repo / ".github/actionlint.yaml").unlink()
    stage(repo)
    assert rules(repo) == ["CONFORM-12"]


def test_12_yml_spelling_fails(repo: Path) -> None:
    (repo / ".github/actionlint.yaml").rename(repo / ".github/actionlint.yml")
    stage(repo)
    assert rules(repo) == ["CONFORM-12"]


# The command: one line per problem, and the exit-code contract


def devkit_conform(path: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "ansible_devkit.cli", "conform", "--path", str(path)],
        capture_output=True,
        text=True,
        timeout=120,
    )


def test_cli_clean_exits_0(repo: Path) -> None:
    p = devkit_conform(repo)
    assert p.returncode == 0 and p.stdout == "", p.stdout + p.stderr
    assert "meets the standard" in p.stderr


def test_cli_one_line_per_problem_exits_1(repo: Path) -> None:
    (repo / ".github/actionlint.yaml").unlink()
    write(repo, ".github/workflows/ci.yml", CI.replace("@v0.2.0", "@main"))
    stage(repo)
    p = devkit_conform(repo)
    assert p.returncode == 1, p.stdout + p.stderr
    assert p.stdout.splitlines() == [
        ".github/workflows/ci.yml: CONFORM-04 `uses:` ref 'main' is not a release tag "
        "(vMAJOR.MINOR.PATCH); a branch moves",
        ".github/actionlint.yaml: CONFORM-12 missing",
    ]


def test_cli_not_a_git_repository_exits_2(repo: Path) -> None:
    shutil.rmtree(repo / ".git")
    p = devkit_conform(repo)
    assert p.returncode == 2 and "could not run" in p.stderr, p.stdout + p.stderr


def test_this_repository_conforms() -> None:
    p = devkit_conform(ROOT)
    assert p.returncode == 0, p.stdout + p.stderr
