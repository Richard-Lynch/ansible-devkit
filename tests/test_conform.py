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
"""

DISCLOSE_ALLOW = """\
# fixture exemptions
rfc1918-10  roles/demo/molecule/default/converge.yml  molecule default address of the fixture
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


ROLE_META = """\
---
galaxy_info:
  author: Someone
  description: >-
    Does one thing.
  license: GPL-3.0-or-later
dependencies: []
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
    write(tmp_path, ".disclose-allow", DISCLOSE_ALLOW)
    write(tmp_path, "galaxy.yml", "---\nnamespace: ex\nname: demo\nversion: 1.2.0\n")
    write(tmp_path, "CHANGELOG.md", CHANGELOG)
    write(
        tmp_path,
        "plugins/module_utils/x.py",
        "# SPDX-License-Identifier: GPL-3.0-or-later\n",
    )
    write(tmp_path, "roles/demo/README.md", "# demo\n")
    write(tmp_path, "roles/demo/meta/main.yml", ROLE_META)
    write(tmp_path, "roles/demo/tasks/main.yml", "---\n[]\n")
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


LOCAL_CI = CI.replace(
    "Richard-Lynch/ansible-devkit/.github/workflows/reusable-ci.yml@v0.2.0",
    "./.github/workflows/reusable-ci.yml",
)


def as_python_repo(root: Path, name: str) -> None:
    (root / "galaxy.yml").unlink()
    write(root, "pyproject.toml", f'[project]\nname = "{name}"\nversion = "1.2.0"\n')
    for wf, text in (("ci", LOCAL_CI), ("release", RELEASE)):
        text = text.replace("kind: collection", "kind: python")
        text = text.replace('      ansible_core: \'["2.20", "2.21"]\'\n', "")
        write(root, f".github/workflows/{wf}.yml", text)
    write(root, ".github/workflows/reusable-ci.yml", "name: reusable-ci\n")
    stage(root)


def test_03_local_reusable_in_another_repository_fails_even_with_the_file(repo: Path) -> None:
    # A repository's own "reusable" workflow is whatever it says it is, and receives its secrets.
    write(repo, ".github/workflows/ci.yml", LOCAL_CI)
    write(repo, ".github/workflows/reusable-ci.yml", "name: reusable-ci\n")
    stage(repo)
    assert rules(repo) == ["CONFORM-03"]


def test_03_local_reusable_in_a_lookalike_python_repository_fails(repo: Path) -> None:
    as_python_repo(repo, "ansible-devkit-fork")
    assert rules(repo) == ["CONFORM-03"]


def test_03_local_reusable_in_ansible_devkit_passes(repo: Path) -> None:
    as_python_repo(repo, "ansible-devkit")
    assert rules(repo) == []


def test_03_job_without_uses_fails(repo: Path) -> None:
    text = RELEASE.replace(
        "    uses: Richard-Lynch/ansible-devkit/.github/workflows/reusable-release.yml@v0.2.0\n",
        "",
    )
    write(repo, ".github/workflows/release.yml", text)
    assert rules(repo) == ["CONFORM-03"]


@pytest.mark.parametrize("value", ["null", "[]", "'a string'"])
def test_02_job_that_is_not_a_mapping_fails(repo: Path, value: str) -> None:
    text = DISCLOSE[: DISCLOSE.index("jobs:")] + f"jobs:\n  disclose: {value}\n"
    write(repo, ".github/workflows/disclose.yml", text)
    assert rules(repo) == ["CONFORM-02"]


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


def test_06_disclose_passing_secrets_fails(repo: Path) -> None:
    text = DISCLOSE + "    secrets:\n      DISCLOSE_PATTERNS: ${{ secrets.DISCLOSE_PATTERNS }}\n"
    write(repo, ".github/workflows/disclose.yml", text)
    assert rules(repo) == ["CONFORM-06"]


def test_06_disclose_inherit_fails(repo: Path) -> None:
    write(repo, ".github/workflows/disclose.yml", DISCLOSE + "    secrets: inherit\n")
    assert rules(repo) == ["CONFORM-06"]


def test_06_disclose_with_no_secrets_passes(repo: Path) -> None:
    write(repo, ".github/workflows/disclose.yml", DISCLOSE)
    assert rules(repo) == []


# CONFORM-14 — .disclose-allow


def test_14_missing_disclose_allow_fails(repo: Path) -> None:
    (repo / ".disclose-allow").unlink()
    stage(repo)
    assert rules(repo) == ["CONFORM-14"]


def test_14_line_without_reason_fails(repo: Path) -> None:
    write(repo, ".disclose-allow", "rfc1918-10 roles/demo/molecule/default/converge.yml\n")
    assert rules(repo) == ["CONFORM-14"]


def test_14_two_word_reason_fails(repo: Path) -> None:
    write(repo, ".disclose-allow", "rfc1918-10 roles/demo/x.yml too short\n")
    assert rules(repo) == ["CONFORM-14"]


@pytest.mark.parametrize("loc", ["*", "**", "tarball:*"])
def test_14_everywhere_location_fails(repo: Path, loc: str) -> None:
    write(repo, ".disclose-allow", f"rfc1918-10 {loc} molecule default address of the fixture\n")
    assert rules(repo) == ["CONFORM-14"]


def test_14_comment_only_file_passes(repo: Path) -> None:
    write(repo, ".disclose-allow", "# nothing exempted yet\n\n")
    assert rules(repo) == []


def test_14_near_miss_glob_location_passes(repo: Path) -> None:
    write(repo, ".disclose-allow", "mac roles/*/molecule/* synthetic MACs in the fixtures\n")
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


@pytest.mark.parametrize(
    "workflow, base, filt",
    [
        ("disclose", DISCLOSE, "    paths: [plugins/**]\n"),
        ("disclose", DISCLOSE, "    paths-ignore: [docs/**]\n"),
        ("disclose", DISCLOSE, "    branches: [main]\n"),
        ("disclose", DISCLOSE, "    branches-ignore: [release/**]\n"),
        ("ci", CI, "    paths-ignore: ['**.md']\n"),
        ("ci", CI, "    branches-ignore: [wip/**]\n"),
        ("ci", CI, "    tags: [v*]\n"),
    ],
)
def test_07_trigger_filter_beyond_the_standard_fails(
    repo: Path, workflow: str, base: str, filt: str
) -> None:
    # Insert the filter under the trigger the test names (pull_request for disclose, push for ci).
    key = "  pull_request:\n" if workflow == "disclose" else "    branches: [main]\n"
    text = base.replace(key, key + filt, 1)
    assert text != base
    write(repo, f".github/workflows/{workflow}.yml", text)
    assert rules(repo) == ["CONFORM-07"]


def test_07_ci_pull_request_filter_fails(repo: Path) -> None:
    text = CI.replace("  pull_request:\n", "  pull_request:\n    paths: [plugins/**]\n")
    write(repo, ".github/workflows/ci.yml", text)
    assert rules(repo) == ["CONFORM-07"]


def test_07_ci_narrowed_types_fail(repo: Path) -> None:
    text = CI.replace("  pull_request:\n", "  pull_request:\n    types: [opened]\n")
    write(repo, ".github/workflows/ci.yml", text)
    assert rules(repo) == ["CONFORM-07"]


def test_07_release_from_a_second_branch_fails(repo: Path) -> None:
    write(repo, ".github/workflows/release.yml", RELEASE.replace("[main]", "[main, next]"))
    assert rules(repo) == ["CONFORM-07"]


@pytest.mark.parametrize(
    "workflow, base", [("ci", CI), ("disclose", DISCLOSE), ("release", RELEASE)]
)
def test_07_if_on_the_caller_job_fails(repo: Path, workflow: str, base: str) -> None:
    key = f"  {workflow}:\n"
    text = base.replace(key, key + "    if: github.actor != 'someone'\n", 1)
    write(repo, f".github/workflows/{workflow}.yml", text)
    assert rules(repo) == ["CONFORM-07"]


def test_07_ci_explicit_default_types_and_extra_event_pass(repo: Path) -> None:
    text = CI.replace(
        "  pull_request:\n",
        "  pull_request:\n    types: [opened, synchronize, reopened]\n  workflow_dispatch:\n",
    )
    write(repo, ".github/workflows/ci.yml", text)
    assert rules(repo) == []


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


# CONFORM-13 — every role in a collection has a README.md and a galaxy_info.description


def test_13_role_without_readme_fails(repo: Path) -> None:
    (repo / "roles/demo/README.md").unlink()
    stage(repo)
    assert [str(p) for p in conform.conform(repo)] == [
        "roles/demo/README.md: CONFORM-13 missing (Galaxy rejects the import)"
    ]


def test_13_readme_in_the_wrong_place_fails(repo: Path) -> None:
    (repo / "roles/demo/README.md").rename(repo / "roles/demo/meta/README.md")
    stage(repo)
    assert rules(repo) == ["CONFORM-13"]


def test_13_role_without_meta_fails(repo: Path) -> None:
    (repo / "roles/demo/meta/main.yml").unlink()
    write(repo, "roles/demo/meta/argument_specs.yml", "---\nargument_specs: {}\n")
    stage(repo)
    assert [str(p) for p in conform.conform(repo)] == [
        "roles/demo/meta/main.yml: CONFORM-13 missing (galaxy_info.description is read from it)"
    ]


@pytest.mark.parametrize(
    "text",
    [
        "---\ndependencies: []\n",
        "---\ngalaxy_info:\n  author: Someone\n",
        "---\ngalaxy_info:\n  description: ''\n",
        "---\ngalaxy_info:\n  description: '   '\n",
        "---\ngalaxy_info:\n  description: [a, b]\n",
        "---\ngalaxy_info: a string\n",
        "",
    ],
    ids=[
        "no-galaxy_info",
        "no-description",
        "empty",
        "blank",
        "list",
        "not-a-mapping",
        "empty-file",
    ],
)
def test_13_no_description_fails(repo: Path, text: str) -> None:
    write(repo, "roles/demo/meta/main.yml", text)
    stage(repo)
    assert [str(p) for p in conform.conform(repo)] == [
        "roles/demo/meta/main.yml: CONFORM-13 has no non-empty `galaxy_info.description`"
    ]


def test_13_meta_that_does_not_parse_fails(repo: Path) -> None:
    write(repo, "roles/demo/meta/main.yml", "galaxy_info: [unclosed\n")
    stage(repo)
    problems = conform.conform(repo)
    assert [p.rule for p in problems] == ["CONFORM-13"]
    assert "does not parse" in problems[0].message and not problems[0].unchecked


def test_13_every_role_is_checked(repo: Path) -> None:
    write(repo, "roles/second/tasks/main.yml", "---\n[]\n")
    stage(repo)
    assert [str(p) for p in conform.conform(repo)] == [
        "roles/second/README.md: CONFORM-13 missing (Galaxy rejects the import)",
        "roles/second/meta/main.yml: CONFORM-13 missing (galaxy_info.description is read from it)",
    ]


def test_13_plain_description_and_extra_keys_pass(repo: Path) -> None:
    write(
        repo,
        "roles/demo/meta/main.yml",
        "---\ngalaxy_info:\n  role_name: demo\n  namespace: ex\n  description: Does one thing.\n"
        "  min_ansible_version: '2.19'\n  galaxy_tags: [a]\ndependencies: []\n",
    )
    stage(repo)
    assert rules(repo) == []


def test_13_collection_without_roles_passes(repo: Path) -> None:
    shutil.rmtree(repo / "roles")
    stage(repo)
    assert rules(repo) == []


def test_13_file_under_roles_is_not_a_role(repo: Path) -> None:
    write(repo, "roles/.keep", "")
    stage(repo)
    assert rules(repo) == []


def test_13_python_repository_is_not_checked(repo: Path) -> None:
    as_python_repo(repo, "x")
    (repo / "roles/demo/README.md").unlink()
    stage(repo)
    assert "CONFORM-13" not in rules(repo)


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
