# SPDX-License-Identifier: GPL-3.0-or-later
"""The `devkit` console script: dispatch, exit codes, and `check all` on this repository.

What matters here is the EXIT CODE contract, because that is what a task runner or CI reads: a single
check's code passes through unchanged, and `check all` never reports a check that could not run
as clean. The last case runs `check all` against this repository, which is the self-check the
package ships with — it fails the moment the repo stops satisfying its own rules.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from ansible_devkit import __version__

ROOT = Path(__file__).resolve().parents[1]


def devkit(*args: str, cwd: Path = ROOT, env: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "ansible_devkit.cli", *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=600,
    )


def test_version() -> None:
    p = devkit("--version")
    assert p.returncode == 0 and __version__ in p.stdout


def test_check_list_names_every_gate() -> None:
    p = devkit("check", "--list")
    assert p.returncode == 0
    for name in ("silent-guards", "molecule-verify", "boundary-lint", "docs-drift"):
        assert name in p.stdout
    assert "gate" in p.stdout


def test_unknown_check_is_a_usage_error() -> None:
    p = devkit("check", "no-such-check")
    assert p.returncode == 2
    assert "no check named" in p.stderr


def test_single_check_passes_its_exit_code_through(tmp_path: Path) -> None:
    # A repo with no devkit.toml: silent-guards has a REQUIRED key, so it exits 2, and so must we.
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    p = devkit("check", "silent-guards", cwd=tmp_path)
    assert p.returncode == 2, p.stderr
    assert "silent_guards.vendored_collections_dir" in p.stderr


def test_single_check_findings_exit_1(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "devkit.toml").write_text(
        '[silent_guards]\nvendored_collections_dir = "collections"\n'
    )
    play = tmp_path / "playbooks" / "x.yml"
    play.parent.mkdir()
    play.write_text(
        "---\n- hosts: all\n  tasks:\n    - name: Count\n      ansible.builtin.set_fact:\n"
        "        n: >-\n          {{ s.split('\\n') | length }}\n"
    )
    p = devkit("check", "silent-guards", "playbooks", cwd=tmp_path)
    assert p.returncode == 1, p.stdout + p.stderr
    assert "YAMLESC-01" in p.stdout


def test_check_all_refuses_extra_args() -> None:
    p = devkit("check", "all", "--whatever")
    assert p.returncode == 2
    assert "takes no extra arguments" in p.stderr


def test_check_all_on_this_repo_is_clean() -> None:
    p = devkit("check", "all")
    assert p.returncode == 0, p.stdout[-4000:] + p.stderr[-4000:]
    summary = p.stderr[p.stderr.rfind("devkit check all:") :]
    assert "FINDINGS" not in summary and "COULD NOT RUN" not in summary, summary
    # 13 gates: 12 run clean, and the one devkit.toml skips is printed with its reason.
    assert summary.count("clean") == 12, summary
    assert "SKIPPED        ha-restart-validated — this repository has no Ansible" in summary


def test_check_all_reports_could_not_run_as_2(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    p = devkit("check", "all", cwd=tmp_path)
    assert p.returncode == 2, p.stderr
    assert "COULD NOT RUN" in p.stderr


def test_check_all_skip_needs_a_reason_and_a_real_gate(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    cfg = tmp_path / "devkit.toml"
    cfg.write_text('[checks]\nskip = [{ name = "ha-restart-validated" }]\n')
    p = devkit("check", "all", cwd=tmp_path)
    assert p.returncode == 2 and "needs a reason" in p.stderr, p.stderr
    cfg.write_text('[checks]\nskip = [{ name = "trap-report", reason = "not a gate at all" }]\n')
    p = devkit("check", "all", cwd=tmp_path)
    assert p.returncode == 2 and "names no gate check" in p.stderr, p.stderr


def test_argspec_is_a_subcommand() -> None:
    p = devkit("argspec", "--help")
    assert p.returncode == 0 and "generate-all" in p.stdout


def test_disclose_is_a_subcommand() -> None:
    p = devkit("disclose", "--help")
    assert p.returncode == 0 and "--local" in p.stdout and "--since" in p.stdout
