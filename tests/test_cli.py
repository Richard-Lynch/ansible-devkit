# SPDX-License-Identifier: GPL-3.0-or-later
"""The `devkit` console script: dispatch, exit codes, and `check all` on this repository.

What matters here is the EXIT CODE contract, because that is what a task runner or CI reads: a single
check's code passes through unchanged, and `check all` never reports a check that could not run
as clean. The last case runs `check all` against this repository, which is the self-check the
package ships with — it fails the moment the repo stops satisfying its own rules.
"""

from __future__ import annotations

import os
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path

import pytest

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
    # Sixteen gates run clean, and the one devkit.toml skips is printed with its reason.
    assert summary.count("clean") == 16, summary
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


def git(
    root: Path, *args: str, hooks: bool = False, input: str = ""
) -> subprocess.CompletedProcess:
    override = [] if hooks else ["-c", "core.hooksPath=/dev/null"]
    return subprocess.run(
        ["git", *override, "-C", str(root), *args],
        input=input,
        capture_output=True,
        text=True,
        timeout=60,
    )


def command(binary: Path, root: Path, *args: str, input: str = "") -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(binary), "hooks", *args],
        cwd=root,
        input=input,
        capture_output=True,
        text=True,
        timeout=60,
    )


def report(result: subprocess.CompletedProcess) -> str:
    return result.stdout + result.stderr


@pytest.fixture
def repo(tmp_path: Path, installed_devkit: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    assert git(root, "init", "-q", "--initial-branch=main").returncode == 0
    assert git(root, "config", "user.name", "Devkit Fixture").returncode == 0
    assert git(root, "config", "user.email", "fixture" + "@" + "example.invalid").returncode == 0
    (root / "devkit.toml").write_text('[hooks]\npre_push = "true"\n')
    assert git(root, "add", "devkit.toml").returncode == 0
    assert git(root, "commit", "-qm", "initial").returncode == 0
    return root


def install(binary: Path, repo: Path) -> Path:
    result = command(binary, repo, "install")
    assert result.returncode == 0, report(result)
    result = command(binary, repo, "path")
    assert result.returncode == 0, report(result)
    return Path(result.stdout.strip())


def stage(repo: Path, name: str, text: str) -> None:
    path = repo / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    assert git(repo, "add", "--", name).returncode == 0


@contextmanager
def readonly_git(repo: Path):
    metadata = repo / ".git"
    modes = {path: path.stat().st_mode for path in [metadata, *metadata.rglob("*")]}
    try:
        for path, mode in modes.items():
            path.chmod(mode & ~0o222)
        yield
    finally:
        for path, mode in modes.items():
            path.chmod(mode)


def test_install_idempotent_absolute_owned_path(installed_devkit: Path, repo: Path) -> None:
    first = command(installed_devkit, repo, "install", "--repo-root", str(repo))
    second = command(installed_devkit, repo, "install")
    assert (first.returncode, first.stdout, first.stderr) == (0, "hooks: installed\n", "")
    assert (second.returncode, second.stdout, second.stderr) == (0, "hooks: ok\n", "")
    directory = Path(command(installed_devkit, repo, "path").stdout.strip())
    assert directory.is_absolute() and not directory.is_relative_to(repo)
    configured = git(repo, "config", "--local", "--get", "core.hooksPath").stdout.strip()
    assert configured == str(directory)
    assert all(os.access(directory / name, os.X_OK) for name in ("pre-commit", "pre-push"))
    assert not (repo / ".githooks").exists()


def test_install_ci_is_explicit_and_does_not_change_config(
    installed_devkit: Path, repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CI", "true")
    result = command(installed_devkit, repo, "install")
    assert (result.returncode, result.stdout, result.stderr) == (
        0,
        "hooks: skipped (CI=true)\n",
        "",
    )
    assert git(repo, "config", "--local", "--get", "core.hooksPath").returncode == 1


def test_linked_worktree_specific_install(
    installed_devkit: Path, repo: Path, tmp_path: Path
) -> None:
    linked = tmp_path / "linked"
    assert git(repo, "worktree", "add", "-qb", "linked", str(linked)).returncode == 0
    assert git(repo, "config", "extensions.worktreeConfig", "true").returncode == 0
    assert git(repo, "config", "core.hooksPath", "old-hooks").returncode == 0
    directory = install(installed_devkit, linked)
    result = command(installed_devkit, linked, "install")
    assert (result.returncode, result.stdout, result.stderr) == (0, "hooks: ok\n", "")
    configured = git(linked, "config", "--worktree", "--get", "core.hooksPath").stdout.strip()
    assert configured == str(directory)
    assert git(repo, "config", "--local", "--get", "core.hooksPath").stdout.strip() == "old-hooks"


def test_install_non_repo_error_is_one_line(installed_devkit: Path, tmp_path: Path) -> None:
    result = command(installed_devkit, tmp_path, "install")
    assert result.returncode == 2
    assert len(result.stdout.splitlines()) == 1 and not result.stderr


def test_install_refuses_toolchain_in_work_tree(installed_devkit: Path) -> None:
    root = installed_devkit.parent.parent
    assert git(root, "init", "-q").returncode == 0
    result = command(installed_devkit, root, "install")
    assert result.returncode == 2 and "outside the work tree" in result.stdout
    assert len(result.stdout.splitlines()) == 1


def test_readonly_metadata_without_hooks_is_exact_failure(
    installed_devkit: Path, repo: Path
) -> None:
    with readonly_git(repo):
        result = command(installed_devkit, repo, "install")
    assert (result.returncode, result.stdout, result.stderr) == (
        3,
        "hooks: NOT INSTALLED (read-only .git)\n",
        "",
    )


def test_precommit_refuses_staged_formatter_violation(installed_devkit: Path, repo: Path) -> None:
    install(installed_devkit, repo)
    stage(repo, "new.py", "answer=  42\n")
    result = git(repo, "commit", "-qm", "must fail", hooks=True)
    assert result.returncode != 0 and "would reformat" in report(result)
    assert git(repo, "log", "-1", "--format=%s").stdout.strip() == "initial"


def test_index_not_working_tree_or_untracked_files(installed_devkit: Path, repo: Path) -> None:
    stage(repo, "space [literal].py", "answer=42\n")
    (repo / "space [literal].py").write_text("answer = 42\n")
    result = command(installed_devkit, repo, "run", "pre-commit", "--staged")
    assert result.returncode != 0 and "would reformat" in report(result)
    stage(repo, "space [literal].py", "answer = 42\n")
    (repo / "space [literal].py").write_text("answer=42\n")
    (repo / "untracked.yml").write_text("not: [valid\n")
    result = command(installed_devkit, repo, "run", "pre-commit")
    assert result.returncode == 0, report(result)
    assert not list(repo.glob(".devkit-hooks-*"))


@pytest.mark.parametrize("text", ["key: [broken\n", "key: one\nkey: two\n", "key: value \n"])
def test_staged_yaml_lint_fails(installed_devkit: Path, repo: Path, text: str) -> None:
    stage(repo, "new.yaml", text)
    result = command(installed_devkit, repo, "run", "pre-commit", "--staged")
    assert result.returncode != 0 and "YAML lint" in report(result)


@pytest.mark.parametrize(
    ("name", "text", "finding"),
    [
        ("inventory.yml", "plugin: constructed\ngroups: {web: hostname}\n", "INVSTRICT-01"),
        ("tasks.yml", "- name: Unseal\n  command: steamos-readonly disable\n", "OUTSIDE a block"),
        (
            "pattern.py",
            'import re\n\npattern = re.compile(r"secret(?=[A-' + 'Z])", re.IGNORECASE)\n',
            "ICASE-01",
        ),
    ],
)
def test_fast_devkit_checks_are_staged_aware(
    installed_devkit: Path, repo: Path, name: str, text: str, finding: str
) -> None:
    stage(repo, name, text)
    (repo / name).write_text("" if name.endswith(".py") else "{}\n")
    result = command(installed_devkit, repo, "run", "pre-commit")
    assert result.returncode != 0 and finding in report(result), report(result)


def test_missing_black_fails_named(
    installed_devkit: Path, repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stage(repo, "clean.py", "answer = 42\n")
    tools = tmp_path / "minimal-tools"
    tools.mkdir()
    git_binary = subprocess.run(["/bin/sh", "-c", "command -v git"], capture_output=True, text=True)
    (tools / "git").symlink_to(git_binary.stdout.strip())
    monkeypatch.setenv("PATH", str(tools))
    result = command(installed_devkit, repo, "run", "pre-commit")
    assert result.returncode != 0 and "missing required tool: black" in report(result)


def test_killed_formatter_is_not_reported_as_clean(
    installed_devkit: Path, repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stage(repo, "clean.py", "answer = 42\n")
    tools = tmp_path / "killed-formatter"
    tools.mkdir()
    (tools / "black").write_text("#!/bin/sh\nkill -TERM $$\n")
    (tools / "black").chmod(0o755)
    monkeypatch.setenv("PATH", str(tools) + os.pathsep + os.environ["PATH"])
    result = command(installed_devkit, repo, "run", "pre-commit")
    assert result.returncode == 143 and "pre-commit FAILED" in report(result), report(result)


def test_readonly_preset_sandbox_still_refuses_violation_without_network(
    installed_devkit: Path, repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install(installed_devkit, repo)
    stage(repo, "new.py", "answer=42\n")
    network_guard = tmp_path / "network-guard"
    network_guard.mkdir()
    (network_guard / "sitecustomize.py").write_text(
        "import socket\n"
        "class OfflineSocket(socket.socket):\n"
        "    def connect(self, *args, **kwargs):\n"
        "        raise OSError('network disabled by test')\n"
        "    connect_ex = connect\n"
        "    sendto = connect\n"
        "socket.socket = OfflineSocket\n"
    )
    monkeypatch.setenv("PYTHONPATH", str(network_guard))
    prefix = installed_devkit.parent.parent
    before = {path: path.read_bytes() for path in prefix.rglob("*") if path.is_file()}
    metadata_before = {
        path: path.read_bytes() for path in (repo / ".git").rglob("*") if path.is_file()
    }
    with readonly_git(repo):
        result = command(installed_devkit, repo, "install")
        assert (result.returncode, result.stdout, result.stderr) == (0, "hooks: ok\n", "")
        result = git(repo, "hook", "run", "pre-commit", hooks=True)
        assert result.returncode != 0 and "would reformat" in report(result), report(result)
        result = command(installed_devkit, repo, "run", "pre-commit", "--staged")
        assert result.returncode != 0 and "would reformat" in report(result), report(result)
        assert command(installed_devkit, repo, "run", "pre-push").returncode == 0
    assert before == {path: path.read_bytes() for path in prefix.rglob("*") if path.is_file()}
    metadata_after = {
        path: path.read_bytes() for path in (repo / ".git").rglob("*") if path.is_file()
    }
    assert metadata_before == metadata_after
    assert not list(repo.glob(".devkit-hooks-*"))


def remote(repo: Path, tmp_path: Path) -> Path:
    destination = tmp_path / "remote.git"
    assert git(repo, "init", "--bare", "-q", str(destination)).returncode == 0
    assert git(repo, "remote", "add", "origin", str(destination)).returncode == 0
    return destination


def test_failing_gate_refuses_real_push_and_preserves_status(
    installed_devkit: Path, repo: Path, tmp_path: Path
) -> None:
    install(installed_devkit, repo)
    destination = remote(repo, tmp_path)
    (repo / "devkit.toml").write_text('[hooks]\npre_push = "exit 17"\n')
    result = command(installed_devkit, repo, "run", "pre-push")
    assert result.returncode == 17, report(result)
    result = git(repo, "push", "origin", "main", hooks=True)
    assert result.returncode != 0 and "FAILED (exit 17)" in report(result), report(result)
    assert git(destination, "show-ref", "--verify", "refs/heads/main").returncode != 0


def test_clean_commit_and_push_pass(installed_devkit: Path, repo: Path, tmp_path: Path) -> None:
    install(installed_devkit, repo)
    stage(repo, "clean.py", "answer = 42\n")
    stage(repo, "clean.yaml", "---\nkey: value\n")
    result = git(repo, "commit", "-qm", "clean", hooks=True)
    assert result.returncode == 0, report(result)
    remote(repo, tmp_path)
    result = git(repo, "push", "origin", "main", hooks=True)
    assert result.returncode == 0 and "pre-push passed" in report(result), report(result)


def test_unchanged_tree_push_skips_failing_gate(installed_devkit: Path, repo: Path) -> None:
    old = git(repo, "rev-parse", "HEAD").stdout.strip()
    assert git(repo, "commit", "--allow-empty", "-qm", "empty").returncode == 0
    new = git(repo, "rev-parse", "HEAD").stdout.strip()
    (repo / "devkit.toml").write_text('[hooks]\npre_push = "exit 17"\n')
    for updates in ("", f"refs/heads/main {new} refs/heads/main {old}\n"):
        result = command(installed_devkit, repo, "run", "pre-push", "--from-git", input=updates)
        assert result.returncode == 0, report(result)
        assert result.stdout == "hooks: pre-push skipped (push changes no files)\n"


def test_unknown_remote_object_does_not_skip(installed_devkit: Path, repo: Path) -> None:
    local = git(repo, "rev-parse", "HEAD").stdout.strip()
    result = command(
        installed_devkit,
        repo,
        "run",
        "pre-push",
        "--from-git",
        input=f"refs/heads/main {local} refs/heads/main {'1' * 40}\n",
    )
    assert result.returncode != 0 and "skipped" not in report(result)


def test_default_make_lint_and_missing_gate_tool_fail_named(
    installed_devkit: Path, repo: Path
) -> None:
    (repo / "devkit.toml").write_text("")
    (repo / "Makefile").write_text("lint:\n\t@exit 9\n")
    result = command(installed_devkit, repo, "run", "pre-push")
    assert result.returncode != 0 and "running make lint" in report(result), report(result)
    (repo / "devkit.toml").write_text('[hooks]\npre_push = "devkit-missing-tool"\n')
    result = command(installed_devkit, repo, "run", "pre-push")
    assert result.returncode == 127 and "devkit-missing-tool" in report(result)


def test_default_devkit_check_all_is_not_a_silent_pass(installed_devkit: Path, repo: Path) -> None:
    (repo / "devkit.toml").write_text("")
    result = command(installed_devkit, repo, "run", "pre-push")
    assert result.returncode != 0 and "running devkit check all" in report(result), report(result)


def test_host_git_must_explicitly_disable_hooks(installed_devkit: Path, repo: Path) -> None:
    install(installed_devkit, repo)
    stage(repo, "agent.py", "answer=42\n")
    unsafe = git(repo, "commit", "-qm", "host must not run this", hooks=True)
    assert unsafe.returncode != 0 and "pre-commit FAILED" in report(unsafe), report(unsafe)
    host = git(repo, "commit", "-qm", "host metadata operation")
    assert host.returncode == 0 and "pre-commit" not in report(host), report(host)


def test_shim_uses_pinned_devkit_not_path(
    installed_devkit: Path, repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install(installed_devkit, repo)
    hostile = tmp_path / "hostile-bin"
    hostile.mkdir()
    (hostile / "devkit").write_text("#!/bin/sh\nprintf 'wrong devkit\\n'\nexit 99\n")
    (hostile / "devkit").chmod(0o755)
    monkeypatch.setenv("PATH", str(hostile) + os.pathsep + os.environ["PATH"])
    stage(repo, "clean.py", "answer = 42\n")
    result = git(repo, "hook", "run", "pre-commit", hooks=True)
    assert result.returncode == 0 and "wrong devkit" not in report(result), report(result)
