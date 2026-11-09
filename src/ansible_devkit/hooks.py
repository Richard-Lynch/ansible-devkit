# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline Git gates; hook entrypoints belong to the installed devkit, not the repository."""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

from ansible_devkit.checks import BY_NAME


class HookError(Exception):
    pass


def hooks_path() -> Path:
    return Path(__file__).resolve().with_name("git_hooks").resolve()


def _git(root: Path, *args: str, allowed: tuple[int, ...] = (0,)) -> subprocess.CompletedProcess:
    try:
        result = subprocess.run(
            ["git", "--literal-pathspecs", "-c", "core.fsmonitor=false", "-C", str(root), *args],
            capture_output=True,
            env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"},
            check=False,
        )
    except FileNotFoundError as exc:
        raise HookError("missing required tool: git") from exc
    if result.returncode not in allowed:
        detail = result.stderr.decode(errors="replace").strip()
        raise HookError(detail or f"git {args[0]} exited {result.returncode}")
    return result


def _root(start: Path) -> Path:
    return Path(_git(start, "rev-parse", "--show-toplevel").stdout.decode().strip()).resolve()


def _writable(path: Path) -> bool:
    return bool(path.stat().st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)) and os.access(
        path, os.W_OK
    )


def install(start: Path) -> tuple[str, int]:
    if os.environ.get("CI") == "true":
        return "hooks: skipped (CI=true)", 0
    root = _root(start)
    directory = hooks_path()
    if directory.is_relative_to(root):
        raise HookError("install devkit outside the work tree (a non-editable, trusted toolchain)")
    binary = directory.parents[4] / "bin" / "devkit"
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise HookError(f"missing required tool: pinned devkit ({binary})")
    if binary.resolve().is_relative_to(root):
        raise HookError("the pinned devkit binary must be outside the work tree")
    for name in ("pre-commit", "pre-push"):
        if not os.access(directory / name, os.X_OK):
            raise HookError(f"missing executable hook: {name}")
    current = _git(root, "config", "--get", "core.hooksPath", allowed=(0, 1))
    if current.stdout.decode().strip() == str(directory):
        return "hooks: ok", 0
    worktree = _git(root, "config", "--bool", "extensions.worktreeConfig", allowed=(0, 1))
    per_worktree = worktree.stdout.strip() == b"true"
    config_name = "config.worktree" if per_worktree else "config"
    config = Path(_git(root, "rev-parse", "--git-path", config_name).stdout.decode().strip())
    if not config.is_absolute():
        config = root / config
    if not _writable(config.parent) or (config.exists() and not _writable(config)):
        return "hooks: NOT INSTALLED (read-only .git)", 3
    result = _git(
        root,
        "config",
        "--worktree" if per_worktree else "--local",
        "core.hooksPath",
        str(directory),
        allowed=(0, 1, 2, 3, 4, 5, 6, 128),
    )
    if result.returncode:
        message = result.stderr.decode(errors="replace")
        if "Read-only file system" in message or "Permission denied" in message:
            return "hooks: NOT INSTALLED (read-only .git)", 3
        raise HookError(message.strip() or "cannot set core.hooksPath")
    return "hooks: installed", 0


def _environment(scratch: Path) -> dict[str, str]:
    return {
        **{name: value for name, value in os.environ.items() if name != "DEVKIT_ROOT"},
        "PATH": str(hooks_path().parents[4] / "bin") + os.pathsep + os.environ.get("PATH", ""),
        "PYTHONDONTWRITEBYTECODE": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "UV_OFFLINE": "1",
        "UV_NO_SYNC": "1",
        "PIP_NO_INDEX": "1",
        "TMPDIR": str(scratch),
        "TMP": str(scratch),
        "TEMP": str(scratch),
        "XDG_CACHE_HOME": str(scratch / "cache"),
        "UV_CACHE_DIR": str(scratch / "uv"),
        "BLACK_CACHE_DIR": str(scratch / "black"),
        "ANSIBLE_LOCAL_TEMP": str(scratch / "ansible"),
    }


def _run(command: list[str], root: Path, env: dict[str, str], source: bytes | None = None) -> int:
    try:
        status = subprocess.run(command, cwd=root, env=env, input=source, check=False).returncode
    except FileNotFoundError as exc:
        raise HookError(f"missing required tool: {command[0]}") from exc
    return status if status >= 0 else 128 - status


def _yaml_lint(path: Path) -> list[str]:
    try:
        from ruamel.yaml import YAML
    except ImportError as exc:
        raise HookError("missing required tool: ruamel.yaml (YAML lint)") from exc
    from ruamel.yaml.error import YAMLError

    text = path.read_text(encoding="utf-8")
    findings = []
    try:
        list(YAML(typ="rt").load_all(text))
    except YAMLError as exc:
        findings.append(f"{path}: YAML lint: {exc}")
    for number, line in enumerate(text.splitlines(), 1):
        if line.rstrip(" \t") != line:
            findings.append(f"{path}:{number}: YAML lint: trailing whitespace")
        if "\t" in line[: len(line) - len(line.lstrip())]:
            findings.append(f"{path}:{number}: YAML lint: tab indentation")
    if text and not text.endswith("\n"):
        findings.append(f"{path}: YAML lint: missing final newline")
    return findings


def pre_commit(root: Path, scratch: Path) -> int:
    unresolved = _git(
        root, "diff", "--no-ext-diff", "--no-textconv", "--name-only", "--diff-filter=U", "-z"
    ).stdout
    if unresolved:
        raise HookError("resolve the unmerged index before running pre-commit")
    changed = _git(
        root,
        "diff",
        "--cached",
        "--no-ext-diff",
        "--no-textconv",
        "--name-only",
        "--diff-filter=ACMRT",
        "--no-renames",
        "-z",
    ).stdout
    names = [os.fsdecode(name) for name in changed.split(b"\0") if name]
    names = [name for name in names if Path(name).suffix in (".py", ".yml", ".yaml")]
    if not names:
        print("hooks: pre-commit skipped (no staged YAML/Python files)")
        return 0
    snapshot = scratch / "index"
    snapshot.mkdir()
    (snapshot / "devkit.toml").write_text('[regex_anchors]\npaths = ["."]\nexclude_prefixes = []\n')
    python_files = []
    yaml_files = []
    for name in names:
        path = snapshot / name
        if not path.resolve().is_relative_to(snapshot):
            raise HookError(f"unsafe staged path: {name!r}")
        entry = _git(root, "ls-files", "--stage", "-z", "--", name).stdout
        if not entry.startswith((b"100644 ", b"100755 ")):
            raise HookError(f"staged YAML/Python must be regular files: {name!r}")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(_git(root, "cat-file", "blob", f":{name}").stdout)
        (python_files if path.suffix == ".py" else yaml_files).append(path)
    env = _environment(scratch)
    status = 0
    if python_files:
        black = shutil.which("black", path=env["PATH"])
        if black is None:
            raise HookError("missing required tool: black")
        for path in python_files:
            name = path.relative_to(snapshot).as_posix()
            status = max(
                status,
                _run(
                    [
                        black,
                        "--check",
                        "--diff",
                        "--workers",
                        "1",
                        "--stdin-filename",
                        name,
                        "-",
                    ],
                    root,
                    env,
                    path.read_bytes(),
                ),
            )
    for path in yaml_files:
        findings = _yaml_lint(path)
        for finding in findings:
            print(finding.replace(str(snapshot) + "/", ""))
        if findings:
            status = max(status, 1)
    checks = []
    if yaml_files:
        checks.extend(
            [("inventory-strict", []), ("rootfs-seal", [str(path) for path in yaml_files])]
        )
    if python_files:
        checks.append(("regex-anchors", [str(path) for path in python_files]))
    for name, paths in checks:
        status = max(
            status,
            _run(
                [sys.executable, str(BY_NAME[name].path), *paths],
                snapshot,
                {**env, "DEVKIT_ROOT": str(snapshot)},
            ),
        )
    print("hooks: pre-commit " + ("passed" if status == 0 else "FAILED"))
    return status


def _push_changes(root: Path, updates: str) -> bool:
    changed = False
    for line in updates.splitlines():
        fields = line.split()
        if len(fields) != 4:
            raise HookError("invalid pre-push ref update (expected four fields)")
        _, local, _, remote = fields
        if not all(re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", value) for value in (local, remote)):
            raise HookError("invalid pre-push object id")
        if set(local) == {"0"} or set(remote) == {"0"}:
            revision = remote if set(local) == {"0"} else local
            changed |= bool(_git(root, "ls-tree", "-r", "--name-only", revision).stdout)
        else:
            result = _git(
                root,
                "diff",
                "--quiet",
                "--no-ext-diff",
                "--no-textconv",
                remote,
                local,
                "--",
                allowed=(0, 1),
            )
            changed |= result.returncode == 1
    return changed


def pre_push(root: Path, scratch: Path, updates: str | None) -> int:
    if updates is not None and not _push_changes(root, updates):
        print("hooks: pre-push skipped (push changes no files)")
        return 0
    config_path = root / "devkit.toml"
    config = tomllib.loads(config_path.read_text()) if config_path.exists() else {}
    settings = config.get("hooks", {})
    if not isinstance(settings, dict):
        raise HookError("devkit.toml: hooks must be a table")
    command = settings.get("pre_push")
    if command is not None and (not isinstance(command, str) or not command.strip()):
        raise HookError("devkit.toml: hooks.pre_push must be a non-empty command string")
    if command is None:
        makefile = root / "Makefile"
        has_lint = makefile.is_file() and re.search(
            r"^(?:[\w.-]+[ \t]+)*lint(?:[ \t]+[\w.-]+)*[ \t]*:(?!=)",
            makefile.read_text(),
            re.MULTILINE,
        )
        command = "make lint" if has_lint else None
    print(f"hooks: pre-push running {command or 'devkit check all'}", flush=True)
    args = (
        ["/bin/sh", "-c", command]
        if command
        else [sys.executable, "-m", "ansible_devkit.cli", "check", "all"]
    )
    env = _environment(scratch)
    for name in _git(root, "rev-parse", "--local-env-vars").stdout.decode().splitlines():
        env.pop(name, None)
    status = _run(args, root, env, b"")
    print("hooks: pre-push " + ("passed" if status == 0 else f"FAILED (exit {status})"))
    return status


def run(event: str, updates: str | None = None) -> int:
    root = _root(Path.cwd())
    with tempfile.TemporaryDirectory(prefix=".devkit-hooks-", dir=root) as directory:
        scratch = Path(directory)
        return (
            pre_commit(root, scratch) if event == "pre-commit" else pre_push(root, scratch, updates)
        )
