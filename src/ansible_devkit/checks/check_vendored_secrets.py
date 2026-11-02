#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Fail if a file vendored under roles/*/files/ looks like it carries a credential.

THE BUG THIS CATCHES. Fetching a device's config into the repo to make a rebuild reproducible is
a good instinct, and it is exactly how a plaintext password gets committed: GUI installers store
whatever the wizard asked for, and "capture the config" does not prompt anyone to read it first.

Deliberately narrow: it matches credential-shaped KEY names in structured config, not arbitrary
high-entropy strings, because an entropy heuristic on a repo full of MAC addresses, hashes and
appids is all false positives and gets disabled within a week.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

# Key names that mean "this value is a secret". Matched as a WHOLE WORD in either naming
# convention, so `sudoPassword` and `api_token` hit while `compass` and `passthrough` do not.
#
# WHY TWO BRANCHES RATHER THAN ONE IGNORECASE PATTERN: `re.IGNORECASE` makes `[A-Z]` match
# lowercase too, so a camelCase boundary written as `(?=[A-Z])` under that flag accepts ANY
# following letter — i.e. it imposes no boundary at all. The original single-pattern version did
# exactly that and matched `passthrough`, `compass` and `tokenizer`. The snake_case branch is
# case-insensitive (it is delimited by `_`/`-`/anchors, which case cannot blur); the camelCase
# branch must stay case-SENSITIVE for its boundary to mean anything.
_SNAKE = (
    r"(?:password|passwd|pass|secret|token|apikey|api_key|api-key"
    r"|credentials|credential|private_key|privkey)"
)
_CAMEL = (
    r"(?:Password|Passwd|Pass|Secret|Token|ApiKey" r"|Credentials|Credential|PrivateKey|PrivKey)"
)

SECRET_KEYS = re.compile(
    r"(?i:(?:^|[_\-])" + _SNAKE + r"(?:$|[_\-]))"
    r"|(?:^|(?<=[a-z0-9]))" + _CAMEL + r"(?:$|(?=[A-Z0-9_\-]))"
)

# A key naming a PATH to a secret, or the command that fetches one, is fine to vendor — the
# value is a filename, not the credential. The docstring promised this exemption; without it
# `password_file` failed the build, which is how a useful check earns a blanket suppression.
PATHISH = re.compile(
    r"(?i)(?:^|[_\-])(?:file|path|dir|cmd|command|helper|prog|program|env)$"
    r"|(?:File|Path|Dir|Cmd|Command|Helper|Env)$"
)


def is_secret_key(key: str) -> bool:
    """True if `key` names a credential rather than a path to one."""
    return bool(SECRET_KEYS.search(key)) and not PATHISH.search(key)


# Values that are obviously not secrets, so a declared-but-empty field does not fail the build.
# Compared case-insensitively: a JSON `null` arrives here as the Python string "None" (str(None)),
# which a literal lowercase "none" in this set silently failed to match.
BENIGN = {"", "null", "none", "false", "true", "0", "changeme", "replace_me", "xxx", "todo"}

SCAN_SUFFIXES = {".json", ".ini", ".conf", ".cfg", ".yaml", ".yml", ".env", ".sh"}


def _walk_json(obj, path=""):
    """Yield (key_path, key, value) for every scalar in a JSON document."""
    if isinstance(obj, dict):
        for key, value in obj.items():
            here = f"{path}.{key}" if path else key
            if isinstance(value, (dict, list)):
                yield from _walk_json(value, here)
            else:
                yield here, key, value
    elif isinstance(obj, list):
        for i, value in enumerate(obj):
            yield from _walk_json(value, f"{path}[{i}]")


def check(path: Path) -> list[str]:
    problems: list[str] = []
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return problems

    if path.suffix == ".json":
        try:
            for keypath, key, value in _walk_json(json.loads(text)):
                text_value = str(value).strip()
                # A Jinja expression is the CORRECT pattern — a reference resolved at run time,
                # not a stored secret. Flagging it would punish the fix and get the check
                # switched off.
                if text_value.startswith("{{") or text_value.lower() in BENIGN:
                    continue
                if is_secret_key(key):
                    problems.append(f"{path}: '{keypath}' looks like a credential")
        except ValueError:
            pass
        return problems

    # Line-oriented formats: KEY=value, KEY: value, and "KEY" "value" (the last used by
    # Samba/rclone-style configs). `export ` / `set ` are stripped first: shell is in
    # SCAN_SUFFIXES and `export SUDO_PASSWORD=...` is the idiomatic way a credential reaches a
    # script, but a bare `^\s*` anchor never matched it.
    for n, line in enumerate(text.splitlines(), 1):
        stripped = re.sub(r"^\s*(?:export|set|declare(?:\s+-\w+)*)\s+", "", line)
        m = re.match(
            # KEY=value / KEY: value — the key may be bare or quoted.
            r'^\s*["\']?([A-Za-z0-9_\-]+)["\']?\s*[:=]\s*["\']?([^"\'\s#]+)'
            # "KEY" "value" — whitespace-separated ONLY when the key is quoted. A bare
            # `word word` separator matched Python's `pass" "$1"` inside an embedded heredoc
            # in a real vendored script; requiring the quotes keeps the Samba/rclone form
            # without treating every two adjacent words in a shell script as a setting.
            r'|^\s*["\']([A-Za-z0-9_\-]+)["\']\s+["\']?([^"\'\s#]+)',
            stripped,
        )
        if not m:
            continue
        key = m.group(1) or m.group(3)
        value = m.group(2) or m.group(4)
        # A Jinja expression is the CORRECT pattern — it is a reference, not a secret.
        if value.startswith("{{") or value.strip().lower() in BENIGN:
            continue
        if is_secret_key(key):
            problems.append(f"{path}:{n}: '{key}' looks like a credential")
    return problems


# Directories that are DEPENDENCY TREES or BUILD OUTPUT, never vendored config.
#
# This checker walks the FILESYSTEM, not the git index, so a gitignored directory is still
# scanned — the same trap yamllint/ansible-lint fall into with a worktree, and
# check_regex_anchors.py with its own skip prefix.
#
# A vendored web app's node_modules produces a hundred FAILs, every one a false positive from
# TypeScript's localised diagnostic catalogues ("Unexpected_token_1012" matches the
# credential-key heuristic). A checker that reports a hundred findings nobody can action is one
# everybody learns to skip — which is how a REAL vendored secret gets scrolled past.
#
# These are matched as PATH SEGMENTS, not substrings, so a legitimately vendored file whose
# name merely contains "dist" (e.g. `files/distribution.conf`) is still scanned.
SKIP_DIR_NAMES = frozenset({"node_modules", "dist", ".vite", "__pycache__", ".git"})


def _skipped(path: Path) -> bool:
    """True when any PATH SEGMENT is a dependency tree or build output directory."""
    return any(part in SKIP_DIR_NAMES for part in path.parts)


def main(argv: list[str]) -> int:
    args = [Path(a) for a in argv[1:]] or [Path("roles")]
    targets: list[Path] = []
    for arg in args:
        if arg.is_dir():
            targets.extend(
                p
                for p in arg.rglob("*")
                if p.is_file()
                and p.suffix in SCAN_SUFFIXES
                and "/files/" in str(p)
                and not _skipped(p)
            )
        elif arg.is_file():
            # An explicitly named file is ALWAYS scanned, even inside a skipped directory: the
            # skip exists to keep a directory walk from drowning in dependencies, not to make a
            # file unscannable when someone points the checker straight at it.
            targets.append(arg)

    problems: list[str] = []
    for path in targets:
        problems.extend(check(path))

    for p in problems:
        print(f"FAIL {p}")
    print(
        f"\ncheck_vendored_secrets: {len(problems)} FAIL across {len(targets)} vendored "
        f"file(s) scanned."
    )
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
