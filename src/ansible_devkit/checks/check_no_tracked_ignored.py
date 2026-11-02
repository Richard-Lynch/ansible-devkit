#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""check_no_tracked_ignored — fail if git TRACKS a path that .gitignore says to ignore.

WHY THIS EXISTS
    The shape this catches: a vendored collections directory (`collections.galaxy`) gets committed
    as an absolute symlink pointing at ITSELF:

        collections.galaxy -> /home/someone/src/repo/collections.galaxy

    `ansible.cfg` expects that path to be a DIRECTORY of galaxy-installed collections, so the commit
    replaces the directory with a self-referential link. Every local `ansible-lint` run then dies
    with "Symlink loop from .../collections.galaxy", in the main checkout and in every worktree,
    and a vendored collection whose absence aborts a play silently vanishes from the collections
    path.

    Two things let it survive review, and both are the point of this check:

      - **`.gitignore` did not stop it.** The path is listed TWICE (`collections.galaxy/` and
        `collections.galaxy`), but gitignore only governs UNTRACKED files: once something is tracked,
        every ignore rule for it is inert. `git check-ignore` reports nothing for a tracked path, so
        the usual way of asking "is this ignored?" answers no and looks reassuring.
      - **CI could not see it.** The symlink is ABSOLUTE and points into the owner's home directory,
        which does not exist on a GitHub-hosted runner — so on CI it is a harmless dangling link,
        while on the machine that matters it is a loop. CI went green.

    That combination — inert ignore rule, plus a defect that only reproduces off-CI — is exactly the
    silent-guard shape, so it gets a check rather than a note.

WHAT IT CHECKS
    TRACKIGNORE-01  a tracked path that the ignore rules would otherwise exclude.
    SELFLINK-01     a tracked symlink whose target resolves to itself, or is absolute (neither can
                    be right in a repo that is cloned to a different path on every machine).

USAGE
    devkit check no-tracked-ignored

Exit codes: 0 = clean, 1 = at least one finding, 2 = usage/internal error.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _devkit_config  # noqa: E402

# The repo checked is the one the command runs in (devkit.toml's root rule), never the one this
# file happens to sit in: installed as a package, that would be site-packages.
REPO = _devkit_config.find_root()


def _git(*args: str) -> str:
    cp = subprocess.run(["git", *args], cwd=REPO, capture_output=True, text=True, timeout=120)
    return cp.stdout


def main() -> int:
    problems: list[str] = []

    tracked = [ln for ln in _git("ls-files").splitlines() if ln.strip()]
    if not tracked:
        print("check_no_tracked_ignored: no tracked files found — not a git repo?")
        return 2

    # `git check-ignore --no-index` answers "would the ignore rules exclude this path?" REGARDLESS
    # of whether it is tracked. Without --no-index, git reports nothing for a tracked path, which is
    # precisely why the collections.galaxy commit looked fine.
    cp = subprocess.run(
        ["git", "check-ignore", "--no-index", "--stdin"],
        cwd=REPO,
        input="\n".join(tracked),
        capture_output=True,
        text=True,
        timeout=120,
    )
    ignored_but_tracked = [ln.strip() for ln in cp.stdout.splitlines() if ln.strip()]

    for path in sorted(ignored_but_tracked):
        problems.append(
            f"{path}: [TRACKIGNORE-01] this path is TRACKED but the ignore rules say to exclude it. "
            "Ignore rules only govern UNTRACKED files, so once a path is committed every rule for "
            "it is inert and `git check-ignore <path>` reports nothing — which is how a "
            "self-referential symlink to a vendored directory ships and breaks ansible-lint "
            "locally while CI stays green. Fix: `git rm --cached "
            f"{path}` (keeps the file on disk), then commit."
        )

    # Tracked symlinks: an absolute target cannot be right in a repo cloned to a different path on
    # every machine, and a self-resolving target is a symlink loop.
    for ln in _git("ls-files", "-s").splitlines():
        if not ln.startswith("120000"):
            continue
        path = ln.split("\t", 1)[1].strip()
        target = (REPO / path).readlink() if (REPO / path).is_symlink() else None
        if target is None:
            continue
        if target.is_absolute():
            problems.append(
                f"{path}: [SELFLINK-01] tracked symlink with an ABSOLUTE target "
                f"('{target}'). The repo is cloned to a different path on every machine, so an "
                "absolute link is either a loop (on the authoring machine) or dangling "
                "(everywhere else) — and the dangling case is why CI cannot catch it. Use a "
                "relative target, or do not track the link."
            )
        elif (REPO / path).resolve() == (REPO / path).parent.resolve() / path.split("/")[-1]:
            # A relative link that resolves back to itself.
            problems.append(
                f"{path}: [SELFLINK-01] tracked symlink resolves to ITSELF — a symlink loop. "
                "Every tool that walks the tree (ansible-lint, yamllint, black) dies on it."
            )

    for pr in problems:
        print(f"FAIL {pr}")
    print(
        f"\ncheck_no_tracked_ignored: {len(problems)} FAIL across {len(tracked)} tracked file(s)."
    )
    return 1 if problems else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # pragma: no cover
        print(f"check_no_tracked_ignored: internal error: {exc}", file=sys.stderr)
        sys.exit(2)
