#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""boundary_lint — enforce the engine/data boundary (rules: docs/RULES.md, `boundary-lint`).

Flags real estate facts (private IPs, real hostnames/domains, public IPs: the patterns listed in
devkit.toml [boundary]) hardcoded in ENGINE paths (roles/ + playbooks/ logic). DATA paths
(inventories except example/, generated/, vars/, secrets) and docs/ are exempt — they legitimately
describe the estate.

Modes:
  --warn     (default) report violations, exit 0  — for the current backlog
  --enforce  report violations, exit 1 if any     — wire this on once a path is clean

Usage:
  scripts/boundary_lint.py [--enforce] [PATH ...]
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _devkit_config  # noqa: E402

# The ENGINE: everything below reads its estate facts from devkit.toml [boundary], so this file
# names no estate. `patterns` (a list of {regex, label}) is REQUIRED — a boundary check with no
# facts to look for reports every file clean. What counts as ENGINE (scanned) vs DATA (exempt):
# engine_roots, exempt_substr (per-estate generated artifacts, estate vars, the sanitized example
# inventory, vendored trees) and exempt_basenames.
try:
    _CFG = _devkit_config.load()
    ESTATE_PATTERNS = [
        (re.compile(str(p["regex"])), str(p["label"])) for p in _CFG.get("boundary.patterns")
    ]
    ENGINE_ROOTS = tuple(_CFG.str_list("boundary.engine_roots", ["roles", "playbooks"]))
    EXEMPT_SUBSTR = tuple(_CFG.str_list("boundary.exempt_substr", []))
    EXEMPT_BASENAMES = tuple(_CFG.str_list("boundary.exempt_basenames", []))
except (_devkit_config.ConfigError, KeyError, TypeError, re.error) as _exc:
    _devkit_config.fatal("boundary_lint", _exc)
SCAN_SUFFIXES = (".yml", ".yaml", ".j2")


def is_exempt(path: Path) -> bool:
    s = str(path)
    if any(x in s for x in EXEMPT_SUBSTR):
        return True
    if path.name in EXEMPT_BASENAMES:
        return True
    return False


def strip_comment(line: str) -> str:
    """Drop trailing '#...' comments so documented/DRIFT/example notes don't trip the lint.
    (Naive: fine for YAML/Jinja here — we only need to ignore obvious comment tails.)"""
    # keep lines that are entirely comments out of scope entirely
    stripped = line.lstrip()
    if stripped.startswith("#") or stripped.startswith("{#"):
        return ""
    # remove an inline ' #comment' tail
    hashpos = line.find(" #")
    return line[:hashpos] if hashpos != -1 else line


def scan_file(path: Path) -> list[tuple[int, str, str]]:
    out: list[tuple[int, str, str]] = []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except (OSError, UnicodeDecodeError):
        return out
    for i, raw in enumerate(text.splitlines(), 1):
        line = strip_comment(raw)
        if not line.strip():
            continue
        for pat, label in ESTATE_PATTERNS:
            m = pat.search(line)
            if m:
                out.append((i, label, m.group(0)))
    return out


def iter_engine_files(roots: list[Path]):
    for root in roots:
        if not root.exists():
            continue
        for p in root.rglob("*"):
            if p.is_file() and p.suffix in SCAN_SUFFIXES and not is_exempt(p):
                yield p


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--enforce", action="store_true", help="exit 1 if any violations")
    ap.add_argument("--warn", action="store_true", help="report only, always exit 0 (default)")
    ap.add_argument("paths", nargs="*", default=list(ENGINE_ROOTS))
    args = ap.parse_args()

    roots = [Path(p) for p in (args.paths or ENGINE_ROOTS)]
    violations = 0
    by_file: dict[str, int] = {}
    for f in iter_engine_files(roots):
        hits = scan_file(f)
        if hits:
            by_file[str(f)] = len(hits)
            violations += len(hits)
            for ln, label, match in hits:
                print(f"{f}:{ln}: estate fact in ENGINE path — {label}: {match}")

    mode = "ENFORCE" if args.enforce else "WARN"
    print(
        f"\nboundary_lint [{mode}]: {violations} estate-fact leak(s) across "
        f"{len(by_file)} ENGINE file(s). See docs/RULES.md (boundary-lint).",
        file=sys.stderr,
    )
    if args.enforce and violations:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
