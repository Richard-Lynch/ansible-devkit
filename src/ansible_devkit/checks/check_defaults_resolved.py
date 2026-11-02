#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""RESOLVE-02 — a generated `*__default` that nothing ever reads.

`defaults/main.yml` is GENERATED from `meta/argument_specs.py` and holds `<name>__default`
vars; the role's tasks use the BARE `<name>`. Something must map one onto the other — a
hand-written "Resolve defaults" `set_fact`, or an inline `| default(<name>__default)` in a
template. When a role has a HAND-WRITTEN resolver, adding an option to the argspec regenerates
the `__default` var and NOTHING reports that the resolver never learned to read it.

The bare name is then UNDEFINED at run time: every play including the role dies with
"'<name>' is undefined" — AFTER its earlier tasks have done their work, so a converge reports
`changed=N failed=1` and "did it work?" is ambiguous on every run, while every task downstream
of the failure silently never executes.

WHY THE CHECK IS "IS THE NAME MENTIONED", NOT A PATTERN MATCH ON THE ASSIGNMENT.
The obvious test — look for `name: "{{ name | default(name__default) }}"` — is almost all
FALSE POSITIVES. A resolver line written as a folded scalar

    role_window_seconds: >-
      {{ role_window_seconds | default(role_window_seconds__default) }}

does not match it. The accurate question is far simpler and has no false positives:
**does anything under the role reference `<name>__default` at all?** If nothing does, the
generated default is dead and the bare name cannot be resolved from it.

A role may resolve a default inline in a template (`{{ x | default(x__default) }}` in a unit
file), which is legitimate — so templates/ is searched too.

Roles whose resolver is GENERATED are skipped: `argspec generate` emits a re-entry guard
(`_<role>__argspec_resolved`, see RESOLVE-01) and regenerates every option together, so the two
lists cannot drift.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _devkit_config  # noqa: E402

RULE = "RESOLVE-02"
DEFAULT_RE = re.compile(r"^(\w+)__default:", re.M)
# The generated resolver's re-entry guard. Its presence means the resolver is machine-written.
GENERATED_MARKER = "__argspec_resolved"


def role_dirs(root: Path) -> list[Path]:
    roles = root / "roles"
    if not roles.is_dir():
        return []
    return sorted(p for p in roles.iterdir() if p.is_dir())


def search_corpus(role: Path) -> tuple[str, bool]:
    """Everything that could resolve an option, plus whether the resolver is generated.

    templates/ counts: a role may legitimately resolve inline in a template
    (`{{ x | default(x__default) }}`) instead of in a set_fact.
    vars/ and handlers/ count for the same reason — the question is whether ANYTHING reads it.
    """
    parts: list[str] = []
    for sub in ("tasks", "templates", "vars", "handlers"):
        d = role / sub
        if not d.is_dir():
            continue
        for f in d.rglob("*"):
            if f.is_file():
                try:
                    parts.append(f.read_text(errors="replace"))
                except OSError:
                    continue
    corpus = "\n".join(parts)
    return corpus, GENERATED_MARKER in corpus


def check_role(role: Path) -> list[str]:
    defaults_file = role / "defaults" / "main.yml"
    if not defaults_file.exists():
        return []
    try:
        names = set(DEFAULT_RE.findall(defaults_file.read_text(errors="replace")))
    except OSError:
        return []
    if not names:
        return []

    corpus, generated = search_corpus(role)
    if generated:
        return []

    findings = []
    for name in sorted(names):
        if f"{name}__default" not in corpus:
            findings.append(
                f"FAIL roles/{role.name}/defaults/main.yml: [{RULE}] `{name}__default` is "
                f"generated into defaults/main.yml but NOTHING under roles/{role.name}/ "
                f"(tasks, templates, vars, handlers) ever references it, so the bare "
                f"`{name}` the tasks use is UNDEFINED at run time. defaults/main.yml is "
                f"GENERATED from meta/argument_specs.py while this role's resolver is "
                f"HAND-WRITTEN, so adding an option regenerates the default and nothing "
                f"reports that the resolver never learned to read it. Fix: add "
                f'`{name}: "{{{{ {name} | default({name}__default) }}}}"` to the role\'s '
                f'"Resolve defaults" set_fact.'
            )
    return findings


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", default=None, help="repo root (default: devkit.toml's root rule)")
    ap.add_argument("--list-rules", action="store_true")
    args = ap.parse_args()

    if args.list_rules:
        print(f"{RULE} (FAIL) — a generated *__default that nothing reads")
        return 0

    root = Path(args.root).resolve() if args.root else _devkit_config.find_root()
    roles = role_dirs(root)
    findings = []
    for r in roles:
        findings.extend(check_role(r))

    for f in findings:
        print(f)
    print(
        f"\ncheck_defaults_resolved: {len(findings)} FAIL across {len(roles)} role(s).",
        file=sys.stderr if findings else sys.stdout,
    )
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
