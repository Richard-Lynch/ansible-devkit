#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""INVSTRICT-01: inventory plugin expressions must be strict and not string literals."""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import yaml

from ansible_devkit.checks._devkit_config import find_root

RULES_TABLE = (
    "INVSTRICT-01  FAIL  inventory expressions without strict or with string literal groups"
)


class InventoryLoader(yaml.SafeLoader):
    """Treat Ansible-specific tagged values as opaque."""


class OpaqueValue:
    """A tagged value whose contents cannot be evaluated."""


def _opaque_tag(loader: InventoryLoader, suffix: str, node: yaml.Node) -> OpaqueValue:
    return OpaqueValue()


InventoryLoader.add_multi_constructor("", _opaque_tag)


def is_string_literal(value: str) -> bool:
    try:
        return isinstance(ast.literal_eval(value.strip()), str)
    except (ValueError, SyntaxError):
        return False


def scan(root: Path) -> tuple[list[str], int]:
    findings = []
    count = 0
    for path in sorted(root.rglob("*")):
        if (
            path.suffix not in (".yml", ".yaml")
            or any(
                part in {".git", ".venv", "collections.galaxy", "roles.galaxy"}
                for part in path.parts
            )
            or any(
                part.startswith(".devkit-hooks-") for part in path.relative_to(root).parts[:-1]
            )
            or not path.is_file()
        ):
            continue
        try:
            doc = yaml.load(path.read_text(encoding="utf-8"), Loader=InventoryLoader)
        except (yaml.YAMLError, UnicodeError) as exc:
            findings.append(f"{path.relative_to(root)}: [INVSTRICT-01] cannot evaluate YAML: {exc}")
            continue
        if isinstance(doc, OpaqueValue) or (
            isinstance(doc, dict)
            and any(
                isinstance(doc.get(key), OpaqueValue)
                for key in ("plugin", "compose", "groups", "keyed_groups", "strict")
            )
        ):
            findings.append(
                f"{path.relative_to(root)}: [INVSTRICT-01] cannot evaluate tagged inventory content"
            )
            continue
        if not isinstance(doc, dict) or "plugin" not in doc:
            continue
        count += 1
        if (
            any(k in doc for k in ("compose", "groups", "keyed_groups"))
            and doc.get("strict") is not True
        ):
            findings.append(
                f"{path.relative_to(root)}: [INVSTRICT-01] expressions require strict: true"
            )
        groups = doc.get("groups")
        if isinstance(groups, dict):
            for name, value in groups.items():
                if isinstance(value, OpaqueValue):
                    findings.append(
                        f"{path.relative_to(root)}: [INVSTRICT-01] cannot evaluate tagged group {name}"
                    )
                elif isinstance(value, str) and is_string_literal(value):
                    findings.append(
                        f"{path.relative_to(root)}: [INVSTRICT-01] group {name} is a string literal"
                    )
    return findings, count


def main(argv: list[str]) -> int:
    if "--list-rules" in argv:
        print(RULES_TABLE)
        return 0
    root = Path(argv[1]).resolve() if len(argv) > 1 else find_root()
    try:
        findings, count = scan(root)
    except OSError as exc:
        print(f"check_inventory_strict: {exc}", file=sys.stderr)
        return 2
    for finding in findings:
        print(f"FAIL {finding}")
    print(f"check_inventory_strict: {len(findings)} FAIL across {count} files")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
