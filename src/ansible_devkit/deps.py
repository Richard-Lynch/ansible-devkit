# SPDX-License-Identifier: GPL-3.0-or-later
"""Install and verify the requirements recorded by ansible-galaxy."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path

import yaml


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


STAMP = ".requirements.sha256"


def stamp_data(requirements: Path, collections: Path, roles: Path) -> dict[str, str]:
    return {
        "requirements_sha256": digest(requirements),
        "roles_path": str(roles.resolve()),
        "collections_path": str(collections.resolve()),
    }


def expected_directories(
    requirements: Path, collections: Path, roles: Path
) -> tuple[dict, list[Path]]:
    text = requirements.read_text(encoding="utf-8")
    doc = yaml.safe_load(text) or {}
    if not isinstance(doc, dict):
        raise ValueError("requirements.yml must be a mapping")
    # Preserve comments on name lines: Galaxy does not retain the collection identity of git URLs.
    markers = re.findall(
        r"^\s*-?\s*name:\s*([^\n#]+?)\s*#\s*collection:\s*([\w]+\.[\w]+)\s*$",
        text,
        re.M,
    )
    names = {name.strip().strip("'\""): collection for name, collection in markers}
    expected = []
    for kind, base in (("roles", roles), ("collections", collections)):
        entries = doc.get(kind) or []
        if not isinstance(entries, list):
            raise ValueError(f"{kind} must be a list")
        for entry in entries:
            name = (
                entry.get("name") or (entry.get("src") if kind == "roles" else None)
                if isinstance(entry, dict)
                else entry
            )
            if not isinstance(name, str):
                raise ValueError(f"invalid {kind} entry")
            if kind == "collections":
                identity = names.get(name, name)
                if not re.fullmatch(r"\w+\.\w+", identity):
                    raise ValueError(f"collection {name!r} needs a # collection: ns.name marker")
                namespace, collection = identity.split(".")
                expected.append(base / "ansible_collections" / namespace / collection)
            else:
                identity = name
                if isinstance(entry, dict) and not entry.get("name"):
                    src = name.split(",", 1)[0].rstrip("/")
                    if "/" in src or ":" in src:
                        identity = src.rsplit("/", 1)[-1].rsplit(":", 1)[-1]
                        identity = identity.removesuffix(".git")
                if not identity or identity in {".", ".."} or "/" in identity or ":" in identity:
                    raise ValueError(f"role {name!r} needs an installed name")
                expected.append(base / identity)
    return doc, expected


def check(requirements: Path, collections: Path, roles: Path) -> bool:
    try:
        recorded = json.loads((collections / STAMP).read_text(encoding="utf-8"))
        _, expected = expected_directories(requirements, collections, roles)
        return recorded == stamp_data(requirements, collections, roles) and all(
            p.is_dir() for p in expected
        )
    except (OSError, UnicodeError, ValueError, yaml.YAMLError):
        return False


def install(requirements: Path, collections: Path, roles: Path) -> None:
    stamp = collections / STAMP
    stamp.unlink(missing_ok=True)
    initial_stamp = stamp_data(requirements, collections, roles)
    doc, expected = expected_directories(requirements, collections, roles)
    for kind, path in (("role", roles), ("collection", collections)):
        if doc.get(kind + "s"):
            subprocess.run(
                [
                    "ansible-galaxy",
                    kind,
                    "install",
                    "-r",
                    str(requirements),
                    "-p",
                    str(path),
                    "--force",
                ],
                check=True,
            )
    missing = [str(p) for p in expected if not p.is_dir()]
    if missing:
        raise ValueError("installed directories missing: " + ", ".join(missing))
    if stamp_data(requirements, collections, roles) != initial_stamp:
        raise ValueError("requirements.yml changed during installation")
    collections.mkdir(parents=True, exist_ok=True)
    stamp.write_text(json.dumps(initial_stamp, sort_keys=True) + "\n", encoding="utf-8")
