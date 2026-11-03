# SPDX-License-Identifier: GPL-3.0-or-later
"""`devkit conform` — check a repository against the public-repository standard.

The standard is what every repository built on ansible-devkit has, and what `copier copy` of this
package's template (copier.yml, template/) generates:

  CONFORM-01  .github/workflows/{ci,disclose,release}.yml exist and parse as YAML mappings
  CONFORM-02  each has exactly one job, with the id `ci` / `disclose` / `release` (the required
              status checks are `ci / gate` and `disclose / gate`)
  CONFORM-03  that job `uses:` the matching ansible-devkit reusable workflow
              (`./.github/workflows/reusable-<x>.yml` only in a repository that has that file)
  CONFORM-04  the `uses:` ref is a release tag, vMAJOR.MINOR.PATCH — never a branch
  CONFORM-05  ci and release pass `kind:` matching the repository (galaxy.yml: collection,
              pyproject.toml: python); ci's `ansible_core`, when given, is a JSON list of "X.Y"
  CONFORM-06  release passes `secrets: inherit`; disclose passes DISCLOSE_PATTERNS and
              DISCLOSE_ALLOW from the repository's secrets
  CONFORM-07  triggers: ci on push to main and pull_request; release on push to main; disclose on
              pull_request types opened, synchronize, reopened and edited
  CONFORM-08  LICENSE is the GPL-3.0 text
  CONFORM-09  CHANGELOG.md has a non-empty `## [<version>]` section for the declared version
              (galaxy.yml `version`, else pyproject.toml `[project].version`)
  CONFORM-10  export.manifest lists exactly the paths `git ls-files` lists
  CONFORM-11  every tracked .py file carries `SPDX-License-Identifier: GPL-3.0-or-later` in its
              first lines
  CONFORM-12  .github/actionlint.yaml exists (the reusable CI's actionlint job reads it)

One line per problem on stdout, `<path>: <RULE> <message>`. Exit 0 when the repository meets the
standard, 1 when it does not, 2 when a rule could not be evaluated (no git repository, an
unreadable file) — a rule that could not run is never reported as met.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tomllib
from dataclasses import dataclass
from pathlib import Path

import yaml

DEVKIT_REPO = "Richard-Lynch/ansible-devkit"

# sha256 of the GPL-3.0 text with every run of whitespace collapsed to one space, so a re-wrapped
# or CRLF copy still matches and any change of wording does not.
GPL3_NORMALISED_SHA256 = "972a178adadacfbdddec346b16d45fd4ed9937ec5e4a5bb46d8685ba4e73a0b1"

TAG_RE = re.compile(r"v\d+\.\d+\.\d+")
CORE_RE = re.compile(r"\d+\.\d+")
SPDX_RE = re.compile(r"SPDX-License-Identifier:\s*GPL-3\.0-or-later\b")
SPDX_HEAD_LINES = 5
DISCLOSE_TYPES = ("opened", "synchronize", "reopened", "edited")
DISCLOSE_SECRETS = ("DISCLOSE_PATTERNS", "DISCLOSE_ALLOW")


@dataclass(frozen=True)
class Problem:
    path: str
    rule: str
    message: str
    # True when the rule could not be evaluated at all (exit 2), not merely unmet (exit 1).
    unchecked: bool = False

    def __str__(self) -> str:
        return f"{self.path}: {self.rule} {self.message}"


@dataclass(frozen=True)
class Caller:
    job: str
    takes_kind: bool


CALLERS = (
    Caller("ci", takes_kind=True),
    Caller("disclose", takes_kind=False),
    Caller("release", takes_kind=True),
)


def _kind(root: Path) -> str | None:
    if (root / "galaxy.yml").is_file():
        return "collection"
    if (root / "pyproject.toml").is_file():
        return "python"
    return None


def _triggers(doc: dict) -> dict:
    """The workflow's events as a mapping, whichever of the three `on:` forms it uses."""
    # PyYAML reads the bare key `on` as the boolean True (YAML 1.1).
    on = doc.get("on", doc.get(True))
    if isinstance(on, str):
        return {on: None}
    if isinstance(on, list):
        return dict.fromkeys(on)
    return on if isinstance(on, dict) else {}


def _branches(trigger: object) -> list:
    if isinstance(trigger, dict):
        b = trigger.get("branches")
        return b if isinstance(b, list) else [b] if isinstance(b, str) else []
    return []


def _check_triggers(c: Caller, events: dict, rel: str) -> list[Problem]:
    out: list[Problem] = []
    if c.job in ("ci", "release") and "main" not in _branches(events.get("push")):
        out.append(Problem(rel, "CONFORM-07", "`on.push.branches` does not include main"))
    if c.job == "ci" and "pull_request" not in events:
        out.append(Problem(rel, "CONFORM-07", "does not run on pull_request"))
    if c.job == "disclose":
        pr = events.get("pull_request")
        if "pull_request" not in events:
            out.append(Problem(rel, "CONFORM-07", "does not run on pull_request"))
        else:
            types = pr.get("types") if isinstance(pr, dict) else None
            types = [types] if isinstance(types, str) else types if isinstance(types, list) else []
            missing = [t for t in DISCLOSE_TYPES if t not in types]
            if missing:
                out.append(
                    Problem(
                        rel,
                        "CONFORM-07",
                        "pull_request types must include "
                        + ", ".join(DISCLOSE_TYPES)
                        + f" (missing: {', '.join(missing)})",
                    )
                )
    return out


def _check_uses(root: Path, c: Caller, uses: object, rel: str) -> list[Problem]:
    reusable = f".github/workflows/reusable-{c.job}.yml"
    if not isinstance(uses, str):
        return [
            Problem(
                rel,
                "CONFORM-03",
                f"job `{c.job}` has no `uses:` (it must call {reusable})",
            )
        ]
    if uses == f"./{reusable}":
        if (root / reusable).is_file():
            return []
        return [
            Problem(
                rel,
                "CONFORM-03",
                f"`uses: {uses}` but this repository has no {reusable}",
            )
        ]
    target, sep, ref = uses.partition("@")
    want = f"{DEVKIT_REPO}/{reusable}"
    if target != want:
        return [Problem(rel, "CONFORM-03", f"`uses: {uses}` does not call {want}")]
    if not sep or not TAG_RE.fullmatch(ref):
        return [
            Problem(
                rel,
                "CONFORM-04",
                f"`uses:` ref {ref!r} is not a release tag (vMAJOR.MINOR.PATCH); a branch moves",
            )
        ]
    return []


def _check_with(c: Caller, job: dict, kind: str | None, rel: str) -> list[Problem]:
    if not c.takes_kind:
        return []
    out: list[Problem] = []
    with_ = job.get("with") if isinstance(job.get("with"), dict) else {}
    got = with_.get("kind")
    if kind is None:
        out.append(
            Problem(
                rel,
                "CONFORM-05",
                "cannot tell the kind: no galaxy.yml or pyproject.toml",
            )
        )
    elif got != kind:
        out.append(Problem(rel, "CONFORM-05", f"`kind: {got}` but this repository is a {kind}"))
    if c.job == "ci" and "ansible_core" in with_:
        raw = with_["ansible_core"]
        try:
            cores = json.loads(raw) if isinstance(raw, str) else None
        except json.JSONDecodeError:
            cores = None
        ok = (
            isinstance(cores, list)
            and cores
            and all(isinstance(v, str) and CORE_RE.fullmatch(v) for v in cores)
        )
        if not ok:
            out.append(
                Problem(
                    rel,
                    "CONFORM-05",
                    f'`ansible_core: {raw}` is not a JSON list of "X.Y" strings, e.g. \'["2.21"]\'',
                )
            )
    return out


def _check_secrets(c: Caller, job: dict, rel: str) -> list[Problem]:
    secrets = job.get("secrets")
    if c.job == "release" and secrets != "inherit":
        return [
            Problem(
                rel,
                "CONFORM-06",
                "job `release` must pass `secrets: inherit` (the release environment's secrets "
                "arrive empty otherwise)",
            )
        ]
    if c.job == "disclose":
        secrets = secrets if isinstance(secrets, dict) else {}
        return [
            Problem(
                rel,
                "CONFORM-06",
                f"job `disclose` must pass {s}: ${{{{ secrets.{s} }}}}",
            )
            for s in DISCLOSE_SECRETS
            if re.fullmatch(rf"\$\{{\{{\s*secrets\.{s}\s*\}}\}}", str(secrets.get(s, ""))) is None
        ]
    return []


def check_callers(root: Path) -> list[Problem]:
    kind = _kind(root)
    out: list[Problem] = []
    for c in CALLERS:
        rel = f".github/workflows/{c.job}.yml"
        path = root / rel
        if not path.is_file():
            out.append(Problem(rel, "CONFORM-01", "missing (every repository has this caller)"))
            continue
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
            out.append(Problem(rel, "CONFORM-01", f"does not parse: {exc}".splitlines()[0]))
            continue
        if not isinstance(doc, dict):
            out.append(Problem(rel, "CONFORM-01", "is not a YAML mapping"))
            continue
        jobs = doc.get("jobs") if isinstance(doc.get("jobs"), dict) else {}
        if c.job not in jobs:
            out.append(
                Problem(
                    rel,
                    "CONFORM-02",
                    f"has no job `{c.job}` (the job id names the required check)",
                )
            )
        extra = sorted(str(j) for j in jobs if j != c.job)
        if extra:
            out.append(
                Problem(
                    rel,
                    "CONFORM-02",
                    f"a thin caller has one job; also has: {', '.join(extra)}",
                )
            )
        job = jobs.get(c.job)
        if isinstance(job, dict):
            out += _check_uses(root, c, job.get("uses"), rel)
            out += _check_with(c, job, kind, rel)
            out += _check_secrets(c, job, rel)
        out += _check_triggers(c, _triggers(doc), rel)
    return out


def check_license(root: Path) -> list[Problem]:
    path = root / "LICENSE"
    if not path.is_file():
        return [Problem("LICENSE", "CONFORM-08", "missing")]
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return [Problem("LICENSE", "CONFORM-08", f"unreadable: {exc}", unchecked=True)]
    digest = hashlib.sha256(" ".join(text.split()).encode()).hexdigest()
    if digest != GPL3_NORMALISED_SHA256:
        return [Problem("LICENSE", "CONFORM-08", "is not the GPL-3.0 text")]
    return []


def declared_version(root: Path) -> tuple[str | None, str]:
    """The version the repository declares and the file it came from."""
    galaxy = root / "galaxy.yml"
    if galaxy.is_file():
        doc = yaml.safe_load(galaxy.read_text(encoding="utf-8"))
        v = doc.get("version") if isinstance(doc, dict) else None
        return (str(v) if v is not None else None), "galaxy.yml"
    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        doc = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        v = doc.get("project", {}).get("version")
        return (str(v) if v is not None else None), "pyproject.toml"
    return None, "galaxy.yml or pyproject.toml"


def check_changelog(root: Path) -> list[Problem]:
    try:
        version, source = declared_version(root)
    except (
        OSError,
        UnicodeDecodeError,
        yaml.YAMLError,
        tomllib.TOMLDecodeError,
    ) as exc:
        msg = f"cannot read the declared version: {exc}".splitlines()[0]
        return [Problem("CHANGELOG.md", "CONFORM-09", msg, unchecked=True)]
    if version is None:
        return [Problem("CHANGELOG.md", "CONFORM-09", f"no version declared in {source}")]
    path = root / "CHANGELOG.md"
    if not path.is_file():
        return [Problem("CHANGELOG.md", "CONFORM-09", "missing")]
    text = path.read_text(encoding="utf-8")
    # The same section match reusable-release.yml uses for the release notes.
    m = re.search(rf"^## \[{re.escape(version)}\][^\n]*\n(.*?)(?=^## \[|\Z)", text, re.M | re.S)
    if not m or not m.group(1).strip():
        return [
            Problem(
                "CHANGELOG.md",
                "CONFORM-09",
                f"has no non-empty `## [{version}]` section ({source} declares {version})",
            )
        ]
    return []


def tracked_files(root: Path) -> list[str] | None:
    try:
        p = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            capture_output=True,
            check=False,
        )
    except OSError:
        return None
    if p.returncode != 0:
        return None
    return [f for f in p.stdout.decode("utf-8", "surrogateescape").split("\0") if f]


def check_manifest(root: Path, tracked: list[str] | None) -> list[Problem]:
    if tracked is None:
        return [Problem("export.manifest", "CONFORM-10", "not a git repository", unchecked=True)]
    path = root / "export.manifest"
    if not path.is_file():
        return [Problem("export.manifest", "CONFORM-10", "missing")]
    listed = [
        s
        for line in path.read_text(encoding="utf-8").splitlines()
        if (s := line.strip()) and not s.startswith("#")
    ]
    have, want = set(listed), set(tracked)
    out = [
        Problem("export.manifest", "CONFORM-10", f"lists {p}, which git does not track")
        for p in sorted(have - want)
    ]
    out += [
        Problem("export.manifest", "CONFORM-10", f"does not list {p}, which git tracks")
        for p in sorted(want - have)
    ]
    return out


def check_spdx(root: Path, tracked: list[str] | None) -> list[Problem]:
    if tracked is None:
        return [Problem(".", "CONFORM-11", "not a git repository", unchecked=True)]
    out: list[Problem] = []
    for rel in sorted(f for f in tracked if f.endswith(".py")):
        path = root / rel
        if not path.is_file():
            continue  # deleted in the working tree; CONFORM-10 sees the index
        try:
            with path.open(encoding="utf-8") as fh:
                head = "".join(fh.readline() for _ in range(SPDX_HEAD_LINES))
        except (OSError, UnicodeDecodeError) as exc:
            out.append(Problem(rel, "CONFORM-11", f"unreadable: {exc}", unchecked=True))
            continue
        if not SPDX_RE.search(head):
            out.append(
                Problem(
                    rel,
                    "CONFORM-11",
                    f"no `SPDX-License-Identifier: GPL-3.0-or-later` in the first "
                    f"{SPDX_HEAD_LINES} lines",
                )
            )
    return out


def check_actionlint(root: Path) -> list[Problem]:
    if (root / ".github" / "actionlint.yaml").is_file():
        return []
    return [Problem(".github/actionlint.yaml", "CONFORM-12", "missing")]


def conform(root: Path) -> list[Problem]:
    tracked = tracked_files(root)
    return [
        *check_callers(root),
        *check_license(root),
        *check_changelog(root),
        *check_manifest(root, tracked),
        *check_spdx(root, tracked),
        *check_actionlint(root),
    ]


def exit_code(problems: list[Problem]) -> int:
    if any(p.unchecked for p in problems):
        return 2
    return 1 if problems else 0
