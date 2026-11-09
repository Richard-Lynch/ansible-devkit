# SPDX-License-Identifier: GPL-3.0-or-later
"""`devkit conform` — check a repository against the public-repository standard.

The standard is what every repository built on ansible-devkit has, and what `copier copy` of this
package's template (copier.yml, template/) generates:

  CONFORM-01  .github/workflows/{ci,disclose,release}.yml exist and parse as YAML mappings
  CONFORM-02  each has exactly one job, with the id `ci` / `disclose` / `release` (the required
              status checks are `ci / gate` and `disclose / gate`)
  CONFORM-03  that job `uses:` the matching ansible-devkit reusable workflow
              (`./.github/workflows/reusable-<x>.yml` only in ansible-devkit itself)
  CONFORM-04  the `uses:` ref is a release tag, vMAJOR.MINOR.PATCH — never a branch
  CONFORM-05  ci and release pass `kind:` matching the repository (galaxy.yml: collection,
              pyproject.toml: python); ci's `ansible_core`, when given, is a JSON list of "X.Y"
  CONFORM-06  release passes `secrets: inherit`; disclose passes NO secrets (the gate's generic
              rules need no private input, and a secret the shared workflow does not declare is a
              workflow error)
  CONFORM-07  triggers: ci on push to main and pull_request; release on push to main; disclose on
              pull_request types opened, synchronize, reopened and edited — with no other filter
              (paths, branches-ignore, a second branch ...) and no `if:` on the caller job
  CONFORM-08  LICENSE is the GPL-3.0 text
  CONFORM-09  CHANGELOG.md has a non-empty `## [<version>]` section for the declared version
              (galaxy.yml `version`, else pyproject.toml `[project].version`)
  CONFORM-10  export.manifest lists exactly the paths `git ls-files` lists
  CONFORM-11  every tracked .py file carries `SPDX-License-Identifier: GPL-3.0-or-later` in its
              first lines
  CONFORM-12  .github/actionlint.yaml exists (the reusable CI's actionlint job reads it)
  CONFORM-13  in a collection, every roles/<role>/ has a README.md and a meta/main.yml whose
              galaxy_info.description is a non-empty string (Galaxy's importer rejects a role with
              no README, and shows no description for a role without one)
  CONFORM-14  `.disclose-allow` exists and every line of it is an exemption the disclose gate
              accepts: `<rule-glob> <location-glob> <reason of three words or more>`, a location
              that is not `*`; the shared disclose workflow reads it from a pull request's base

  CONFORM-15  Makefile has the five standard targets with single devkit recipes
  CONFORM-16  opt-in dependency input files exist (ADR-59)
  CONFORM-17  Makefile has a thin hooks-install target calling devkit hooks install

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


# The only trigger filters the standard has. Anything else (branches-ignore, paths, paths-ignore,
# tags, a second branch, a narrower `types`) lets a change reach main without the gate running, or
# runs a release from a branch that is not main.
PR_DEFAULT_TYPES = ("opened", "synchronize", "reopened")


def _as_list(v: object) -> list | None:
    if isinstance(v, str):
        return [v]
    return v if isinstance(v, list) else None


def _check_push_main(events: dict, rel: str) -> list[Problem]:
    if "push" not in events:
        return [Problem(rel, "CONFORM-07", "does not run on push (the standard: branches [main])")]
    push = events["push"]
    if not isinstance(push, dict) or _as_list(push.get("branches")) != ["main"]:
        return [Problem(rel, "CONFORM-07", "`on.push` must be exactly `branches: [main]`")]
    extra = sorted(str(k) for k in push if k != "branches")
    if extra:
        return [
            Problem(
                rel, "CONFORM-07", f"`on.push` has filters beyond the standard: {', '.join(extra)}"
            )
        ]
    return []


def _check_pull_request(events: dict, rel: str, required_types: tuple[str, ...]) -> list[Problem]:
    if "pull_request" not in events:
        return [Problem(rel, "CONFORM-07", "does not run on pull_request")]
    pr = events["pull_request"]
    if pr is None:
        pr = {}
    if not isinstance(pr, dict):
        return [Problem(rel, "CONFORM-07", "`on.pull_request` is not a mapping")]
    out: list[Problem] = []
    extra = sorted(str(k) for k in pr if k != "types")
    if extra:
        out.append(
            Problem(
                rel,
                "CONFORM-07",
                f"`on.pull_request` has filters beyond the standard: {', '.join(extra)}",
            )
        )
    types = _as_list(pr["types"]) if "types" in pr else list(PR_DEFAULT_TYPES)
    missing = [t for t in required_types if t not in (types or [])]
    if missing:
        out.append(
            Problem(
                rel,
                "CONFORM-07",
                "pull_request types must include "
                + ", ".join(required_types)
                + f" (missing: {', '.join(missing)})",
            )
        )
    return out


def _check_triggers(c: Caller, events: dict, rel: str) -> list[Problem]:
    out: list[Problem] = []
    if c.job in ("ci", "release"):
        out += _check_push_main(events, rel)
    if c.job == "ci":
        out += _check_pull_request(events, rel, PR_DEFAULT_TYPES)
    if c.job == "disclose":
        out += _check_pull_request(events, rel, DISCLOSE_TYPES)
    return out


def _is_devkit(root: Path) -> bool:
    """True only for ansible-devkit itself, the one repository that calls its own copies."""
    try:
        doc = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        return False
    project = doc.get("project")
    return isinstance(project, dict) and project.get("name") == "ansible-devkit"


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
        # A local "reusable" workflow is whatever the repository says it is, and it receives the
        # caller's secrets: only ansible-devkit, whose copy IS the shared workflow, may use one.
        if _is_devkit(root) and (root / reusable).is_file():
            return []
        return [
            Problem(
                rel,
                "CONFORM-03",
                f"`uses: {uses}` is a local workflow; only ansible-devkit may call its own copy "
                f"(call {DEVKIT_REPO}/{reusable}@<tag>)",
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
    if c.job == "disclose" and secrets is not None:
        return [
            Problem(
                rel,
                "CONFORM-06",
                "job `disclose` passes secrets; the shared gate takes none (its rules need no "
                "private input, and an undeclared secret is a workflow error)",
            )
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
        if c.job in jobs and not isinstance(job, dict):
            out.append(Problem(rel, "CONFORM-02", f"job `{c.job}` is not a mapping"))
        if isinstance(job, dict):
            if "if" in job:
                out.append(
                    Problem(
                        rel, "CONFORM-07", f"job `{c.job}` has an `if:`, which can skip the gate"
                    )
                )
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


def _role_description(meta: Path, rel: str) -> list[Problem]:
    if not meta.is_file():
        return [Problem(rel, "CONFORM-13", "missing (galaxy_info.description is read from it)")]
    try:
        doc = yaml.safe_load(meta.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError) as exc:
        return [Problem(rel, "CONFORM-13", f"unreadable: {exc}", unchecked=True)]
    except yaml.YAMLError as exc:
        return [Problem(rel, "CONFORM-13", f"does not parse: {exc}".splitlines()[0])]
    info = doc.get("galaxy_info") if isinstance(doc, dict) else None
    description = info.get("description") if isinstance(info, dict) else None
    if not isinstance(description, str) or not description.strip():
        return [Problem(rel, "CONFORM-13", "has no non-empty `galaxy_info.description`")]
    return []


def check_roles(root: Path) -> list[Problem]:
    """Every role of a collection has a README.md and a galaxy_info.description.

    Galaxy's importer fails a collection containing a role with no README, and lists a role whose
    meta/main.yml has no galaxy_info.description without one. Neither stops `ansible-galaxy
    collection build` or the upload: both surface only in the import result, after the release.
    """
    roles_dir = root / "roles"
    if _kind(root) != "collection" or not roles_dir.is_dir():
        return []
    out: list[Problem] = []
    for role in sorted(p for p in roles_dir.iterdir() if p.is_dir()):
        rel = f"roles/{role.name}"
        if not (role / "README.md").is_file():
            out.append(
                Problem(f"{rel}/README.md", "CONFORM-13", "missing (Galaxy rejects the import)")
            )
        out += _role_description(role / "meta" / "main.yml", f"{rel}/meta/main.yml")
    return out


def check_disclose_allow(root: Path) -> list[Problem]:
    """`.disclose-allow` exists and parses the way `devkit disclose --allow` reads it, so the shared
    workflow never meets a file it must refuse (which would fail every pull request of the repo)."""
    rel = ".disclose-allow"
    path = root / rel
    if not path.is_file():
        return [
            Problem(rel, "CONFORM-14", "missing (the disclose workflow reads it from the base)")
        ]
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return [Problem(rel, "CONFORM-14", f"unreadable: {exc}", unchecked=True)]
    out: list[Problem] = []
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 2)
        if len(parts) < 3 or len(parts[2].split()) < 3:
            out.append(
                Problem(
                    f"{rel}:{n}",
                    "CONFORM-14",
                    "an exemption needs a rule, a location and a reason of three words or more",
                )
            )
        elif parts[1].strip("*") == "" or parts[1] in ("tarball:*", "tarball:**"):
            out.append(
                Problem(f"{rel}:{n}", "CONFORM-14", f"location {parts[1]!r} exempts everywhere")
            )
    return out


def check_makefile(root: Path, config: dict) -> list[Problem]:
    path = root / "Makefile"
    if not path.is_file():
        return [
            Problem("Makefile", "CONFORM-15", "missing"),
            Problem("Makefile", "CONFORM-17", "missing hooks-install target"),
        ]
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        return [Problem("Makefile", "CONFORM-15", f"unreadable: {exc}", unchecked=True)]
    targets = {
        name: []
        for name in ("help", "test", "lint", "deps-install", "deps-check", "hooks-install")
    }
    seen = set()
    active = []
    for line in lines:
        if line.startswith("\t"):
            for name in active:
                targets[name].append(line.strip())
        elif line.strip() and not line.lstrip().startswith("#"):
            match = re.match(r"^([^:=]+):(?!=)(.*)$", line)
            active = []
            if match:
                active = [name for name in match.group(1).split() if name in targets]
                seen.update(active)
                if ";" in match.group(2):
                    for name in active:
                        targets[name].append(match.group(2).split(";", 1)[1].strip())
    policy = config.get("makefile_policy_targets", [])
    if not isinstance(policy, list) or not all(isinstance(x, str) for x in policy):
        return [
            Problem(
                "devkit.toml", "CONFORM-15", "makefile_policy_targets must be a list of strings"
            )
        ]
    out = []
    for name, recipe in targets.items():
        if name == "hooks-install":
            if name not in seen or len(recipe) != 1 or not re.fullmatch(
                r"@?devkit\s+hooks\s+install(?:\s+--repo-root\s+\.)?", recipe[0]
            ):
                out.append(
                    Problem(
                        "Makefile",
                        "CONFORM-17",
                        "hooks-install must have a single `devkit hooks install` invocation",
                    )
                )
            continue
        if name not in seen:
            out.append(Problem("Makefile", "CONFORM-15", f"missing target {name}"))
        elif name not in policy and (
            len(recipe) != 1 or not re.fullmatch(r"@?devkit(?:\s+[-\w./]+)+", recipe[0])
        ):
            out.append(
                Problem(
                    "Makefile", "CONFORM-15", f"target {name} must have a single devkit invocation"
                )
            )
    return out


def check_dependency_inputs(root: Path, config: dict) -> list[Problem]:
    required = config.get("require_dependency_inputs", False)
    if not isinstance(required, bool):
        return [Problem("devkit.toml", "CONFORM-16", "require_dependency_inputs must be a boolean")]
    return [
        Problem(name, "CONFORM-16", "missing")
        for name in ("bindep.txt", "pyproject.toml", "uv.lock", "requirements.yml")
        if required and not (root / name).is_file()
    ]


def conform_config(root: Path) -> tuple[dict, list[Problem]]:
    path = root / "devkit.toml"
    if not path.exists():
        return {}, []
    try:
        config = tomllib.loads(path.read_text(encoding="utf-8")).get("conform", {})
        if not isinstance(config, dict):
            raise ValueError("conform must be a table")
        return config, []
    except (OSError, UnicodeError, tomllib.TOMLDecodeError, ValueError) as exc:
        return {}, [
            Problem(
                "devkit.toml", "CONFORM-15", f"cannot read configuration: {exc}", unchecked=True
            )
        ]


def conform(root: Path) -> list[Problem]:
    tracked = tracked_files(root)
    config, config_problems = conform_config(root)
    return [
        *config_problems,
        *check_makefile(root, config),
        *check_dependency_inputs(root, config),
        *check_callers(root),
        *check_license(root),
        *check_changelog(root),
        *check_manifest(root, tracked),
        *check_spdx(root, tracked),
        *check_actionlint(root),
        *check_roles(root),
        *check_disclose_allow(root),
    ]


def exit_code(problems: list[Problem]) -> int:
    if any(p.unchecked for p in problems):
        return 2
    return 1 if problems else 0
