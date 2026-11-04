#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""check_dependencies — every dependency a repository built on devkit declares is pinned the way
the dependency standard says (DEP-02..05), baseline-FAIL.

The collection-side port of the hub's `make lint-deps` (IaaC scripts/hooks/check_dependencies.py,
DEP-01..06). A collection has no Python lock of its own, so DEP-01 (lock drift) and DEP-06
(declared twice in pyproject.toml / requirements.yml) stay hub-only; the rules every collection
repo shares are here, and `devkit check all` runs them in every repository's CI.

THE RULES
    DEP-02  An install that bypasses a pinned declaration. In shell (any tracked file; backslash
            continuations joined; `#` a comment only outside quotes and after whitespace):
            `pip[N] install`, `python[N] -m pip install`, `uv pip install`, `uv tool
            install|run`, `uvx`, `pipx install|run|inject`. Allowed: `-r`/`-c` naming a file listed
            in devkit.toml `[dependencies] requirement_files`, `-e .`/`.`, upgrading pip itself. A
            finding: any package, a URL/VCS/archive/path requirement, an index override, or an
            argument that cannot be resolved. In a play or role, the pip module
            (`ansible.builtin.pip`, `ansible.legacy.pip`, `pip`; dict, free-form or `args:`) may
            install on a target only `==`-pinned names or a declared requirements file.
    DEP-03  A container image that is `:latest` or carries no tag and no digest (compose files,
            role defaults/templates/files/tasks, playbooks, workflows' container/services,
            Dockerfile/Containerfile FROM). An image built from a Jinja variable is judged where
            the variable is set.
    DEP-04  A non-local `uses:` not pinned to a 40-hex commit SHA, workflows PARSED (one that does
            not parse is a finding); a `docker://` action needs a @sha256: digest. ONE exception,
            the same one `devkit conform` CONFORM-04 requires: a JOB-level call of
            Richard-Lynch/ansible-devkit's own reusable workflows at a release tag vX.Y.Z (the tag
            rulesets make those immutable; Renovate moves them).
    DEP-05  A collection's dependencies are declared, as ranges. With a galaxy.yml: every
            `dependencies:` value is a range with a lower bound (`>=1.2.0` or
            `>=1.2.0,<2.0.0`; never `*`, an exact pin or empty: a library that pins exactly makes
            every consumer's resolver fail), and every collection a role (roles/*/tasks|handlers:
            an FQCN module or `role:`/`name:` reference) or a plugin (`ansible_collections.<ns>.
            <name>` import) uses is declared. Without one, a requirements.yml declares them. Only
            ansible.builtin, ansible.legacy and the collection itself are exempt.

BASELINE-FAIL
    devkit.toml `[dependencies] baseline` (default deps-baseline.json) records the violations a
    repository had when the rule arrived, each WITH A REASON. A new finding fails, a baseline entry
    that no longer occurs fails (the baseline only shrinks), and an entry with no reason is a
    config error (exit 2): a baseline is a recorded decision, never a quiet off switch.
    `--update-baseline` rewrites the counts and keeps the reasons; a new entry gets the reason
    "UNREVIEWED", which the next run refuses until someone writes a real one.

SCOPE
    Tracked files (`git ls-files -z`; a tracked entry that cannot be resolved exits 2, a deleted
    one or a submodule is skipped). Skipped as test data or prose: tests/, docs/, .claude/, *.md
    and molecule/ scenarios.

Exit codes: 0 clean against the baseline, 1 a new finding or a stale entry, 2 could not run.
"""

from __future__ import annotations

import json
import re
import shlex
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _devkit_config  # noqa: E402

RULES = {
    "DEP-02": "an install that bypasses a pinned declaration (ad-hoc package, URL/VCS/path, index)",
    "DEP-03": "container image that is :latest or untagged",
    "DEP-04": "non-local uses: not pinned to a 40-hex commit SHA (docker:// needs a digest)",
    "DEP-05": "a collection dependency undeclared, or declared without a range",
}
DEVKIT_REPO = "Richard-Lynch/ansible-devkit"
DEFAULT_BASELINE = "deps-baseline.json"
UNREVIEWED = "UNREVIEWED"
SKIP_PREFIXES = ("docs/", "tests/", ".claude/")
SKIP_PARTS = ("/molecule/",)
SELF: tuple[str, ...] = ("src/ansible_devkit/checks/check_dependencies.py",)
SHA40 = re.compile(r"[0-9a-f]{40}")
RELEASE_TAG = re.compile(r"v\d+\.\d+\.\d+")
PLUGIN_IMPORT = re.compile(
    r"^\s*(?:from|import)\s+ansible_collections\.([a-z_][a-z0-9_]*)\.([a-z_][a-z0-9_]*)\b", re.M
)
IMAGE_REF = re.compile(r"[a-z0-9][a-z0-9._/:-]*(?:@sha256:[0-9a-f]{64})?")
DOCKERFILE = re.compile(r"(^|[._-])(dockerfile|containerfile)([._-].*)?$")
PIP_MODULES = ("ansible.builtin.pip", "ansible.legacy.pip", "pip")
OPT_GENERATED_FILE = {"-r", "--requirement", "-c", "--constraint"}
OPT_EDITABLE = {"-e", "--editable"}
OPT_INDEX = {"-i", "--index-url", "--extra-index-url", "-f", "--find-links", "--trusted-host"}
OPT_VALUE_OTHER = {
    "--python", "-t", "--target", "--prefix", "--root", "--cache-dir", "--src", "--platform",
    "--python-version", "--implementation", "--abi", "--progress-bar", "--log", "--proxy",
    "--timeout", "--retries", "--exists-action", "--upgrade-strategy", "--only-binary",
    "--no-binary", "--report", "-p", "--with", "--from", "--python-preference",
}  # fmt: skip
SHELL_SEPARATORS = {";", "&", "&&", "|", "||", "(", ")", "`", "\n"}
ARCHIVE = (".whl", ".tar.gz", ".tgz", ".zip", ".tar.bz2", ".tar")


@dataclass(frozen=True)
class Finding:
    rule: str
    path: str
    name: str
    line: int
    msg: str

    @property
    def key(self) -> str:
        return f"{self.rule}|{self.path}|{self.name}"


class Unresolvable(RuntimeError):
    """A tracked path that cannot be read: exit 2, never a silent skip."""


def norm_pkg(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _git(root: Path, *args: str) -> list[str]:
    p = subprocess.run(["git", *args, "-z"], cwd=root, capture_output=True)
    if p.returncode != 0:
        raise Unresolvable(f"git {' '.join(args)} failed in {root}: {p.stderr.decode().strip()}")
    return [x for x in p.stdout.decode("utf-8", "surrogateescape").split("\0") if x]


def tracked(root: Path) -> list[str]:
    files = _git(root, "ls-files")
    deleted = set(_git(root, "ls-files", "--deleted"))
    submodules = {
        e.split("\t", 1)[1] for e in _git(root, "ls-files", "-s") if e.startswith("160000 ")
    }
    out = []
    for f in files:
        p = root / f
        if f in deleted or f in submodules or p.is_symlink():
            continue
        if not p.is_file():
            raise Unresolvable(f"tracked path {f!r} cannot be resolved to a file under {root}")
        out.append(f)
    return out


def skipped(f: str) -> bool:
    return (
        f.startswith(SKIP_PREFIXES)
        or f.endswith(".md")
        or f in SELF
        or any(part in "/" + f for part in SKIP_PARTS)
    )


def read(root: Path, f: str) -> str:
    try:
        return (root / f).read_text(errors="ignore")
    except OSError as e:
        raise Unresolvable(f"cannot read tracked file {f}: {e}") from e


def line_of(text: str, needle: str) -> int:
    i = text.find(needle)
    return text.count("\n", 0, i) + 1 if i >= 0 else 0


# ---- DEP-02: shell ----------------------------------------------------------------------------
def strip_comment(line: str) -> str:
    """Cut at the first `#` that is outside quotes and starts a word, as a shell does."""
    quote = None
    for i, c in enumerate(line):
        if quote:
            if c == quote:
                quote = None
            elif c == "\\" and quote == '"':
                continue
        elif c in "'\"":
            quote = c
        elif c == "#" and (i == 0 or line[i - 1].isspace()):
            return line[:i]
    return line


def tokenize(line: str) -> list[str]:
    """Shell-aware: `#` starts a comment only outside quotes and at a word boundary (shlex), and
    a quoted argument that itself holds a command (`sh -c "pip install x"`) is split once more."""
    line = strip_comment(line)
    try:
        lex = shlex.shlex(line, posix=True, punctuation_chars=";&|()`")
        lex.whitespace_split = True
        lex.commenters = ""  # shlex would end a word at `a#b`; strip_comment did it the shell way
        toks = list(lex)
    except ValueError:  # unbalanced quotes: a fragment of a larger string; be conservative
        toks = []
        for t in line.split():
            if t.startswith("#"):
                break
            toks.append(t.strip("'\""))
    out: list[str] = []
    for t in toks:
        if " " in t and re.search(r"\b(pip|pipx|uv|uvx|python)", t):
            out.extend(tokenize(t))
        else:
            out.append(t)
    return out


def logical_lines(text: str) -> list[tuple[int, str]]:
    """Backslash-continued lines joined, each tagged with the line it starts on."""
    out, buf, start = [], "", 0
    for i, line in enumerate(text.splitlines(), 1):
        if not buf:
            start = i
        if line.rstrip().endswith("\\"):
            buf += line.rstrip()[:-1] + " "
            continue
        out.append((start, buf + line))
        buf = ""
    if buf:
        out.append((start, buf))
    return out


def base(tok: str) -> str:
    return tok.rsplit("/", 1)[-1]


def install_args(toks: list[str], i: int) -> tuple[str, list[str]] | None:
    """If toks[i] starts an install command, return (form, its arguments up to a separator)."""
    b = base(toks[i])
    rest = toks[i + 1 :]

    def until_sep(xs: list[str]) -> list[str]:
        out = []
        for x in xs:
            if x in SHELL_SEPARATORS or set(x) <= set(";&|()`"):
                break
            out.append(x)
        return out

    def after_globals(xs: list[str], verbs: tuple[str, ...]) -> tuple[str, list[str]] | None:
        j = 0
        while j < len(xs) and xs[j].startswith("-"):
            j += 2 if xs[j] in OPT_VALUE_OTHER else 1
        if j < len(xs) and xs[j] in verbs:
            return xs[j], until_sep(xs[j + 1 :])
        return None

    if re.fullmatch(r"pip[0-9.]*", b):
        r = after_globals(rest, ("install",))
        return ("pip", r[1]) if r else None
    if re.fullmatch(r"python[0-9.]*", b):
        j = 0
        while j < len(rest) and rest[j].startswith("-") and rest[j] != "-m":
            j += 1
        if j + 1 < len(rest) and rest[j] == "-m" and rest[j + 1] == "pip":
            r = after_globals(rest[j + 2 :], ("install",))
            return ("pip", r[1]) if r else None
        return None
    if b == "uv":
        if rest[:1] == ["pip"]:
            r = after_globals(rest[1:], ("install",))
            return ("pip", r[1]) if r else None
        if rest[:1] == ["tool"]:
            r = after_globals(rest[1:], ("install", "run"))
            return (("run" if r[0] == "run" else "tool"), r[1]) if r else None
        return None
    if b == "uvx":
        return "run", until_sep(rest)
    if b == "pipx":
        r = after_globals(rest, ("install", "run", "inject"))
        return (("run" if r[0] == "run" else "tool"), r[1]) if r else None
    return None


def judge_args(args: list[str], gen: set[str], form: str) -> list[tuple[str, str]]:
    """(name, why) per offending argument. form 'tool' = every positional is a package."""
    bad: list[tuple[str, str]] = []
    # Prose quoting a command ("run `pip install -r requirements.txt`, then...") leaves
    # punctuation glued to the last word; it is not part of the argument.
    args = [a.strip("'\"").rstrip(",.;:)") or a for a in args]
    j = 0
    while j < len(args):
        a = args[j]
        opt, eq, inline = a.partition("=") if a.startswith("--") else (a, "", "")
        takes = opt in OPT_GENERATED_FILE | OPT_EDITABLE | OPT_INDEX | OPT_VALUE_OTHER
        val = inline
        if takes and not eq:
            val = args[j + 1] if j + 1 < len(args) else ""
            j += 1
        j += 1
        if opt in OPT_GENERATED_FILE:
            if base(val) not in gen or re.search(r"[$`{]", val):
                bad.append(
                    (
                        base(val) or "?",
                        f"`{opt} {val}` is not a requirements file devkit.toml declares ([dependencies] requirement_files)",
                    )
                )
            continue
        if opt in OPT_EDITABLE:
            if val not in (".", "./"):
                bad.append((val or "?", f"`{opt} {val}`: only the project itself (`-e .`)"))
            continue
        if opt in OPT_INDEX:
            bad.append((opt, f"`{opt}` overrides where packages come from"))
            continue
        if takes or a.startswith("-"):
            continue
        if form == "pip" and a in (".", "./"):
            continue
        if re.search(r"[$`]|\{\{|\}\}", a):
            bad.append((a, f"install argument `{a}` cannot be resolved statically"))
            continue
        if "git+" in a or "://" in a or a.endswith(ARCHIVE) or "/" in a:
            bad.append((a, f"`{a}` installs from a URL, VCS or path, outside the lock"))
            continue
        name = re.split(r"[<>=!~\[;@ ]", a, maxsplit=1)[0]
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name):
            bad.append((a, f"install argument `{a}` is not a recognisable requirement"))
            continue
        if form == "pip" and norm_pkg(name) == "pip":
            continue  # upgrading the installer is not a dependency
        bad.append(
            (
                norm_pkg(name),
                f"ad-hoc install of `{a}`: pin it in a requirements file devkit.toml declares, or drop it",
            )
        )
    return bad


def run_requirement(args: list[str]) -> list[str]:
    for j, a in enumerate(args):
        if a == "--from":
            return [args[j + 1]] if j + 1 < len(args) else ["?"]
        if a.startswith("--from="):
            return [a.split("=", 1)[1]]
    j = 0
    while j < len(args):
        if args[j] in OPT_VALUE_OTHER:
            j += 2
        elif args[j].startswith("-"):
            j += 1
        else:
            return [args[j]]
    return []


def dep02_shell(f: str, text: str, gen: set[str]) -> list[Finding]:
    out: list[Finding] = []
    if not re.search(r"\b(install|uvx|tool\s+run|pipx)\b", text):
        return out
    for lineno, line in logical_lines(text):
        if not re.search(r"pip|uv", line):
            continue
        toks = tokenize(line)
        consumed: set[int] = set()
        for i in range(len(toks)):
            if i in consumed:
                continue
            hit = install_args(toks, i)
            if hit is None:
                continue
            # `python -m pip install x` is found at `python` AND at its `pip`: judge it once.
            if re.fullmatch(r"python[0-9.]*", base(toks[i])) and "pip" in toks[i + 1 :]:
                consumed.add(toks.index("pip", i + 1))
            form, args = hit
            if form == "run":
                # `uvx [--from SPEC] TOOL ARGS...`: the requirement is SPEC, else TOOL; what
                # follows TOOL is the tool's own command line, not packages.
                form, args = "tool", run_requirement(args)
            for name, why in judge_args(args, gen, form):
                out.append(Finding("DEP-02", f, name, lineno, why))
    return out


# ---- DEP-02: the pip module --------------------------------------------------------------------
def _walk_tasks(node):
    if isinstance(node, list):
        for x in node:
            yield from _walk_tasks(x)
    elif isinstance(node, dict):
        yield node
        for v in node.values():
            if isinstance(v, (list, dict)):
                yield from _walk_tasks(v)


def _resolve_var(expr: str, text: str) -> str | None:
    """`{{ name }}` -> a literal `name: value` defined in the same file, else None."""
    m = re.fullmatch(r"\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}", expr.strip())
    if not m:
        return None
    vals = re.findall(rf"^\s*{m.group(1)}:\s*['\"]?([^'\"\s#{{}}]+)['\"]?\s*$", text, re.M)
    return vals[0] if len(set(vals)) == 1 else None


def dep02_module(f: str, text: str, gen: set[str]) -> list[Finding]:
    if not re.search(r"(^|\s|\.)pip:", text):
        return []
    try:
        docs = list(yaml.safe_load_all(text))
    except yaml.YAMLError as e:
        return [Finding("DEP-02", f, "unparseable", 0, f"file uses pip but does not parse: {e}")]
    out: list[Finding] = []
    for task in _walk_tasks(docs):
        key = next((k for k in PIP_MODULES if k in task), None)
        if key is None or "hosts" in task:
            continue
        mod = task[key]
        line = line_of(text, f"{key}:")
        if isinstance(mod, str):
            try:
                mod = dict(kv.split("=", 1) for kv in shlex.split(mod))
            except ValueError:
                mod = None
        if isinstance(mod, dict) and isinstance(task.get("args"), dict):
            mod = {**task["args"], **mod}
        if mod is None and isinstance(task.get("args"), dict):
            mod = task["args"]
        if not isinstance(mod, dict):
            out.append(
                Finding(
                    "DEP-02",
                    f,
                    "unknown-shape",
                    line,
                    f"{key} task of a shape this check cannot read: {mod!r:.60}",
                )
            )
            continue
        if "extra_args" in mod:
            for name, why in judge_args(shlex.split(str(mod["extra_args"])), gen, "pip"):
                if why.startswith(("`-", "`--")) or "overrides" in why:
                    out.append(Finding("DEP-02", f, name, line, f"extra_args: {why}"))
        if "requirements" in mod:
            req = str(mod["requirements"])
            if "{{" in req:
                req = _resolve_var(req, text) or req
            if "{{" in req or base(req) not in gen:
                out.append(
                    Finding(
                        "DEP-02",
                        f,
                        base(req),
                        line,
                        f"pip module requirements `{req}` is not a requirements file "
                        "devkit.toml declares (or cannot be resolved)",
                    )
                )
        if "name" not in mod:
            if "requirements" not in mod:
                out.append(
                    Finding(
                        "DEP-02",
                        f,
                        "no-name",
                        line,
                        f"{key} task with neither name nor requirements",
                    )
                )
            continue
        names = mod["name"] if isinstance(mod["name"], list) else [mod["name"]]
        resolved: list[str] = []
        for n in names:
            n = str(n)
            if "{{" in n:
                loop = task.get("loop", task.get("with_items"))
                if (
                    re.fullmatch(r"\{\{\s*item\s*\}\}", n.strip())
                    and isinstance(loop, list)
                    and all(isinstance(x, str) and "{{" not in x for x in loop)
                ):
                    resolved += loop
                    continue
                out.append(
                    Finding(
                        "DEP-02",
                        f,
                        n.strip(),
                        line,
                        f"pip module name `{n}` cannot be resolved statically",
                    )
                )
                continue
            resolved.append(n)
        version = mod.get("version")
        for n in resolved:
            n = n.strip()
            if (
                version is not None
                and "{{" not in str(version)
                and re.fullmatch(r"[\w.\[\],-]+", n)
            ):
                continue
            if re.fullmatch(r"[A-Za-z0-9._\[\],-]+==[A-Za-z0-9._+-]+", n):
                continue
            name = re.split(r"[<>=!~\[;@ ]", n, maxsplit=1)[0]
            out.append(
                Finding(
                    "DEP-02",
                    f,
                    norm_pkg(name),
                    line,
                    f"pip module installs `{n}` without an exact `==` pin",
                )
            )
    return out


# ---- DEP-03 ------------------------------------------------------------------------------------
def image_problem(ref: str) -> str | None:
    if "{{" in ref or "${" in ref or ref.startswith("$"):
        return None
    if "@sha256:" in ref:
        return None
    last = ref.rsplit("/", 1)[-1]
    if ":" not in last:
        return "untagged"
    if last.split(":", 1)[1] == "latest":
        return ":latest"
    return None


def is_dockerfile(f: str) -> bool:
    return bool(DOCKERFILE.search(Path(f).name.lower()))


def dep03(root: Path, files: list[str]) -> list[Finding]:
    out: list[Finding] = []
    key_re = re.compile(
        r"^\s*-?\s*(image|[\w]*_image|container):\s*['\"]?([^'\"\s#]+)['\"]?\s*(#.*)?$"
    )
    for f in files:
        if skipped(f):
            continue
        name = Path(f).name
        if is_dockerfile(f):
            stages: set[str] = set()
            for i, line in enumerate(read(root, f).splitlines(), 1):
                m = re.match(r"^\s*FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?", line, re.I)
                if not m:
                    continue
                ref = m.group(1)
                # Judge the ref against the stages defined BEFORE this line, then add this one's
                # alias: `FROM python AS python` names the registry image, not itself.
                if ref.lower() != "scratch" and ref.lower() not in stages:
                    prob = image_problem(ref)
                    if prob:
                        out.append(
                            Finding(
                                "DEP-03",
                                f,
                                ref.split("@")[0],
                                i,
                                f"FROM {ref} is {prob}: pin a tag (and a digest)",
                            )
                        )
                if m.group(2):
                    stages.add(m.group(2).lower())
            continue
        if not f.endswith((".yml", ".yaml", ".j2")):
            continue
        in_scope = (
            "compose" in name
            or "/defaults/" in f
            or "/templates/" in f
            or "/files/" in f
            or f.startswith(("playbooks/", ".github/", "ci/", "roles/", "inventories/"))
        )
        if not in_scope:
            continue
        text = read(root, f)
        for i, line in enumerate(text.splitlines(), 1):
            m = key_re.match(line)
            if not m:
                continue
            key, ref = m.group(1), m.group(2)
            if "://" in ref and not ref.startswith("docker://"):
                continue
            ref = ref.removeprefix("docker://")
            if not IMAGE_REF.fullmatch(ref):
                continue
            if "/" not in ref and ":" not in ref and key not in ("image", "container"):
                continue
            if ref in ("true", "false", "null", "none") or ref.isdigit():
                continue
            if key == "container" and not f.startswith(".github/"):
                continue  # a module's `container:` argument names a running container
            if ref.lower().endswith((".png", ".jpg", ".jpeg", ".svg", ".webp", ".gif", ".ico")):
                continue  # a picture, not a container image
            if key.endswith("_image"):
                prefix = key[: -len("_image")]
                if re.search(rf"^\s*{re.escape(prefix)}_(tag|digest|version):", text, re.M):
                    continue  # repository here, tag/digest in a sibling key
            prob = image_problem(ref)
            if prob:
                out.append(
                    Finding(
                        "DEP-03",
                        f,
                        ref.split("@")[0].split(":")[0],
                        i,
                        f"image {ref} is {prob}: pin a tag (and a digest)",
                    )
                )
    return out


def dep02(root: Path, files: list[str], gen: set[str]) -> list[Finding]:
    out: list[Finding] = []
    for f in files:
        if skipped(f) or f in gen or f.endswith((".lock", ".json")):
            continue
        text = read(root, f)
        out.extend(dep02_shell(f, text, gen))
        if f.endswith((".yml", ".yaml")):
            out.extend(dep02_module(f, text, gen))
    return out


# ---- DEP-04 ------------------------------------------------------------------------------------
def _uses_refs(doc) -> list[tuple[str, bool]]:
    """(ref, job_level) for every `uses:` in a workflow or composite action."""
    refs: list[tuple[str, bool]] = []
    if not isinstance(doc, dict):
        return refs

    def steps(xs):
        for s in xs or []:
            if isinstance(s, dict) and "uses" in s:
                refs.append((str(s["uses"]), False))

    jobs = doc.get("jobs")
    for job in jobs.values() if isinstance(jobs, dict) else []:
        if isinstance(job, dict):
            if "uses" in job:
                refs.append((str(job["uses"]), True))
            steps(job.get("steps"))
    runs = doc.get("runs")
    if isinstance(runs, dict):
        steps(runs.get("steps"))
    return refs


def dep04(root: Path, files: list[str]) -> list[Finding]:
    out: list[Finding] = []
    for f in files:
        if not f.startswith(".github/") or not f.endswith((".yml", ".yaml")):
            continue
        if not (
            f.startswith(".github/workflows/") or Path(f).name in ("action.yml", "action.yaml")
        ):
            continue
        text = read(root, f)
        try:
            docs = list(yaml.safe_load_all(text))
        except yaml.YAMLError as e:
            out.append(Finding("DEP-04", f, "unparseable", 0, f"workflow does not parse: {e}"))
            continue
        for doc in docs:
            for ref, job_level in _uses_refs(doc):
                line = line_of(text, ref)
                if ref.startswith("./"):
                    continue
                if ref.startswith("docker://"):
                    img = ref.removeprefix("docker://")
                    if "@sha256:" not in img:
                        why = image_problem(img) or "not pinned by digest"
                        out.append(
                            Finding(
                                "DEP-04",
                                f,
                                img.split("@")[0],
                                line,
                                f"`uses: {ref}` is {why}: a docker:// action needs a @sha256: digest",
                            )
                        )
                    continue
                target, _, version = ref.partition("@")
                if SHA40.fullmatch(version):
                    continue
                if (
                    job_level
                    and target.startswith(f"{DEVKIT_REPO}/.github/workflows/reusable-")
                    and RELEASE_TAG.fullmatch(version)
                ):
                    continue  # CONFORM-04: devkit's own reusable workflows by release tag
                out.append(
                    Finding(
                        "DEP-04",
                        f,
                        f"{target}@{version or '(none)'}",
                        line,
                        f"`uses: {ref}` is not pinned to a commit SHA (write "
                        f"`{target}@<40-hex sha> # {version or 'vX'}`)",
                    )
                )
    return out


# ---- DEP-05 ------------------------------------------------------------------------------------
RANGE = re.compile(r"^\s*>=\s*\d+(\.\d+){0,2}\s*(,\s*<\s*\d+(\.\d+){0,2}\s*)?$")


def declared(root: Path) -> tuple[str | None, dict[str, str], list[Finding]]:
    """(this collection's ns.name or None, {declared collection: spec}, parse findings)."""
    g = root / "galaxy.yml"
    if g.is_file():
        try:
            data = yaml.safe_load(g.read_text()) or {}
        except yaml.YAMLError as e:
            return None, {}, [Finding("DEP-05", "galaxy.yml", "unparseable", 0, f"galaxy.yml: {e}")]
        if not isinstance(data, dict):
            return None, {}, [Finding("DEP-05", "galaxy.yml", "unparseable", 0, "not a mapping")]
        me = f"{data.get('namespace')}.{data.get('name')}"
        deps = data.get("dependencies") or {}
        if not isinstance(deps, dict):
            return (
                me,
                {},
                [
                    Finding(
                        "DEP-05", "galaxy.yml", "dependencies", 0, "dependencies: is not a mapping"
                    )
                ],
            )
        return me, {str(k): str(v) for k, v in deps.items()}, []
    r = root / "requirements.yml"
    if r.is_file():
        try:
            data = yaml.safe_load(r.read_text()) or {}
        except yaml.YAMLError as e:
            return None, {}, [Finding("DEP-05", "requirements.yml", "unparseable", 0, str(e))]
        out = {}
        for item in (data.get("collections") or []) if isinstance(data, dict) else []:
            n = item.get("name") if isinstance(item, dict) else item
            if isinstance(n, str):
                out[n] = str(item.get("version", "")) if isinstance(item, dict) else ""
        return None, out, []
    return None, {}, []


FQCN = re.compile(r"([a-z_][a-z0-9_]*\.[a-z_][a-z0-9_]*)\.[a-z_][a-z0-9_]*")
ROLE_MODULES = (
    "include_role", "import_role", "ansible.builtin.include_role", "ansible.builtin.import_role",
    "ansible.legacy.include_role", "ansible.legacy.import_role",
)  # fmt: skip
TASK_BLOCKS = ("block", "rescue", "always")


def collections_used(doc) -> list[str]:
    """Collections a PARSED task file uses: a task's FQCN module key, and the role named by an
    include_role/import_role. Parsed, not grepped: `name: net.ipv4.ip_forward` (a sysctl key) and
    `item.item.name:` inside a Jinja scalar are not module references."""
    out: list[str] = []

    def tasks(xs) -> None:
        for t in xs if isinstance(xs, list) else []:
            if not isinstance(t, dict):
                continue
            for k, v in t.items():
                if k in TASK_BLOCKS:
                    tasks(v)
                    continue
                m = FQCN.fullmatch(str(k))
                if m:
                    out.append(m.group(1))
                if k in ROLE_MODULES:
                    name = v.get("name") if isinstance(v, dict) else None
                    m2 = FQCN.fullmatch(str(name)) if isinstance(name, str) else None
                    if m2:
                        out.append(m2.group(1))

    tasks(doc)
    return out


def dep05(root: Path, files: list[str]) -> list[Finding]:
    me, decl, out = declared(root)
    if out:
        return out
    if me is not None:
        for coll, spec in sorted(decl.items()):
            if not RANGE.match(spec):
                out.append(
                    Finding(
                        "DEP-05",
                        "galaxy.yml",
                        f"range:{coll}",
                        0,
                        f"galaxy.yml dependency {coll}: '{spec}' is not a range with a lower bound "
                        "(write '>=X.Y.Z' or '>=X.Y.Z,<N.0.0')",
                    )
                )
    exempt = {"ansible.builtin", "ansible.legacy", me}
    seen: set[tuple[str, str]] = set()
    for f in files:
        if skipped(f):
            continue
        m = re.match(r"roles/([^/]+)/(tasks|handlers)/.*\.ya?ml$", f)
        if m:
            where = f"roles/{m.group(1)}"
            try:
                used = collections_used(yaml.safe_load(read(root, f)))
            except yaml.YAMLError as e:
                out.append(Finding("DEP-05", f, "unparseable", 0, f"task file does not parse: {e}"))
                continue
        elif f.startswith("plugins/") and f.endswith(".py"):
            where = f
            used = [f"{a}.{b}" for a, b in PLUGIN_IMPORT.findall(read(root, f))]
        else:
            continue
        for coll in used:
            if coll in exempt or coll in decl or (where, coll) in seen:
                continue
            seen.add((where, coll))
            home = "galaxy.yml dependencies" if me is not None else "requirements.yml"
            out.append(
                Finding(
                    "DEP-05", where, coll, 0, f"{where} uses {coll}, which {home} does not declare"
                )
            )
    return out


def scan(root: Path, gen: set[str]) -> list[Finding]:
    files = tracked(root)
    return dep02(root, files, gen) + dep03(root, files) + dep04(root, files) + dep05(root, files)


# ---- baseline ----------------------------------------------------------------------------------
def load_baseline(p: Path) -> tuple[dict[str, int], dict[str, str]]:
    if not p.is_file():
        return {}, {}
    data = json.loads(p.read_text())
    entries = {k: int(v) for k, v in (data.get("entries") or {}).items()}
    reasons = {k: str(v) for k, v in (data.get("reasons") or {}).items()}
    return entries, reasons


def write_baseline(p: Path, findings: list[Finding], reasons: dict[str, str]) -> int:
    counts = Counter(f.key for f in findings)
    doc = {
        "_comment": (
            "devkit check dependencies baseline: violations that existed when DEP-02..05 arrived. "
            "key = RULE|path|name, value = occurrences, and a reason for each. New ones FAIL; an "
            "entry that no longer occurs FAILS until removed. Regenerate with "
            "`devkit check dependencies --update-baseline` after a fix, never to admit a new one."
        ),
        "entries": dict(sorted(counts.items())),
        "reasons": {k: reasons.get(k, UNREVIEWED) for k in sorted(counts)},
    }
    p.write_text(json.dumps(doc, indent=2) + "\n")
    return sum(counts.values())


def main(argv: list[str]) -> int:
    args = list(argv)
    if "--list-rules" in args:
        for r, d in RULES.items():
            print(f"{r}  FAIL  {d}")
        return 0
    update = "--update-baseline" in args
    if update:
        args.remove("--update-baseline")
    if args:
        print(f"check_dependencies: unknown argument(s): {' '.join(args)}", file=sys.stderr)
        return 2
    try:
        cfg = _devkit_config.load()
        root = cfg.root
        gen = set(cfg.str_list("dependencies.requirement_files", []))
        bpath = root / cfg.string("dependencies.baseline", DEFAULT_BASELINE)
    except _devkit_config.ConfigError as exc:
        _devkit_config.fatal("check_dependencies", exc)
    try:
        findings = scan(root, gen)
        baseline, reasons = load_baseline(bpath)
    except (Unresolvable, OSError, ValueError) as e:
        print(f"check_dependencies: {e}", file=sys.stderr)
        return 2
    if update:
        n = write_baseline(bpath, findings, reasons)
        print(f"check_dependencies: baseline {bpath.name} rewritten, {n} occurrence(s)")
        return 0
    missing = [
        k for k in baseline if len(reasons.get(k, "").split()) < 3 or reasons.get(k) == UNREVIEWED
    ]
    if missing:
        for k in missing:
            print(
                f"check_dependencies: baseline entry {k} has no reason (at least three words)",
                file=sys.stderr,
            )
        print(
            f"check_dependencies: config error: {bpath.name}: every entry needs a reason",
            file=sys.stderr,
        )
        return 2
    counts = Counter(f.key for f in findings)
    by_key: dict[str, list[Finding]] = {}
    for f in findings:
        by_key.setdefault(f.key, []).append(f)
    new: list[Finding] = []
    for key, fs in by_key.items():
        allowed = baseline.get(key, 0)
        if len(fs) > allowed:
            new.extend(fs[allowed:])
    stale = [(k, v, counts.get(k, 0)) for k, v in sorted(baseline.items()) if counts.get(k, 0) < v]
    for f in new:
        loc = f"{f.path}:{f.line}" if f.line else f.path
        print(f"{f.rule} {loc}: {f.msg}")
    for k, want, have in stale:
        print(
            f"STALE baseline entry {k} (baselined {want}, found {have}): fixed, so remove it "
            "(`devkit check dependencies --update-baseline`)"
        )
    tolerated = sum(min(baseline.get(k, 0), c) for k, c in counts.items())
    if new or stale:
        print(
            f"check_dependencies: {len(new)} new finding(s), {len(stale)} stale baseline "
            f"entr{'y' if len(stale) == 1 else 'ies'} ({tolerated} baselined occurrence(s) tolerated)"
        )
        return 1
    print(f"check_dependencies: clean ({tolerated} baselined occurrence(s) tolerated, none new)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
