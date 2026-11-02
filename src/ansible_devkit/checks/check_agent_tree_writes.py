#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Fail if a root-run Ansible write lands under a tree the AGENT can write, unguarded.

THE BUG THIS CATCHES. A ROOT-run operation that reads, writes, chowns or deletes BY NAME under a
directory an unprivileged agent can write goes wherever a symlink the agent planted points. For
example, `file: state=directory owner=...` on a sub-directory of the agent's tree followed by a
copy and a prune into it: a planted `<tree>/sub -> /etc` makes root chown /etc, write into it and
delete every file in it the source did not have. Any root-run read-modify-write of a file inside
the tree has the same exposure.

Ansible's file modules resolve the path by name. `follow: false` (file/copy/template) makes the
LAST component a name to replace rather than a link to follow, and a preceding `stat` +
`assert ... islnk` HARD GATE refuses a link that is already there; that pair is the accepted
in-play form. Two things it can NOT cover (ansible-core 2.21):

  * `lineinfile` (and `blockinfile`/`replace`) read and write the realpath() of their dest and
    take NO `follow:` parameter at all ("Unsupported parameters ... follow"). Against a planted
    `<tree>/.env -> <victim>`, the line is written into the victim and the link is left in place.
    No gate in front of them closes the stat-then-write window, so they are never accepted here.
  * `follow: false` protects ONLY the last component. A path with an agent-controlled directory
    between the tree root and the name (`<tree>/sub/name`) is redirected by a link at that
    directory, which the leaf's islnk gate never inspects.

Both of those go through a confined helper instead — an fd walk with O_NOFOLLOW at every
component, named per repo in devkit.toml `agent_tree.helper_names` — or run the write AS the
agent (`become_user`), which can then do nothing it could not already do.

RULE

  AGENTTREE-01  FAIL  a file/copy/template/lineinfile/blockinfile/replace task whose path is BELOW
                      a known agent-writable tree root, run as root (no non-root become_user),
                      that is not: file/copy/template with `follow: false`, a PRECEDING
                      `assert` mentioning `islnk` in the same file, and a path whose static part
                      is one component below the root.

THE TREE ROOTS are per-repo facts, so they live in devkit.toml ([agent_tree]: tree_roots,
concat_roots, config_dir_aliases — all three required): typically the agent's state directory
and any per-task data or home directories it owns. The root ITSELF is not below it (its parent is
root-owned, so the agent cannot replace it). A variable is followed one hop at a time within its
role or play directory: an alias of a configured root (`_cfg: "{{ agent_config_dir | default(...)
}}"`) and a variable whose value is under a tree root both count.

DELIBERATELY NOT FLAGGED: molecule scenarios (a test fixture writing into a temp tree it made is
not the estate), reads (`slurp`, `stat`), and `command`/`shell` (the confined helper is invoked
that way). A finding that is genuinely safe for a reason this rule cannot see is suppressed on the
task with `# guard-check: ignore AGENTTREE-01 — <reason>`; a suppression without a reason is
itself a finding.

Run:  devkit check agent-tree-writes [paths...]   (default: roles playbooks)
      --list-rules   print the rule table (read by check_docs_drift.py's DOCRULE-01)
Tests: uv run tests/suites/test_check_agent_tree_writes.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _devkit_config  # noqa: E402

try:
    import yaml
except ImportError:  # --list-rules must still answer (check_docs_drift runs on docs-only changes)
    yaml = None  # type: ignore[assignment]

RULE = "AGENTTREE-01"
RULES_TABLE = (
    f"{RULE}  FAIL  root-run file/copy/template/lineinfile/blockinfile/replace below an "
    "agent-writable tree without follow: false + a preceding islnk gate (or a confined helper)"
)

try:
    _CFG = _devkit_config.load()
    EXEMPT_SUBSTR = (*_CFG.str_list("paths.vendored", []), "/.git/", "/molecule/")
    # Tree roots, matched on NORMALISED text (spaces inside {{ }} removed). Each must be followed
    # by "/<more>" to be BELOW the root.
    TREE_ROOTS = tuple(_CFG.str_list("agent_tree.tree_roots"))
    # Jinja concatenation onto a root, e.g. `cfg_dir ~ ('/x' if c else '/data') ~ '/f'`.
    CONCAT_ROOTS = tuple(_CFG.str_list("agent_tree.concat_roots"))
    # {var: suffix}: a variable whose whole value is `{{ var }}` (optionally filtered) is an ALIAS
    # of `var`, and `{{ alias }}<suffix>` is then a tree root too.
    CONFIG_DIR_ALIASES: dict[str, str] = {
        str(k): str(v) for k, v in dict(_CFG.get("agent_tree.config_dir_aliases")).items()
    }
    # The confined helpers the repo provides, named in every finding ("" names none).
    _helpers = _CFG.string("agent_tree.helper_names", "")
    HELPER_NAMES = f"{_helpers}: " if _helpers else ""
except (_devkit_config.ConfigError, TypeError, ValueError) as _exc:
    _devkit_config.fatal("check_agent_tree_writes", _exc)
WRITE_MODULES = {"file", "copy", "template", "lineinfile", "blockinfile", "replace"}
# Modules where `follow: false` + an islnk gate is an accepted guard. lineinfile/blockinfile/
# replace are absent on purpose: they realpath() the dest and have no follow parameter.
FOLLOW_GUARDABLE = {"file", "copy", "template"}
PATH_KEYS = ("path", "dest", "name", "destfile")

# One alias pattern per configured config dir: `{{ var }}` or `{{ var | default(...) }}`.
CONFIG_DIR_ALIAS_RES = {
    var: re.compile(r"^\{\{" + re.escape(var) + r"(?:\|[^{}]*)?\}\}$") for var in CONFIG_DIR_ALIASES
}
SUPPRESS_RE = re.compile(rf"#\s*guard-check:\s*ignore\s+{RULE}\b\s*(?:[-—]+\s*(\S.*))?$")
JINJA_RE = re.compile(r"\{\{\s*(.*?)\s*\}\}", re.S)
FALSE_WORDS = {"false", "no", "off", "0"}
ROOT_USERS = {"root", "0", ""}


def norm(text: str) -> str:
    """Remove the spaces inside every {{ }} so `{{ x }}` and `{{x}}` compare equal."""
    return JINJA_RE.sub(lambda m: "{{" + re.sub(r"\s+", "", m.group(1)) + "}}", text)


_LOADER = None


def _loader():
    """A SafeLoader that records each mapping's first and last line (for suppressions)."""
    global _LOADER
    if _LOADER is None:

        class LineLoader(yaml.SafeLoader):
            pass

        def construct_mapping(loader, node, deep=False):
            mapping = yaml.SafeLoader.construct_mapping(loader, node, deep=deep)
            mapping["__line__"] = node.start_mark.line + 1
            mapping["__end__"] = node.end_mark.line + 1
            return mapping

        LineLoader.add_constructor(
            yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct_mapping
        )
        _LOADER = LineLoader
    return _LOADER


def load(path: Path):
    try:
        return yaml.load(
            path.read_text(errors="replace"), Loader=_loader()
        )  # noqa: S506 - SafeLoader
    except yaml.YAMLError:
        return None


def is_exempt(path: Path) -> bool:
    s = path.as_posix()
    return any(x in s for x in EXEMPT_SUBSTR)


def unit_of(path: Path) -> Path:
    """The scope a variable definition is visible in: a role, or a playbook service directory
    (tasks/, maintenance/ and files/ belong to the directory above them)."""
    parts = path.parts
    if "roles" in parts:
        i = parts.index("roles")
        if len(parts) > i + 1:
            return Path(*parts[: i + 2])
    d = path.parent
    while d.name in ("tasks", "maintenance", "files", "vars", "handlers"):
        d = d.parent
    return d


def _flat(value) -> str:
    if isinstance(value, dict):
        return " ".join(
            f"{k} {_flat(v)}" for k, v in value.items() if k not in ("__line__", "__end__")
        )
    if isinstance(value, list):
        return " ".join(_flat(v) for v in value)
    return "" if value is None else str(value)


def below_root(text: str, tainted: set[str], aliases: dict[str, str]) -> tuple[bool, bool]:
    """(is the text below an agent tree root, is its static part MORE than one component below).

    A tainted variable is below a root by definition, at an unknown depth (reported as not deep:
    only a statically visible depth is a deterministic finding)."""
    t = norm(text)
    roots = list(TREE_ROOTS) + [
        rf"\{{\{{{re.escape(a)}\}}\}}{re.escape(s)}" for a, s in aliases.items()
    ]
    hit = deep = False
    for root in roots:
        for m in re.finditer("(?:" + root + r")(/[^\s'\"\]},]+)", t):
            rest = m.group(1)
            static = rest.split("{{", 1)[0]
            comps = [c for c in static.split("/") if c]
            hit = True
            if len(comps) >= 2 or (len(comps) == 1 and "{{" in rest and static.endswith("/")):
                deep = True
    if any(re.search(c, t) for c in CONCAT_ROOTS):
        hit = True
    for v in tainted:
        if re.search(rf"\{{\{{{re.escape(v)}(?:[\}}|.\[~ ]|$)", t) or re.search(
            rf"(?<![\w.]){re.escape(v)}\s*~", t
        ):
            hit = True
    return hit, deep


def collect_defs(node, out: dict[str, list[str]]) -> None:
    """Every `name: value` under a vars:/set_fact: mapping, plus a vars file's top level."""
    if isinstance(node, list):
        for x in node:
            collect_defs(x, out)
        return
    if not isinstance(node, dict):
        return
    for key, val in node.items():
        if key in ("vars", "set_fact", "ansible.builtin.set_fact") and isinstance(val, dict):
            for name, v in val.items():
                if name not in ("__line__", "__end__", "cacheable"):
                    out.setdefault(name, []).append(_flat(v))
        elif isinstance(val, (dict, list)):
            collect_defs(val, out)


def resolve_taint(defs: dict[str, list[str]]) -> tuple[set[str], dict[str, str]]:
    """A name may be defined in several files of one unit: ANY definition that is an alias, or is
    below a root, makes it one (the direction that flags, never the one that hides)."""
    aliases: dict[str, str] = {}
    for n, vs in defs.items():
        for var, alias_re in CONFIG_DIR_ALIAS_RES.items():
            if any(alias_re.match(norm(v.strip())) for v in vs):
                aliases.setdefault(n, CONFIG_DIR_ALIASES[var])
    tainted: set[str] = set()
    changed = True
    while changed:
        changed = False
        for name, values in defs.items():
            if name in tainted or name in aliases:
                continue
            if below_root(" ".join(values), tainted, aliases)[0]:
                tainted.add(name)
                changed = True
    return tainted, aliases


def _module(task: dict) -> str | None:
    for key in task:
        if not isinstance(key, str):
            continue
        short = key.rsplit(".", 1)[-1]
        if short in WRITE_MODULES and (
            key == short or key.startswith(("ansible.builtin.", "ansible.legacy."))
        ):
            return key
    return None


def _args(task: dict, key: str) -> dict:
    val = task.get(key)
    if isinstance(val, dict):
        return val
    if isinstance(
        val, str
    ):  # free-form `file: path=... state=...`: the whole line is the path text
        follow = re.search(r"\bfollow=(\S+)", val)
        return {"path": val, **({"follow": follow.group(1)} if follow else {})}
    return {}


def _path_text(task: dict, args: dict) -> str:
    """The destination text, with `item` references resolved against a literal loop."""
    text = " ".join(str(args[k]) for k in PATH_KEYS if k in args)
    loop = task.get("loop", task.get("with_items"))
    if loop is None or "item" not in text:
        return text
    if isinstance(loop, list):
        keys = re.findall(r"item\.(\w+)", text) or re.findall(r"item\[['\"](\w+)['\"]\]", text)
        extra = []
        for it in loop:
            if isinstance(it, dict):
                extra += [str(it.get(k, "")) for k in keys] if keys else [_flat(it)]
            else:
                extra.append(str(it))
        return text + " " + " ".join(extra)
    return text + " " + str(loop)


def _is_false(v) -> bool:
    return v is False or str(v).strip().lower() in FALSE_WORDS


def _suppressed(lines: list[str], start: int, end: int) -> tuple[bool, str | None]:
    """A suppression on the task's own lines or the line just above it. (ok, bare-finding)."""
    for n in range(max(start - 1, 1), min(end, len(lines)) + 1):
        m = SUPPRESS_RE.search(lines[n - 1])
        if m:
            if not (m.group(1) or "").strip():
                return False, f"line {n}: a suppression of {RULE} must say why (`— <reason>`)"
            return True, None
    return False, None


def check_file(path: Path, tainted: set[str], aliases: dict[str, str]) -> list[str]:
    doc = load(path)
    if not isinstance(doc, list):
        return []
    lines = path.read_text(errors="replace").splitlines()
    findings: list[str] = []
    state = {"gate": False}

    def walk(tasks, become_user):
        if not isinstance(tasks, list):
            return
        for t in tasks:
            if not isinstance(t, dict):
                continue
            bu = t.get("become_user", become_user)
            if t.get("become") is False:
                bu = None
            if any(
                k in t for k in ("assert", "ansible.builtin.assert", "fail", "ansible.builtin.fail")
            ):
                if "islnk" in _flat(t):
                    state["gate"] = True
            for key in (
                "pre_tasks",
                "tasks",
                "block",
                "rescue",
                "always",
                "post_tasks",
                "handlers",
            ):
                walk(t.get(key), bu)
            key = _module(t)
            if not key:
                continue
            args = _args(t, key)
            text = _path_text(t, args)
            hit, deep = below_root(text, tainted, aliases)
            if not hit:
                continue
            if bu is not None and norm(str(bu)).strip() not in ROOT_USERS:
                continue  # runs as the agent (or another non-root user): it can do no more
            short = key.rsplit(".", 1)[-1]
            follow_false = _is_false(args.get("follow", "unset"))
            if short in FOLLOW_GUARDABLE and follow_false and state["gate"] and not deep:
                continue
            ok, bare = _suppressed(lines, t.get("__line__", 1), t.get("__end__", 1))
            if ok:
                continue
            name = t.get("name", "(unnamed)")
            where = f"{path}:{t.get('__line__', '?')}"
            dest = " ".join(str(args[k]) for k in PATH_KEYS if k in args)
            if short not in FOLLOW_GUARDABLE:
                why = (
                    f"{short} reads and writes the realpath() of its dest and takes no `follow:`, so "
                    "a link the agent plants there redirects it and no gate before it closes that"
                )
            elif deep:
                why = (
                    "follow: false protects only the LAST component, and this path has a directory "
                    "the agent controls between the tree root and the name, which a link redirects"
                )
            else:
                missing = [
                    m
                    for m, ok_ in (
                        ("`follow: false`", follow_false),
                        ("a preceding `assert` on `stat.islnk`", state["gate"]),
                    )
                    if not ok_
                ]
                why = f"it lacks {' and '.join(missing)}"
            findings.append(
                f"{where}: [{RULE}] task '{name}' ({short}) writes {dest!s} under an agent-writable "
                f"tree as root: {why}. Use a confined helper ({HELPER_NAMES}an fd "
                f"walk with O_NOFOLLOW at every component), run it as the agent (become_user), or, "
                f"for file/copy/template one level below the root, `follow: false` behind a "
                f"stat(follow: false) + islnk HARD GATE." + (f" Also: {bare}" if bare else "")
            )

    for play in doc:
        if isinstance(play, dict) and "hosts" in play:
            bu = None if play.get("become") is False else play.get("become_user")
            for key in ("pre_tasks", "tasks", "post_tasks", "handlers"):
                walk(play.get(key), bu)
        else:
            walk([play], None)
    return findings


def iter_files(args: list[str]) -> list[Path]:
    out: list[Path] = []
    for a in args:
        p = Path(a)
        if p.is_dir():
            out += sorted(x for x in p.rglob("*") if x.suffix in (".yml", ".yaml"))
        elif p.is_file():
            out.append(p)
    return [p for p in out if not is_exempt(p)]


def scan(files: list[Path]) -> list[str]:
    defs_by_unit: dict[Path, dict[str, list[str]]] = {}
    docs = {}
    for f in files:
        docs[f] = load(f)
        defs = defs_by_unit.setdefault(unit_of(f), {})
        if f.parent.name in ("vars", "defaults") and isinstance(docs[f], dict):
            for k, v in docs[f].items():
                if k not in ("__line__", "__end__"):
                    defs.setdefault(k, []).append(_flat(v))
        collect_defs(docs[f], defs)
    taint = {u: resolve_taint(d) for u, d in defs_by_unit.items()}
    findings: list[str] = []
    for f in files:
        tainted, aliases = taint[unit_of(f)]
        findings += check_file(f, tainted, aliases)
    return findings


def main(argv: list[str]) -> int:
    if "--list-rules" in argv:
        print(RULES_TABLE)
        return 0
    if yaml is None:
        print(
            "check_agent_tree_writes: PyYAML is required to scan (only --list-rules works without it)"
        )
        return 2
    files = iter_files(argv[1:] or _CFG.str_list("paths.ansible_roots", ["roles", "playbooks"]))
    findings = scan(files)
    for f in findings:
        print(f"FAIL {f}")
    print(f"\ncheck_agent_tree_writes: {len(findings)} FAIL across {len(files)} file(s) scanned.")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
