#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Fail if a task that RENDERS a credential into a file can print it under `--diff`.

THE BUG THIS CATCHES. A `--check --diff` run writes credentials into whatever records the run,
because a template task rendered a file containing a secret and the task had no `no_log`. `--diff`
prints the whole before/after of the rendered file, and a run-log callback records every task
result, so the diff IS the log line — a compose template carrying an API password, a database
password and a JWT secret, each printed in clear. A log scrubber that only knows the values that
passed through a credential cache never sees them.

WHAT IS CHECKED. A task that writes rendered text into a file — `template`, `copy` with
`content:`, `lineinfile` (`line:`), `blockinfile` (`block:`), `replace` (`replace:`), `ini_file`
(`value:`) — whose rendered text references a CREDENTIAL must carry `no_log: true` (on the task,
or inherited from an enclosing block/play). For `template` the source FILE is resolved the way
Ansible resolves it (a bare `src:` against the role's templates/, then the task file's directory;
a Jinja-prefixed `src:` such as `{{ role_files }}/x.j2` by its static tail under the role's
templates/ and files/) and scanned. A call of `deployment_config` — which renders EVERY `.j2`
under its `deployment_config_source` with a template task of its own that has no `no_log` — is
checked against the `.j2` files in that directory, and must pass `apply: {no_log: true}`
(include_role) or `no_log: true` (import_role).

A CREDENTIAL is a Jinja reference (outside string literals; filter and test names excluded) whose
name, split on `_`/`.`/camelCase, contains password|passwd|pw|secret|token|apikey|api_key|
private_key|privkey|jwt — unless its LAST word says it is ABOUT a credential rather than one
(`password_file`, `token_ttl`, `api_key_enabled`, `jwt_secret_op_item`; see NOT_A_SECRET_SUFFIX).
Or any secret-store lookup (`onepassword*`, `*vault*`, `password`, `passwordstore`, ...). A name
defined in the same role/play directory (vars:, set_fact:, a vars file) from a credential counts
too, followed to a fixpoint, so `_db_pw: "{{ lookup('...onepassword...') }}"` is one.

WHY no_log AND NOT `diff: false`. `diff: false` suppresses only the diff. `no_log: true` also
hides the task's failure output and `-vvv` module arguments, which for `copy content:` and the
lineinfile family ARE the secret; it is the rule every rulebook here already states ("no_log: true
on any task that handles a credential"); and a single requirement is one a reviewer can check by
eye. So `diff: false` alone is NOT accepted. A templated `no_log: "{{ x }}"` is not accepted
either: it can evaluate false, which makes it a guard this check cannot see the outcome of.

NOT CHECKED, deliberately: `copy` with `src:` (copies bytes unrendered — a literal secret in the
source is check_vendored_secrets' job); a diff-capable task editing a file that ALREADY holds a
secret written by something else (the diff prints the whole file, but which file holds what is
run-time state); molecule scenarios (fixture secrets, not real ones). A task whose `src:` cannot be
resolved statically is COUNTED in the summary, never silently passed.

SUPPRESSION: `# guard-check: ignore DIFFLEAK-01 — <reason>` on the task's lines or the line above;
a suppression with no reason is itself a finding.

Run:  devkit check diff-leak [paths...]   (default: the configured paths.ansible_roots)
      --list-rules   print the rule table (read by docs-drift's DOCRULE-01)
      --unresolved   also list every task whose template source could not be resolved
Tests: tests/suites/test_check_diff_leak.py
"""

from __future__ import annotations

import glob
import os
import re
import sys
from pathlib import Path

import jinja2
from jinja2 import nodes

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _devkit_config  # noqa: E402

try:
    import yaml
except ImportError:  # --list-rules must still answer (check_docs_drift runs on docs-only changes)
    yaml = None  # type: ignore[assignment]

RULE = "DIFFLEAK-01"
RULES_TABLE = (
    f"{RULE}  FAIL  a template/copy content/lineinfile/blockinfile/replace/ini_file task (or a "
    "deployment_config sweep) rendering a credential without no_log: true — --diff prints it"
)

try:
    _CFG = _devkit_config.load()
    EXEMPT_SUBSTR = (*_CFG.str_list("paths.vendored", []), "/.git/", "/molecule/")
    DEFAULT_ROOTS = _CFG.str_list("paths.ansible_roots", ["roles", "playbooks"])
except (_devkit_config.ConfigError, TypeError, ValueError) as _exc:
    _devkit_config.fatal("check_diff_leak", _exc)

# ---------------------------------------------------------------------------------------------
# What counts as a credential
# ---------------------------------------------------------------------------------------------

# Words (after splitting an identifier on `_`, `.`, `-` and camelCase) that name a credential.
# Two-word credentials (api_key, private_key) are matched on the joined form below.
SECRET_WORDS = frozenset(
    {"password", "passwd", "pw", "secret", "token", "apikey", "privkey", "jwt"}
)
SECRET_PAIRS = frozenset({("api", "key"), ("private", "key")})

# A LAST word that makes the name ABOUT a credential rather than the credential: where it lives,
# how long it lasts, whether it is on, what 1Password item holds it. `password_file` renders a
# path; `token_ttl` renders a duration. Tuned against this repo (see the test suite's near-misses).
NOT_A_SECRET_SUFFIX = frozenset(
    {
        "file",
        "files",
        "path",
        "dir",
        "directory",
        "cmd",
        "command",
        "helper",
        "env",
        "var",
        "name",
        "names",
        "id",
        "ids",
        "ttl",
        "expiry",
        "expires",
        "lifetime",
        "timeout",
        "age",
        "length",
        "len",
        "url",
        "uri",
        "endpoint",
        "header",
        "enabled",
        "enable",
        "disabled",
        "required",
        "mode",
        "owner",
        "group",
        "item",
        "items",
        "field",
        "section",
        "vault",
        "ref",
        "label",
        "title",
        "version",
        "type",
        "count",
        "set",
        "present",
        "defined",
        "configured",
        "changed",
        "rotate",
        "confirm",
        "policy",
        "scope",
        "scopes",
        "hash",
        "fingerprint",
        "sha",
        "sha256",
        "checksum",
        "user",
        "username",
        "login",
    }
)

# Secret-store lookups: a `lookup('onepassword', ...)`-shaped call renders a secret whatever name
# it is assigned to.
SECRET_LOOKUP_RE = re.compile(
    r"(?i)onepassword|1password|vault|password|passwordstore|bitwarden|keepass|secret|cyberark"
)
JINJA_ANY_RE = re.compile(r"\{\{.*?\}\}|\{%.*?%\}", re.S)
LOOKUP_FUNCS = frozenset({"lookup", "query", "q"})
# Lookups that render the value of a variable or environment variable named by their argument.
NAME_LOOKUPS = frozenset({"vars", "varnames", "env"})
# Accessors whose literal string argument names the key being read.
ACCESSOR_METHODS = frozenset({"get", "pop", "getattr", "setdefault"})
ACCESSOR_FILTERS = frozenset({"json_query", "extract", "attr", "map"})

# Filters whose OUTPUT never reveals their input: `vault(...)` renders ciphertext, the one-way
# hashes render a digest. A credential is protected only when it sits under one of these in the
# expression TREE — the value being filtered, or the filter's own arguments (the vault password).
# Jinja's filter binds tighter than `~`/`+`/`and`/`or`/`if`, so `secret ~ x | vault(pw)` vaults
# only `x`; text-level pipe splitting got that wrong (security review, 2026-11-06), which is why
# this is jinja2's own parser and not a regex.
VAULT_FILTERS = frozenset({"vault", "hash", "password_hash", "checksum", "md5", "sha1"})


def _is_vault_filter(name: str) -> bool:
    return name in VAULT_FILTERS or (
        name.startswith("ansible.builtin.") and name[len("ansible.builtin.") :] in VAULT_FILTERS
    )


class TemplateParseError(Exception):
    """The text is not valid Jinja: the caller records UNRESOLVED, never a pass."""


_ENV = jinja2.Environment(extensions=["jinja2.ext.do", "jinja2.ext.loopcontrols"])


def parse_template(text: str) -> nodes.Template:
    try:
        return _ENV.parse(text)
    except jinja2.TemplateSyntaxError as exc:
        raise TemplateParseError(f"line {exc.lineno}: {exc.message}") from exc


def _words(name: str) -> list[str]:
    return [w.lower() for w in re.split(r"[_.]|(?<=[a-z0-9])(?=[A-Z])", name) if w]


def is_secret_name(name: str) -> bool:
    words = _words(name)
    if not words or words[-1] in NOT_A_SECRET_SUFFIX:
        return False
    if any(w in SECRET_WORDS for w in words):
        return True
    return any((a, b) in SECRET_PAIRS for a, b in zip(words, words[1:]))


def _ref_path(node: nodes.Node) -> str | None:
    """`a`, `a.b.c`, `a['b']` as a dotted path, or None when the base is not a plain name chain."""
    if isinstance(node, nodes.Name):
        return node.name
    if isinstance(node, nodes.Getattr):
        base = _ref_path(node.node)
        return f"{base}.{node.attr}" if base else None
    if isinstance(node, nodes.Getitem):
        base = _ref_path(node.node)
        if base is None:
            return None
        if isinstance(node.arg, nodes.Const) and isinstance(node.arg.value, str):
            return f"{base}.{node.arg.value}"
        return base
    return None


def _is_credential(path: str, tainted: set[str] | frozenset[str]) -> bool:
    parts = path.split(".")
    return any(is_secret_name(x) for x in parts) or is_secret_name(path) or parts[0] in tainted


def _lookup_plugin(call: nodes.Call) -> str | None:
    if isinstance(call.node, nodes.Name) and call.node.name in LOOKUP_FUNCS and call.args:
        first = call.args[0]
        if isinstance(first, nodes.Const) and isinstance(first.value, str):
            return first.value
    return None


def _collect(node: nodes.Node, tainted: set[str] | frozenset[str], hits: set[str]) -> None:
    """Every credential whose VALUE an expression node emits. Walks jinja2's AST: a reference is
    protected only under a vault/hash Filter node; a Test or Compare emits a boolean, not the
    value; a conditional emits one of its branches, never its test."""
    if isinstance(node, nodes.Filter) and _is_vault_filter(node.name):
        return
    if isinstance(node, (nodes.Test, nodes.Compare)):
        return
    if isinstance(node, nodes.CondExpr):
        _collect(node.expr1, tainted, hits)
        if node.expr2 is not None:
            _collect(node.expr2, tainted, hits)
        return
    path = _ref_path(node)
    if path is not None:
        if _is_credential(path, tainted):
            hits.add(path)
        # `d[secret_key]`: the base is reported above; a non-literal subscript is an expression too.
        if isinstance(node, nodes.Getitem) and not isinstance(node.arg, nodes.Const):
            _collect(node.arg, tainted, hits)
        return
    # `(lookup(...)).password`, `f()['token']`: the base is not a name chain, but the attribute
    # or literal key still says what is being read (security review, 2026-11-06).
    if isinstance(node, nodes.Getattr) and is_secret_name(node.attr):
        hits.add(f"<expr>.{node.attr}")
    if (
        isinstance(node, nodes.Getitem)
        and isinstance(node.arg, nodes.Const)
        and isinstance(node.arg.value, str)
        and is_secret_name(node.arg.value)
    ):
        hits.add(f"<expr>.{node.arg.value}")
    # `.get('api_token')`, `| json_query('db.password')`: a literal accessor argument names the key.
    if isinstance(node, nodes.Call) and isinstance(node.node, nodes.Getattr):
        if node.node.attr in ACCESSOR_METHODS:
            for arg in node.args:
                if isinstance(arg, nodes.Const) and isinstance(arg.value, str):
                    if _is_credential(arg.value, tainted):
                        hits.add(f"<expr>.{node.node.attr}('{arg.value}')")
    if isinstance(node, nodes.Filter) and node.name.rsplit(".", 1)[-1] in ACCESSOR_FILTERS:
        for arg in node.args:
            if isinstance(arg, nodes.Const) and isinstance(arg.value, str):
                if _is_credential(arg.value, tainted):
                    hits.add(f"| {node.name}('{arg.value}')")
    if isinstance(node, nodes.Call):
        plugin = _lookup_plugin(node)
        if plugin and SECRET_LOOKUP_RE.search(plugin):
            hits.add(f"lookup('{plugin}')")
        if plugin and classify_lookup(plugin) == "opaque":
            # `lookup('file', '/etc/db_password')`: the path names what it holds.
            for arg in node.args[1:]:
                if isinstance(arg, nodes.Const) and isinstance(arg.value, str):
                    if _is_credential(arg.value, tainted) or SECRET_LOOKUP_RE.search(arg.value):
                        hits.add(f"lookup('{plugin}', '{arg.value}')")
        if plugin and plugin.rsplit(".", 1)[-1] in NAME_LOOKUPS:
            # `lookup('vars', 'db_password')` / `lookup('env', 'DB_PASSWORD')` render the value
            # of a NAMED variable: the literal name is the reference (own adversarial pass,
            # 2026-11-06).
            for arg in node.args[1:]:
                if isinstance(arg, nodes.Const) and isinstance(arg.value, str):
                    if _is_credential(arg.value, tainted):
                        hits.add(f"lookup('{plugin}', '{arg.value}')")
    for child in node.iter_child_nodes():
        _collect(child, tainted, hits)


def _target_names(target: nodes.Node) -> list[str]:
    if isinstance(target, nodes.Name):
        return [target.name]
    if isinstance(target, (nodes.Tuple, nodes.List)):
        return [n for item in target.items for n in _target_names(item)]
    return []


def _template_targets(node: nodes.Node) -> tuple[list[str], list[str]]:
    """(literal template names, non-literal expressions) of an include/import/extends."""
    tmpl = node.template
    if isinstance(tmpl, nodes.Const) and isinstance(tmpl.value, str):
        return [tmpl.value], []
    if isinstance(tmpl, (nodes.List, nodes.Tuple)):
        lits = [
            i.value for i in tmpl.items if isinstance(i, nodes.Const) and isinstance(i.value, str)
        ]
        others = [type(i).__name__ for i in tmpl.items if not isinstance(i, nodes.Const)]
        return lits, others
    return [], [type(tmpl).__name__]


class _Analysis:
    """One walk of a parsed template, in source order (so `{% set %}` before a use is seen)."""

    def __init__(self, tainted: set[str] | frozenset[str]) -> None:
        self.tainted = set(tainted)
        self.hits: set[str] = set()
        self.includes: list[str] = []
        self.non_literal_includes: list[str] = []
        # (plugin, literal first argument or None) for every lookup/query call: a `template`
        # lookup renders ANOTHER file into this text, a `file` lookup copies one in unrendered.
        self.lookups: list[tuple[str, str | None]] = []

    def expr(self, node: nodes.Node) -> set[str]:
        found: set[str] = set()
        _collect(node, self.tainted, found)
        for call in node.find_all(nodes.Call) if not isinstance(node, nodes.Call) else [node]:
            plugin = _lookup_plugin(call)
            if plugin is None:
                continue
            arg = call.args[1] if len(call.args) > 1 else None
            lit = arg.value if isinstance(arg, nodes.Const) and isinstance(arg.value, str) else None
            self.lookups.append((plugin, lit))
        if isinstance(node, nodes.Call):
            for child in node.iter_child_nodes():
                for call in child.find_all(nodes.Call):
                    plugin = _lookup_plugin(call)
                    if plugin is not None:
                        arg = call.args[1] if len(call.args) > 1 else None
                        lit = (
                            arg.value
                            if isinstance(arg, nodes.Const) and isinstance(arg.value, str)
                            else None
                        )
                        self.lookups.append((plugin, lit))
        return found

    def walk(self, node: nodes.Node) -> None:
        if isinstance(node, nodes.Output):
            for child in node.nodes:
                if not isinstance(child, nodes.TemplateData):
                    self.hits |= self.expr(child)
            return
        if isinstance(node, nodes.Assign):
            if self.expr(node.node):
                self.tainted.update(_target_names(node.target))
            return
        if isinstance(node, nodes.AssignBlock):
            inner = _Analysis(self.tainted)
            for b in node.body:
                inner.walk(b)
            self.includes += inner.includes
            self.non_literal_includes += inner.non_literal_includes
            self.lookups += inner.lookups
            # The block's text becomes the variable: a credential, a lookup of any kind or an
            # include this check could not follow all make it one (fail closed).
            if inner.hits or inner.lookups or inner.includes or inner.non_literal_includes:
                self.tainted.update(_target_names(node.target))
            return
        if isinstance(node, nodes.For):
            if self.expr(node.iter):
                self.tainted.update(_target_names(node.target))
            for b in list(node.body) + list(node.else_ or []):
                self.walk(b)
            return
        if isinstance(node, (nodes.Include, nodes.Import, nodes.FromImport, nodes.Extends)):
            lits, others = _template_targets(node)
            self.includes += lits
            self.non_literal_includes += others
            return
        if isinstance(node, nodes.If):
            # The test renders nothing; the branches do.
            for b in list(node.body) + list(node.elif_) + list(node.else_):
                self.walk(b)
            return
        if isinstance(node, nodes.With):
            for target, value in zip(node.targets, node.values):
                if self.expr(value):
                    self.tainted.update(_target_names(target))
            for b in node.body:
                self.walk(b)
            return
        if isinstance(node, nodes.Macro):
            # A default that is a credential makes the parameter one inside the body.
            names = [a.name for a in node.args]
            for name, default in zip(names[len(names) - len(node.defaults) :], node.defaults):
                if self.expr(default):
                    self.tainted.add(name)
            for b in node.body:
                self.walk(b)
            return
        if isinstance(node, nodes.CallBlock):
            self.hits |= self.expr(node.call)
            for b in node.body:
                self.walk(b)
            return
        if isinstance(node, nodes.FilterBlock):
            if _is_vault_filter(node.filter.name):
                return  # `{% filter vault(pw) %}...{% endfilter %}`: the whole body is ciphertext
            for b in node.body:
                self.walk(b)
            return
        if isinstance(node, nodes.ExprStmt):
            # `{% do ... %}` emits nothing, but what it evaluates may be a secret-store read or a
            # file lookup this check must still account for; judged as if emitted (fail closed).
            self.hits |= self.expr(node.node)
            return
        # Anything else: every expression child is judged as emitted (fail closed), every
        # statement child is walked.
        for child in node.iter_child_nodes():
            if isinstance(child, nodes.Expr):
                self.hits |= self.expr(child)
            else:
                self.walk(child)


def analyse(text: str, tainted: set[str] | frozenset[str] = frozenset()) -> _Analysis:
    """Parse `text` (a template body or one task argument) and walk it. Raises TemplateParseError."""
    a = _Analysis(tainted)
    a.walk(parse_template(text))
    return a


def credential_refs(text: str, tainted: frozenset[str] | set[str] = frozenset()) -> set[str]:
    """The credential references whose VALUE `text` would render (names only — never a value).

    Raises TemplateParseError when `text` is not valid Jinja: a caller that cannot judge a text
    records it as UNRESOLVED (a rendered file) or treats it as tainted (a variable)."""
    return analyse(text, tainted).hits


def credential_refs_or_tainted(text: str, tainted: frozenset[str] | set[str]) -> set[str]:
    """For a VARIABLE's value: its credential references, or — when the value does not parse as
    Jinja — a marker so the variable is treated as a credential rather than ignored."""
    try:
        return credential_refs(text, tainted)
    except TemplateParseError:
        return {"<unparseable>"}


# Lookup plugins are matched on their SHORT name for the `ansible.builtin` / `ansible.legacy` /
# bare namespaces; a THIRD-PARTY lookup whose short name says it reads a file or a template is
# UNRESOLVED (its search path and semantics are its own), never a pass.
CORE_LOOKUP_NAMESPACES = frozenset({"", "ansible.builtin", "ansible.legacy"})
# A template's first line may override the delimiters; the `template` module's own options do the
# same per task. Either makes the default-delimiter parse meaningless.
JINJA_HEADER_RE = re.compile(r"\A\s*#jinja2:")
DELIMITER_ARGS = frozenset(
    {
        "variable_start_string",
        "variable_end_string",
        "block_start_string",
        "block_end_string",
        "comment_start_string",
        "comment_end_string",
    }
)
RENDERING_LOOKUPS = frozenset({"template"})
# Lookups whose output is content this check cannot see: a file copied in unrendered, a command's
# output, a URL, a CSV/INI cell, lines of a command. Each is UNRESOLVED, never a pass.
UNRENDERED_FILE_LOOKUPS = frozenset(
    {"file", "fileglob", "first_found", "pipe", "lines", "url", "csvfile", "ini"}
)


def classify_lookup(plugin: str) -> str:
    """'render' (a core template lookup), 'opaque' (content this check cannot see, or any
    third-party file/template reader) or 'other'."""
    ns, _, short = plugin.rpartition(".")
    if ns in CORE_LOOKUP_NAMESPACES:
        if short in RENDERING_LOOKUPS:
            return "render"
        return "opaque" if short in UNRENDERED_FILE_LOOKUPS else "other"
    return "opaque" if short in RENDERING_LOOKUPS | UNRENDERED_FILE_LOOKUPS else "other"


def _lookup_render_refs(
    lookups: list[tuple[str, str | None]],
    here: Path,
    tainted: set[str] | frozenset[str],
    role: Path | None,
    seen: set[Path] | None,
) -> tuple[set[str], list[str]]:
    """`lookup('template', X)` renders X into the output: X is resolved like a `template: src:`
    (the role's templates/, then beside the caller) and scanned recursively; a non-literal X, or
    one no search path holds, is unresolved. `lookup('file', X)` copies X in UNRENDERED, and what a
    file holds is not knowable here: unresolved, never a pass (security review, 2026-11-06)."""
    refs: set[str] = set()
    missing: list[str] = []
    for plugin, lit in lookups:
        kind = classify_lookup(plugin)
        if kind == "render":
            if lit is None:
                missing.append("renders lookup('template', <non-literal>)")
                continue
            bases = [here]
            if role is not None:
                bases += [role / "templates", role / "files"]
            for b in bases:
                q = Path(os.path.normpath(b / lit))
                if q.is_file():
                    sub_refs, sub_missing = template_refs(q, tainted, role, seen)
                    refs |= sub_refs
                    missing += sub_missing
                    break
            else:
                missing.append(f"renders lookup('template', {lit!r}), which no search path holds")
        elif kind == "opaque":
            missing.append(
                f"copies lookup({plugin!r}, {lit!r}) in unrendered: its content is unknown"
            )
    return refs, missing


def template_refs(
    path: Path,
    tainted: set[str] | frozenset[str],
    role: Path | None,
    _seen: set[Path] | None = None,
) -> tuple[set[str], list[str]]:
    """Credential references in a template AND in every template it includes, imports or
    extends, followed recursively with a cycle guard. Returns (refs, unresolved): a template that
    does not parse, an include target that is not a string literal, or one no search path holds
    is reported, never dropped."""
    seen = _seen if _seen is not None else set()
    if path in seen:
        return set(), []
    seen.add(path)
    text = path.read_text(errors="replace")
    if JINJA_HEADER_RE.match(text):
        # `#jinja2: variable_start_string: ...` changes the delimiters for this file, so a
        # default-delimiter parse is wrong by construction. Not judged: unresolved (fail closed).
        return set(), ["declares custom Jinja delimiters (#jinja2: header); not judged"]
    try:
        a = analyse(text, tainted)
    except TemplateParseError as exc:
        return set(), [f"does not parse as Jinja ({exc}); its references cannot be judged"]
    refs = set(a.hits)
    missing = [f"includes a non-literal template ({kind})" for kind in a.non_literal_includes]
    inc_refs, inc_missing = _lookup_render_refs(a.lookups, path.parent, a.tainted, role, seen)
    refs |= inc_refs
    missing += inc_missing
    for target in a.includes:
        bases = [path.parent]
        if role is not None:
            bases += [role / "templates", role / "files"]
        for b in bases:
            q = Path(os.path.normpath(b / target))
            if q.is_file():
                sub_refs, sub_missing = template_refs(q, a.tainted, role, seen)
                refs |= sub_refs
                missing += sub_missing
                break
        else:
            missing.append(f"includes {target!r}, which no template search path holds")
    return refs, missing


# ---------------------------------------------------------------------------------------------
# YAML loading
# ---------------------------------------------------------------------------------------------

_LOADER = None


def _last_line(node) -> int:
    """The 1-based line of the last character of `node`'s content. PyYAML's end_mark for a block
    collection is the NEXT token's position (often the next sibling's line), so the end is taken
    from the last value node, recursively."""
    import yaml as _y

    if isinstance(node, _y.ScalarNode):
        em = node.end_mark
        # A block scalar's end mark sits at column 0 of the following line.
        return em.line if em.column == 0 and em.line > node.start_mark.line else em.line + 1
    if isinstance(node, _y.SequenceNode) and node.value:
        return _last_line(node.value[-1])
    if isinstance(node, _y.MappingNode) and node.value:
        return _last_line(node.value[-1][1])
    return node.start_mark.line + 1


def _loader():
    global _LOADER
    if _LOADER is None:

        class LineLoader(yaml.SafeLoader):
            pass

        def construct_mapping(loader, node, deep=False):
            mapping = yaml.SafeLoader.construct_mapping(loader, node, deep=deep)
            mapping["__line__"] = node.start_mark.line + 1
            mapping["__end__"] = _last_line(node)
            return mapping

        LineLoader.add_constructor(
            yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct_mapping
        )
        # Vault-encrypted scalars: an opaque value, never a reference.
        LineLoader.add_constructor("!vault", lambda loader, node: "")
        LineLoader.add_constructor("!unsafe", lambda loader, node: loader.construct_scalar(node))
        _LOADER = LineLoader
    return _LOADER


class _ParseError:
    def __init__(self, exc: Exception) -> None:
        self.exc = exc


PARSE_ERROR = _ParseError  # type marker


def load(path: Path):
    """The document, None for an EMPTY file, or a _ParseError the caller must report: a task
    file that does not parse may hold a render task this check never saw (fail closed)."""
    try:
        return yaml.load(path.read_text(errors="replace"), Loader=_loader())  # noqa: S506
    except (yaml.YAMLError, ValueError) as exc:
        return _ParseError(exc)


# Directories whose YAML is DATA (a mapping), not a task list: a mapping at the top of one of these
# is expected; a mapping at the top of a tasks/handlers/playbook file is not a task file at all.
NON_TASK_DIRS = frozenset(
    {"vars", "defaults", "meta", "group_vars", "host_vars", "files", "templates", "molecule"}
)


def _is_task_file(path: Path) -> bool:
    return not any(part in NON_TASK_DIRS for part in path.parts)


VARS_DIRS = frozenset({"vars", "defaults", "group_vars", "host_vars"})


def _is_vars_data(path: Path) -> bool:
    """Top-level variable data: any YAML under vars/, defaults/, group_vars/ or host_vars/ at
    ANY depth (vars/main/*.yml, group_vars/all/*.yml, host_vars/<host>/*.yml), or a *_vars dir."""
    parts = path.parts[:-1]
    return any(p in VARS_DIRS or p.endswith("_vars") for p in parts)


def is_exempt(path: Path) -> bool:
    s = path.as_posix()
    return any(x in s for x in EXEMPT_SUBSTR)


def _flat(value) -> str:
    if isinstance(value, dict):
        return " ".join(
            f"{k} {_flat(v)}" for k, v in value.items() if k not in ("__line__", "__end__")
        )
    if isinstance(value, list):
        return " ".join(_flat(v) for v in value)
    return "" if value is None else str(value)


def role_of(path: Path) -> Path | None:
    parts = path.parts
    if "roles" in parts:
        i = len(parts) - 1 - parts[::-1].index("roles")
        if len(parts) > i + 2:
            return Path(*parts[: i + 2])
    return None


def unit_of(path: Path) -> Path:
    """The scope a variable definition is visible in: a role, or a playbook directory."""
    role = role_of(path)
    if role is not None:
        return role
    d = path.parent
    while d.name in ("tasks", "maintenance", "files", "templates", "vars", "handlers"):
        d = d.parent
    return d


# ---------------------------------------------------------------------------------------------
# Taint: names defined from a credential
# ---------------------------------------------------------------------------------------------


def collect_defs(node, out: dict[str, list[str]], top: bool = False) -> None:
    if isinstance(node, dict) and top:
        for name, v in node.items():
            if isinstance(name, str) and not name.startswith("__"):
                out.setdefault(name, []).append(_flat(v))
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


def resolve_taint(defs: dict[str, list[str]]) -> set[str]:
    """A name ANY of whose definitions references a credential is one (the flagging direction),
    whatever the name looks like: `token_file: "{{ api_token }}"` holds the token, and the
    not-a-secret suffixes apply only to detection BY NAME (security review, 2026-11-06)."""
    tainted: set[str] = set()
    changed = True
    while changed:
        changed = False
        for name, values in defs.items():
            if name in tainted:
                continue
            if credential_refs_or_tainted(" ".join(values), tainted):
                tainted.add(name)
                changed = True
    return tainted


# ---------------------------------------------------------------------------------------------
# Source resolution
# ---------------------------------------------------------------------------------------------


def _substitute_dirs(src: str, task_file: Path) -> str:
    """Replace `{{ role_path }}` and `{{ playbook_dir }}` with the directories they name here."""
    role = role_of(task_file)
    if role is not None:
        src = re.sub(r"\{\{\s*role_path\s*\}\}", role.as_posix(), src)
    # playbook_dir is the directory of the PLAYBOOK; a task file under tasks/ belongs to the one above.
    play_dir = task_file.parent.parent if task_file.parent.name == "tasks" else task_file.parent
    return re.sub(r"\{\{\s*playbook_dir\s*\}\}", play_dir.as_posix(), src)


def _literal(src: str) -> bool:
    return "{{" not in src and "{%" not in src


def _glob_regex(src: str) -> re.Pattern[str] | None:
    """A regex for a src with Jinja in it (each block matches anything), or None when the last
    path component has no literal text at all (`{{ item }}`) — that matches every file."""
    last = src.rsplit("/", 1)[-1]
    if not JINJA_ANY_RE.sub("", last).strip(". "):
        return None
    pieces = re.split(r"\{\{.*?\}\}|\{%.*?%\}", src)
    return re.compile("(?:^|/)" + ".*".join(re.escape(x) for x in pieces).lstrip("/") + "$")


def resolve_template(src: str, task_file: Path) -> list[Path]:
    """The file(s) a `template: src:` renders, resolved as Ansible would (or [] if unknown)."""
    role = role_of(task_file)
    src = _substitute_dirs(src, task_file)
    if _literal(src):
        p = Path(src)
        if (
            p.is_absolute()
            or (Path.cwd() / p).is_file()
            and src.startswith(("roles/", "playbooks/"))
        ):
            q = Path(os.path.normpath(p))
            return [q] if q.is_file() else []
        bases = []
        if role is not None:
            bases += [role / "templates", role]
        d = task_file.parent
        bases += [d / "templates", d, d.parent / "templates", d.parent]
        for b in bases:
            q = Path(os.path.normpath(b / p))
            if q.is_file():
                return [q]
        return []
    rx = _glob_regex(src)
    if rx is None:
        return []
    search = [role / "templates", role / "files"] if role is not None else []
    d = task_file.parent
    search += [d / "templates", d]
    hits: list[Path] = []
    for base in search:
        if base.is_dir():
            hits += [p for p in base.rglob("*") if p.is_file() and rx.search(p.as_posix())]
    return sorted(set(hits))


def resolve_fileglob(patterns, task_file: Path) -> tuple[list[Path], list[str]]:
    """(the files a `with_fileglob:` list expands to, the patterns that could not be resolved) —
    a non-literal pattern, or one that matches nothing. The caller reports the second list: a
    pattern this check cannot expand was silently dropped before (security review, 2026-11-06)."""
    out: list[Path] = []
    unresolved: list[str] = []
    for pat in patterns if isinstance(patterns, list) else [patterns]:
        sub = _substitute_dirs(str(pat), task_file)
        if not _literal(sub):
            unresolved.append(f"with_fileglob {str(pat)!r} is not static")
            continue
        role = role_of(task_file)
        if not os.path.isabs(sub) and not (role is not None and sub.startswith(role.as_posix())):
            base = (role / "files") if role is not None else task_file.parent
            sub = (base / sub).as_posix()
        hits = [Path(x) for x in sorted(glob.glob(os.path.normpath(sub))) if os.path.isfile(x)]
        if not hits:
            unresolved.append(f"with_fileglob {str(pat)!r} matches no file")
        out += hits
    return out, unresolved


def resolve_sweep_dir(source: str, task_file: Path, defs: dict[str, list[str]]) -> Path | None:
    """The directory a deployment_config_source names. `{{ <x>_files }}`/`{{ role_path }}/files`
    are the role's files/ (with any static suffix); a variable is followed one hop."""
    role = role_of(task_file)
    s = source.strip()
    m = re.fullmatch(r"\{\{\s*([A-Za-z_]\w*)\s*\}\}(/.*)?", s)
    if m:
        var, rest = m.group(1), (m.group(2) or "")
        if var == "role_path" and role is not None:
            return role / rest.lstrip("/")
        for v in defs.get(var, []):
            vm = re.fullmatch(r"\{\{\s*role_path\s*\}\}(/.*)?", v.strip())
            if vm and role is not None:
                return role / (vm.group(1) or "").lstrip("/") / rest.lstrip("/")
        if var.endswith("files") and role is not None:
            return role / "files" / rest.lstrip("/")
    return None


# ---------------------------------------------------------------------------------------------
# Task walk
# ---------------------------------------------------------------------------------------------

# Every argument whose value is RENDERED into the file, aliases included, from each module's own
# argument spec (`ansible-doc --json`; tests/suites/test_check_diff_leak.py asserts this table
# against the installed ansible-core). `template` renders its `src` FILE instead. An alias that
# was missing here (blockinfile `content`, lineinfile `value`, ini_file `values`) was a task the
# check never looked at (security review, 2026-11-06).
RENDER_ARGS: dict[str, tuple[str, ...]] = {
    "template": (),
    "copy": ("content",),
    "lineinfile": ("line", "value"),
    "blockinfile": ("block", "content"),
    "replace": ("replace",),
    "ini_file": ("value", "values"),
    # ansible.windows renders the same way; a Windows host's secrets are not less secret.
    "win_template": (),
    "win_copy": ("content",),
    "win_lineinfile": ("line",),
}
INCLUDE_KEYS = ("include_role", "import_role")
TRUE_WORDS = {"true", "yes", "on", "1"}
SUPPRESS_RE = re.compile(rf"#\s*guard-check:\s*ignore\s+{RULE}\b\s*(?:[-—]+\s*(\S.*))?$")


try:
    from ansible.parsing.splitter import parse_kv as _parse_kv
except Exception:  # ansible-core is optional for this check; without it free-form is unresolved
    _parse_kv = None


def _parse_free_form(text: str) -> dict | None:
    """Free-form `k=v k2="v 2"` module args, split the way Ansible splits them (quotes and Jinja
    with spaces respected). None when ansible-core is absent or the text does not parse — a
    `(\\w+)=(\\S+)` regex broke on both and silently produced the wrong dest/src."""
    if _parse_kv is None:
        return None
    try:
        parsed = _parse_kv(text)
    except Exception:
        return None
    return {str(k): v for k, v in parsed.items()} if isinstance(parsed, dict) else None


def _short(key: str) -> str:
    return key.rsplit(".", 1)[-1]


def _is_render_key(key) -> bool:
    """A module is matched on its SHORT name whatever its namespace: `ansible.builtin.template`,
    `ansible.legacy.template`, a collection's `template` — a third-party module that calls itself
    `copy` or `template` renders files too, and is judged rather than skipped."""
    return isinstance(key, str) and _short(key) in RENDER_ARGS


def _module(task: dict) -> str | None:
    for key in task:
        if _is_render_key(key):
            return key
    return None


def _module_and_args(task: dict) -> tuple[str | None, object, str | None]:
    """(short module name, its args, problem) for a task, in every form Ansible accepts:
    `template: {...}` / `template: k=v`, `action: template k=v`, `action: {module: template, ...}`
    (args inline or under `args:`), `local_action:` likewise — and a task-level `args:` mapping
    merged over the module's own. `problem` names why the args could not be determined; the caller
    records that as UNRESOLVED (security review, 2026-11-06: `args:` and `action:` were skipped
    silently, and a secret rendered through either was never seen)."""
    key = _module(task)
    short: str | None = None
    args: object = None
    if key is not None:
        short = _short(key)
        args = task.get(key)
    else:
        for akey in ("action", "local_action"):
            if akey not in task:
                continue
            a = task[akey]
            if isinstance(a, str):
                mod, _, rest = a.strip().partition(" ")
                if not _is_render_key(mod):
                    return None, None, None
                short, args = _short(mod), rest
            elif isinstance(a, dict):
                mod = a.get("module")
                if not isinstance(mod, str) or not _is_render_key(mod):
                    return None, None, None
                short = _short(mod)
                inner = a.get("args")
                merged = {
                    k: v for k, v in a.items() if k not in ("module", "args", "__line__", "__end__")
                }
                if isinstance(inner, dict):
                    merged.update(inner)
                elif isinstance(inner, str):
                    parsed = _parse_free_form(inner)
                    if parsed is None:
                        return short, None, f"{akey}: args could not be parsed"
                    merged.update(parsed)
                elif inner is not None:
                    return short, None, f"{akey}: args is neither a mapping nor k=v"
                args = merged
            else:
                return None, None, f"{akey} is neither a string nor a mapping"
            break
        else:
            return None, None, None
    if isinstance(args, str):  # free-form k=v
        parsed = _parse_free_form(args)
        if parsed is None:
            return (
                short,
                None,
                "free-form args could not be parsed"
                + ("" if _parse_kv else " (ansible-core not importable)"),
            )
        args = parsed
    elif args is None:
        args = {}
    if not isinstance(args, dict):
        return short, None, "module args are neither a mapping nor k=v"
    extra = task.get("args")
    if isinstance(extra, dict):
        args = {**args, **{k: v for k, v in extra.items() if k not in ("__line__", "__end__")}}
    elif extra is not None:
        return short, None, "task-level args: is not a mapping"
    return short, args, None


def _include(task: dict) -> str | None:
    for key in task:
        if isinstance(key, str) and _short(key) in INCLUDE_KEYS:
            return key
    return None


def _truthy(v) -> bool:
    return v is True or str(v).strip().lower() in TRUE_WORDS


def _suppressed(lines: list[str], start: int, end: int) -> tuple[bool, str | None]:
    """A suppression counts on the task's OWN lines (start..end, where end is the last line of its
    last value, never the next sibling's start), or on a comment line directly above it. An earlier
    range reached the mapping's end mark, which PyYAML places at the next token — so a comment on
    the next task covered this one (security review, 2026-11-06)."""
    first = start
    if start >= 2 and re.match(r"^\s*#", lines[start - 2]):
        first = start - 1
    for n in range(max(first, 1), min(end, len(lines)) + 1):
        m = SUPPRESS_RE.search(lines[n - 1])
        if m:
            if not (m.group(1) or "").strip():
                return (
                    False,
                    f"line {n}: a suppression of {RULE} must say why (`— <reason>`)",
                )
            return True, None
    return False, None


class Scan:
    def __init__(self) -> None:
        self.findings: list[str] = []
        self.unresolved: list[str] = []
        self.tasks_checked = 0
        self.files_rendered: set[Path] = set()

    def check_file(self, path: Path, tainted: set[str], defs: dict[str, list[str]]) -> None:
        doc = load(path)
        if isinstance(doc, _ParseError):
            if not _is_task_file(path):
                return  # application config under files/ (HA's `!include` tags, ...) is data
            msg = str(doc.exc).splitlines()[0][:160]
            self.unresolved.append(f"{path}: does not parse as YAML ({msg})")
            self.findings.append(
                f"{path}: [{RULE}] the file does not parse as YAML ({msg}), so any render task in "
                "it is unseen. Fix the YAML: an unparseable task file is a finding, never a pass."
            )
            return
        if doc is None:
            return  # an empty file renders nothing
        if not isinstance(doc, list):
            # A mapping at the top is DATA (vars beside a play, a generated answer file, a card):
            # Ansible refuses it as a play or task list, so no render task hides in it. Under
            # tasks/ or handlers/ it is an authoring error worth a finding.
            if path.parent.name in ("tasks", "handlers"):
                self.unresolved.append(f"{path}: top level is not a task list")
                self.findings.append(
                    f"{path}: [{RULE}] the top level is a {type(doc).__name__}, not a task list, "
                    "so nothing in it is judged. A task file is a list; move data to vars/."
                )
            return
        lines = path.read_text(errors="replace").splitlines()

        def report(t: dict, what: str, refs: set[str], fix: str) -> None:
            ok, bare = _suppressed(lines, t.get("__line__", 1), t.get("__end__", 1))
            if ok:
                return
            name = t.get("name", "(unnamed)")
            self.findings.append(
                f"{path}:{t.get('__line__', '?')}: [{RULE}] task '{name}' {what} referencing "
                f"{', '.join(sorted(refs))} without no_log: true, so --diff prints the rendered "
                f"credential into the run log. {fix}" + (f" Also: {bare}" if bare else "")
            )

        def walk(tasks, no_log: bool) -> None:
            if not isinstance(tasks, list):
                return
            for t in tasks:
                if not isinstance(t, dict):
                    self.unresolved.append(
                        f"{path}: a task entry is not a mapping ({t!r}); not judged"
                    )
                    continue
                nl = _truthy(t["no_log"]) if "no_log" in t else no_log
                for sub in ("block", "rescue", "always"):
                    walk(t.get(sub), nl)
                local = set(tainted)
                tvars = t.get("vars")
                if isinstance(tvars, dict):
                    for n, v in tvars.items():
                        if isinstance(n, str) and credential_refs_or_tainted(_flat(v), local):
                            local.add(n)  # defined from a credential: tainted whatever its name
                short, margs, problem = _module_and_args(t)
                if short is not None:
                    if problem is not None:
                        self.tasks_checked += 1
                        self.unresolved.append(
                            f"{path}:{t.get('__line__', '?')}: {short}: {problem}"
                        )
                        if not nl:
                            report(
                                t,
                                f"has {short} arguments this check cannot read ({problem})",
                                {"<unresolved>"},
                                "Write the arguments as a mapping, add `no_log: true`, or "
                                "suppress with a reason: unreadable arguments are a finding, "
                                "never a pass.",
                            )
                    else:
                        self._render_task(path, t, short, margs, nl, local, report)
                ikey = _include(t)
                if ikey:
                    self._sweep_task(path, t, ikey, nl, local, defs, report)

        for play in doc:
            if isinstance(play, dict) and "hosts" in play:
                nl = _truthy(play.get("no_log", False))
                ptainted = set(tainted)
                pv = play.get("vars")
                if isinstance(pv, dict):
                    for n, v in pv.items():
                        if isinstance(n, str) and credential_refs_or_tainted(_flat(v), ptainted):
                            ptainted.add(n)
                tainted_saved = tainted
                tainted = ptainted  # noqa: PLW2901 - play vars scope its tasks
                for key in ("pre_tasks", "tasks", "post_tasks", "handlers"):
                    walk(play.get(key), nl)
                tainted = tainted_saved
            else:
                walk([play], False)

    def _render_task(self, path, t, short, args, no_log, local, report) -> None:
        self.tasks_checked += 1
        if short in ("template", "win_template"):
            src = str(args.get("src", ""))
            loop = t.get("loop", t.get("with_items"))
            files: list[Path] = []
            srcs = [src]
            glob_problems: list[str] = []
            if "with_fileglob" in t and re.fullmatch(r"\{\{\s*item\s*\}\}", src.strip()):
                srcs = []
                files, glob_problems = resolve_fileglob(t["with_fileglob"], path)
                self.unresolved += [f"{path}:{t.get('__line__', '?')}: {g}" for g in glob_problems]
            elif "item" in src and isinstance(loop, list):
                srcs = []
                for it in loop:
                    if isinstance(it, dict):
                        sub = re.sub(
                            r"\{\{\s*item\.(\w+)\s*\}\}",
                            lambda m: str(it.get(m.group(1), "")),
                            src,
                        )
                    else:
                        sub = re.sub(r"\{\{\s*item\s*\}\}", str(it), src)
                    srcs.append(sub)
            for s in srcs:
                got = resolve_template(s, path)
                if not got:
                    self.unresolved.append(f"{path}:{t.get('__line__', '?')}: src {s!r}")
                files += got
            refs: set[str] = set()
            problems: list[str] = list(glob_problems)
            custom = sorted(DELIMITER_ARGS & set(args))
            if custom:
                problems.append(f"uses custom Jinja delimiters ({', '.join(custom)}); not judged")
                self.unresolved.append(
                    f"{path}:{t.get('__line__', '?')}: custom Jinja delimiters {custom}"
                )
                files = []  # a default-delimiter scan of the file would be wrong
                srcs = []
            for s_ in srcs:
                if not resolve_template(s_, path):
                    problems.append(f"src {s_!r} could not be resolved")
            for f in files:
                self.files_rendered.add(f)
                got, missing = template_refs(f, local, role_of(path))
                refs |= got
                problems += [f"{f.name} {m}" for m in missing]
                self.unresolved += [
                    f"{path}:{t.get('__line__', '?')}: {f.name} {m}" for m in missing
                ]
            if problems and not refs and not no_log:
                # (a credential finding on the same task already fails it; one finding per task)
                report(
                    t,
                    "renders content this check cannot resolve (" + "; ".join(problems) + ")",
                    {"<unresolved>"},
                    "Add `no_log: true` to the task, make the source static, or suppress with a "
                    "reason: an unresolved source is a finding, never a pass.",
                )
            if refs and not no_log:
                rels = ", ".join(sorted({f.name for f in files}))
                report(
                    t,
                    f"renders {rels}",
                    refs,
                    "Add `no_log: true` to the task (and a 0600/0640 mode if the file is a "
                    "credential file).",
                )
            return
        present = [a for a in RENDER_ARGS[short] if a in args]
        for arg in present:
            try:
                a = analyse(_flat(args[arg]), local)
            except TemplateParseError as exc:
                self.unresolved.append(
                    f"{path}:{t.get('__line__', '?')}: `{arg}:` does not parse as Jinja ({exc})"
                )
                if not no_log:
                    report(
                        t,
                        f"writes `{arg}:` whose text does not parse as Jinja ({exc})",
                        {"<unresolved>"},
                        "Fix the expression, add `no_log: true`, or suppress with a reason: an "
                        "unparseable source is a finding, never a pass.",
                    )
                continue
            refs = set(a.hits)
            more, missing = _lookup_render_refs(
                a.lookups, path.parent, a.tainted, role_of(path), None
            )
            refs |= more
            self.unresolved += [f"{path}:{t.get('__line__', '?')}: `{arg}:` {m}" for m in missing]
            if missing and not refs and not no_log:
                report(
                    t,
                    f"writes `{arg}:` with content this check cannot resolve ("
                    + "; ".join(missing)
                    + ")",
                    {"<unresolved>"},
                    "Add `no_log: true` to the task, make the content static, or suppress with a "
                    "reason: an unresolved source is a finding, never a pass.",
                )
            if refs and not no_log:
                report(t, f"writes `{arg}:`", refs, "Add `no_log: true` to the task.")

    def _sweep_task(self, path, t, ikey, no_log, local, defs, report) -> None:
        args = t.get(ikey)
        if isinstance(args, str):  # `include_role: name=x apply=...` free-form
            parsed = _parse_free_form(args)
            if parsed is None:
                self.tasks_checked += 1
                self.unresolved.append(
                    f"{path}:{t.get('__line__', '?')}: {_short(ikey)} free-form args could not "
                    "be parsed"
                )
                if not no_log:
                    report(
                        t,
                        f"has {_short(ikey)} arguments this check cannot read",
                        {"<unresolved>"},
                        "Write the arguments as a mapping, add `no_log: true`, or suppress with "
                        "a reason: unreadable arguments are a finding, never a pass.",
                    )
                return
            args = parsed
        if not isinstance(args, dict):
            self.tasks_checked += 1
            self.unresolved.append(
                f"{path}:{t.get('__line__', '?')}: {_short(ikey)} args are not a mapping"
            )
            if not no_log:
                report(
                    t,
                    f"has {_short(ikey)} arguments this check cannot read",
                    {"<unresolved>"},
                    "Write the arguments as a mapping, add `no_log: true`, or suppress with a "
                    "reason: unreadable arguments are a finding, never a pass.",
                )
            return
        name = str(args.get("name", ""))
        if not name.endswith("deployment_config"):
            return
        self.tasks_checked += 1
        # What covers deployment_config's OWN template task: the play/block no_log for an
        # import_role, `apply: {no_log: true}` for an include_role. Decided once, used by every
        # report below (an unresolved sweep was judged on the outer no_log alone before).
        if _short(ikey) == "import_role":
            covered = no_log
        else:
            apply = args.get("apply")
            covered = isinstance(apply, dict) and _truthy(apply.get("no_log", False))
        tvars = t.get("vars") if isinstance(t.get("vars"), dict) else {}
        source = str(tvars.get("deployment_config_source", ""))
        d = resolve_sweep_dir(source, path, defs)
        if d is None or not d.is_dir():
            self.unresolved.append(
                f"{path}:{t.get('__line__', '?')}: deployment_config_source {source!r}"
            )
            if not covered:
                report(
                    t,
                    f"sweeps deployment_config_source {source!r}, which this check cannot resolve",
                    {"<unresolved>"},
                    "Make the source static, pass `apply: {no_log: true}`, or suppress with a "
                    "reason: an unresolved source is a finding, never a pass.",
                )
            return
        refs: set[str] = set()
        names = []
        sweep_problems: list[str] = []
        for f in sorted(d.rglob("*.j2")):
            got, missing = template_refs(f, local, role_of(path))
            self.unresolved += [f"{path}:{t.get('__line__', '?')}: {f.name} {m}" for m in missing]
            sweep_problems += [f"{f.relative_to(d).as_posix()} {m}" for m in missing]
            if got:
                names.append(f.relative_to(d).as_posix())
                refs |= got
        if sweep_problems and not refs and not covered:
            report(
                t,
                f"sweeps {d}/ through deployment_config with content this check cannot resolve ("
                + "; ".join(sweep_problems)
                + ")",
                {"<unresolved>"},
                "Pass `apply: {no_log: true}` / `no_log: true`, make the templates static, or "
                "suppress with a reason: an unresolved source is a finding, never a pass.",
            )
        if not refs or covered:
            return
        report(
            t,
            f"sweeps {d}/ through deployment_config, which renders {', '.join(names)}",
            refs,
            "deployment_config's own template task has no no_log: pass `apply: {no_log: true}` "
            "on the include_role, or move the credential template to the role's templates/ and "
            "render it in its own task with no_log: true.",
        )


def iter_files(args: list[str]) -> list[Path]:
    out: list[Path] = []
    for a in args:
        p = Path(a)
        if p.is_dir():
            out += sorted(x for x in p.rglob("*") if x.suffix in (".yml", ".yaml"))
        elif p.is_file():
            out.append(p)
    return [p for p in out if not is_exempt(p)]


def scan(files: list[Path]) -> Scan:
    # Definitions are scoped to a unit (role or playbook directory) and include its vars files.
    units: dict[Path, dict[str, list[str]]] = {}
    unit_dirs = {unit_of(f) for f in files}
    for u in unit_dirs:
        defs: dict[str, list[str]] = {}
        if u.is_dir():
            for y in sorted(u.rglob("*")):
                if y.suffix not in (".yml", ".yaml") or is_exempt(y):
                    continue
                doc = load(y)
                if isinstance(doc, _ParseError):
                    continue  # reported by check_file when the file is a task file
                top = _is_vars_data(y)
                collect_defs(doc, defs, top=top)
        units[u] = defs
    taint = {u: resolve_taint(d) for u, d in units.items()}
    s = Scan()
    for f in files:
        u = unit_of(f)
        s.check_file(f, taint[u], units[u])
    return s


def main(argv: list[str]) -> int:
    if "--list-rules" in argv:
        print(RULES_TABLE)
        return 0
    if yaml is None:
        print("check_diff_leak: PyYAML is required to scan (only --list-rules works without it)")
        return 2
    show_unresolved = "--unresolved" in argv
    paths = [a for a in argv[1:] if not a.startswith("--")]
    files = iter_files(paths or DEFAULT_ROOTS)
    s = scan(files)
    for f in s.findings:
        print(f"FAIL {f}")
    if show_unresolved:
        for u in s.unresolved:
            print(f"UNRESOLVED {u}")
    print(
        f"\ncheck_diff_leak: {len(s.findings)} FAIL across {s.tasks_checked} render task(s) in "
        f"{len(files)} file(s); {len(s.unresolved)} source(s) could not be resolved statically "
        f"(--unresolved lists them)."
    )
    return 1 if s.findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
