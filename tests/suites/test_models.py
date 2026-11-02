#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for the argspec model + generator (ansible_devkit/argspec/models.py).

Run:  uv run tests/suites/test_models.py
      (exit 0 = all pass, 1 = failures; prints a per-case report)

WHY THESE CASES. Every one corresponds to a defect this library could allow:

  * list defaults          `if` where `elif` belonged made a list-of-dicts with declared
                           sub-options emit a bare DICT of those sub-defaults instead of []. A
                           role whose tasks iterate that variable gets a dict where it requires a
                           list.
  * constraint leakage     min_value/max_value/pattern are NOT enforced by Ansible's role-argspec
                           validator. Emitting them into argument_specs.yml would produce a spec
                           that LOOKS enforced and is not — the silent-guard shape.
  * no_log                 must reach the emitted spec (Ansible enforces it) AND must suppress the
                           value in generated guard messages. A guard that prints the secret it
                           protects leaks on exactly the path taken when something is wrong.
  * generated headers      a generate-all run silently destroys hand-written documentation in
                           a defaults file. Files
                           say they are generated, and descriptions are emitted as comments so
                           hand-written prose is unnecessary in the first place.
  * `off` / truthy         a bare `off` default lands in YAML as the BOOLEAN false. `Table = off`
                           renders `Table = False` into a config that expects `off`.

The style mirrors test_check_silent_guards.py: stdlib only, no pytest requirement,
each case a readable statement of intent.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from _paths import ROOT  # tests/suites/_paths.py

# Test the source beside this file, not whichever copy happens to be installed.
sys.path.insert(0, str(ROOT / "src"))

from ansible_devkit.argspec.models import (  # noqa: E402
    ArgumentSpec,
    ArgumentSpecs,
    OptionSpec,
)

RESULTS: list[tuple[bool, str, str]] = []


def check(label: str, condition: bool, detail: str = "") -> None:
    RESULTS.append((bool(condition), label, detail))


def expect_raises(label: str, fn) -> None:
    try:
        fn()
    except Exception:
        RESULTS.append((True, label, ""))
    else:
        RESULTS.append((False, label, "expected a validation error, got none"))


def _specs(**options) -> ArgumentSpecs:
    return ArgumentSpecs(
        argument_specs={"main": ArgumentSpec(version_added="1.0", author="test", options=options)}
    )


# ---------------------------------------------------------------------------------------------
# 1. LIST DEFAULTS
# ---------------------------------------------------------------------------------------------
sp = _specs(
    peers=OptionSpec(
        type="list",
        elements="dict",
        default=[],
        options={
            "endpoint": OptionSpec(type="str", default=""),
            "keepalive": OptionSpec(type="int", default=0),
        },
    )
)
peers_default = sp._model_dump_defaults()["main"]["peers__default"]
check(
    "a list with declared sub-options defaults to its OWN default, not a merge of theirs",
    peers_default == [],
    f"got {peers_default!r} (the bug produced {{'endpoint': '', 'keepalive': 0}})",
)

sp = _specs(packages=OptionSpec(type="list", elements="str", default=[]))
check(
    "a plain list default survives as []",
    sp._model_dump_defaults()["main"]["packages__default"] == [],
)

sp = _specs(
    settings=OptionSpec(
        type="dict",
        options={"a": OptionSpec(type="str", default="x")},
    )
)
check(
    "a DICT option still merges its sub-option defaults (unchanged behaviour)",
    sp._model_dump_defaults()["main"]["settings__default"] == {"a": "x"},
)

sp = _specs(nodes=OptionSpec(type="list", elements="dict", default=[{"name": "a"}]))
check(
    "a list with a NON-empty default keeps it verbatim",
    sp._model_dump_defaults()["main"]["nodes__default"] == [{"name": "a"}],
)

# ---------------------------------------------------------------------------------------------
# 2. CONSTRAINTS — declared here, never emitted as if Ansible enforced them
# ---------------------------------------------------------------------------------------------
sp = _specs(mtu=OptionSpec(type="int", default=1420, min_value=1280, max_value=1420))
emitted = sp.model_dump_ansible()
check("min_value is NOT emitted into the argspec yaml", "min_value" not in emitted)
check("max_value is NOT emitted into the argspec yaml", "max_value" not in emitted)
check(
    "the constraint IS available for guard generation",
    sp.constraints()["main"]["mtu"]["min_value"] == 1280,
)

sp = _specs(addr=OptionSpec(type="str", pattern=r"^\d+/\d+$"))
check("pattern is NOT emitted into the argspec yaml", "pattern" not in sp.model_dump_ansible())
check(
    "pattern IS available for guard generation",
    sp.constraints()["main"]["addr"]["pattern"] == r"^\d+/\d+$",
)

sp = _specs(ips=OptionSpec(type="list", default=[], forbidden_values=["0.0.0.0/0"]))
check(
    "forbidden_values reaches the guards",
    sp.constraints()["main"]["ips"]["forbidden_values"] == ["0.0.0.0/0"],
)

# ---------------------------------------------------------------------------------------------
# 3. no_log — enforced by Ansible, and never echoed by a guard
# ---------------------------------------------------------------------------------------------
sp = _specs(secret=OptionSpec(type="str", default="", no_log=True, min_length=1))
check("no_log IS emitted (Ansible enforces it)", "no_log" in sp.model_dump_ansible())
check(
    "no_log is flagged to the guards generator so it can suppress the value",
    sp.constraints()["main"]["secret"].get("_no_log") is True,
)

sp = _specs(public=OptionSpec(type="str", default="", min_length=1))
check(
    "a non-secret option is NOT flagged no_log",
    "_no_log" not in sp.constraints()["main"]["public"],
)

# ---------------------------------------------------------------------------------------------
# 4. VALIDATION — malformed specs are rejected at authoring time
# ---------------------------------------------------------------------------------------------
expect_raises(
    "min_value > max_value is rejected", lambda: OptionSpec(type="int", min_value=9, max_value=1)
)
expect_raises(
    "a numeric range on a str option is rejected", lambda: OptionSpec(type="str", min_value=1)
)
expect_raises(
    "min_length on an int option is rejected", lambda: OptionSpec(type="int", min_length=1)
)
expect_raises(
    "an uncompilable pattern is rejected", lambda: OptionSpec(type="str", pattern="([oops")
)
expect_raises("elements on a non-list is rejected", lambda: OptionSpec(type="str", elements="str"))
expect_raises(
    "an unknown field is rejected (extra=forbid)", lambda: OptionSpec(type="str", nonsense=1)
)

check(
    "a valid range is accepted",
    OptionSpec(type="int", min_value=1, max_value=2).min_value == 1,
)

# ---------------------------------------------------------------------------------------------
# 5. GENERATED HEADERS + DESCRIPTIONS-AS-COMMENTS
#    Why: a generate-all run destroyed hand-written documentation in two roles. The fix is that
#    generated files say so, AND carry the prose themselves so hand-writing is unnecessary.
# ---------------------------------------------------------------------------------------------
sp = _specs(
    proto=OptionSpec(
        type="str",
        default="quic",
        description=["Edge transport.", "http2 where QUIC cannot establish."],
    )
)
rendered = sp._render_defaults_file("main", role="demo")
check(
    "generated defaults announce themselves",
    "AUTO-GENERATED" in rendered and "DO NOT EDIT" in rendered,
)
check("generated defaults name their source of truth", "meta/argument_specs.py" in rendered)
check("generated defaults name the regeneration command", "tools/argspec/cli.py" in rendered)
check("a description is emitted as a comment", "# Edge transport." in rendered)
check(
    "a MULTI-LINE description emits every line", "# http2 where QUIC cannot establish." in rendered
)
check("the value itself is still emitted", "proto__default: quic" in rendered)
check(
    "the argspec yaml also announces itself", "AUTO-GENERATED" in sp.model_dump_ansible(role="demo")
)

sp = _specs(undocumented=OptionSpec(type="str", default="x"))
check(
    "an option with no description still renders its value",
    "undocumented__default: x" in sp._render_defaults_file("main"),
)

# SPDX headers are OPT-IN. A role that sets spdx_license gets it as the first line of EVERY
# generated file; one that does not must regenerate byte-identical (no stray blank line either).
sp = _specs(proto=OptionSpec(type="str", default="quic"))
sp_spdx = ArgumentSpecs(argument_specs=sp.argument_specs, spdx_license="GPL-3.0-or-later")
for label, text in (
    ("argspec yaml", sp_spdx.model_dump_ansible(role="demo")),
    ("defaults file", sp_spdx._render_defaults_file("main", role="demo")),
    ("resolver", sp_spdx._render_resolver_file(role="demo")),
):
    check(
        f"an opted-in {label} starts with the SPDX line",
        text.startswith("# SPDX-License-Identifier: GPL-3.0-or-later\n---\n"),
    )
check(
    "a role that does not opt in gets no SPDX line and still starts with ---",
    sp.model_dump_ansible(role="demo").startswith("---\n")
    and "SPDX" not in sp._render_defaults_file("main", role="demo"),
)
check(
    "spdx_license never leaks into the Ansible argspec body",
    "spdx_license" not in sp_spdx.model_dump_ansible(role="demo"),
)

# ---------------------------------------------------------------------------------------------
# 6. THE `off` TRAP — a bare off/on/yes/no default is YAML's boolean, not a string
# ---------------------------------------------------------------------------------------------
sp = _specs(table=OptionSpec(type="str", default="none"))
check(
    "a safe string sentinel round-trips as a string",
    "table__default: none" in sp._render_defaults_file("main"),
)

import ruamel.yaml  # noqa: E402

_yaml = ruamel.yaml.YAML(typ="safe")
for word in ("off", "on", "yes", "no"):
    sp = _specs(flag=OptionSpec(type="str", default=word))
    loaded = _yaml.load(sp._render_defaults_file("main"))["flag__default"]
    check(
        f"a default of {word!r} survives a YAML round-trip as a STRING, not a boolean",
        isinstance(loaded, str),
        f"loaded as {loaded!r} ({type(loaded).__name__}) — `Table = off` would render as a boolean",
    )

# ---------------------------------------------------------------------------------------------
# 6b. THE GENERATED RESOLVER
#     Why: defaults/main.yml holds `<name>__default`, so something must bind it to the plain name.
#     When nothing does, a role ships a declared default that is dead — the variable evaluates
#     Undefined at run time and nothing said so at generation time. Six were added in one sitting.
# ---------------------------------------------------------------------------------------------
sp = _specs(
    a=OptionSpec(type="str", default="x"),
    needed=OptionSpec(type="str", required=True),
    nodefault=OptionSpec(type="str"),
)
resolver = sp._render_resolver_file(role="demo")
check(
    "the resolver binds an optional option to its default",
    'a: "{{ a | default(a__default) if a__default is defined else a | default(omit) }}"'
    in resolver,
    "the `is defined` guard is required: defaults files other than main.yml are never auto-loaded",
)
check(
    "the resolver does NOT bind a REQUIRED option",
    "needed:" not in resolver,
    "binding it would let an omitted required option silently take a default instead of failing",
)
check("the resolver skips an option with no default", "nodefault:" not in resolver)
check(
    "the resolver announces itself as generated",
    "AUTO-GENERATED" in resolver and "DO NOT EDIT" in resolver,
)

multi_ep = ArgumentSpecs(
    argument_specs={
        "main": ArgumentSpec(
            version_added="1.0", author="t", options={"shared": OptionSpec(type="str", default="1")}
        ),
        "verify": ArgumentSpec(
            version_added="1.0",
            author="t",
            options={"only_verify": OptionSpec(type="str", default="2")},
        ),
    }
)
resolver = multi_ep._render_resolver_file()
check(
    "the resolver covers options from EVERY entrypoint",
    "shared:" in resolver and "only_verify:" in resolver,
    "entrypoints share option sets; a variable missing here is the exact failure this prevents",
)
check(
    "an option appearing in two entrypoints is bound once PER BRANCH",
    # Two bindings, not one: the resolver emits a first-call branch and a repeat-call branch (see
    # _render_resolver_file). What must not happen is the same option appearing TWICE inside one
    # branch, which is what a de-duplication bug across entrypoints would look like.
    resolver.count("shared: ") == 2
    and resolver.count(
        'shared: "{{ shared | default(shared__default) '
        'if shared__default is defined else shared | default(omit) }}"'
    )
    == 1
    and resolver.count(
        'shared: "{{ shared__default if shared__default is defined else shared | default(omit) }}"'
    )
    == 1,
)

_named = multi_ep._render_resolver_file("some_role")
check(
    "the resolver guards the two branches on a role-namespaced marker",
    # Namespaced by ROLE so two different roles in one play cannot disable each other's first-call
    # branch by sharing one marker name.
    "_some_role__argspec_resolved: true" in _named
    and "when: not (_some_role__argspec_resolved | default(false))" in _named
    and "when: _some_role__argspec_resolved | default(false)" in _named,
    "an unguarded repeat-call branch would clobber a caller's value on the FIRST call",
)

check(
    "a repeat call rebinds the default rather than reading the role's own leftover fact",
    # The bug this exists to prevent: role called twice in one play, second caller omits an option
    # and silently inherits the first caller's value instead of the declared default.
    'shared: "{{ shared__default if shared__default is defined else shared | default(omit) }}"'
    in resolver,
    "reading `shared | default(...)` on re-entry resolves to the stale fact, not the default",
)

check(
    "the rebind tolerates an unreachable __default",
    # The generator writes one defaults file per ENTRYPOINT but Ansible only auto-loads
    # defaults/main.yml, so an option declared on a non-main entrypoint has no `__default` at run
    # time. A bare `{{ x__default }}` on the rebind then raises "undefined" on the SECOND call —
    # the shape of a role whose teardown/verify options live in their own defaults files and
    # which is called twice in one play.
    "if shared__default is defined else shared | default(omit)" in resolver,
    "a bare {{ x__default }} rebind breaks any role whose defaults live outside defaults/main.yml",
)

sp = _specs(secret=OptionSpec(type="str", default="", no_log=True))
check(
    "a resolver binding a no_log option carries no_log itself",
    "no_log: true" in sp._render_resolver_file(),
    "set_fact would otherwise print every resolved value, including the secret",
)

sp = _specs(plain=OptionSpec(type="str", default="x"))
check(
    "a resolver with no secrets does NOT set no_log",
    "no_log: true" not in sp._render_resolver_file(),
    "blanket no_log would hide ordinary values and make debugging worse",
)

sp = _specs(
    req=OptionSpec(type="dict", required=True, options={"sub": OptionSpec(type="str", default="s")})
)
check(
    "a REQUIRED option still EMITS its default, for templates that reference sub-fields",
    "req__default" in sp._render_defaults_file("main"),
    "templates read role_config__default.<sub-field>; suppressing the emission breaks them",
)

# ---------------------------------------------------------------------------------------------
# 7. FILE WRITING — one file per entrypoint, each self-describing
# ---------------------------------------------------------------------------------------------
multi = ArgumentSpecs(
    argument_specs={
        "main": ArgumentSpec(
            version_added="1.0", author="t", options={"a": OptionSpec(type="str", default="1")}
        ),
        "verify": ArgumentSpec(
            version_added="1.0", author="t", options={"b": OptionSpec(type="str", default="2")}
        ),
    }
)
with tempfile.TemporaryDirectory() as td:
    out = Path(td)
    multi.model_dump_defaults_ansible_to(out, role="demo")
    check(
        "one defaults file per entrypoint",
        (out / "main.yml").exists() and (out / "verify.yml").exists(),
    )
    check(
        "each names its entrypoint", "Entrypoint:      verify" in (out / "verify.yml").read_text()
    )
    check("each carries only its own options", "b__default" not in (out / "main.yml").read_text())

# ---------------------------------------------------------------------------------------------
# 8. ROUND-TRIP — generated YAML must PARSE, not merely contain the right substrings
# ---------------------------------------------------------------------------------------------
sp = _specs(
    n=OptionSpec(type="int", default=1, description="A number."),
    s=OptionSpec(type="str", default="x: y", description=["Colons.", "And: more."]),
    l=OptionSpec(type="list", default=[], description="A list."),
)
parsed = _yaml.load(sp._render_defaults_file("main"))
check(
    "generated defaults parse as valid YAML with the right values",
    parsed == {"n__default": 1, "s__default": "x: y", "l__default": []},
    f"got {parsed!r}",
)
check(
    "generated argspec yaml parses as valid YAML",
    "argument_specs" in _yaml.load(sp.model_dump_ansible()),
)


# ---------------------------------------------------------------------------------------------
if __name__ == "__main__":
    failed = [r for r in RESULTS if not r[0]]
    for ok, label, detail in RESULTS:
        print(f"{'PASS' if ok else 'FAIL'}  {label}")
        if not ok and detail:
            print(f"      {detail}")
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} passed")
    sys.exit(1 if failed else 0)
