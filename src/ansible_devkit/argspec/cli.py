# SPDX-License-Identifier: GPL-3.0-or-later
from collections import namedtuple
import importlib.util
import logging
from logging.handlers import RotatingFileHandler
import os
import re
import sys
import click
from pathlib import Path
from ansible_devkit.argspec.models import (
    REGENERATE_COMMAND,
    ArgumentSpecs,
    ArgumentSpec,
    OptionSpec,
)
import importlib

# APP_NAME = "ANSIBLE_ARGSPEC"
ROLES_PATH = Path("roles")
META_DIR = "meta"
DEFAULT_DIR = "defaults"
SKIP_FILE = "SKIP"
ARGSPECS_PY_FILE = "argument_specs.py"
ARGSPECS_FILE = "argument_specs.yml"
TASKS_DIR = "tasks"
GUARDS_FILE = "_argspec_guards.yml"
RESOLVER_FILE = "_resolve_defaults.yml"
EXPORT_NAME_PY = "argument_specs"

CONFIGURED_ROLES_PATH = Path("configured_roles.txt")


def _completion_roles(ctx, args, incomplete):
    # Start config
    option_keys = ["name"]
    # End config

    DEFAULT_OPTION_KEYS = ["value", "help"]
    Option = namedtuple("Option", field_names=[*DEFAULT_OPTION_KEYS, *option_keys])

    # Start config
    options = [
        *(
            Option(name=item, value=item, help=f"{ROLES_PATH}/{item}")
            for item in os.listdir(ROLES_PATH)
        )
    ]
    conditions = [lambda option, incomplete: incomplete in option.name]
    # End config

    suggestions = []
    for option in options:
        if all(condition(option, incomplete) for condition in conditions):
            suggestions.append(
                click.shell_completion.CompletionItem(value=option.value, help=option.help)
            )

    return suggestions


def get_argument_specs(argspec_config_path) -> ArgumentSpecs:
    # Dynamically include the roles argument_spec.py.
    #
    # A role's argument_specs.py may import helper modules from the PROJECT it lives in (shared
    # option specs, project constants). ROLES_PATH is relative to the working
    # directory, so the project root IS the working directory: put it first on sys.path. Without
    # this, a script entrypoint gets its own directory as sys.path[0], and a project installed
    # editable elsewhere (another checkout of the same repo) silently supplies those helpers instead.
    project_root = str(Path.cwd())
    if sys.path[0] != project_root:
        sys.path.insert(0, project_root)
    spec_name = str(argspec_config_path).replace("/", ".")
    spec_path = str(argspec_config_path)

    spec = importlib.util.spec_from_file_location(spec_name, spec_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec_name] = module
    spec.loader.exec_module(module)
    if not hasattr(module, EXPORT_NAME_PY):
        raise click.ClickException(f"{spec_path} must define {EXPORT_NAME_PY}")
    argument_specs = module.argument_specs
    return argument_specs


def _render_guards(role: str, constraints: dict) -> str:
    """Render assert tasks for the constraints Ansible cannot enforce.

    GENERATED — every condition is emitted on ONE line. A condition split across lines inside a
    YAML block scalar gets folded and stops meaning what it looks like it means.
    """
    lines = [
        "---",
        f"# GENERATED from roles/{role}/meta/argument_specs.py — DO NOT EDIT.",
        f"# Regenerate with: {REGENERATE_COMMAND} x generate " + role,
        "#",
        "# These are the constraints Ansible's role-argspec validator CANNOT enforce. It handles",
        "# type/required/choices/no_log, but has no numeric-range, length or pattern checking, so",
        "# without this file those declarations would be decorative.",
        "#",
        "# Include from the role's entrypoints:  - ansible.builtin.include_tasks: " + GUARDS_FILE,
        "",
    ]
    # Entrypoints usually SHARE an options dict, so the same constraint appears under each. Emit
    # each unique (option, constraint) pair ONCE: the guards run per include, not per entrypoint,
    # and triplicated asserts bury a genuine addition in review noise.
    merged: dict = {}
    for options in constraints.values():
        for name, c in options.items():
            merged.setdefault(name, c)

    if True:
        for name, c in sorted(merged.items()):
            conds, describe = [], []
            if "min_value" in c:
                conds.append(f"{name} | int >= {c['min_value']}")
                describe.append(f">= {c['min_value']}")
            if "max_value" in c:
                conds.append(f"{name} | int <= {c['max_value']}")
                describe.append(f"<= {c['max_value']}")
            if "min_length" in c:
                conds.append(f"{name} | default('') | length >= {c['min_length']}")
                describe.append(f"at least {c['min_length']} long")
            if "pattern" in c:
                conds.append(f"{name} | default('') is match({c['pattern']!r})")
                describe.append(f"matching {c['pattern']!r}")
            if "forbidden_values" in c:
                forbidden = list(c["forbidden_values"])
                if c.get("_type") == "list":
                    conds.append(
                        f"{name} | default([]) | select('in', {forbidden!r}) | list | length == 0"
                    )
                else:
                    conds.append(f"{name} not in {forbidden!r}")
                describe.append(f"never one of {forbidden!r}")
            if "element_constraints" in c:
                ec = c["element_constraints"]
                if "forbidden_values" in ec:
                    forbidden = list(ec["forbidden_values"])
                    conds.append(
                        f"{name} | default([]) | flatten | select('in', {forbidden!r}) | list | length == 0"
                    )
                    describe.append(f"no element in {forbidden!r}")
            if not conds:
                continue
            lines.append(f"- name: \"GUARD (generated) — {name} must be {'; '.join(describe)}\"")
            lines.append("  ansible.builtin.assert:")
            lines.append("    that:")
            for cond in conds:
                lines.append(f'      - "{cond}"')
            # NEVER echo the value of a no_log option. A guard whose failure message prints the
            # secret it was protecting is worse than no guard — it leaks on exactly the code path
            # that gets hit when something is wrong and someone is reading the output.
            if c.get("_no_log"):
                got = "(value suppressed — no_log)"
            else:
                got = f"{{{{ {name} | default('(unset)') }}}}"
            lines.append(
                f'    fail_msg: "{name} violates a constraint declared in '
                f'meta/argument_specs.py: must be {"; ".join(describe)}. Got: {got}"'
            )
            lines.append("    quiet: true")
            lines.append(f"  when: {name} is defined")
            lines.append("")
    # rstrip: the per-guard loop appends a separating blank line, which leaves a trailing one at
    # EOF that yamllint flags as empty-lines. Strip it rather than shipping a generated file that
    # cannot pass the repo's own lint.
    return "\n".join(lines).rstrip("\n") + "\n"


def _generate(role: str):
    """Generate argument spec YAML for a given role."""
    role_path = ROLES_PATH / role
    meta_path = role_path / META_DIR
    argspec_path = meta_path / ARGSPECS_PY_FILE
    argspec_output_path = meta_path / ARGSPECS_FILE
    default_path = role_path / DEFAULT_DIR
    default_skip = default_path / SKIP_FILE
    print(f"Generating {role=} in {role_path=}")

    required_paths = [role_path, meta_path, argspec_path]
    for path in required_paths:
        if not path.exists():
            raise click.BadParameter(f"Cannot find '{path}'")

    created_paths = [default_path]
    for path in created_paths:
        if not path.exists():
            click.echo(f"Creating '{path}'")
            path.mkdir(parents=True)

    # Dynamically fetch the argument_specs from the role
    argument_specs = get_argument_specs(argspec_path)

    # Dump the argument_specs.yml file based on the role config
    argument_specs.model_dump_ansible_to(argspec_output_path, role=role)
    click.echo(f"✔ Generated argument_specs for role '{role}' at {argspec_output_path}")

    # Render the defaults RESOLVER — the task file binding each option to its generated default.
    # Skipped where defaults are not generated (a SKIP marker): there would be no `__default`
    # variables to bind.
    resolver_path = role_path / TASKS_DIR / RESOLVER_FILE
    if not default_skip.exists():
        resolver_path.parent.mkdir(parents=True, exist_ok=True)
        resolver_path.write_text(argument_specs._render_resolver_file(role))
        click.echo(f"✔ Generated defaults resolver for role '{role}' at {resolver_path}")
    elif resolver_path.exists():
        resolver_path.unlink()
        click.echo(f"✔ Removed stale defaults resolver for role '{role}'")

    # Render the constraints Ansible CANNOT enforce into a guards task file. Ansible's role-argspec
    # validator handles type/required/choices/no_log but has NO numeric-range, length or pattern
    # checking — so declaring a range in the argspec alone would be decorative. Generating a real
    # assert file keeps the interface declared in ONE place while making the constraint actually
    # fire at run time.
    constraints = argument_specs.constraints()
    guards_path = role_path / TASKS_DIR / GUARDS_FILE
    if constraints:
        guards_path.parent.mkdir(parents=True, exist_ok=True)
        guards_path.write_text(_render_guards(role, constraints))
        click.echo(f"✔ Generated argspec guards for role '{role}' at {guards_path}")
    elif guards_path.exists():
        # No constraints left — remove a stale generated file rather than leaving a guard that no
        # longer matches the spec.
        guards_path.unlink()
        click.echo(f"✔ Removed stale argspec guards for role '{role}'")

    if default_skip.exists():
        click.echo(f"Skipping defaults generation because '{default_skip=}' exists")
    else:
        # Dump the defaults file based on the roles config
        argument_specs.model_dump_defaults_ansible_to(default_path, role=role)
        click.echo(f"✔ Generated defaults for role '{role}' at {default_path}")

    return True


def _get_all_roles() -> list[str]:
    with open(CONFIGURED_ROLES_PATH, "r") as f:
        return [line.strip() for line in f.readlines()]


def _set_all_roles(roles: list[str]):
    with open(CONFIGURED_ROLES_PATH, "w") as f:
        f.writelines([role + "\n" for role in roles])


def _add_role_to_configured_roles(role: str) -> bool:
    # APPEND, preserving the existing order. The previous `list(set(roles))` round-trip reordered
    # the WHOLE file on every `generate`, because Python's set iteration order for strings depends
    # on the per-process hash seed — so any change that touched one role rewrote the whole list,
    # which buries the one real addition in review and conflicts with every other such change.
    roles = _get_all_roles()
    if role not in roles:
        roles.append(role)
    _set_all_roles(roles)


@click.group(invoke_without_command=True)
@click.argument(
    "role",
    required=False,
    shell_complete=_completion_roles,
)
@click.pass_context
def cli(ctx, role):
    # Guard: a bare `cli.py generate-all` / `cli.py generate` must dispatch to the SUBCOMMAND, not be
    # swallowed as the optional `role` positional (which produced "Cannot find roles/generate-all").
    if role in cli.commands:
        ctx.invoke(cli.commands[role])
        return
    if ctx.invoked_subcommand is None:
        if role is None:
            ctx.invoke(generate_all)
        else:
            ctx.invoke(generate, role=role)


@cli.command()
@click.argument(
    "role",
    required=True,
    shell_complete=_completion_roles,
)
def add(role: str):
    return _add_role_to_configured_roles(role)


@cli.command()
@click.argument(
    "role",
    required=True,
    shell_complete=_completion_roles,
)
def generate(role: str):
    _generate(role)
    _add_role_to_configured_roles(role)


@cli.command()
def generate_all():
    roles = _get_all_roles()
    for role in roles:
        _generate(role)


def _audit_resolvers() -> list[tuple[str, list[str]]]:
    """Find declared defaults that can never be applied.

    THE FAILURE THIS CATCHES. defaults/main.yml holds `<name>__default`, so something must bind
    that to the plain name the tasks use. When nothing does, the declared default is DEAD: the
    variable evaluates Undefined at run time, and nothing says so at generation time.

    A default counts as resolved if `<name>__default` appears ANYWHERE outside defaults/ — the
    generated resolver, a hand-written setup_vars.yml, or inline in a template as
    `{{ x | default(x__default) }}`. All three are legitimate; nowhere is not.

    Returns [(role, [unresolved variable names])].
    """
    problems: list[tuple[str, list[str]]] = []
    for role_dir in sorted(ROLES_PATH.iterdir()):
        if not role_dir.is_dir():
            continue
        defaults = role_dir / DEFAULT_DIR / "main.yml"
        if not defaults.exists() or (role_dir / DEFAULT_DIR / SKIP_FILE).exists():
            continue

        declared = re.findall(r"^([a-z_][a-z0-9_]*)__default:", defaults.read_text(), re.M)
        if not declared:
            continue

        # REQUIRED options are deliberately not bound by the resolver: binding one would let a
        # caller who omitted it silently receive the default instead of Ansible's validation error.
        # Their defaults exist only so templates can reference SUB-fields explicitly, so
        # "unreferenced" is expected rather than a defect.
        try:
            spec_module = get_argument_specs(role_dir / META_DIR / ARGSPECS_PY_FILE)
            required = {
                key
                for argspec in spec_module.argument_specs.values()
                for key, opt in argspec.options.items()
                if opt.required
            }
            declared = [n for n in declared if n not in required]
        except Exception:
            # Cannot load the spec — report on everything rather than silently narrowing.
            pass

        body = ""
        for f in role_dir.rglob("*"):
            if not f.is_file() or DEFAULT_DIR in f.parts:
                continue
            if f.suffix in {".yml", ".yaml", ".j2"}:
                body += f.read_text(errors="ignore")

        unresolved = [n for n in declared if f"{n}__default" not in body]
        if unresolved:
            problems.append((role_dir.name, unresolved))
    return problems


@cli.command("audit-resolvers")
def audit_resolvers():
    """Fail if any role declares a default that nothing ever resolves."""
    problems = _audit_resolvers()
    if problems:
        click.echo("Declared defaults that are NEVER resolved (the variable will be Undefined):")
        for role, names in problems:
            click.echo(f"  {role}: {', '.join(names)}")
        click.echo(
            "\nFix by including the generated resolver as the first task of each entrypoint:\n"
            "  - ansible.builtin.include_tasks: _resolve_defaults.yml\n"
            "or by resolving inline where the variable is used."
        )
        raise SystemExit(1)
    click.echo("✔ Every declared default is resolved somewhere.")


def main():
    """Console-script entrypoint (`argspec`)."""
    cli()


if __name__ == "__main__":
    main()
