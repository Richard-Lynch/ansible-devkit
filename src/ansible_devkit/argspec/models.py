# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations
from pathlib import Path
from pydantic import BaseModel, field_validator, model_validator
from io import StringIO
from typing import Literal, Optional
from pydantic import BaseModel, Field
import re
from ruamel.yaml import YAML

OptionType = str | int | float | bool | list | dict
OptionTypeStr = Literal["str", "int", "float", "bool", "list", "dict"]

# The command every generated file names as the way to regenerate it. It is written INTO the
# generated output, so changing it rewrites the header of every generated file in every role;
# keep it stable across releases.
REGENERATE_COMMAND = "venv/bin/python tools/argspec/cli.py"


# Keys Ansible's own role-argspec validator understands and ENFORCES at run time. Anything here is
# real enforcement; anything outside it is documentation or has to be checked by a task.
# Verified against ansible.module_utils.common.parameters (no_log, choices, and the cross-argument
# checks are all handled there).
_ANSIBLE_ENFORCED = {
    "description",
    "version_added",
    "type",
    "required",
    "default",
    "choices",
    "elements",
    "options",
    "no_log",
    "aliases",
}


class OptionSpec(BaseModel):
    description: Optional[str | list[str]] = None
    version_added: Optional[str] = None
    type: Optional[OptionTypeStr] = "str"
    required: Optional[bool] = False
    default: Optional[OptionType] = None
    choices: Optional[list[OptionType]] = None
    elements: Optional[str] = None  # only if type == list
    options: Optional[dict[str, OptionSpec]] = None  # nested dicts

    # --- enforced by Ansible ---------------------------------------------------------------
    no_log: Optional[bool] = None
    """Suppress this value in output. Ansible enforces this — set it on EVERY secret-bearing
    option. Without it a validation failure message can echo the secret into logs and CI."""

    aliases: Optional[list[str]] = None
    """Alternative names for this option, honoured by Ansible."""

    # --- NOT enforced by Ansible: emitted as guard metadata, not into the argspec YAML ------
    # Ansible's role-argspec validator has no numeric-range or pattern checking. Declaring these
    # here does NOT make them enforced by itself — the `argspec` CLI renders them into a
    # generated guards file that a role includes, so the constraint is checked at run time with a
    # real assert. They live here so the interface is declared in ONE place instead of drifting
    # between the argspec and a hand-written guards task file.
    min_value: Optional[int | float] = None
    max_value: Optional[int | float] = None
    forbidden_values: Optional[list[OptionType]] = None
    """Values that must be REJECTED. For the case where almost anything is valid except a few
    catastrophic entries — e.g. 0.0.0.0/0 in a WireGuard AllowedIPs list, which silently converts
    a site link into a full-tunnel VPN and can strand a remote host."""

    min_length: Optional[int] = None
    """Minimum length of a str or list. min_length=1 on a str is the idiomatic 'must not be
    empty', which `required` does NOT give you — a required option can still be an empty string."""

    pattern: Optional[str] = None
    """Regex the value must match, as a documented constraint checked in the generated guards."""

    element_constraints: Optional[dict[str, OptionType]] = None
    """Constraints applied to EACH element of a list, e.g.
    {"forbidden_values": ["0.0.0.0/0"]}. Needed because list options carry their real risk in the
    elements, not the container."""

    @model_validator(mode="after")
    def check_type_restrictions(self):
        if self.type != "list" and self.elements is not None:
            raise ValueError("`elements` is only valid when type is 'list'")
        if (self.type != "dict" and self.options is not None) and not (
            self.type == "list" and self.elements == "dict"
        ):
            raise ValueError("`options` is only valid when type is 'dict'")
        if self.min_value is not None and self.max_value is not None:
            if self.min_value > self.max_value:
                raise ValueError("`min_value` cannot exceed `max_value`")
        if (self.min_value is not None or self.max_value is not None) and self.type not in (
            "int",
            "float",
        ):
            raise ValueError("`min_value`/`max_value` are only valid for int or float options")
        if self.min_length is not None and self.type not in ("str", "list"):
            raise ValueError("`min_length` is only valid for str or list options")
        if self.pattern is not None:
            try:
                re.compile(self.pattern)
            except re.error as exc:
                raise ValueError(f"`pattern` is not a valid regex: {exc}") from exc
        return self

    def ansible_fields(self) -> dict:
        """The subset Ansible actually understands. Constraint keys are deliberately EXCLUDED —
        emitting them would produce an argspec that looks enforced and is not."""
        data = self.model_dump(exclude_none=True)
        return {k: v for k, v in data.items() if k in _ANSIBLE_ENFORCED}

    def guard_constraints(self) -> dict:
        """The subset Ansible cannot enforce, for the generated guards file."""
        keys = (
            "min_value",
            "max_value",
            "forbidden_values",
            "min_length",
            "pattern",
            "element_constraints",
        )
        data = self.model_dump(exclude_none=True)
        return {k: v for k, v in data.items() if k in keys}

    @field_validator("version_added")
    @classmethod
    def check_version_format(cls, value):
        if value and not re.match(r"^\d+\.\d+$", value):
            raise ValueError("version_added must be in format 'X.Y'")
        return value

    class Config:
        extra = "forbid"


OptionSpec.update_forward_refs()


class ArgumentSpec(BaseModel):
    short_description: Optional[str] = Field(
        default=None, max_length=80, description="Short summary (<=80 chars)"
    )
    description: Optional[str | list[str]] = None
    version_added: Optional[str]
    author: str | list[str]
    options: dict[str, OptionSpec]

    @field_validator("version_added")
    @classmethod
    def check_version_format(cls, value):
        if value and not re.match(r"^\d+\.\d+$", value):
            raise ValueError("version_added must be in format 'X.Y'")
        return value


class ArgumentSpecs(BaseModel):
    argument_specs: dict[str, ArgumentSpec]
    # SPDX licence identifier stamped as the FIRST line of every file generated from this spec.
    # Opt-in per role (None emits nothing), so roles that do not set it regenerate byte-identical.
    # Set by the roles destined for a public collection, where every shipped file carries one.
    spdx_license: Optional[str] = None

    def _to_ansible(self, data, stream) -> str:
        yaml = YAML()
        yaml.indent(mapping=2, sequence=4, offset=2)
        yaml.preserve_quotes = True
        # Don't line-wrap: ruamel's default width (~80) folds long description strings and leaves
        # trailing whitespace at the fold points, which trips yaml[trailing-spaces] in ansible-lint.
        yaml.width = 4096
        yaml.dump(data, stream)

    def _ansible_view(self) -> dict:
        """The argspec as Ansible understands it. Constraint keys (min_value, forbidden_values,
        ...) are STRIPPED: emitting them would produce a spec that looks enforced and is not.
        They are rendered into the generated guards file instead."""

        def strip(options: dict[str, OptionSpec]) -> dict:
            out = {}
            for key, spec in options.items():
                fields = spec.ansible_fields()
                if spec.options:
                    fields["options"] = strip(spec.options)
                out[key] = fields
            return out

        return {
            "argument_specs": {
                name: {
                    **{
                        k: v
                        for k, v in argspec.model_dump(exclude_none=True).items()
                        if k != "options"
                    },
                    "options": strip(argspec.options),
                }
                for name, argspec in self.argument_specs.items()
            }
        }

    def model_dump_ansible(self, role: str | None = None) -> str:
        stream = StringIO()
        self._to_ansible(self._ansible_view(), stream)
        body = stream.getvalue()
        # ruamel emits its own "---"; the header already provides one.
        body = body[4:] if body.startswith("---\n") else body
        return (
            "\n".join(self._generated_header(role, "argument spec", spdx=self.spdx_license)) + body
        )

    def model_dump_ansible_to(self, path: Path, role: str | None = None):
        path.write_text(self.model_dump_ansible(role=role))

    def constraints(self) -> dict:
        """Per-entrypoint constraint metadata that Ansible cannot enforce, for the generated
        guards file. Shape: {entrypoint: {option_name: {constraint: value}}}."""
        out = {}
        for name, argspec in self.argument_specs.items():
            per_option = {}
            for key, spec in argspec.options.items():
                c = spec.guard_constraints()
                if c:
                    c["_type"] = spec.type
                    # Carried so the guards generator knows never to echo this value.
                    if spec.no_log:
                        c["_no_log"] = True
                    per_option[key] = c
            if per_option:
                out[name] = per_option
        return out

    # ---------------------------------------------------------------------------------------
    # Generated-file headers.
    #
    # Every file this library writes is fully generated and will be overwritten without warning.
    # Saying so IN the file is the only thing that reliably stops someone editing it — a
    # generate-all run silently destroys any hand-written documentation in a defaults file.
    # ---------------------------------------------------------------------------------------
    @staticmethod
    def _generated_header(
        role: str | None, kind: str, entrypoint: str | None = None, spdx: str | None = None
    ) -> list[str]:
        where = f"roles/{role}/meta/argument_specs.py" if role else "meta/argument_specs.py"
        cmd = (
            f"{REGENERATE_COMMAND} x generate {role}"
            if role
            else f"{REGENERATE_COMMAND} generate-all"
        )
        lines = [f"# SPDX-License-Identifier: {spdx}"] if spdx else []
        lines += [
            "---",
            f"# AUTO-GENERATED {kind} — DO NOT EDIT.",
            "#",
            f"# Source of truth: {where}",
            f"# Regenerate:      {cmd}",
            "#",
            "# Edits here are silently overwritten on the next generation. To change a value or its",
            "# documentation, change the OptionSpec in the source file above — descriptions there",
            "# are emitted as the comments in this file.",
        ]
        if entrypoint:
            lines.append(f"# Entrypoint:      {entrypoint}")
        lines.append("")
        return lines

    @staticmethod
    def _as_comment(description: str | list[str] | None) -> list[str]:
        """Render an OptionSpec description as YAML comment lines.

        This is what makes generated defaults files self-documenting, and therefore what makes
        hand-written defaults unnecessary. The prose lives in the Pydantic model; the generator
        puts it where a reader of defaults/main.yml will actually see it.
        """
        if not description:
            return []
        parts = [description] if isinstance(description, str) else list(description)
        out: list[str] = []
        for part in parts:
            for line in str(part).splitlines():
                out.append(f"# {line}".rstrip())
        return out

    def _model_dump_defaults(self) -> dict:
        """
        Returns a flat dictionary of variable defaults suitable for defaults/main.yml
        based on the top-level ArgumentSpec's options and their default values.
        """

        def extract_defaults(options: dict[str, OptionSpec], depth=0) -> dict:
            result = {}
            for key, spec in options.items():
                name = f"{key}__default" if depth == 0 else key
                # NOTE: a REQUIRED option still gets its default emitted, and that is deliberate.
                # It is never applied to the option as a whole (Ansible fails validation if the
                # caller omits it), but roles legitimately reference the SUB-defaults to fill in
                # fields the caller left out — e.g. a role's templates read
                # `config.journal.max_age | default(role_config__default.journal.max_age)`.
                # Suppressing these broke four roles that still referenced them, so the emission
                # stays and the RESOLVER is what skips required options instead.
                if spec.type == "dict" and spec.options:
                    # A dict option's default is the merge of its sub-option defaults.
                    nested = extract_defaults(spec.options, depth=depth + 1)
                    if nested:
                        result[name] = nested
                elif spec.type == "list":
                    # A LIST's default is its OWN default (normally []), NEVER the merge of its
                    # sub-option defaults. The previous version used `if` rather than `elif` here
                    # and recursed into spec.options, so a list-of-dicts with declared sub-options
                    # emitted a bare DICT of those sub-defaults where a list belonged — e.g.
                    # `{endpoint: '', persistent_keepalive: 0}` instead of `[]`. Ansible then
                    # rejected the role's own generated default with "is of type dict and we were
                    # unable to convert to list".
                    if spec.default is not None:
                        result[name] = spec.default
                elif spec.default is not None:
                    result[name] = spec.default
            return result

        spec_defaults = {}
        for spec_name, argument_spec in self.argument_specs.items():
            spec_defaults[spec_name] = extract_defaults(argument_spec.options)

        return spec_defaults

    def _render_resolver_file(self, role: str | None = None) -> str:
        """Render the task file that binds every option to its default.

        WHY THIS IS GENERATED. defaults/main.yml holds `<name>__default`, not the plain name the
        tasks use, so every role needs a resolver — and until now each was hand-written and had to
        be kept in sync with the argspec by memory, and it is not: roles ship a `__default`
        that nothing ever resolved, so the declared default was dead and the variable evaluated
        Undefined at run time. Six of those were added in a single sitting.

        Generating it from the same source as the defaults means the two cannot drift.

        Every option across every entrypoint is bound, because entrypoints share option sets and a
        variable missing from the resolver is exactly the failure this file exists to prevent.

        RE-ENTRY. `set_fact` persists for the rest of the play, so a role invoked TWICE in one play
        would see its own leftover facts on the second call: a later caller that OMITS an option
        silently inherits the earlier caller's value instead of the declared default: call 1
        passing state=absent leaves call 2 resolving to `absent` when it asks for nothing and
        should get `present`. For a role designed to be called per-entity that is structural,
        not incidental.

        The fix is two branches keyed on a private `_<role>__resolved` marker:

          * FIRST call  — no marker: bind `x | default(x__default)` as before.
          * REPEAT call — marker set: bind `x__default` outright, IGNORING this role's own facts.

        That is correct rather than lossy because an include-level `vars:` SHADOWS the fact, so on a
        repeat call a caller-supplied value is still visible as `x` and still wins; only the
        "nothing supplied this time, stale fact present" case is forced back to the default, which
        is exactly the bug. Across four alternating calls — supplied, default, supplied,
        default.

        Roles called once per play — almost all of them — are unaffected: the marker is never set
        on entry, so only the first branch ever runs and the emitted behaviour is unchanged.
        """
        merged: dict[str, OptionSpec] = {}
        for argspec in self.argument_specs.values():
            for key, spec in argspec.options.items():
                merged.setdefault(key, spec)

        # The marker is namespaced by role so two different roles in one play cannot disable each
        # other's first-call branch. Falls back to a literal when the role name is unknown.
        marker = f"_{role}__argspec_resolved" if role else "_argspec_resolved"

        bindable: list[tuple[str, OptionSpec]] = []
        no_log = False
        for key, spec in merged.items():
            if spec.required:
                # Binding a REQUIRED option to a default would defeat its requiredness: the caller
                # omitting it would silently get the default instead of Ansible's validation error.
                # Its sub-defaults remain available for templates to reference explicitly.
                continue
            if spec.default is None:
                # No default to fall back to: binding it would turn "unset" into a hard Undefined
                # error at resolve time instead of at the point of use, where the message is
                # actually about the variable.
                continue
            bindable.append((key, spec))
            if spec.no_log:
                no_log = True

        lines = self._generated_header(role, "defaults resolver", spdx=self.spdx_license)
        lines += [
            "# Binds every declared option to its generated default, so a caller-supplied value",
            "# wins and an unsupplied one falls back rather than evaluating Undefined.",
            "#",
            "# Include this FIRST from every entrypoint:",
            "#   - ansible.builtin.include_tasks: _resolve_defaults.yml",
            "#",
            "# Role-specific setup logic belongs in tasks/setup_vars.yml, NOT here — this file is",
            "# overwritten on every generation.",
            "#",
            "# TWO BRANCHES, because `set_fact` persists for the whole play. A role invoked twice in",
            "# one play would otherwise see its OWN leftover facts on the second call, so a later",
            "# caller that omitted an option silently inherited the earlier caller's value instead of",
            "# the declared default. On a repeat call this ignores the role's own facts and rebinds",
            "# the defaults; an include-level `vars:` shadows the fact, so a value the caller DID",
            "# supply this time still wins. Roles called once per play only ever run the first branch.",
        ]

        if not bindable:
            lines += [
                "",
                "# No option declares a default, so there is nothing to bind.",
                "- name: Resolve declared options over their generated defaults",
                "  ansible.builtin.meta: noop",
            ]
            return "\n".join(lines).rstrip("\n") + "\n"

        no_log_lines = (
            [
                "  # At least one option carries no_log, and set_fact would otherwise print every",
                "  # resolved value — including that one — in the task result.",
                "  no_log: true",
            ]
            if no_log
            else []
        )

        lines += [
            "",
            "- name: Resolve declared options over their generated defaults",
            "  ansible.builtin.set_fact:",
        ]
        # `<name>__default is defined` guard, not a bare reference. The generator writes one
        # defaults file per ENTRYPOINT and Ansible only auto-loads defaults/main.yml, so an option
        # declared on a non-main entrypoint has NO `__default` variable at run time. Binding it
        # unguarded raises "'x__default' is undefined" for every caller of that role — a role whose
        # teardown/verify options live in their own defaults files fails this way on the FIRST
        # call, before any of the re-entry work.
        #
        # Leaving such an option UNSET is correct: its consumer already guards it inline
        # (teardown.yml reads `<role>_teardown_confirm | default(false)`), and binding it to a
        # value the role cannot see would be inventing one.
        lines += [
            f'    {key}: "{{{{ {key} | default({key}__default) '
            f'if {key}__default is defined else {key} | default(omit) }}}}"'
            for key, _ in bindable
        ]
        lines += [f"  when: not ({marker} | default(false))"]
        lines += no_log_lines

        lines += [
            "",
            "- name: Rebind the defaults on a repeat call, ignoring this role's own leftover facts",
            "  ansible.builtin.set_fact:",
        ]
        # `| default(<name>)` on the REBIND, not a bare dereference. The generator writes one
        # defaults file per ENTRYPOINT, but Ansible only auto-loads defaults/main.yml — so an option
        # declared on a non-main entrypoint has no `__default` variable at run time. A bare
        # `{{ x__default }}` here then raises "'x__default' is undefined" on the SECOND call, on a
        # path that worked before this branch existed.
        #
        # A role whose teardown/verify options live in defaults/teardown.yml and defaults/verify.yml
        # fails on the second of two calls in one play with
        # '<role>_teardown_confirm__default is undefined'.
        #
        # Falling back to the option's own current value keeps the caller's include-level vars
        # winning (they shadow the stale fact) and degrades to "leave it alone" for an option whose
        # default is unreachable — which is the pre-existing behaviour, not a new failure.
        lines += [
            f'    {key}: "{{{{ {key}__default '
            f'if {key}__default is defined else {key} | default(omit) }}}}"'
            for key, _ in bindable
        ]
        lines += [f"  when: {marker} | default(false)"]
        lines += no_log_lines

        lines += [
            "",
            "- name: Record that this role has resolved its options in this play",
            "  ansible.builtin.set_fact:",
            f"    {marker}: true",
        ]
        return "\n".join(lines).rstrip("\n") + "\n"

    def _render_defaults_file(self, entrypoint: str, role: str | None = None) -> str:
        """One defaults file, with each value preceded by its description as comments."""
        argspec = self.argument_specs[entrypoint]
        lines = self._generated_header(role, "defaults file", entrypoint, spdx=self.spdx_license)

        for key, spec in argspec.options.items():
            name = f"{key}__default"
            # Mirror _model_dump_defaults' decision about what gets a default at all, so the
            # rendered file and the dict view can never disagree.
            if spec.type == "dict" and spec.options:
                nested = self._model_dump_defaults()[entrypoint].get(name)
                if nested is None:
                    continue
                value = nested
            elif spec.default is None:
                continue
            else:
                value = spec.default

            comment = self._as_comment(spec.description)
            if comment:
                if lines and lines[-1] != "":
                    lines.append("")
                lines.extend(comment)

            stream = StringIO()
            self._to_ansible({name: value}, stream)
            lines.extend(stream.getvalue().rstrip("\n").splitlines())

        return "\n".join(lines).rstrip("\n") + "\n"

    def model_dump_defaults_ansible(self) -> str:
        stream = StringIO()
        for entrypoint in self.argument_specs:
            stream.write(self._render_defaults_file(entrypoint))
        return stream.getvalue()

    def model_dump_defaults_ansible_to(self, path: Path, role: str | None = None) -> None:
        for entrypoint in self.argument_specs:
            (path / f"{entrypoint}.yml").write_text(
                self._render_defaults_file(entrypoint, role=role)
            )
