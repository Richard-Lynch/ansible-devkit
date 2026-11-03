# SPDX-License-Identifier: GPL-3.0-or-later
"""`devkit` — the console script.

  devkit check <name> [ARGS...]   run one check (ARGS go to the script unchanged)
  devkit check all                run every gate check against the current repository
  devkit check --list             the registry, with which checks `all` runs
  devkit conform [--path DIR]     check a repository against the public-repository standard
  devkit disclose ...             the disclosure gate (see ansible_devkit.disclose)
  devkit argspec ...              the argspec generator (also installed as `argspec`)
  devkit trap-report ...          rank recorded trap hits
  devkit record-trap-hits         the PostToolUse trap-hit recorder (payload on stdin)

Checks run as subprocesses of the SAME interpreter, in the caller's working directory, so a check
sees the repository it is run from and reads its devkit.toml exactly as a task runner or CI would. The
exit code of a single check is passed through unchanged (0 clean, 1 findings, 2 could not run);
`check all` exits 2 if any check could not run, else 1 if any found something, else 0 — a check
that could not run is never reported as clean.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import click

from ansible_devkit import __version__
from ansible_devkit import conform as _conform
from ansible_devkit.argspec.cli import cli as argspec_cli
from ansible_devkit.checks import BY_NAME, CHECKS, Check, _devkit_config
from ansible_devkit.disclose import disclose as _disclose


def _run(check: Check, args: tuple[str, ...]) -> int:
    cmd = [sys.executable, str(check.path), *check.default_args, *args]
    return subprocess.run(cmd, check=False).returncode


def _skips() -> dict[str, str]:
    """devkit.toml `[checks] skip = [{ name = ..., reason = ... }]`: gates `check all` leaves out.

    A skip is printed in the summary with its reason, so it is a recorded decision rather than a
    missing line. A skip with no reason, or naming no known gate, is a config error (exit 2): the
    one thing a skip list must never be is a quiet way to turn a check off.
    """
    try:
        entries = _devkit_config.load().get("checks.skip", [])
    except _devkit_config.ConfigError as exc:
        _devkit_config.fatal("devkit check all", exc)
    skips: dict[str, str] = {}
    for i, e in enumerate(entries if isinstance(entries, list) else [entries]):
        name = e.get("name") if isinstance(e, dict) else None
        reason = e.get("reason") if isinstance(e, dict) else None
        if name not in BY_NAME or not BY_NAME[name].gate:
            _devkit_config.fatal(
                "devkit check all",
                _devkit_config.ConfigError(f"checks.skip[{i}] names no gate check: {name!r}"),
            )
        if not isinstance(reason, str) or len(reason.split()) < 3:
            _devkit_config.fatal(
                "devkit check all",
                _devkit_config.ConfigError(f"checks.skip[{i}] ({name}) needs a reason"),
            )
        skips[name] = reason
    return skips


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="devkit")
def devkit() -> None:
    """Generic tooling for Ansible role repositories."""


@devkit.command(context_settings={"ignore_unknown_options": True, "allow_extra_args": True})
@click.argument("name", required=False)
@click.argument("args", nargs=-1, type=click.UNPROCESSED)
@click.option("--list", "list_", is_flag=True, help="list the registered checks and exit")
def check(name: str | None, args: tuple[str, ...], list_: bool) -> None:
    """Run one check by NAME, or `all` gate checks, against the current repository."""
    if list_ or name is None:
        width = max(len(c.name) for c in CHECKS)
        for c in CHECKS:
            tag = "gate" if c.gate else "    "
            click.echo(f"  {c.name:<{width}}  {tag}  {c.summary}")
        if name is None and not list_:
            raise click.UsageError("name a check, or `all`")
        return
    if name == "all":
        if args:
            raise click.UsageError(
                "`check all` takes no extra arguments; run one check to pass some"
            )
        skipped = _skips()
        results: list[tuple[Check, int]] = []
        for c in (c for c in CHECKS if c.gate):
            if c.name in skipped:
                continue
            click.echo(f"\n=== devkit check {c.name}", err=True)
            results.append((c, _run(c, ())))
        click.echo("\ndevkit check all:", err=True)
        for c, rc in results:
            verdict = {0: "clean", 1: "FINDINGS", 2: "COULD NOT RUN"}.get(rc, f"exit {rc}")
            click.echo(f"  {verdict:<14} {c.name}", err=True)
        for name, reason in skipped.items():
            click.echo(f"  {'SKIPPED':<14} {name} — {reason}", err=True)
        codes = {rc for _, rc in results}
        if codes - {0, 1}:
            sys.exit(2)
        sys.exit(1 if 1 in codes else 0)
    c = BY_NAME.get(name)
    if c is None:
        raise click.UsageError(f"no check named {name!r}; `devkit check --list` names them")
    sys.exit(_run(c, args))


@devkit.command()
@click.option(
    "--path",
    "path",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=Path("."),
    show_default=True,
    help="the repository to check",
)
def conform(path: Path) -> None:
    """Check a repository against the public-repository standard (one line per problem)."""
    root = path.resolve()
    problems = _conform.conform(root)
    for p in problems:
        click.echo(str(p))
    rc = _conform.exit_code(problems)
    if rc == 0:
        click.echo(f"devkit conform: {root} meets the standard", err=True)
    else:
        unchecked = sum(p.unchecked for p in problems)
        click.echo(
            f"devkit conform: {len(problems)} problem(s) in {root}"
            + (f", {unchecked} rule check(s) could not run" if unchecked else ""),
            err=True,
        )
    sys.exit(rc)


@devkit.command(
    context_settings={
        "ignore_unknown_options": True,
        "allow_extra_args": True,
        # `devkit disclose --help` is the gate's own help, not this wrapper's.
        "help_option_names": [],
    }
)
@click.argument("args", nargs=-1, type=click.UNPROCESSED)
def disclose(args: tuple[str, ...]) -> None:
    """Prove a commit and its history are fit for a PUBLIC repository (ARGS: see --help)."""
    sys.exit(_disclose.main(list(args)))


@devkit.command("trap-report", context_settings={"ignore_unknown_options": True})
@click.argument("args", nargs=-1, type=click.UNPROCESSED)
def trap_report(args: tuple[str, ...]) -> None:
    """Rank recorded trap hits by how often each is hit."""
    sys.exit(_run(BY_NAME["trap-report"], args))


@devkit.command("record-trap-hits")
def record_trap_hits() -> None:
    """PostToolUse recorder: read the tool payload on stdin, append a record per finding."""
    sys.exit(_run(BY_NAME["record-trap-hits"], ()))


devkit.add_command(argspec_cli, "argspec")


def main() -> None:
    devkit()


if __name__ == "__main__":
    main()
