# ansible-devkit

Generic tooling for Ansible role repositories:

- **`argspec`** — generate a role's `meta/argument_specs.yml`,
  `defaults/main.yml`, a defaults resolver and a constraint-guard task file from
  ONE declaration, a `meta/argument_specs.py` built with pydantic models.
  Ansible's role-argspec validator enforces type/required/choices/no_log; the
  ranges, lengths and patterns it cannot enforce become a generated `assert`
  file instead of decoration.
- **`devkit check`** — static checks over an Ansible repository for the class of
  defect that reads as a safety check and is structurally unable to fire: a
  `meta:` task with `until:`, a `grep -q` under `pipefail`, a `\n` inside a
  folded scalar, a verify.yml molecule never runs, a generated default nothing
  reads, a root-run write under a tree an agent can redirect. Each rule has a
  fixture that must FAIL and a near-miss that must PASS; `docs/RULES.md` lists
  them all.
- **`devkit disclose`** — the generic half of a disclosure gate for publishing
  from a private repository: manifest equality, secret scanners over the full
  history, a private pattern file over every blob, commit message and identity,
  exact matches of known secret values, and the same again over a built tarball.
  It never prints a matched value, and it fails closed.

- **`devkit conform`** and a **copier template** — the public-repository
  standard as a check and as a generator: the three thin workflow callers pinned
  to a devkit tag, GPL-3.0, a CHANGELOG section for the declared version, an
  `export.manifest` equal to `git ls-files`, SPDX headers.

Everything that names an estate — hosts, addresses, tree roots, vault names —
lives in the consuming repository's `devkit.toml`, never in this package.

## Install

Releases are git tags; there is no PyPI package. Pin a tag:

```sh
# as a tool (puts `devkit` and `argspec` on PATH)
uv tool install git+https://github.com/Richard-Lynch/ansible-devkit@v0.2.3

# or as a dev dependency of your Ansible repository
uv add --dev "ansible-devkit @ git+https://github.com/Richard-Lynch/ansible-devkit@v0.2.3"
```

Python 3.12 or newer. `devkit disclose` also needs `gitleaks` and `trufflehog`
on `PATH` (it refuses to run without them unless told `--allow-missing <tool>`,
which it records in its report).

## Quickstart

```sh
cp /path/to/ansible-devkit/devkit.toml.example devkit.toml   # then fill in the placeholders
devkit check --list          # the registry: which checks `all` runs
devkit check all             # every gate check against this repository
devkit check silent-guards roles playbooks --fail-on-warn
argspec generate my_role     # roles/my_role/meta/argument_specs.py -> .yml, defaults, resolver, guards
```

Each check is a stand-alone script run as a subprocess in your working
directory. It resolves the repository as `$DEVKIT_ROOT`, else the git toplevel
of the working directory, and reads `<root>/devkit.toml`. Exit codes: **0**
clean, **1** findings, **2** the check could not run — a REQUIRED key missing
from `devkit.toml` is exit 2 naming the key, never a quiet pass. `check all`
exits 2 if any check could not run.

### `devkit.toml`

`devkit.toml.example` documents every key. The shape:

```toml
[paths]
vendored = ["roles.galaxy/", "collections.galaxy/"]   # trees every check skips
ansible_roots = ["roles", "playbooks"]

[silent_guards]
vendored_collections_dir = "collections.galaxy"       # REQUIRED (MOLCOLL-01)

[agent_tree]
tree_roots = []            # REQUIRED; an empty list is an explicit "none here"
concat_roots = []
config_dir_aliases = {}
```

A key a check requires has no default on purpose: a checker that guesses where
your repo keeps things, and finds nothing there, reports a clean repo it never
looked at.

### The repository standard

```sh
devkit conform                 # or: devkit conform --path /path/to/repo
```

prints one line per problem (`<path>: CONFORM-NN <message>`) and exits 0, 1, or
2 when a rule could not run (for example, not a git repository).
`docs/RULES.md` lists the rules.

A new collection repository that already conforms comes from the copier
template (`copier.yml` at this repository's root, files under `template/`):

```sh
uv tool install copier         # or: uv add --dev "ansible-devkit[template] @ git+...@v0.2.3"
copier copy --vcs-ref v0.2.3 gh:Richard-Lynch/ansible-devkit ansible-collection-demo
cd ansible-collection-demo && git init -q && git add -A && devkit conform
```

It asks for the namespace, name, first version, author, GitHub owner, the
ansible-core versions CI tests and the devkit tag the workflows call, and writes
`galaxy.yml`, `meta/runtime.yml`, `LICENSE`, `README.md`, `CHANGELOG.md`,
`.gitignore`, `devkit.toml`, `export.manifest`, `.github/actionlint.yaml` and the
`ci`, `disclose` and `release` callers.

### The disclosure gate

```sh
devkit disclose --repo /path/to/export --sha <full sha> \
  --patterns /private/patterns.json --secrets-cache /private/cache.json \
  [--manifest export.manifest] [--allow allow.txt] [--tarball built.tar.gz] [--report out.json] \
  [--published <already-public ancestor commit>]
```

`--published` names a commit that is already public (a pull request's base on the default
branch): a path deleted since then is not unlisted history while every blob it held there is
already public.

The pattern file is JSON —
`{"patterns": [{"id": "...", "kind": "literal", "value": "..."}, {"id": "...", "kind": "regex", "regex": "..."}]}`
— and is generated by the publishing repository from what it knows about itself;
this package deliberately has no idea what to put in it. A finding names a step,
a rule id and a location. RFC 5737 addresses and `example.com` / `.test` names
are exempt; anything else needs a line in an allow file with a reason.

This repository's own `disclose` workflow re-runs the gate on every pull request
with the pattern file supplied as an Actions secret, and fails if the secret is
absent.

## The argspec generator

```python
# roles/my_role/meta/argument_specs.py
from ansible_devkit.argspec import ArgumentSpec, ArgumentSpecs, OptionSpec

argument_specs = ArgumentSpecs(
    argument_specs={
        "main": ArgumentSpec(
            short_description="Deploy my_role",
            options={
                "my_role_port": OptionSpec(type="int", default=8080, min_value=1024, max_value=65535),
                "my_role_token": OptionSpec(type="str", required=True, no_log=True),
            },
        )
    }
)
```

`argspec generate my_role` writes `meta/argument_specs.yml` (what Ansible
enforces), `defaults/main.yml` (as `<name>__default`, so an omitted option is
distinguishable from a passed one), `tasks/_resolve_defaults.yml` (binds each
option to its default, with a re-entry guard for a role included twice) and
`tasks/_argspec_guards.yml` (the constraints Ansible cannot enforce, as asserts
that never print a `no_log` value). Include the resolver and guards from the
role's entrypoints; the generated headers name the regeneration command.

## Development

```sh
uv sync --frozen           # the lockfile is the source of truth
uv run pytest              # tests/test_suites.py runs every suite under tests/suites/
uv run devkit check all    # the package checks itself (devkit.toml at the repo root)
uv run tests/suites/test_check_silent_guards.py   # one suite on its own, from the repo root
```

Changing a check ships with its test case in both directions — a fixture that
must FAIL and a near-miss that must PASS — and a new rule id must be documented
in `docs/RULES.md`, which `devkit check docs-drift` enforces against the
checkers' own `--list-rules`.

## Layout

```
src/ansible_devkit/
  argspec/      models + the `argspec` CLI
  checks/       one script per check, `_devkit_config.py` (the devkit.toml loader), the registry
  disclose/     disclose.py and its gitleaks base config
  scripts/      affected-scenarios.sh — the molecule scenario selector MOLVERIFY-05 consults
  conform.py    `devkit conform`, the repository-standard rules
  cli.py        the `devkit` console script
tests/          pytest entry points; tests/suites/ holds the stand-alone suites and their fixture repo
docs/RULES.md   every rule id, tagged, with what it catches
copier.yml      the questions of the collection-repository template; template/ holds its files
devkit.toml     this repository's own configuration (it checks itself)
export.manifest every path in the repository, for the disclosure gate's manifest step
```

## License

GPL-3.0-or-later. See `LICENSE`; every source file carries an SPDX header.
