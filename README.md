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
- **`devkit disclose`** — the one scanner of a disclosure gate for publishing
  from a private repository: generic rules that need no input (private address
  ranges, device MACs, email addresses, SteamID64s, `op://` references), the
  secret scanners, an optional PRIVATE file of the publisher's own literals, the
  exact values of its known secrets, and the same again over a built tarball —
  over what a push adds (`--since` the already-public commit) or the whole
  history. A generic finding never prints the matched text, and it fails closed.

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
uv tool install git+https://github.com/Richard-Lynch/ansible-devkit@v0.5.1

# or as a dev dependency of your Ansible repository
uv add --dev "ansible-devkit @ git+https://github.com/Richard-Lynch/ansible-devkit@v0.5.1"
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
uv tool install copier         # or: uv add --dev "ansible-devkit[template] @ git+...@v0.5.1"
copier copy --vcs-ref v0.5.1 gh:Richard-Lynch/ansible-devkit ansible-collection-demo
cd ansible-collection-demo && git init -q && git add -A && devkit conform
```

It asks for the namespace, name, first version, author, GitHub owner, the
ansible-core versions CI tests and the devkit tag the workflows call, and writes
`galaxy.yml`, `meta/runtime.yml`, `LICENSE`, `README.md`, `CHANGELOG.md`,
`.gitignore`, `devkit.toml`, `export.manifest`, `.github/actionlint.yaml` and the
`ci`, `disclose` and `release` callers.

### The disclosure gate

```sh
# in public CI: no input but the repository (and the exemptions of its base branch)
devkit disclose --repo /path/to/checkout --sha <full sha> --since <base sha> \
  --allow-missing secrets-cache [--allow .disclose-allow] [--report out.json]

# in the private repository that publishes: the same, plus its two private inputs
devkit disclose --repo /path/to/export --sha <full sha> [--since <remote main>] \
  --local /private/literals.txt --secrets-cache /private/cache.json \
  [--allow allow.txt]... [--tarball built.tar.gz] [--report out.json]
```

The generic rules ship with the package and name no estate: RFC 1918 and RFC 6598
addresses, universally-administered device MACs, email addresses outside the
RFC 2606 names and noreply mailboxes, SteamID64s of real accounts, and `op://`
secret references. `--local` adds the publisher's own literals and regexes
(plain text, `<category> <value>` or `regex <name> <pattern>` per line); that
file is private and never reaches public CI. `--since` names a commit that is
already public (a pull request's base, the remote's main): only the blobs,
commit messages and identities new since it are scanned; without it the whole
history is. A finding names a rule and a location. A generic or known-secret
finding never carries the matched text; a local literal's rule is the literal,
so a report made with `--local` is as private as that file.

Exemptions are `<rule-glob> <location-glob> <reason>` lines; one location glob
covers a tree path and the same path inside the tarball. Every repository built
on this package carries a `.disclose-allow` for its own fixtures (a molecule
default address, a synthetic key); the shared `disclose` workflow reads it from
the pull request's BASE, so a pull request cannot widen the exemptions that
judge it (a new fixture exemption lands in its own pull request first). This
repository's own `disclose` workflow runs the gate on every pull request with no
private input at all.

### Dependencies and Renovate

`devkit check dependencies` (part of `check all`) enforces the dependency standard on any
repository: no ad-hoc `pip`/`uvx` install (DEP-02), no `:latest` or untagged image (DEP-03), every
`uses:` pinned to a commit SHA (DEP-04; devkit's own reusable workflows by release tag), and every
collection a role or plugin uses declared in `galaxy.yml` as a range (DEP-05). It is
baseline-FAIL: `deps-baseline.json` lists what a repository already had, each with a reason, and
only shrinks (`devkit check dependencies --update-baseline` after a fix). Rules: `docs/RULES.md`.

`renovate/default.json` is the shared Renovate policy; a repository's `renovate.json` extends it
pinned to a release tag (`github>Richard-Lynch/ansible-devkit//renovate/default#vX.Y.Z`), with every automerge decision in the repository's own file, and the template writes that file.

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
export.manifest every path in the repository (CONFORM-10: it equals `git ls-files`)
.disclose-allow exemptions for this repository's own fixtures, read by the disclose workflow
```

## License

GPL-3.0-or-later. See `LICENSE`; every source file carries an SPDX header.
