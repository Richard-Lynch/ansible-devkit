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

- **`devkit hooks`** — install devkit-owned Git hooks once; run the same offline
  staged and full gates automatically, or manually in a sandbox with read-only Git metadata.

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

### Dependencies and repository conformance

`devkit deps install` installs the roles and collections in `requirements.yml` with
`ansible-galaxy --force`, verifies their directories and records a JSON stamp with the requirements SHA-256 and resolved
role and collection paths. Git
collection entries must have `# collection: namespace.name` on the name line.
`devkit deps check` compares the stamp and verifies every required directory without network access. Both accept
`--requirements`, `--collections-path`, and `--roles-path`.

`devkit check inventory-strict` enforces INVSTRICT-01 for inventory plugin expressions.
`devkit conform` requires a Makefile with help, test, lint, deps-install, deps-check and hooks-install
targets, each with a single devkit invocation. `[conform] makefile_policy_targets`
can exempt named targets except hooks-install (CONFORM-17 always requires
`devkit hooks install`, not a wrapper that ignores its failure).
Set `[conform] require_dependency_inputs = true` to require
`bindep.txt`, `pyproject.toml`, `uv.lock` and `requirements.yml` (ADR-59).

### Git hooks: automatic gates, including agent sandboxes

Provision a **non-editable devkit installation outside the work tree**, in a
standard POSIX Python virtual environment with `bin/devkit`. Include Black in
the toolchain (or the repository's existing environment) for staged Python
formatting. The installed devkit already includes its YAML lint dependency,
`ruamel.yaml`; hooks do not download or install anything. A checkout-local
`.venv` or editable source checkout is not a safe location for the hook package.

```sh
/opt/devkit/bin/devkit hooks path
/opt/devkit/bin/devkit hooks install --repo-root /workspace/repo
```

`hooks path` prints the absolute directory shipped inside that installation.
`hooks install` sets `core.hooksPath` to that **one fixed devkit-owned directory**,
never `.githooks/`, a copied shim in the repository, or a generated script in
Git metadata. Its packaged executable shims invoke the **same installation's
pinned `bin/devkit`**, not whichever `devkit` happens to be on `PATH`. Upgrading
devkit in a versioned environment requires rerunning install to select its new
path. Renovate bumps and their release notes can propagate these gates; this
feature does not change any consuming repository or coder deployment yet.

Install always prints exactly one line:

| Situation | Output | Exit |
| --- | --- | --- |
| First install, or replacing another hooksPath | `hooks: installed` | 0 |
| Already points to this installation, including read-only `.git` | `hooks: ok` | 0 |
| `CI=true` (CI runs the gates directly) | `hooks: skipped (CI=true)` | 0 |
| Read-only Git metadata and not enabled | `hooks: NOT INSTALLED (read-only .git)` | 3 |

Other errors print one `hooks: NOT INSTALLED (...)` line and exit 2. There is
no silent success. Linked worktrees and worktree-specific Git configuration
are supported. `make hooks-install` is the thin repository entrypoint,
enforced by `devkit conform`. The Copier template's `bootstrap.sh` calls it;
run `sh bootstrap.sh` after `git init` on a new checkout, with the provisioned
devkit on `PATH`. Normal setup then installs hooks without a separate reminder.

#### What the hooks check

**Pre-commit** reads the actual index blobs, including newly added files,
renames and partial staging; unstaged edits and untracked files are not checked.
Only staged regular `.py`, `.yml` and `.yaml` files are examined. It runs:

- Black's formatter check on staged Python, using the repository's formatter configuration.
- YAML lint using devkit's existing `ruamel.yaml`: syntax, duplicate keys,
  trailing whitespace, indentation tabs and the final newline (Ansible tags are accepted).
- The file-local fast subset of `devkit check`: `inventory-strict`,
  `rootfs-seal` (YAML) and `regex-anchors` (Python), over only those staged files.

Index snapshots, temporary files and caches live in a temporary directory
**inside the work tree** and are cleaned up. Neither the index nor `.git` is
written. Git is invoked without optional locks, Python subprocess bytecode is
disabled, and no formatter auto-fixes the working copy. Missing required tools
(for example `black`) fail with the tool's name; they never cause a skip.
Cross-file and repository-wide checks belong to the full gate, not this subset.

**Pre-push** runs the full repository gate. Configure a shell command in
`devkit.toml` when the repository has a dedicated offline target:

```toml
[hooks]
pre_push = "make lint-hooks"
```

Without this setting it runs `make lint` if the Makefile defines `lint`, else
`devkit check all`. A nonzero gate exit refuses the push; the standalone runner
preserves its exit status. Git's supplied local/remote ref updates are compared
without fetching: an empty update stream or changes to commits with identical
trees print `hooks: pre-push skipped (push changes no files)`. New and deleted
refs are checked too. Missing comparison objects fail closed rather than fetch
or skip. A manual run has no ref-update stream, so always runs the full gate.

#### Manual commands for agents

These are plain commands, not commands that require a commit or push:

```sh
devkit hooks run pre-commit --staged
devkit hooks run pre-push
```

Both work with read-only `.git`. The first checks the **already staged index**;
if an agent cannot stage its new edits, the second runs the full gate against
its working tree before handing work back. They need only the provisioned
tools, no network. The runner redirects common tool caches/temporary files
into the work tree and sets `UV_OFFLINE=1`, `UV_NO_SYNC=1` and `PIP_NO_INDEX=1`.
Configured gate commands must themselves be offline and confine their writes
to the work tree: the runner is not an OS sandbox for arbitrary shell commands.
Whole-tree tools must exclude the reserved `.devkit-hooks-*` scratch directories;
devkit's inventory scanner and the template's `.gitignore` already do so.
The sandbox's disabled network and read-only external mounts enforce that
boundary. Do not configure targets that install tools, sync environments or
download dependencies; provision those in the image first.

#### Security and coder deployment requirement

A tracked, agent-writable `.githooks/` would let host-side Git execute code
written by an agent on the host: the same vulnerability class as the
worker-sessiond 2.1.2 P1 finding. Keeping the entrypoints in the installed
devkit, outside the clone, avoids that trust inversion. For coder workers the
**entire devkit toolchain, including its pinned binary and hooks directory,
must be mounted read-only from the image**, at a stable absolute path. The
host can set that path before starting the sandbox **without executing any
repository code**:

```sh
hooks_dir=$(/opt/devkit/bin/devkit hooks path)
git -c core.hooksPath=/dev/null -C "$clone" config --local core.hooksPath "$hooks_dir"
```

**Every host-side Git command against an agent clone must explicitly disable
hooks with `git -c core.hooksPath=/dev/null ...`**, including host commits and
pushes. Do not run these gates on the host: the actual full gate can invoke
the clone's Makefile/configured command and belongs **inside the sandbox and
in CI**. A packaged trusted shim is not permission to execute a repository's
gate on the host. An automated integration test demonstrates refusal with
hooks enabled and bypass with this explicit host override. Coder service
mounting and host-command wiring are requirements for a later adoption card,
not changes included here.

Git's `--no-verify` bypass **cannot be prevented by Git hooks**; writable Git
configuration can also be changed by its owner. Hooks provide automatic local
feedback, not a security boundary against their caller. **CI is the real
backstop**, and must independently run the required full gate and formatter
check with required branch protection, regardless of installed hooks.
