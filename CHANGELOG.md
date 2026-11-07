# Changelog

All notable changes to `ansible-devkit`. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[SemVer](https://semver.org/). Installed from git tags (`v<version>`).

## [0.5.0] — 2026-11-05

### Added

- **`devkit check diff-leak`** (gate): DIFFLEAK-01, a task that renders a credential into a file
  (`template`, `copy content:`, the lineinfile family, `ini_file`, a `deployment_config` sweep)
  without `no_log: true`, so `--diff` prints the secret into the run log. The template source is
  resolved the way Ansible resolves it; a source that cannot be resolved is counted, never passed.
- **`devkit check workflow-fork-guard`** (gate): FORKGUARD-01, a `pull_request`-triggered job that
  can select a self-hosted runner with no canonical fork guard (an `if:` conjunct, or a `runs-on`
  that picks a hosted label first for a fork PR); nothing is accepted under `pull_request_target`.
  Reusable workflows are judged too (a MEDIUM fail-open finding in the hub's copy, 2026-11-06): a
  local `uses: ./.github/workflows/x.yml` is followed and the callee's jobs judged under the
  caller's triggers, recursively with a cycle guard; a `workflow_call`-only workflow no scanned
  caller reaches is judged as fork-reachable; a remote reusable call must be pinned to a commit
  SHA (FORKGUARD-02), except ansible-devkit's own reusable workflows at a release tag.
  Three further security-review rounds are folded in with a FAIL fixture and a near-miss each: the
  fork guard must be the whole `if:` or a conjunct of its ONLY top-level disjunct (`guard && x ||
  true` is rejected); the hosted-first `runs-on` form is matched in full (`... || vars.NAME ||
  '"hosted"') }}`, nothing after it); a local callee is resolved relative to the caller's own
  directory and an unreached `workflow_call` workflow is judged in the `pull_request_target`
  context (hosted literal only). In `diff-leak`: a vault/hash filter exempts only the value it is
  applied to at the top level of the expression and only up to its balanced closing paren
  (`secret ~ (x | vault(pw))` and `x | vault(pw) ~ secret` are both findings); a suppression
  comment covers the task's own lines or the comment directly above it, never the next sibling;
  free-form `k=v` is split with Ansible's own `parse_kv`, and a task whose args cannot be parsed is
  counted as unresolved, never passed. A fourth round (1 HIGH): the fork-reachable trigger set is
  `pull_request`, `pull_request_target`, `pull_request_review`, `pull_request_review_comment`,
  `issue_comment` and `workflow_run`, and every one but plain `pull_request` accepts a hosted
  literal only; `diff-leak` merges a task-level `args:` mapping, reads the `action:` /
  `local_action:` forms (string and mapping), records a task whose args cannot be determined as
  unresolved, and follows `{% include %}`, `{% import %}`, `{% from %}` and `{% extends %}` into
  the role's templates recursively (cycle-guarded), counting a non-literal or missing target as
  unresolved.
  Fifth round (2 MEDIUM) and the structural fix: `diff-leak` no longer scans Jinja with regexes.
  Every expression, `{% set %}`, `{% for %}` and include target is read from jinja2's own AST
  (jinja2 is now a dependency): a credential is protected only when its node sits under a
  vault/hash `Filter` node, so operator precedence is Jinja's (`secret ~ x | vault(pw)` vaults
  only `x`); a text that does not parse is UNRESOLVED (a file) or tainted (a variable), never a
  pass. The rendering-argument table carries every alias from the modules' own argument specs
  (`lineinfile value`, `blockinfile content`, `ini_file values`) and the suite asserts it against
  the installed ansible-core through `ansible-doc --json`.
  Sixth round (3 MEDIUM): a hosted `runs-on` is an ALLOWLIST of GitHub's documented labels
  (extended per repository in devkit.toml `[workflow_fork_guard] hosted_labels`), never a prefix
  pattern (`ubuntu-lab` is self-hosted); any file offering `workflow_call` that no scanned caller
  reaches is judged in the strictest context whatever its other triggers; `diff-leak` follows
  `lookup('template', <literal>)` the way it follows `template: src:` and counts a non-literal
  target, or any `lookup('file', ...)` (unrendered content), as unresolved.
  Own adversarial pass: `lookup('vars'|'env', '<secret-named>')` renders the named value and is a
  finding; `pipe`, `url`, `csvfile`, `ini`, `lines` and `first_found` lookups are content this
  check cannot see (unresolved); `ansible.windows` `win_template`/`win_copy`/`win_lineinfile`
  render like their POSIX twins and are scanned.
  Seventh round (1 HIGH): the hosted-first `runs-on` form's two labels are captured and each
  checked against the hosted allowlist (no prefix pattern remains in the module); an `if:` with a
  `${{ }}` block anywhere but as one wrapper around the whole expression is unguarded (GitHub
  concatenates the blocks' text). `diff-leak`: `With`, `Macro` defaults, `CallBlock`,
  `FilterBlock` (a vault filter block protects its body) and `ExprStmt` are handled and every
  other expression child is judged as emitted; a task whose rendered content is UNRESOLVED and
  that carries no `no_log` is a FINDING (fail closed), with the credential heuristics also run on
  the arguments of `file`/`pipe`-style lookups; module and lookup names are matched on their
  SHORT name (`ansible.legacy.template`, a collection's own `template`), and a third-party
  file/template-reading lookup is unresolved.
  Eighth round: every early exit in both checks judges or records — a `with_fileglob` pattern
  that is not static or matches nothing, an `include_role`/`import_role` whose free-form args
  cannot be parsed, a render argument whose Jinja does not parse and a task entry that is not a
  mapping are all UNRESOLVED (a finding without `no_log`; the sweep's cover is `apply.no_log` for
  an include_role); in `workflow-fork-guard` a `jobs:` that is not a mapping, a job that is not a
  mapping and a job with neither `runs-on` nor `uses` are findings, never skips.
  Ninth round: a `{% set %}` block whose body holds any lookup or an include this check could
  not follow taints its variable; an attribute, literal subscript, `.get()`/`.pop()` argument or
  `json_query`/`extract` path named like a credential is a reference even when the base is an
  expression (`(lookup(...)).password`); a task file that does not parse as YAML, or whose top
  level is not a list, is UNRESOLVED and a finding — for task and play files; a mapping beside a
  play and any file under files/ or vars/ is data, which Ansible would refuse as tasks anyway.
  Tenth round: a template with a `#jinja2:` delimiter header, or a `template` task setting the
  `*_start_string`/`*_end_string` options, is UNRESOLVED (a default-delimiter parse is wrong by
  construction); variable data is any YAML under `vars/`, `defaults/`, `group_vars/` or
  `host_vars/` at any depth; the not-a-secret suffixes (`_file`, `_ttl`, ...) apply only to
  detection BY NAME — a name DEFINED from a credential is tainted whatever it is called.

### Threat model and stopping rule for `diff-leak` and `workflow-fork-guard`

These two checks guard against the repository's OWN accidental leaks and misconfigurations: a
maintainer who forgets `no_log` on a task that renders a secret, or who lets a repository variable
route a fork PR onto a persistent runner. They are static heuristics over YAML and Jinja, and they
fail CLOSED: anything they cannot resolve is a finding unless the task carries `no_log` or a
suppression with a reason. They are **not** a boundary against an adversarial author: someone who
controls the repository's code can always construct a shape a static check does not model, and the
answer to that threat is review and the runner/credential boundary, not more regexes. After ten
security-review rounds on 0.5.0 (each with a FAIL fixture and a near-miss), a further finding on
these two checks is tracked as an issue rather than blocking a release, unless it is HIGH or shows
a real leak path in a repository's ACTUAL code.
- **`docs-drift` reads `devkit:<check>` rule sources**: `docs.rule_sources` may name a check this
  package provides, and DOCRULE-01 lists its rules through `devkit check <name> --list-rules`, so a
  repository that keeps no copy of the generic checks still compares its rulebook against what it
  enforces. A source that cannot run is a config error (exit 2), never an empty set.

### Changed

- **`boundary-lint` honours `--warn`** when the registry's `--enforce` is also present, so
  `devkit check boundary-lint --warn` is a report (exit 0) and `devkit check all` still enforces.

Both checks and their suites come from the IaaC hub (M6 batch 2), where they had gated every PR
since 2026-11-03 / 2026-11-04; the suites are unchanged apart from their locators.

## [0.4.1] — 2026-11-05

### Changed (security review of the Renovate policy)

- **Repositories pin the preset**: `github>Richard-Lynch/ansible-devkit//renovate/default#vX.Y.Z`
  (the template writes the release it was generated from), so the shared policy moves only
  through a reviewed PR in each repository.
- **The preset turns no automerge on.** Every automerge decision lives in the repository's own
  `renovate.json`, after the preset, so a later preset cannot widen it: everything off, then only
  `actions/*` PATCH releases at least 5 days old (`minimumReleaseAge`). Third-party actions and
  digest-only updates are always reviewed; Galaxy content (it runs on the privileged controller
  and is not hash-locked) is always reviewed; a repository with a Dockerfile scopes its
  `dockerfile` updates by `matchFileNames` with automerge off.

## [0.4.0] — 2026-11-04

### Added

- **`devkit check dependencies`** (gate, so every repository's `devkit check all` runs it):
  DEP-02 no ad-hoc `pip`/`uv`/`uvx`/`pipx` install (and no unpinned pip-module install), DEP-03
  no `:latest` or untagged image, DEP-04 every non-local `uses:` pinned to a commit SHA (a
  `docker://` action by digest; devkit's own reusable workflows by release tag, as CONFORM-04
  requires), DEP-05 every collection a role or plugin uses declared in `galaxy.yml` as a range.
  Baseline-FAIL: `deps-baseline.json` records what a repository already had, each entry with a
  reason; a new finding, a stale entry or an entry without a reason fails. The collection-side
  port of the hub's `make lint-deps` (DEP-01 and DEP-06 need a Python lock and stay there).
- **Renovate**: `renovate/default.json`, the shared policy every repository extends
  (`local>Richard-Lynch/ansible-devkit//renovate/default`): GitHub Actions pinned to digests in one
  PR, devkit's reusable-workflow tags in another, `galaxy.yml` collection ranges widened (never
  pinned), uv.lock in one Python PR plus monthly lock maintenance, patch/digest bumps automerged
  once `ci / gate` and `disclose / gate` pass, majors only from the dependency dashboard. The
  template ships a `renovate.json` that extends it.
- The template writes `.python-version` (question `python_version`, default devkit's own).

### Changed

- **The shared CI and release use the CALLER's Python**: `reusable-ci.yml` (kind=collection) and
  `reusable-release.yml` read the caller's `.python-version` instead of a hardcoded "3.12". A
  caller without one gets `PYTHON_FALLBACK`, which is devkit's own `.python-version` (a test fails
  if they differ): a missing file must not fail every collection that predates it, and the
  version devkit is tested on is the one known to work.

## [0.3.2] — 2026-11-04

### Changed

- The gate's own suite assembles every planted fixture value at run time (the device MAC, the
  `op://` reference and the non-example email, as the private addresses already were), so this
  repository's `.disclose-allow` exempts nothing. A path-scoped generic `mac` exemption would
  read as if it covered a real device; a fixture MAC is locally administered instead.

## [0.3.1] — 2026-11-04

### Changed

- **`reusable-disclose.yml` takes no secrets and needs no private input.** It runs
  `devkit disclose` with the generic rules over what the pull request adds (`--since` the base
  when the base is the default branch; the whole history otherwise), gitleaks and trufflehog
  included, and reads the repository's own fixture exemptions from `.disclose-allow` at the pull
  request's BASE — never from the head, so a pull request cannot widen the exemptions that judge
  it. The `DISCLOSE_PATTERNS` and `DISCLOSE_ALLOW` secrets are no longer read; a caller that still
  passes them is a workflow error, and `devkit conform` **CONFORM-06** now requires the `disclose`
  caller to pass no secrets. The template's `disclose.yml` and this repository's own are updated.

### Added

- `devkit conform` rule **`CONFORM-14`**: `.disclose-allow` exists and every line of it is an
  exemption the gate accepts (a rule, a location that is not `*`, a reason of three words or
  more). The shared workflow reads the file from a pull request's base, so a file the gate would
  refuse fails every pull request of the repository; this catches it in the pull request that
  writes it.

## [0.3.0] — 2026-11-04

### Changed

- **`devkit disclose` is the one scanner, and it ships no estate values.** The private pattern
  file (`--patterns`) is gone. In its place: GENERIC rules that need no input — `rfc1918-10`,
  `rfc1918-172`, `rfc1918-192`, `rfc6598-100` (private and shared IPv4 ranges), `mac` (a
  universally-administered unicast MAC; a locally-administered, multicast or all-zero one is a
  fixture), `email` (outside the RFC 2606 names; a noreply mailbox, the `git@` user of an SSH
  URL, a systemd `unit@instance.service` name and an iSCSI `@iqn.` instance are not addresses),
  `steamid64` (an account id of 1000 or more) and `op-ref` (an `op://` reference that starts
  with a vault name) — and an optional `--local FILE` of the publisher's own literals and
  regexes, plain text, one per line (`<category> <value>` / `regex <name> <pattern>`). A local
  literal's rule is `<category>:<value>`, so an exemption names the literal in plain text; the
  local file and the report of a run that used it are private by construction.
- **Scope**: `--since COMMIT` (an already-public ancestor of the scanned commit) scans only the
  blobs, commit messages and identities new since it, which is what a push adds. Without it the
  whole history of the commit is scanned. `--published` is gone; so is the manifest step
  (`MANIFEST-01..03`): the tree-equals-manifest check is `devkit conform` CONFORM-10, and the
  built tarball's members are checked against the tree at the scanned commit (`ARTIFACT-01`).
- **One allow line covers a tree path and the same path inside the tarball**: a `tarball:`
  twin line is no longer needed (an explicit `tarball:<glob>` still works). A location of `*`
  or `**` is refused (exit 2), and so is a local file that holds no entries or does not parse.
- The report's per-step `status` is the step's raw verdict (before exemptions), labelled as such
  (`raw_findings`); the top-level `result` and `findings` are what decide the exit code.

### Added

- `.disclose-allow` at the repository root, here and in the collection template: the
  exemptions for a repository's OWN fixtures (a molecule default address, a synthetic key, a
  test email), in the same `<rule-glob> <location-glob> <reason>` form. The next release's
  shared `disclose` workflow reads it from the pull request's base.

## [0.2.3] — 2026-11-03

### Added

- `devkit disclose --published <commit>`: an ancestor of the scanned commit that is already
  public. A path deleted since then is not reported as `MANIFEST-03` (unlisted path in history)
  when every blob it held at that path is one the published commit's history already carried
  there. Without it, no change that deletes a file could pass, because the manifest must equal
  the tree. A new blob at an old path, or a path added and deleted after the published commit,
  still fails; every other step scans the full history unchanged. A short, unknown or
  non-ancestor `--published` is an error, never a pass.
- `reusable-disclose.yml` passes the pull request's base commit as `--published` when the base is
  the default branch; any other base gets no exemption.

### Fixed

- `MANIFEST-03` walks every commit's tree, so a blob that also sat at a second path no longer
  hides that path (`git rev-list --objects` names a blob once).

## [0.2.2] — 2026-11-03

### Added

- `devkit conform` rule **`CONFORM-13`**: in a collection, every `roles/<role>/` has a
  `README.md` and a `meta/main.yml` whose `galaxy_info.description` is a non-empty string.
  Galaxy's importer fails a collection containing a role with no README, and shows no
  description for a role without one; neither stops `ansible-galaxy collection build` or the
  upload, so both otherwise surface only in the import result after the release has run.

## [0.2.1] — 2026-11-03

### Fixed

- `reusable-release.yml` (`kind: collection`): the Galaxy upload is judged by its HTTP status and
  completion by polling the public version endpoint, never by parsing a response body. A release
  whose upload succeeded failed afterwards on an empty import-task response; a re-run then
  completed it, after the sha256 check confirmed Galaxy held the built tarball.

## [0.2.0] — 2026-11-03

### Added

- **`devkit conform [--path DIR]`**: checks a repository against the
  public-repository standard and prints one line per problem (rules
  `CONFORM-01`..`CONFORM-12`, listed in `docs/RULES.md`): the `ci`, `disclose`
  and `release` callers with the right job ids, `uses:` target (a local
  reusable workflow only in ansible-devkit itself), release-tag ref, `kind`,
  secrets, and triggers with no filter or job `if:` that could skip the gate; a GPL-3.0 `LICENSE`; a `CHANGELOG.md` section
  for the declared version; `export.manifest` equal to `git ls-files`; SPDX
  headers on tracked `.py` files; `.github/actionlint.yaml`. Exits 2 when a rule
  could not be evaluated, such as outside a git repository.
- **A copier template** for a new Ansible collection repository (`copier.yml`,
  `template/`), generating `galaxy.yml`, `meta/runtime.yml`, `LICENSE`,
  `README.md`, `CHANGELOG.md`, `.gitignore`, `devkit.toml`, `export.manifest`,
  `.github/actionlint.yaml` and the three thin callers pinned to a devkit tag.
  A generated repository passes `devkit conform` and `devkit check all`.
  `copier` is an optional extra (`ansible-devkit[template]`) and a dev
  dependency, not a runtime dependency.
- `tests/test_conform.py` (a failing fixture and a passing near-miss per rule)
  and `tests/test_template.py`, run by `reusable-ci.yml`'s python job.

- **`reusable-ci.yml`**: an `actionlint` job for every kind, from a pinned release
  tarball whose sha256 is verified; it reads the caller's
  `.github/actionlint.yaml`. `ci / gate` requires it, so the caller-facing
  check name is unchanged.

### Changed

- **`reusable-ci.yml`**: the collection matrix job is named `collection` (the
  ansible-core version is in its step names and the expanded check names), so
  the job no longer shows an unrendered matrix expression when it is skipped.
- **Build backend pinned exactly**: `[build-system] requires` is
  `hatchling==1.33.0`, so a build is reproducible from the repository alone.

## [0.1.0] — 2026-11-02

First release.

### Added

- **`argspec`** (`ansible_devkit.argspec`): generate a role's
  `meta/argument_specs.yml`, `defaults/main.yml`, defaults resolver and
  constraint guards from a `meta/argument_specs.py` built with pydantic models
  (`ArgumentSpecs`, `ArgumentSpec`, `OptionSpec`). Constraints Ansible cannot
  enforce (ranges, lengths, patterns, forbidden values) become a generated
  assert file; `no_log` options never echo their value.
  `argspec audit-resolvers` finds declared defaults nothing resolves.
- **`devkit check`** and the static checks (`ansible_devkit.checks`), each
  configured by the consuming repo's `devkit.toml` and runnable on its own:
  `silent-guards`, `rootfs-seal`, `vendored-secrets`, `agent-tree-writes`,
  `ha-restart-validated`, `molecule-verify` (with the `affected-scenarios.sh`
  selector), `no-tracked-ignored`, `defaults-resolved`, `regex-anchors`,
  `traps-are-checked`, `ci-covers-hook-tests`, `docs-drift`, `boundary-lint`;
  plus `trap-report` and the `record-trap-hits` PostToolUse recorder.
  `docs/RULES.md` lists every rule id.
- **`devkit disclose`** (`ansible_devkit.disclose`): the generic half of a
  disclosure gate for publishing from a private repository — manifest equality,
  gitleaks and trufflehog over the full history, private pattern matching over
  every blob, commit message and identity, exact-match of known secret values,
  and the same again over a built tarball. It never prints a matched value and
  fails closed.
- `devkit.toml.example` documenting every key; `docs/RULES.md`, the package's
  own rulebook, which `devkit check all` verifies against the checkers.
- Test suites under `tests/suites/`, run by `uv run pytest`, including
  `test_portable_checks.py`: every check clean on a fixture repository, one
  injected violation per rule caught, and a missing REQUIRED key exits 2.
- **Shared workflows** for every repo built on ansible-devkit, called from thin
  per-repo files pinned to a devkit tag:
  - `reusable-ci.yml` (`kind: python | collection`): the CI gate; for a
    collection, `ansible-test sanity` and `units` across an ansible-core matrix
    plus `devkit check all`. Always reported as the single check `ci / gate`.
  - `reusable-disclose.yml`: the disclosure gate on every pull request, failing
    closed without its pattern secret. Reported as `disclose / gate`.
  - `reusable-release.yml`: releases on merge of a version bump. A secret-free
    build job verifies and builds; a separate publish job in the main-only
    `release` environment checks the artifact digests, publishes a collection
    to Galaxy, and creates the tag and GitHub release with a release-App token.

[0.2.2]: https://github.com/Richard-Lynch/ansible-devkit/releases/tag/v0.2.2
[0.2.1]: https://github.com/Richard-Lynch/ansible-devkit/releases/tag/v0.2.1
[0.2.0]: https://github.com/Richard-Lynch/ansible-devkit/releases/tag/v0.2.0
[0.1.0]: https://github.com/Richard-Lynch/ansible-devkit/releases/tag/v0.1.0
