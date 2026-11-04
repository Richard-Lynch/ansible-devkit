# Changelog

All notable changes to `ansible-devkit`. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[SemVer](https://semver.org/). Installed from git tags (`v<version>`).

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
