# Changelog

All notable changes to `ansible-devkit`. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[SemVer](https://semver.org/). Installed from git tags (`v<version>`).

## [0.2.0] — 2026-11-03

### Added

- **`devkit conform [--path DIR]`**: checks a repository against the
  public-repository standard and prints one line per problem (rules
  `CONFORM-01`..`CONFORM-12`, listed in `docs/RULES.md`): the `ci`, `disclose`
  and `release` callers with the right job ids, `uses:` target, release-tag ref,
  `kind`, secrets and triggers; a GPL-3.0 `LICENSE`; a `CHANGELOG.md` section
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

[0.2.0]: https://github.com/Richard-Lynch/ansible-devkit/releases/tag/v0.2.0
[0.1.0]: https://github.com/Richard-Lynch/ansible-devkit/releases/tag/v0.1.0
