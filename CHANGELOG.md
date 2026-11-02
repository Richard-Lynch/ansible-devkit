# Changelog

All notable changes to `ansible-devkit`. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[SemVer](https://semver.org/). Installed from git tags (`v<version>`).

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

[0.1.0]: https://github.com/Richard-Lynch/ansible-devkit/releases/tag/v0.1.0
