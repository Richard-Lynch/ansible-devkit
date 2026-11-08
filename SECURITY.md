# Security

## Reporting

Report a vulnerability privately through GitHub's "Report a vulnerability" (Security tab), not in
a public issue.

## What this tooling trusts

- **A pull request is data, never code.** `reusable-disclose.yml` checks out the PR into `scan/`
  and only reads it. `devkit` itself is installed from a TRUSTED commit — this shared workflow's
  own commit (`job.workflow_sha`), or, when the repository calling it IS devkit, the PR's BASE
  commit, and only when that base is the protected default branch — so a PR can never change the
  implementation that judges it. The repository's own fixture exemptions
  (`.disclose-allow`) are likewise read from the PR's BASE, never from the PR head, so a PR cannot
  widen the exemptions that judge it.
- **`devkit disclose` fails closed.** A scanner (`gitleaks`, `trufflehog`) that cannot be
  installed, a base that cannot be resolved, or a gate error is a failed run, never a skipped
  step. A finding names a rule and a location; it never prints the matched text.
- **Releases hold no shared key.** `reusable-release.yml` splits build from publish: the `build`
  job runs the repository's own code (tests, `devkit check all`, the build backend) and holds no
  secret and no environment. The `publish` job holds the release key, checks out nothing, and runs
  no repository code — it downloads the artifacts `build` uploaded, verifies their digest against
  what `build` recorded, mints a one-hour token from the release GitHub App scoped to this
  repository only, reserves the `v<version>` tag atomically (so two runs, or a run racing a
  hand-made tag, cannot both publish under it), and only then creates the release. The `publish`
  job runs in the `release` environment, which deploys from `main` only and holds no stored
  secret beyond the App credentials.

## Dependency notes

- `uv.lock` pins every Python dependency exactly; CI and the release build both run
  `uv sync --frozen`, which fails rather than silently re-resolving if the lockfile and
  `pyproject.toml` ever disagree.
- The disclosure gate installs `gitleaks` and `trufflehog` from pinned release URLs, each verified
  against a checksum recorded in the workflow before it is extracted and put on `PATH`.
