# SPDX-License-Identifier: GPL-3.0-or-later
"""The disclosure gate: prove one exact commit, and all of its history, is fit for a PUBLIC repo.

This is the GENERIC half. It carries no knowledge of any estate: every pattern that names one
arrives in a private pattern file passed by path (`--patterns`), which never lives in the repo
being scanned. Generating that file, and the push that follows a pass, belong to the private
repository that publishes.

`ansible_devkit.disclose.disclose.main(argv)` is what `devkit disclose` runs; `gitleaks-base.toml`
beside it is the gitleaks configuration the gate uses (default rules, no path allowlist).
"""
