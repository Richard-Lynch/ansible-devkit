# Rules

Every rule id a check in this package can emit, with its level and what it
catches. This file is the package's own rulebook: `devkit check docs-drift`
(DOCRULE-01) fails if a configured checker can emit a rule that is not listed
here, and `devkit check traps-are-checked` (TRAPTAG-01) fails if any bullet in
the section below carries no tag. The levels:

- **[FAIL]** — a deterministic rule; CI will not merge a violation.
- **[warn]** — a heuristic with plausible false positives; reported, not
  enforced (pass `--fail-on-warn` to `silent-guards` to enforce them too).
- **[you: <reason>]** — not mechanically checkable, and the reason says why.
  None here: this file lists machine-checked rules only.

A finding is suppressed on the task with
`# guard-check: ignore <RULE-ID> — <reason>`; a suppression with no reason is
itself a finding (SUPPRESS-01). Each rule ships with a fixture that must FAIL
and a near-miss that must PASS (`tests/suites/`); the near-miss is what makes a
rule survivable, because the obvious first form of every rule here
false-positives.

## Known traps in this codebase

### Control flow that exits green on failure (`silent-guards`)

- **[FAIL META-01]** `ansible.builtin.meta` combined with
  `until:`/`retries:`/`delay:` — meta actions bypass the retry machinery, so the
  keys parse and are never consulted.
- **[FAIL PIPEQ-01]** `cmd | grep -q` under `set -o pipefail` — `grep -q` closes
  the pipe on its first match, the writer takes SIGPIPE, and the pipeline
  reports failure on a MATCH.
- **[warn FAILED-01]** branching on `.failed` / `is failed` after
  `failed_when: false` — the flag is False even on a genuine failure, so the
  branch can never fire.
- **[warn UNTIL-01]** an `until:` loop with no later assert re-checking the
  register — a wait that exhausts its retries then continues, so a failed wait
  exits green.
- **[warn HANDLER-01]** a `set_fact` that exists only in `handlers/main.yml` —
  handlers run at play end, so a same-run guard reads the stale value.
- **[FAIL CHECKMODE-01]** documentation claiming `ansible_check_mode` can be set
  via `-e` — it is a read-only magic variable; the extra-var is accepted and
  ignored.
- **[warn CHECKMODE-02]** `when: ansible_check_mode` inside a block carrying its
  own `check_mode:` key — the guard sees the outer run's state, not the block's.
- **[warn INDEXGUARD-01]** an unexplained single-character index guard
  (`lv_attr[4]`) in front of a destructive command — a wrong index guards
  nothing; cite the field layout.

### Parsing command output (`silent-guards`)

- **[FAIL IPSUB-01]** a substring test against an IP literal
  (`'192.0.2.2' in stdout`) — it also matches `192.0.2.20` and `192.0.2.255`;
  compare exact list membership.
- **[warn DIGRC-01]** a `dig` result judged by stdout emptiness — `dig` writes
  diagnostics to stdout on failure; check `rc` and reject `^;;`.
- **[warn TIMERUNIT-01]** `systemctl stop <unit>` where `<unit>.timer` also
  exists in the repo — the stop resolves to the `.service` and the timer
  survives.
- **[FAIL PGREPMULTI-01]** `pgrep`/`pkill` given more than one pattern — procps
  takes exactly one and fails silently (empty output under `2>/dev/null` reads
  as "not running").
- **[warn STRINT-01]** a string-coerced value compared against a bare int
  literal — `"3" == 3` is False with no error; cast with `| int`.

### Jinja and YAML evaluation (`silent-guards`)

- **[FAIL MAPKEY-01]** a Jinja expression inside a YAML mapping KEY — values
  template, keys do not.
- **[FAIL REGEX-01]** a POSIX bracket class (`[:alnum:]`) inside a Python/Jinja
  regex — Python's `re` has no POSIX classes; the pattern matches nothing.
- **[warn REGEX-02]** `\b` inside a non-raw regex-ish string — a backspace, not
  a word boundary.
- **[FAIL IPADDRTEST-01]** `ansible.utils.ipaddr` used as a test inside
  `selectattr`/`rejectattr` — it is a filter and raises.
- **[FAIL JINJACOMMENT-01]** `#` inside a `{{ }}` expression — only `{# #}` is a
  comment; this is a render-time syntax error.
- **[FAIL YAMLESC-01]** a `\n`/`\t` escape inside a Jinja expression in a
  NON-double-quoted YAML scalar — only the double-quoted style processes
  escapes, so `split('\n')` in a `>-` scalar never splits. Decided by the
  enclosing scalar, not the inner quotes.
- **[warn ANCHOR-01]** a `$` anchor without `(?m)` against multi-line stdout —
  matches only at the end of the whole string.
- **[warn ASSERTKEY-01]** a comment line between two `assert: that:` items — it
  can break a folded plain-scalar continuation and swallow the next condition.
- **[FAIL CONDMAP-01]** an unquoted `: ` inside a conditional LIST ITEM
  (`when:`, `until:`, `*_when:`, `assert that:`) — YAML parses it as a one-key
  mapping, and Ansible rejects it only when the task runs.
- **[FAIL INSPECTENV-01]** a container inspect result (`docker_container_info`,
  `docker_container` with any state but `absent`, a bare `docker inspect`)
  registered without `no_log` — the document carries `Config.Env`, every secret
  the container runs with.
- **[FAIL RESOLVE-01]** a generated defaults resolver with no re-entry guard —
  `set_fact` persists for the play, so a role included twice reads the first
  call's values.
- **[FAIL SUPPRESS-01]** a `guard-check: ignore` comment with no reason.

### Tests that cannot fail, or fail for the wrong reason

- **[FAIL MOLCOLL-01]** a molecule scenario using a collection plugin without
  the vendored collections directory (`silent_guards.vendored_collections_dir`)
  in `ANSIBLE_COLLECTIONS_PATH` — passes locally, fails CI.
- **[warn MOLMIRROR-01]** a molecule verify/converge that re-derives the role's
  own filter chain over a hand-typed stub list, never calling the role — it
  asserts the copy against itself.
- **[warn MOLMIRROR-02]** a molecule scenario that hand-copies the role's
  `__default` resolution instead of including its resolver — a second source of
  truth that drifts.
- **[FAIL MOLVERIFY-01]** a scenario `test_sequence` that omits `verify` while a
  verify playbook exists — every assertion in it is decoration.
- **[FAIL MOLVERIFY-02]** a verifier that is disabled or not `ansible`, so
  verify.yml never runs.
- **[FAIL MOLVERIFY-03]** `provisioner.playbooks.verify` missing or naming some
  other file — molecule prints `verify: Missing playbook` and exits 0.
- **[FAIL MOLVERIFY-04]** a verify play whose `hosts:` matches no platform —
  `no hosts matched` is a green run. A host added by an earlier play in the same
  file counts.
- **[FAIL MOLVERIFY-05]** a scenario with a verify playbook that CI never runs —
  judged by asking the configured selector (`molecule.selector`) for its
  full-run answer, not by a string in a workflow. `# ci-exempt: <reason>` in
  molecule.yml opts a scenario out, with the reason required.
- **[FAIL MOLVERIFY-06]** a `test_sequence` that runs `prepare` with no
  `destroy` before it — prepare is skipped on the next run.
- **[FAIL RESOLVE-02]** a generated `<name>__default` that nothing under the
  role references — the bare name is undefined and the play dies mid-run, after
  earlier tasks have acted (`defaults-resolved`). Roles whose resolver is
  generated are skipped: those two lists cannot drift.

### Python and repository hygiene

- **[FAIL ICASE-01]** `re.IGNORECASE` on a pattern using `[A-Z]` as a camelCase
  boundary — under that flag the lookahead accepts any letter, so the pattern is
  simultaneously noisy and blind (`regex-anchors`). Suppress a deliberate
  fixture with `# regex-check: ignore ICASE-01 — <reason>`.
- **[FAIL TRACKIGNORE-01]** a tracked path that `.gitignore` lists — ignore
  rules govern only untracked files, so the listing protects nothing; it also
  catches a force-added secret (`no-tracked-ignored`). Fix:
  `git rm --cached <path>`.
- **[FAIL SELFLINK-01]** a tracked symlink whose target is absolute or resolves
  to itself — it dangles on every other machine and loops on this one
  (`no-tracked-ignored`).
- **[FAIL AGENTTREE-01]** a root-run
  `file`/`copy`/`template`/`lineinfile`/`blockinfile`/`replace` below a
  configured agent-writable tree (`agent_tree.tree_roots`) without
  `follow: false` AND a preceding `islnk` gate, or a confined helper — a planted
  link redirects the write out of the tree. `lineinfile`/`blockinfile`/`replace`
  take no `follow:` and are never accepted (`agent-tree-writes`).
- **[FAIL TRAPTAG-01]** a bullet in the rulebook's trap section with no
  `[FAIL X]`, `[warn X]` or `[you: <reason>]` tag — "nobody wrote the rule yet"
  and "this cannot be checked" are different claims, and only the second may
  stay (`traps-are-checked`).
- **[FAIL DOCRULE-01]** a rule a configured checker can emit
  (`docs.rule_sources`, via `--list-rules`) that the rulebook never mentions — a
  CI failure citing a rule nobody can look up is unactionable (`docs-drift`).

## Checks without a rule id

These report a finding by description rather than an id; each exits 1 on any
finding.

- **`rootfs-seal`** — an unseal of an immutable rootfs
  (`steamos-readonly disable`, `mount -o remount,rw /`) that is not inside a
  `block:` whose `always:` re-seals it. An unseal before the block leaves the
  filesystem writable if the play is interrupted, with nothing to warn.
- **`vendored-secrets`** — a credential-shaped KEY (`password`, `api_token`,
  `PrivateKey`, ...) in a structured config file vendored under
  `roles/*/files/`. Matched as a whole word in snake_case (case-insensitive) and
  camelCase (case-sensitive), so `compass` and `tokenizer` do not fire.
- **`ha-restart-validated`** — a Home Assistant Supervisor
  `core_restart`/`core_start`/`core_stop` (`ha_restart.supervisor_modules`) with
  no `core_check` earlier in the same file: a restart that loads an unvalidated
  config is an outage.
- **`ci-covers-hook-tests`** — a `test_*.py` under `ci_coverage.suite_dirs` that
  no workflow under `ci_coverage.workflow_dir` names. A suite CI never runs is
  green locally, green on the PR and absent from the gate; deleting the line is
  a failure too.
- **`boundary-lint`** — a configured estate fact (`boundary.patterns`: private
  addresses, real hostnames, a public IP) in an ENGINE path
  (`boundary.engine_roots`, minus the exempt data paths). A role that works on a
  second machine with only inventory changes has none.

## The repository standard (`devkit conform`)

`devkit conform [--path DIR]` checks a repository against the standard every
repository built on ansible-devkit meets, and that the copier template
(`copier.yml`, `template/`) generates. It prints one line per problem,
`<path>: <RULE> <message>`, and exits 0 when the repository conforms, 1 when it
does not, and 2 when a rule could not be evaluated (no git repository, an
unreadable file). Each rule has a failing fixture and a passing near-miss in
`tests/test_conform.py`.

| Rule       | The repository must have                                                                                                                   |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| CONFORM-01 | `.github/workflows/ci.yml`, `disclose.yml` and `release.yml`, each a YAML mapping                                                          |
| CONFORM-02 | exactly one job in each, with the id `ci` / `disclose` / `release` (the id names the required check, e.g. `ci / gate`)                     |
| CONFORM-03 | that job calling `Richard-Lynch/ansible-devkit/.github/workflows/reusable-<id>.yml` (`./.github/workflows/...` only where that file exists) |
| CONFORM-04 | the `uses:` ref a release tag, `vMAJOR.MINOR.PATCH` — a branch moves under the caller                                                      |
| CONFORM-05 | `kind:` on ci and release matching the repository (`galaxy.yml`: collection, `pyproject.toml`: python); ci's `ansible_core`, if given, a JSON list of `"X.Y"` |
| CONFORM-06 | `secrets: inherit` on release; `DISCLOSE_PATTERNS` and `DISCLOSE_ALLOW` passed from `secrets.` on disclose                                 |
| CONFORM-07 | ci on push to main and `pull_request`; release on push to main; disclose on `pull_request` types opened, synchronize, reopened, edited     |
| CONFORM-08 | `LICENSE` the GPL-3.0 text (compared with whitespace normalised)                                                                           |
| CONFORM-09 | a non-empty `## [<version>]` section in `CHANGELOG.md` for the version `galaxy.yml` (else `pyproject.toml`) declares                       |
| CONFORM-10 | `export.manifest` listing exactly the paths `git ls-files` lists                                                                           |
| CONFORM-11 | `SPDX-License-Identifier: GPL-3.0-or-later` in the first five lines of every tracked `.py` file                                            |
| CONFORM-12 | `.github/actionlint.yaml` (the reusable CI's actionlint job reads it)                                                                      |
