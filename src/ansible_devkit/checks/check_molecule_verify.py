#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Fail if a molecule scenario has a verify playbook that `molecule test` will not actually run.

THE BUG THIS CATCHES. Every assertion in a scenario's verify.yml is a guard, and molecule has
several ways to skip that guard WHILE REPORTING GREEN. None of them prints an error; each ends in
`failed=0` and exit 0. With molecule 26.8.0, appending `assert: {that: [false]}` to a
scenario's verify.yml:

  - as written                                        -> exit 2 at verify (the guard works)
  - `playbooks: {verify: verfy.yml}` (a typo)          -> exit 0, "verify: Missing playbook"
  - verify play `hosts: instance` (no such platform)  -> exit 0, "skipping: no hosts matched"

and, by molecule's own code (verifier/ansible.py), `verifier: {enabled: false}` logs "Skipping,
verifier is disabled" and a non-ansible verifier never reads verify.yml at all. A scenario whose
`test_sequence:` omits `verify` simply never reaches it. Finally, a scenario CI never invokes
verifies nothing however it is configured: CI runs `molecule test` (the `default` scenario only)
per role, and a playbook-level scenario only if the configured selector lists it. A selector
that lists none leaves every playbook-level scenario unrun, and a scenario that has never run
on CI's platform may not even start there (a macOS-only tool, a BSD-only flag).

Rules, per scenario directory that holds a molecule.yml:
  MOLVERIFY-01  test_sequence is set and does not contain `verify`
  MOLVERIFY-02  the verifier is disabled, or is not the ansible verifier, so verify.yml is ignored
  MOLVERIFY-03  provisioner.playbooks.verify names a file that does not exist, or a file other
                than the scenario's own verify.yml -- molecule reports "Missing playbook", green
  MOLVERIFY-04  a verify play's `hosts:` matches no platform or platform group -- "no hosts matched"
  MOLVERIFY-05  the scenario is never run by CI: a role scenario not named `default`, or a
                playbook-level scenario absent from the CI selector's run-everything output.
                A scenario that cannot run on CI's Ubuntu says so with a `# ci-exempt: <reason>`
                line in its molecule.yml (the selector leaves it out); an empty reason is a FAIL.
  MOLVERIFY-06  test_sequence runs `prepare` with no `destroy` before it. destroy is the only step
                that resets molecule's state.yml (under its ephemeral directory, keyed on the role
                NAME, so shared by every checkout). Without it `prepared: true` outlives a passing
                run and the next run logs "Skipping, instances already prepared.": prepare's
                start-from-empty and fixtures never run, and converge/verify test whatever the
                previous run left. The symptom is a gate that fails on alternate runs and
                "passes alone" (a FAILED run's --destroy=always
                resets the flag; a passing run does not). A sequence without `prepare` has
                nothing to skip and is not flagged.

Rules 01-05 apply only to scenarios that HAVE a verify playbook: a scenario with nothing to verify
cannot silently skip it. MOLVERIFY-06 applies to every scenario with a custom test_sequence.
Templated `hosts:` values (`{{ ... }}`) are not judged.

Run:  devkit check molecule-verify [repo_root]
      --list-rules   print the rule table (read by check_docs_drift.py's DOCRULE-01)
Tests: uv run tests/suites/test_check_molecule_verify.py
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _devkit_config  # noqa: E402

try:
    import yaml
except ImportError:  # --list-rules must still answer (check_docs_drift runs on docs-only changes)
    yaml = None  # type: ignore[assignment]

RULES_TABLE = "\n".join(
    (
        "MOLVERIFY-01  FAIL  scenario test_sequence omits verify while a verify playbook exists",
        "MOLVERIFY-02  FAIL  verifier disabled or not ansible, so verify.yml is never run",
        "MOLVERIFY-03  FAIL  provisioner.playbooks.verify is missing or not the scenario's verify.yml",
        "MOLVERIFY-04  FAIL  a verify play's hosts: matches no molecule platform (no hosts matched)",
        "MOLVERIFY-05  FAIL  a scenario with a verify playbook that no CI workflow runs",
        "MOLVERIFY-06  FAIL  test_sequence runs prepare with no destroy before it (prepare is skipped on the next run)",
    )
)

# The CI selector. Asked for its run-everything answer (a Makefile change always selects ALL), so
# MOLVERIFY-05 checks what CI will actually run rather than a string in a workflow.
# Per-repo (devkit.toml [molecule] selector), relative to the root scanned. REQUIRED: a repo with no
# selector cannot say which playbook scenarios CI runs, and must say so rather than guess.
try:
    SELECTOR = Path(_devkit_config.load().string("molecule.selector"))
except _devkit_config.ConfigError as _exc:
    _devkit_config.fatal("check_molecule_verify", _exc)
# Same pattern as the selector's; a bare `# ci-exempt:` with no reason does not match it.
EXEMPT = re.compile(r"^# ci-exempt:[ \t]*\S", re.MULTILINE)
EXEMPT_BARE = re.compile(r"^# ci-exempt:", re.MULTILINE)

# Host patterns molecule's generated inventory always answers.
ALWAYS_HOSTS = {"all", "ungrouped"}


def _load(path: Path) -> Any:
    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def scenarios(root: Path) -> list[Path]:
    found = list(root.glob("roles/*/molecule/*/molecule.yml"))
    found += list(root.glob("playbooks/**/molecule/*/molecule.yml"))
    return sorted(p.parent for p in found)


def ci_playbook_scenarios(root: Path) -> set[str]:
    """The playbook-level scenarios CI runs on a full run; empty if the selector cannot say.

    Empty fails every playbook scenario, which is the right direction: a selector that cannot be
    asked is not evidence that it runs them.
    """
    exe = root / SELECTOR
    if not exe.is_file():
        return set()
    env = {**os.environ, "CHANGED_FILES": "Makefile", _devkit_config.ROOT_ENV: str(root)}
    try:
        out = subprocess.run(
            ["bash", str(exe)], capture_output=True, text=True, env=env, cwd=root, timeout=60
        ).stdout
        return set(json.loads(out).get("playbook_scenarios") or [])
    except Exception:  # noqa: BLE001 — unreadable selector output selects nothing
        return set()


def check_scenario(scen: Path, root: Path, ci_playbooks: set[str]) -> list[str]:
    rel = scen.relative_to(root)
    cfg = _load(scen / "molecule.yml") or {}
    provisioner = cfg.get("provisioner") or {}
    playbooks = provisioner.get("playbooks") or {}
    out: list[str] = []
    seq = (cfg.get("scenario") or {}).get("test_sequence")
    if isinstance(seq, list) and "prepare" in seq and "destroy" not in seq[: seq.index("prepare")]:
        out.append(
            f"{rel}: [MOLVERIFY-06] test_sequence {seq} runs prepare with no destroy before it — "
            "molecule's `prepared` flag outlives a passing run, so the next run skips prepare"
        )

    own_verify = scen / "verify.yml"
    configured = playbooks.get("verify")
    if not own_verify.is_file() and not configured:
        return out  # nothing to verify, so none of 01-05 can skip it silently

    if seq is not None and "verify" not in seq:
        out.append(f"{rel}: [MOLVERIFY-01] test_sequence {seq} omits verify")

    verifier = cfg.get("verifier") or {}
    if verifier.get("enabled") is False:
        out.append(f"{rel}: [MOLVERIFY-02] verifier.enabled is false")
    if verifier.get("name", "ansible") != "ansible":
        out.append(
            f"{rel}: [MOLVERIFY-02] verifier is '{verifier.get('name')}', which never runs verify.yml"
        )

    target = own_verify
    if configured:
        target = (scen / configured).resolve()
        if not target.is_file():
            out.append(
                f"{rel}: [MOLVERIFY-03] playbooks.verify '{configured}' does not exist — "
                "molecule reports 'Missing playbook' and stays green"
            )
        elif own_verify.is_file() and target != own_verify.resolve():
            out.append(
                f"{rel}: [MOLVERIFY-03] playbooks.verify '{configured}' is not the scenario's "
                "verify.yml, so verify.yml never runs"
            )

    if target.is_file():
        out += _check_hosts(rel, target, cfg)

    top = rel.parts[0] if rel.parts else ""
    if top == "roles" and scen.name != "default":
        out.append(
            f"{rel}: [MOLVERIFY-05] CI runs only the `default` scenario per role "
            f"(`molecule test`); '{scen.name}' never runs"
        )
    text = (scen / "molecule.yml").read_text(encoding="utf-8")
    if EXEMPT_BARE.search(text) and not EXEMPT.search(text):
        out.append(f"{rel}: [MOLVERIFY-05] `# ci-exempt:` with no reason")
    elif top == "playbooks" and EXEMPT.search(text):
        pass  # out of CI on purpose, with the reason on record; a local run can still exercise it
    elif top == "playbooks" and str(rel) not in ci_playbooks:
        out.append(
            f"{rel}: [MOLVERIFY-05] {SELECTOR} does not list this playbook-level scenario even "
            "on a full run, so it never runs in CI"
        )
    return out


def _check_hosts(rel: Path, verify: Path, cfg: dict) -> list[str]:
    known = set(ALWAYS_HOSTS)
    for plat in cfg.get("platforms") or []:
        known.add(str(plat.get("name")))
        known.update(str(g) for g in plat.get("groups") or [])
    plays = _load(verify) or []
    out: list[str] = []
    for play in plays if isinstance(plays, list) else []:
        if not isinstance(play, dict) or "hosts" not in play:
            continue  # import_playbook and the like
        hosts = play["hosts"]
        patterns = hosts if isinstance(hosts, list) else str(hosts).replace(",", ":").split(":")
        patterns = [str(p).strip().lstrip("!&") for p in patterns if str(p).strip()]
        if any("{{" in p or "*" in p for p in patterns):
            continue
        if not any(p in known for p in patterns):
            out.append(
                f"{rel}: [MOLVERIFY-04] verify play '{play.get('name', '?')}' targets "
                f"hosts: {hosts}, which matches no platform {sorted(known - ALWAYS_HOSTS)} — "
                "'no hosts matched' is a green run"
            )
        # A host added by THIS play exists for every LATER play in the same run (a scenario may
        # add a fact-free alias this way); it does not exist for an earlier one.
        known.update(_added_hosts(play))
    return out


def _added_hosts(node: Any) -> set[str]:
    names: set[str] = set()
    if isinstance(node, dict):
        for key in ("add_host", "ansible.builtin.add_host"):
            args = node.get(key)
            if isinstance(args, dict):
                for k in ("name", "hostname", "host"):
                    if k in args:
                        names.add(str(args[k]))
                names.update(str(g) for g in _as_list(args.get("groups") or args.get("group")))
        for v in node.values():
            names |= _added_hosts(v)
    elif isinstance(node, list):
        for v in node:
            names |= _added_hosts(v)
    return names


def _as_list(v: Any) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else str(v).split(",")


def scan(root: Path) -> list[str]:
    ci = ci_playbook_scenarios(root)
    findings: list[str] = []
    for scen in scenarios(root):
        findings += check_scenario(scen, root, ci)
    return findings


def main(argv: list[str]) -> int:
    if "--list-rules" in argv:
        print(RULES_TABLE)
        return 0
    if yaml is None:
        print(
            "check_molecule_verify: PyYAML is required to scan (only --list-rules works without it)"
        )
        return 2
    args = [a for a in argv[1:] if not a.startswith("-")]
    root = Path(args[0] if args else ".").resolve()
    found = scenarios(root)
    findings = scan(root)
    for f in findings:
        print(f"FAIL {f}")
    print(f"\ncheck_molecule_verify: {len(findings)} FAIL across {len(found)} scenario(s).")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
