#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Cases for check_vendored_secrets.py — including that every pattern can actually FIRE.

WHY THIS EXISTS. A GUI installer's settings file vendored wholesale carries whatever the wizard
asked for — a sudo password, an account password, an API token. A hook that guards against that
and is itself untested is in the one state a safety check must never be in.

The cases below pin three bugs the obvious key regex has:

  1. `password_file` and `passwordFile` FAIL the build, though a path to a secret is fine to
     vendor. A check that flags the correct pattern gets suppressed.
  2. `compass`, `passthrough` and `tokenizer` all match as credentials — pure false positives.
  3. `PrivateKey` does NOT match while `private_key` does, so camelCase coverage is a coin flip.

Root cause of 2 and 3, and the reason the camelCase branch is case-SENSITIVE: `re.IGNORECASE`
makes `[A-Z]` match lowercase, so the `(?=[A-Z])` word boundary accepted any following letter and
therefore bounded nothing at all. Same family as the `\\b`-in-a-non-raw-string and POSIX-class
traps: a pattern that reads as anchored and is not.

So every key shape here is tested in BOTH directions — a key that must be flagged, and a
near-miss that must not be. A guard nobody proved can fire is decoration.

Fixture values are all the literal string NOT-A-REAL-VALUE. The checker matches credential-shaped
KEY NAMES and never inspects the value's shape, so realistic-looking secrets would buy the tests
nothing — and they tripped gitleaks in CI, which is a required check. A test fixture that fails
the repo's own secret scanner teaches people to weaken the scanner.

Run: uv run tests/suites/test_check_vendored_secrets.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from _paths import CHECKS, ROOT  # noqa: F401 — tests/suites/_paths.py

sys.path.insert(0, str(CHECKS))

from check_vendored_secrets import check, is_secret_key, main as scan_main  # noqa: E402

FAIL, OK = "fail", "ok"

# ---------------------------------------------------------------------------
# Key-name classification. The regex is the whole safety property, so it is
# tested directly as well as through the file scanners.
# ---------------------------------------------------------------------------

# Keys that name a credential. Every naming convention a GUI installer might emit.
SECRET_KEY_CASES: list[str] = [
    "password",
    "passwd",
    "PASSWORD",
    "Password",
    "sudo_password",
    "sudoPassword",
    "SudoPassword",
    "secret",
    "my_secret",
    "client_secret",
    "SecretKey",
    "clientSecret",
    "token",
    "api_token",
    "authToken",
    "AuthToken",
    "TOKEN",
    "apikey",
    "api_key",
    "api-key",
    "apiKey",
    "ApiKey",
    "credential",
    "credentials",
    "userCredentials",
    "privkey",
    "private_key",
    "PrivateKey",
    "PrivKey",
    "pass",
    "userPass",
]

# Keys that do NOT name a credential: a path/handle to one, or an innocent word that merely
# contains "pass"/"token"/"secret" as a substring.
BENIGN_KEY_CASES: list[str] = [
    # a PATH to a secret is fine to vendor — the value is a filename
    "password_file",
    "passwordFile",
    "secret_path",
    "secretPath",
    "token_env",
    "tokenFile",
    "credentials_dir",
    "askpass_cmd",
    "PasswordHelper",
    # substrings, not words
    "compass",
    "encompass",
    "passthrough",
    "Passthrough",
    "PASSTHROUGH",
    "bypass",
    "passing",
    "tokenizer",
    "tokens_per_sec",
    "secretary",
    # ordinary config keys
    "username",
    "hostname",
    "appid",
    "class",
    "port",
    "mode",
]


def _key_cases() -> tuple[int, int, list[str]]:
    passed = failed = 0
    failures: list[str] = []
    for key in SECRET_KEY_CASES:
        if is_secret_key(key):
            passed += 1
        else:
            failed += 1
            failures.append(f"  FAIL  want flagged, not flagged: {key!r}")
    for key in BENIGN_KEY_CASES:
        if not is_secret_key(key):
            passed += 1
        else:
            failed += 1
            failures.append(f"  FAIL  want clean, flagged: {key!r}")
    return passed, failed, failures


# ---------------------------------------------------------------------------
# Whole-file scans. (expected, suffix, content, label)
# ---------------------------------------------------------------------------

# The shape of a GUI installer's settings file, reduced to its structure.
INSTALLER_SHAPE = """{
  "systemName": "handheld",
  "userName": "user",
  "sudoPassword": "NOT-A-REAL-VALUE",
  "cloudSync": {"provider": "rclone", "token": "NOT-A-REAL-VALUE"},
  "achievements": {"raUser": "user", "raPassword": "NOT-A-REAL-VALUE"}
}"""

FILE_CASES: list[tuple[str, str, str, str]] = [
    # ---- the installer-settings shape, which must fail ----
    (FAIL, ".json", INSTALLER_SHAPE, "json: the GUI-installer settings shape"),
    (FAIL, ".json", '{"apiKey": "NOT-A-REAL-VALUE"}', "json: camelCase apiKey"),
    (
        FAIL,
        ".json",
        '{"outer": {"inner": {"password": "NOT-A-REAL-VALUE"}}}',
        "json: nested password",
    ),
    (FAIL, ".json", '{"accounts": [{"token": "NOT-A-REAL-VALUE"}]}', "json: secret inside a list"),
    (FAIL, ".env", "API_TOKEN=NOT-A-REAL-VALUE\n", "env: KEY=value"),
    (FAIL, ".conf", "password: NOT-A-REAL-VALUE\n", "conf: KEY: value"),
    (FAIL, ".ini", '"client_secret" "NOT-A-REAL-VALUE"\n', "ini: quoted KEY value"),
    (FAIL, ".sh", "export SUDO_PASSWORD=NOT-A-REAL-VALUE\n", "sh: exported credential"),
    # ---- the CORRECT pattern must stay clean, or the check gets suppressed ----
    (
        OK,
        ".json",
        '{"password": "{{ vault_device_sudo_password }}"}',
        "near-miss: Jinja reference is the fix, not a secret",
    ),
    (
        OK,
        ".json",
        "{\"apiKey\": \"{{ lookup('ansible.builtin.env', 'x') }}\"}",
        "near-miss: templated lookup is the fix",
    ),
    (OK, ".json", '{"password": ""}', "near-miss: declared but empty"),
    (OK, ".json", '{"password": null}', "near-miss: declared as null"),
    (OK, ".json", '{"password": "changeme"}', "near-miss: placeholder value"),
    (
        OK,
        ".json",
        '{"password_file": "/run/secrets/app.pw"}',
        "near-miss: a PATH to a secret is fine to vendor",
    ),
    (
        OK,
        ".json",
        '{"passwordFile": "/run/secrets/app.pw"}',
        "near-miss: camelCase path to a secret",
    ),
    # ---- innocent config must not be flagged ----
    (
        OK,
        ".json",
        '{"audioPassthrough": true, "compass": "north"}',
        "near-miss: 'pass' as a substring is not a credential",
    ),
    (
        OK,
        ".json",
        '{"tokenizer": "bpe", "tokens_per_sec": 42}',
        "near-miss: 'token' as a substring is not a credential",
    ),
    (
        OK,
        ".json",
        '{"userName": "user", "hostname": "handheld", "appid": 12345}',
        "near-miss: ordinary config keys",
    ),
    # ---- the harness must not crash on junk ----
    (OK, ".json", "{not valid json at all", "malformed JSON does not break the scan"),
    (OK, ".conf", "", "empty file"),
    # An embedded python heredoc in a vendored shell script can end a block with
    # `pass" "$1"`, which a whitespace-separated KEY/value rule read as a credential named `pass`.
    (
        OK,
        ".sh",
        'except Exception:\n    pass" "$1" 2>/dev/null && return 0\n',
        "near-miss: python `pass` in an embedded heredoc is not a setting",
    ),
    (OK, ".conf", "# password: this is a comment\n", "comment-only line is not a setting"),
]


def _skip_cases() -> tuple[int, int, list[str]]:
    """A dependency tree is skipped; a real vendored file beside it is still scanned."""
    passed = failed = 0
    failures: list[str] = []
    # The same credential-shaped content is written to BOTH paths, so the only thing deciding
    # the outcome is WHERE the file is. Anything else and the test would be asserting that the
    # key regex works, which is already covered above.
    content = '{"api_key": "NOT-A-REAL-VALUE"}\n'

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "roles" / "demo" / "files"

        # MUST BE SKIPPED: a dependency tree and a build output directory.
        for skipped in ("node_modules/pkg/lang.json", "dist/assets/bundle.json"):
            p = root / "app" / skipped
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")

        # MUST BE SCANNED: an ordinary vendored config. Without this the skip could widen to
        # "scan nothing" and every case above would still pass.
        real = root / "config" / "settings.json"
        real.parent.mkdir(parents=True, exist_ok=True)
        real.write_text(content, encoding="utf-8")

        rc = scan_main(["check_vendored_secrets", str(Path(tmp) / "roles")])

        # The real file must still be caught -> non-zero exit.
        if rc == 1:
            passed += 1
            print("  PASS  FAIL  a vendored config beside node_modules is STILL scanned")
        else:
            failed += 1
            failures.append(
                "  FAIL  the skip is too broad: a real vendored secret was not reported"
            )

        # And with ONLY the skipped directories present, the scan must come back clean.
        real.unlink()
        rc_clean = scan_main(["check_vendored_secrets", str(Path(tmp) / "roles")])
        if rc_clean == 0:
            passed += 1
            print("  PASS  ok    node_modules/ and dist/ are NOT scanned")
        else:
            failed += 1
            failures.append("  FAIL  a dependency tree was scanned; the skip did not fire")

        # A file EXPLICITLY NAMED inside a skipped directory is still scanned — the skip governs
        # the directory WALK, not whether a file can ever be checked.
        named = root / "app" / "node_modules" / "pkg" / "lang.json"
        if check(named):
            passed += 1
            print("  PASS  FAIL  an explicitly named file inside node_modules is scanned")
        else:
            failed += 1
            failures.append("  FAIL  check() ignored a file it was pointed at directly")

    return passed, failed, failures


def main() -> int:
    passed = failed = 0
    failures: list[str] = []

    key_passed, key_failed, key_failures = _key_cases()
    passed += key_passed
    failed += key_failed
    failures.extend(key_failures)
    print(f"  key classification: {key_passed}/{key_passed + key_failed} cases")

    for expected, suffix, content, label in FILE_CASES:
        with tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False) as fh:
            fh.write(content)
            path = Path(fh.name)
        try:
            got = FAIL if check(path) else OK
        finally:
            path.unlink(missing_ok=True)

        if got == expected:
            passed += 1
            print(f"  PASS  {expected:<4}  {label}")
        else:
            failed += 1
            failures.append(f"  FAIL  want {expected}, got {got}  {label}")

    # ---- directory skips: the walk must not drown in dependency trees -------------------
    #
    # BOTH DIRECTIONS, because a skip that is too broad is as bad as no skip. A vendored web
    # app's node_modules produces a hundred FAILs, every one a false positive from TypeScript's
    # localised diagnostic catalogues — a checker reporting a
    # hundred unactionable findings is one people learn to ignore, which is how a REAL vendored
    # secret gets scrolled past.
    skip_passed, skip_failed, skip_failures = _skip_cases()
    passed += skip_passed
    failed += skip_failed
    failures.extend(skip_failures)
    print(f"  directory skips: {skip_passed}/{skip_passed + skip_failed} cases")

    # An unreadable path must return no findings rather than raising — the hook runs over a whole
    # tree and one bad entry must not take the scan down with it.
    try:
        check(Path("/nonexistent/vendored/file.json"))
        passed += 1
        print("  PASS  ok    nonexistent path does not crash the scan")
    except Exception as exc:  # noqa: BLE001
        failed += 1
        failures.append(f"  FAIL  nonexistent path raised {exc!r}")

    for line in failures:
        print(line)

    total = passed + failed
    print(f"\n{total - failed}/{total} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
