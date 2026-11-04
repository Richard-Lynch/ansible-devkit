#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for the disclosure gate (ansible_devkit/disclose/disclose.py).

Run:  uv run tests/suites/test_disclose.py   (exit 0 = all pass)

Every case builds a synthetic export repo in a temp dir, so nothing here reads any estate. The
scanners are FAKED on PATH by default (CI has neither installed), which tests the gate's own
wiring: a fake that reports a leak must fail the gate, a fake that errors must fail it CLOSED, and
an absent trufflehog must fail it unless --allow-missing names it. When the real gitleaks is
installed, one extra case proves the real binary is wired correctly too.

Every rule has a planted value that must FAIL and a near-miss that must PASS: the generic rules
(private addresses, MACs, emails, SteamID64s, op:// references) with no input at all, the local
literals and regexes from a --local file, the known secret values, the scope of --since, the
allow-list, and the tarball.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

from _paths import DISCLOSE  # tests/suites/_paths.py

SECRET = "s3cr3t-VALUE-0123456789abcdefXYZ"  # the synthetic "cached credential"
HOST = "zebrahost"
VAULT = "Synthetic-Estate-Vault"
DOMAIN = "estate-synthetic.net"
# Fixture values that the GENERIC rules must flag, and their near-misses. The private addresses
# and the owner-like email are ASSEMBLED at run time, so this file does not itself trip the rules
# it tests when the gate scans the devkit repository.
PRIV_A, PRIV_B, PRIV_C = (
    ".".join(["10", *rest]) for rest in (["70", "0", "12"], ["1", "2", "3"], ["0", "0", "1"])
)
PRIV_172, PRIV_192, SHARED_100 = (
    ".".join(parts)
    for parts in (["172", "16", "5", "9"], ["192", "168", "7", "8"], ["100", "64", "3", "4"])
)
NEAR_172, NEAR_100 = "172.32.0.1", "100.128.0.1"
# Assembled at run time, like the addresses: the suite's own file must carry no planted value, so
# the repository needs no exemption for it (and no generic `mac` exemption exists anywhere).
MAC_DEVICE = ":".join(["4c", "eb", "42", "1f", "9a", "07"])
MAC_DEVICE_DASH = "-".join(["4c", "eb", "42", "1f", "9a", "08"])
MAC_LOCAL, MAC_BCAST, MAC_ZERO = (
    "02:00:5e:00:00:01",
    "ff:ff:ff:ff:ff:ff",
    "00:00:00:00:00:00",
)
EMAIL_REAL = "@".join(["someone", "estate-synthetic" + ".net"])
EMAIL_NOREPLY = "12345+someone@users.noreply.github.com"
STEAM_BASE = 76561197960265728
STEAM_REAL = str(STEAM_BASE + 4000000)
STEAM_FIXTURE = str(STEAM_BASE + 1)
OP_REF = "op:" + "//Synthetic-Vault/some-item/password"

LOCAL = (
    f"host {HOST}\nvault {VAULT}\ndomain {DOMAIN}\nregex item-prefix \\bvaultpath/[a-z]+/[a-z-]+\n"
)

FAKE_OK = "#!/bin/sh\nexit 0\n"
# A fake gitleaks that reports one leak in its JSON report and exits 1, as the real one does.
FAKE_GITLEAKS_LEAK = """#!/bin/sh
while [ $# -gt 0 ]; do
  if [ "$1" = "--report-path" ]; then shift; echo '[{"RuleID":"fake-rule","File":"a.py","StartLine":3,"Commit":"abc","Secret":"REDACTED"}]' > "$1"; fi
  shift
done
exit 1
"""
FAKE_ERROR = "#!/bin/sh\nexit 7\n"

results: list[tuple[bool, str]] = []


def check(cond: bool, label: str) -> None:
    results.append((cond, label))
    print(f"  {'PASS' if cond else 'FAIL'}  {label}")


class Env:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.bin = root / "bin"
        self.bin.mkdir()
        # git must stay resolvable even though the real scanners' directory is left off PATH.
        os.symlink(shutil.which("git"), self.bin / "git")
        self.local = root / "local.txt"
        self.local.write_text(LOCAL)
        self.cache = root / "cache.json"
        self.cache.write_text(
            json.dumps({"Vault:svc/item:password:": SECRET, "Vault:x:short:": "tiny"})
        )

    def fake(self, name: str, body: str | None) -> None:
        p = self.bin / name
        if p.exists():
            p.unlink()
        if body is not None:
            p.write_text(body)
            p.chmod(p.stat().st_mode | stat.S_IXUSR)

    def repo(self, files: dict[str, str], *, history: list[dict] | None = None,
             message: str = "initial", email: str = "dev@example.com") -> tuple[Path, str]:  # fmt: skip
        r = Path(tempfile.mkdtemp(dir=self.root))
        env = {**os.environ, "GIT_AUTHOR_NAME": "Dev", "GIT_COMMITTER_NAME": "Dev",
               "GIT_AUTHOR_EMAIL": email, "GIT_COMMITTER_EMAIL": email}  # fmt: skip

        def g(*a: str) -> str:
            return subprocess.run(
                ["git", "-C", str(r), *a],
                check=True,
                capture_output=True,
                text=True,
                env=env,
            ).stdout

        g("init", "-q", "-b", "main")
        for earlier in history or []:
            for path, text in earlier.items():
                (r / path).parent.mkdir(parents=True, exist_ok=True)
                (r / path).write_text(text)
            g("add", "-A")
            g("commit", "-q", "-m", "earlier")
            for path in earlier:
                if path not in files:
                    g("rm", "-q", path)
        for path, text in files.items():
            (r / path).parent.mkdir(parents=True, exist_ok=True)
            (r / path).write_text(text)
        g("add", "-A")
        g("commit", "-q", "-m", message)
        return r, g("rev-parse", "HEAD").strip()

    def run(self, repo: Path, sha: str, *extra: str, allow_missing: tuple[str, ...] = (),
            local: bool = False) -> tuple[int, dict, str]:  # fmt: skip
        out = self.root / "report.json"
        cmd = [sys.executable, str(DISCLOSE), "--repo", str(repo), "--sha", sha,
               "--secrets-cache", str(self.cache), "--report", str(out), *extra]  # fmt: skip
        if local:
            cmd += ["--local", str(self.local)]
        for t in allow_missing:
            cmd += ["--allow-missing", t]
        env = {**os.environ, "PATH": str(self.bin)}
        p = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=120)
        raw = out.read_text() if out.exists() else "{}"
        if out.exists():
            out.unlink()
        return p.returncode, json.loads(raw), raw + p.stdout + p.stderr


CLEAN = {
    "README.md": "A tool. Docs at https://example.com and host build.test.\nExample IP 192.0.2.10.\n",
    "src/tool.py": "print('hello')\n",
}


def rules(rep: dict) -> set[str]:
    return {f["rule"] for f in rep.get("findings", [])}


def parent(r: Path, rev: str) -> str:
    return subprocess.run(["git", "-C", str(r), "rev-parse", rev], check=True,
                          capture_output=True, text=True).stdout.strip()  # fmt: skip


def generic_cases(e: Env) -> None:
    """The rules that need NO input: what public CI runs."""
    r, sha = e.repo(CLEAN)
    rc, rep, _ = e.run(r, sha)
    check(
        rc == 0 and rep["result"] == "pass",
        f"clean synthetic repo exits 0 with no local file (rc={rc}, {rep.get('errors')})",
    )
    check(
        set(rep["steps"]) >= {"secrets", "literals+known", "scope"}
        and rep["steps"]["scope"]["local_patterns"] == 0,
        "every step is recorded, and the scope says no local patterns were used",
    )

    for label, text, rule in (
        ("a 10.x address", f"ADDR = '{PRIV_A}'\n", "rfc1918-10"),
        ("a 172.16/12 address", f"ADDR = '{PRIV_172}'\n", "rfc1918-172"),
        ("a 192.168/16 address", f"ADDR = '{PRIV_192}'\n", "rfc1918-192"),
        ("a 100.64/10 address", f"ADDR = '{SHARED_100}'\n", "rfc6598-100"),
        ("a device MAC", f"hw = '{MAC_DEVICE}'\n", "mac"),
        ("a device MAC in dash form", f"hw = '{MAC_DEVICE_DASH}'\n", "mac"),
        ("an email outside the example names", f"contact: {EMAIL_REAL}\n", "email"),
        ("a SteamID64", f"steamid: {STEAM_REAL}\n", "steamid64"),
        ("an op:// reference", f"ref = '{OP_REF}'\n", "op-ref"),
    ):
        r, sha = e.repo({**CLEAN, "src/net.py": text})
        rc, rep, raw = e.run(r, sha)
        check(rc == 1 and rule in rules(rep), f"generic: {label} fails the gate ({rule})")
        planted = text.split("'")[1] if "'" in text else text.split(": ")[1].strip()
        check(planted not in raw, f"generic: the matched {label} is NOT in the report")
    f = next(x for x in rep["findings"] if x["rule"] == "op-ref")
    check(
        f["location"] == "src/net.py" and f["line"] == 1,
        "a finding names the file and line",
    )

    r, sha = e.repo(
        {
            **CLEAN,
            "src/v.py": (
                f"V = '1{PRIV_A}'\nW = '1.{PRIV_C}'\nX = '{NEAR_172}'\nY = '{NEAR_100}'\n"
                f"Z = '198.51.100.7'\n"
                f"L = '{MAC_LOCAL}'\nB = '{MAC_BCAST}'\nN = '{MAC_ZERO}'\n"
                f"U = '123e4567-e89b-12d3-a456-426614174000'\n"
                f"E1 = 'dev@example.com'\nE2 = 'ops@example.org'\nE3 = 'a@b.test'\n"
                f"E4 = '{EMAIL_NOREPLY}'\nE5 = 'noreply@github.com'\nE6 = 'root@localhost'\n"
                f"E7 = 'noreply@some-vendor.net'\nE8 = 'git@some-forge.net:org/repo.git'\n"
                f"E9 = 'mnt-data@100.service'\nE10 = 'x@iqn.2005-10.org.vendor.ctl:lun.mount'\n"
                f"S1 = '{STEAM_FIXTURE}'\nS2 = '12345678901234567'\n"
                f"O = 'op://<vault>/<item>/<field>'\nP = 'op read op://... is wrong'\n"
            ),
        }
    )
    rc, rep, _ = e.run(r, sha)
    check(
        rc == 0,
        "near-misses pass: 110.x, a dotted version, 172.32, 100.128, an RFC 5737 address, a "
        "locally-administered / broadcast / zero MAC, a UUID, example and noreply emails, a "
        f"fixture SteamID64, a 17-digit non-Steam number, an op:// placeholder ({sorted(rules(rep))})",
    )

    r, sha = e.repo(CLEAN, email=EMAIL_REAL)
    rc, rep, raw = e.run(r, sha)
    check(
        rc == 1 and "email" in rules(rep)
        and any(x["location"].endswith(":author-email") for x in rep["findings"]),
        "an email outside the example names as COMMIT AUTHOR fails the gate",
    )  # fmt: skip
    check(EMAIL_REAL not in raw, "the author email is NOT in the report")
    r, sha = e.repo(CLEAN, email=EMAIL_NOREPLY)
    rc, rep, _ = e.run(r, sha)
    check(rc == 0, "near-miss: the GitHub noreply address as commit author passes")


def local_cases(e: Env) -> None:
    """The publisher's own literals and regexes, from --local."""
    r, sha = e.repo(CLEAN)
    rc, rep, _ = e.run(r, sha, local=True)
    check(
        rc == 0 and rep["steps"]["scope"]["local_patterns"] == 4,
        f"clean repo passes with a local file, and the scope counts its entries (rc={rc})",
    )

    r, sha = e.repo(CLEAN, message=f"deploy to {HOST} tonight")
    rc, rep, _ = e.run(r, sha, local=True)
    check(
        rc == 1 and f"host:{HOST}" in rules(rep),
        "local: a hostname in a COMMIT MESSAGE fails, and the rule names the literal",
    )
    rc, rep, _ = e.run(r, sha)
    check(rc == 0, "near-miss: without the local file the same hostname is not a finding")

    r, sha = e.repo(CLEAN, history=[{"src/tool.py": f"VAULT = '{VAULT}'\n"}])
    rc, rep, _ = e.run(r, sha, local=True)
    check(
        rc == 1 and f"vault:{VAULT}" in rules(rep),
        "local: a vault name present only in an EARLIER commit fails (full history by default)",
    )

    r, sha = e.repo({**CLEAN, "src/sub.py": f"URL = 'https://metrics.{DOMAIN}/x'\n"})
    rc, rep, _ = e.run(r, sha, local=True)
    check(
        rc == 1 and f"domain:{DOMAIN}" in rules(rep),
        "local: a subdomain of a domain fails",
    )

    r, sha = e.repo({**CLEAN, "src/op.py": "ITEM = 'vaultpath/zebra/demo-token'\n"})
    rc, rep, _ = e.run(r, sha, local=True)
    check(
        rc == 1 and "item-prefix" in rules(rep),
        "local: a regex line fails on its match",
    )

    r, sha = e.repo({**CLEAN, "src/v.py": f"# {HOST}s and pre{HOST} and {HOST}9\n"})
    rc, rep, _ = e.run(r, sha, local=True)
    check(
        rc == 0,
        f"near-miss: a literal inside a longer word passes ({sorted(rules(rep))})",
    )
    r, sha = e.repo({**CLEAN, "src/v.py": f"role_{HOST}_x = 1\n"})
    rc, rep, _ = e.run(r, sha, local=True)
    check(rc == 1, "a literal bounded by underscores (a role or option name) IS a finding")

    r, sha = e.repo({**CLEAN, "conf/app.env": f"TOKEN={SECRET}\n"})
    rc, rep, raw = e.run(r, sha)
    check(
        rc == 1 and any(x.startswith("known-secret:svc/item") for x in rules(rep)),
        "a cached secret value fails the gate",
    )
    check(
        SECRET not in raw,
        "the secret value appears NOWHERE in the report or the output",
    )

    # a local file that cannot do its job is an error, never a thinner scan
    r, sha = e.repo(CLEAN)
    bad = e.root / "bad-local.txt"
    for label, text in (
        ("an EMPTY local file", "# nothing\n"),
        ("a literal with no value", "host\n"),
        ("a regex with no pattern", "regex name\n"),
        ("an invalid regex", "regex name [unclosed\n"),
        ("a regex named like a generic rule", "regex mac x\n"),
        ("a two-character literal", "host ab\n"),
    ):
        bad.write_text(text)
        rc, rep, _ = e.run(r, sha, "--local", str(bad))
        check(rc == 2, f"{label} is exit 2, not a pass")


def since_cases(e: Env) -> None:
    """--since: only what the push adds is scanned."""
    r, sha = e.repo(
        {**CLEAN, "src/new.py": "x = 1\n"},
        history=[{"src/old.py": f"A = '{PRIV_A}'\n"}],
    )
    rc, rep, _ = e.run(r, sha)
    check(
        rc == 1 and "rfc1918-10" in rules(rep),
        "without --since an address in history fails",
    )
    rc, rep, _ = e.run(r, sha, "--since", parent(r, "HEAD~1"))
    check(
        rc == 0 and rep["steps"]["scope"]["since"] == parent(r, "HEAD~1"),
        f"--since: the same address, already public, is not rescanned (rc={rc})",
    )
    r, sha = e.repo({**CLEAN, "src/new.py": f"A = '{PRIV_A}'\n"}, history=[{"src/old.py": "x\n"}])
    rc, rep, _ = e.run(r, sha, "--since", parent(r, "HEAD~1"))
    check(
        rc == 1 and "rfc1918-10" in rules(rep),
        "--since: an address in a NEW blob fails",
    )
    r, sha = e.repo(CLEAN, history=[{"src/old.py": "x\n"}], message=f"to {HOST}")
    rc, rep, _ = e.run(r, sha, "--since", parent(r, "HEAD~1"), local=True)
    check(
        rc == 1 and f"host:{HOST}" in rules(rep),
        "--since: the NEW commit's message is scanned",
    )
    r, sha = e.repo(CLEAN, history=[{"src/old.py": "x\n"}])
    check(
        e.run(r, sha, "--since", sha)[0] == 2,
        "--since the scanned commit itself is exit 2",
    )
    check(e.run(r, sha, "--since", sha[:12])[0] == 2, "--since a short id is exit 2")
    r2, sha2 = e.repo(CLEAN)
    check(
        e.run(r, sha, "--since", sha2)[0] == 2,
        "--since a commit not in the repo is exit 2",
    )
    subprocess.run(["git", "-C", str(r), "fetch", "-q", str(r2), "main"], check=True)
    check(e.run(r, sha, "--since", sha2)[0] == 2, "--since a non-ancestor is exit 2")


def allow_cases(e: Env) -> None:
    r, sha = e.repo({**CLEAN, "src/net.py": f"ADDR = '{PRIV_A}'\n"})
    allow = e.root / "allow.txt"
    allow.write_text("rfc1918-10 src/net.py documented lab default address\n")
    rc, rep, _ = e.run(r, sha, "--allow", str(allow))
    check(
        rc == 0 and rep["allowed"][0]["matched"] == 1,
        "an allow-list line with a reason suppresses, and is counted",
    )
    for label, text in (
        ("WITHOUT a reason", "rfc1918-10 src/net.py\n"),
        ("with a two-word reason", "rfc1918-10 src/net.py too short\n"),
        ("with location `*`", "rfc1918-10 * documented lab default address\n"),
        ("with location `**`", "rfc1918-10 ** documented lab default address\n"),
        (
            "with location `tarball:*`",
            "rfc1918-10 tarball:* documented lab default address\n",
        ),
    ):
        allow.write_text(text)
        rc, rep, _ = e.run(r, sha, "--allow", str(allow))
        check(rc == 2, f"an allow-list line {label} is a gate error (exit 2)")

    # several --allow files: every file applies, and each rule is reported with its file
    r, sha = e.repo({**CLEAN, "src/net.py": f"ADDR = '{PRIV_A}'\n", "README.md": f"See {HOST}.\n"})
    one, two = e.root / "allow-global.txt", e.root / "allow-repo.txt"
    one.write_text("rfc1918-10 src/net.py documented lab default address\n")
    two.write_text(f"host:{HOST} README.md the product this repo manages\n")
    rc, rep, _ = e.run(r, sha, "--allow", str(one), "--allow", str(two), local=True)
    check(
        rc == 0 and sorted(a["file"] for a in rep["allowed"]) == sorted([str(one), str(two)]),
        "two --allow files BOTH apply, each rule reported with its file",
    )
    rc, rep, _ = e.run(r, sha, "--allow", str(one), local=True)
    check(
        rc == 1 and rules(rep) == {f"host:{HOST}"},
        "near-miss: with only the first --allow file, the second file's finding still fails",
    )
    rc, rep, _ = e.run(r, sha, "--allow", str(one), "--allow", str(two))
    check(
        rc == 0 and rep["allowed"][1]["matched"] == 0,
        "an allow line for a local literal matches nothing when no local file is given",
    )


def scanner_cases(e: Env) -> None:
    r, sha = e.repo(CLEAN)
    e.fake("gitleaks", FAKE_GITLEAKS_LEAK)
    rc, rep, raw = e.run(r, sha)
    check(
        rc == 1 and "gitleaks:fake-rule" in rules(rep),
        "a gitleaks finding fails the gate",
    )
    e.fake("gitleaks", FAKE_ERROR)
    rc, rep, _ = e.run(r, sha)
    check(rc == 2, "gitleaks ERRORING fails closed (exit 2), never a pass")
    e.fake("gitleaks", FAKE_OK)
    e.fake("trufflehog", None)
    rc, rep, _ = e.run(r, sha)
    check(
        rc == 2 and "trufflehog" in " ".join(rep["errors"]),
        "trufflehog NOT installed fails closed",
    )
    rc, rep, _ = e.run(r, sha, allow_missing=("trufflehog",))
    check(
        rc == 0 and any("trufflehog" in n for n in rep["notes"]),
        "--allow-missing trufflehog runs, and says so",
    )
    e.fake("trufflehog", FAKE_ERROR)
    rc, rep, _ = e.run(r, sha)
    check(rc == 2, "trufflehog ERRORING fails closed")
    e.fake("trufflehog", FAKE_OK)

    # inputs that would make the gate scan nothing
    rc, rep, _ = e.run(r, "deadbeef" * 5)
    check(rc == 2, "a SHA that is not in the repo is exit 2")
    p = subprocess.run([sys.executable, str(DISCLOSE), "--repo", str(r), "--sha", sha],
                       capture_output=True, text=True, env={**os.environ, "PATH": str(e.bin)})  # fmt: skip
    check(
        p.returncode == 2,
        "no secrets cache (and no --allow-missing secrets-cache) is exit 2",
    )
    p = subprocess.run([sys.executable, str(DISCLOSE), "--repo", str(r), "--sha", sha,
                        "--allow-missing", "secrets-cache"], capture_output=True, text=True,
                       env={**os.environ, "PATH": str(e.bin)})  # fmt: skip
    check(
        p.returncode == 0 and "known-value check explicitly skipped" in p.stdout,
        "--allow-missing secrets-cache runs the generic checks and records the skip",
    )

    real = shutil.which("gitleaks")
    if real:
        os.symlink(real, e.bin / "gitleaks.real")
        e.fake("gitleaks", None)
        os.rename(e.bin / "gitleaks.real", e.bin / "gitleaks")
        key = "ghp_" + "Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv1Wx2"
        r, sha = e.repo({**CLEAN, "docs/notes.md": f"token: {key}\n"})
        rc, rep, raw = e.run(r, sha)
        check(
            rc == 1 and any(x.startswith("gitleaks:") for x in rules(rep)),
            "REAL gitleaks: a token in docs/*.md fails (no docs exclusion)",
        )
        check(key not in raw, "REAL gitleaks: the token is not in the report")
        r, sha = e.repo({**CLEAN, "docs/notes.md": f"token: {key}\n"}, history=[{"a.txt": "x\n"}])
        rc, rep, _ = e.run(r, sha, "--since", parent(r, "HEAD~1"))
        check(
            rc == 1 and any(x.startswith("gitleaks:") for x in rules(rep)),
            "REAL gitleaks: a token in the commits since --since fails",
        )
        e.fake("gitleaks", FAKE_OK)
    else:
        print("  SKIP  real gitleaks not installed (its wiring is covered by the fakes above)")


def artifact_cases(e: Env) -> None:
    r, sha = e.repo(CLEAN)

    def tarball(members: dict[str, str]) -> Path:
        t = Path(tempfile.mkdtemp(dir=e.root)) / "coll.tar.gz"
        src = t.parent / "src"
        for name, text in members.items():
            (src / name).parent.mkdir(parents=True, exist_ok=True)
            (src / name).write_text(text)
        with tarfile.open(t, "w:gz") as tf:
            for name in members:
                tf.add(src / name, arcname=name)
        return t

    t = tarball({**CLEAN, "MANIFEST.json": "{}"})
    rc, rep, _ = e.run(r, sha, "--tarball", str(t))
    check(
        rc == 0 and len(rep["steps"]["artifact"].get("sha256", "")) == 64,
        "a clean tarball passes and its sha256 is recorded",
    )
    t = tarball({**CLEAN, "extra.txt": "x\n"})
    rc, rep, _ = e.run(r, sha, "--tarball", str(t))
    check(
        rc == 1 and "ARTIFACT-01 file not in the tree at SHA" in rules(rep),
        "a tarball member that is not in the tree at SHA fails",
    )
    t = tarball({**CLEAN, "README.md": f"see {PRIV_A}\n"})
    rc, rep, _ = e.run(r, sha, "--tarball", str(t))
    check(
        rc == 1 and any(f["location"] == "tarball:README.md" for f in rep["findings"]),
        "a private address inside the tarball fails, at a tarball: location",
    )
    t = tarball({**CLEAN, "README.md": f"see {HOST}\n"})
    rc, rep, _ = e.run(r, sha, "--tarball", str(t), local=True)
    check(
        rc == 1 and f"host:{HOST}" in rules(rep),
        "a local literal inside the tarball fails",
    )

    # ONE allow line covers the tree path and the same path in the tarball
    r, sha = e.repo({**CLEAN, "src/net.py": f"ADDR = '{PRIV_A}'\n"})
    t = tarball({**CLEAN, "src/net.py": f"ADDR = '{PRIV_A}'\n"})
    allow = e.root / "allow.txt"
    allow.write_text("rfc1918-10 src/net.py documented lab default address\n")
    rc, rep, _ = e.run(r, sha, "--tarball", str(t), "--allow", str(allow))
    check(
        rc == 0 and rep["allowed"][0]["matched"] == 2,
        f"one allow line exempts the tree path AND tarball:<path> (rc={rc}, {rep['allowed']})",
    )
    allow.write_text("rfc1918-10 src/other.py documented lab default address\n")
    rc, rep, _ = e.run(r, sha, "--tarball", str(t), "--allow", str(allow))
    locs = sorted(f["location"] for f in rep["findings"])
    check(
        rc == 1 and locs == ["src/net.py", "tarball:src/net.py"],
        f"near-miss: an allow line for another path leaves both locations failing ({locs})",
    )
    allow.write_text("rfc1918-10 tarball:src/net.py the built copy, explicitly\n")
    rc, rep, _ = e.run(r, sha, "--tarball", str(t), "--allow", str(allow))
    check(
        rc == 1 and sorted(f["location"] for f in rep["findings"]) == ["src/net.py"],
        "an explicit tarball: glob still works and covers only the tarball",
    )


def main() -> int:
    if not shutil.which("git"):
        print("FAIL: git is required")
        return 1
    with tempfile.TemporaryDirectory() as td:
        e = Env(Path(td))
        e.fake("gitleaks", FAKE_OK)
        e.fake("trufflehog", FAKE_OK)
        generic_cases(e)
        local_cases(e)
        since_cases(e)
        allow_cases(e)
        artifact_cases(e)
        scanner_cases(e)
    failed = [label for ok, label in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} passed")
    for label in failed:
        print(f"  FAILED: {label}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
