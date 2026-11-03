#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for the disclosure gate (ansible_devkit/disclose/disclose.py).

Run:  uv run tests/suites/test_disclose.py   (exit 0 = all pass)

Every case builds a synthetic export repo in a temp dir, so nothing here reads the estate. The
scanners are FAKED on PATH by default (CI has neither installed), which tests the gate's own
wiring: a fake that reports a leak must fail the gate, a fake that errors must fail it CLOSED, and
an absent trufflehog must fail it unless --allow-missing names it. When the real gitleaks is
installed, one extra case proves the real binary is wired correctly too.

The acceptance cases — an injected 10.x address, an estate hostname, a vault
name, a cached secret value and an unlisted file — each must exit non-zero; a clean repo exits 0.
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
OWNER_EMAIL = "owner@estate-synthetic.net"
# Private addresses are ASSEMBLED at run time, so this file (which goes to devkit) does not itself
# trip the RFC1918 rule it tests when the gate scans the devkit export.
PRIV_A, PRIV_B, PRIV_C = (
    ".".join(["10", *rest]) for rest in (["70", "0", "12"], ["1", "2", "3"], ["0", "0", "1"])
)

PATTERNS = {
    "version": 1,
    "patterns": [
        {"id": "host:aaaa", "kind": "literal", "value": HOST},
        {"id": "vault:bbbb", "kind": "literal", "value": VAULT},
        {"id": "domain:cccc", "kind": "literal", "value": DOMAIN},
        {"id": "owner:dddd", "kind": "literal", "value": OWNER_EMAIL},
        {"id": "rfc1918-10", "kind": "regex", "regex": r"(?<![0-9.])10(?:\.\d{1,3}){3}(?![0-9]|\.[0-9])"},
    ],
}  # fmt: skip

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
        self.patterns = root / "patterns.json"
        self.patterns.write_text(json.dumps(PATTERNS))
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

    def repo(self, files: dict[str, str], *, manifest: list[str] | None = None, history: list[dict] | None = None,
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
        listed = manifest if manifest is not None else sorted([*files, "export.manifest"])
        (r / "export.manifest").write_text("\n".join(listed) + "\n")
        g("add", "-A")
        g("commit", "-q", "-m", message)
        return r, g("rev-parse", "HEAD").strip()

    def run(
        self, repo: Path, sha: str, *extra: str, allow_missing: tuple[str, ...] = ()
    ) -> tuple[int, dict, str]:
        out = self.root / "report.json"
        cmd = [sys.executable, str(DISCLOSE), "--repo", str(repo), "--sha", sha, "--patterns", str(self.patterns),
               "--secrets-cache", str(self.cache), "--report", str(out), *extra]  # fmt: skip
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


def gate_cases(e: Env) -> None:
    e.fake("gitleaks", FAKE_OK)
    e.fake("trufflehog", FAKE_OK)

    r, sha = e.repo(CLEAN)
    rc, rep, _ = e.run(r, sha)
    check(
        rc == 0 and rep["result"] == "pass",
        f"clean synthetic repo exits 0 (rc={rc}, {rep.get('errors')})",
    )
    check(
        set(rep["steps"]) >= {"manifest", "secrets", "literals+known"},
        "every step is recorded in the report",
    )

    r, sha = e.repo({**CLEAN, "src/net.py": f"ADDR = '{PRIV_A}'\n"})
    rc, rep, _ = e.run(r, sha)
    check(
        rc == 1 and "rfc1918-10" in rules(rep),
        "an injected 10.x address fails the gate",
    )
    f = next(x for x in rep["findings"] if x["rule"] == "rfc1918-10")
    check(
        f["location"] == "src/net.py" and f["line"] == 1,
        "a finding names the file and line",
    )

    r, sha = e.repo(CLEAN, message=f"deploy to {HOST} tonight")
    rc, rep, _ = e.run(r, sha)
    check(
        rc == 1 and "host:aaaa" in rules(rep),
        "an estate hostname in a COMMIT MESSAGE fails the gate",
    )

    r, sha = e.repo(CLEAN, history=[{"src/tool.py": f"VAULT = '{VAULT}'\n"}])
    rc, rep, _ = e.run(r, sha)
    check(
        rc == 1 and "vault:bbbb" in rules(rep),
        "a vault name present only in an EARLIER commit fails the gate (full history)",
    )

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

    r, sha = e.repo(
        {**CLEAN, "notes.txt": "scratch\n"},
        manifest=sorted([*CLEAN, "export.manifest"]),
    )
    rc, rep, _ = e.run(r, sha)
    check(
        rc == 1 and "MANIFEST-01 unlisted file" in rules(rep),
        "an unlisted file fails the gate",
    )

    r, sha = e.repo(CLEAN, manifest=sorted([*CLEAN, "export.manifest", "gone.py"]))
    rc, rep, _ = e.run(r, sha)
    check(
        rc == 1 and "MANIFEST-02 listed file missing" in rules(rep),
        "a listed file that is missing fails the gate",
    )

    r, sha = e.repo(CLEAN, history=[{"old/leftover.cfg": "x = 1\n"}])
    rc, rep, _ = e.run(r, sha)
    check(
        rc == 1 and "MANIFEST-03 unlisted path in history" in rules(rep),
        "a path only in HISTORY must be listed too",
    )

    # --published: content already public at a path the new commit deletes is not unlisted history
    # (docs/standards/CHANGING_THE_RULES.md: the case it exempts, and each near-miss it must not).
    def parent(r: Path, rev: str) -> str:
        return subprocess.run(["git", "-C", str(r), "rev-parse", rev], check=True,
                              capture_output=True, text=True).stdout.strip()  # fmt: skip

    r, sha = e.repo(CLEAN, history=[{"old/leftover.cfg": "x = 1\n"}])
    rc, rep, out = e.run(r, sha, "--published", parent(r, "HEAD~1"))
    check(
        rc == 0,
        f"--published: a deleted path whose blob is already public PASSES (rc={rc})",
    )
    r, sha = e.repo(
        CLEAN, history=[{"old/leftover.cfg": "x = 1\n"}, {"old/leftover.cfg": "x = 2\n"}]
    )
    rc, rep, _ = e.run(r, sha, "--published", parent(r, "HEAD~2"))
    check(
        rc == 1 and "MANIFEST-03 unlisted path in history" in rules(rep),
        "--published: the same path with a NEW blob since the published commit FAILS",
    )
    r, sha = e.repo(CLEAN, history=[{"old/public.cfg": "p\n"}, {"new/branch_only.cfg": "b\n"}])
    rc, rep, _ = e.run(r, sha, "--published", parent(r, "HEAD~2"))
    locs = {f["location"] for f in rep.get("findings", []) if f["rule"].startswith("MANIFEST-03")}
    check(
        rc == 1 and locs == {"new/branch_only.cfg"},
        f"--published: a path added AND deleted after the published commit FAILS, the public one does not ({locs})",
    )
    r2, sha2 = e.repo(CLEAN)
    other = parent(r2, "HEAD")
    rc, rep, _ = e.run(r, sha, "--published", sha[:12])
    check(rc == 2, "--published: a short commit id is an error, not a pass")
    rc, rep, _ = e.run(r2, sha2, "--published", parent(r, "HEAD~2"))
    check(rc == 2, "--published: a commit that is not in the repo is an error, not a pass")
    subprocess.run(["git", "-C", str(r), "fetch", "-q", str(r2), "main"], check=True)
    rc, rep, _ = e.run(r, sha, "--published", other)
    check(rc == 2, "--published: a commit that is not an ANCESTOR of SHA is an error, not a pass")

    r, sha = e.repo(CLEAN, email=OWNER_EMAIL)
    rc, rep, _ = e.run(r, sha)
    check(
        rc == 1 and "owner:dddd" in rules(rep),
        "the owner's email as commit author fails the gate",
    )

    r, sha = e.repo({**CLEAN, "src/sub.py": f"URL = 'https://metrics.{DOMAIN}/x'\n"})
    rc, rep, raw = e.run(r, sha)
    check(
        rc == 1 and "domain:cccc" in rules(rep),
        "a subdomain of an estate domain fails the gate",
    )
    check(DOMAIN not in raw, "a matched LITERAL never appears in the report or the output")

    # near-misses: these must NOT fire
    r, sha = e.repo(
        {
            **CLEAN,
            "src/v.py": f"V = '1{PRIV_A}'  # {HOST}s and pre{HOST}\nW = '1.{PRIV_C}'\n",
        }
    )
    rc, rep, _ = e.run(r, sha)
    check(
        rc == 0,
        f"near-miss: 110.x, a dotted version and a hostname inside a longer word pass ({rules(rep)})",
    )

    # allow-list
    r, sha = e.repo({**CLEAN, "src/net.py": f"ADDR = '{PRIV_A}'\n"})
    allow = e.root / "allow.txt"
    allow.write_text("rfc1918-10 src/net.py documented lab default address\n")
    rc, rep, _ = e.run(r, sha, "--allow", str(allow))
    check(
        rc == 0 and rep["allowed"][0]["matched"] == 1,
        "an allow-list line with a reason suppresses, and is counted",
    )
    allow.write_text("rfc1918-10 src/net.py\n")
    rc, rep, _ = e.run(r, sha, "--allow", str(allow))
    check(rc == 2, "an allow-list line WITHOUT a reason is a gate error (exit 2)")

    # scanners
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
    empty = e.root / "empty.json"
    empty.write_text(json.dumps({"patterns": []}))
    p = subprocess.run([sys.executable, str(DISCLOSE), "--repo", str(r), "--sha", sha, "--patterns", str(empty),
                        "--secrets-cache", str(e.cache)], capture_output=True, text=True,
                       env={**os.environ, "PATH": str(e.bin)})  # fmt: skip
    check(p.returncode == 2, "an EMPTY pattern file is exit 2, not a clean scan")
    p = subprocess.run([sys.executable, str(DISCLOSE), "--repo", str(r), "--sha", sha, "--patterns", str(e.patterns)],
                       capture_output=True, text=True, env={**os.environ, "PATH": str(e.bin)})  # fmt: skip
    check(
        p.returncode == 2,
        "no secrets cache (and no --allow-missing secrets-cache) is exit 2",
    )

    # artifact (step 5)
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
        rc == 1 and "ARTIFACT-01 file not in manifest" in rules(rep),
        "a tarball member not in the manifest fails",
    )
    t = tarball({**CLEAN, "README.md": f"see {HOST}\n"})
    rc, rep, _ = e.run(r, sha, "--tarball", str(t))
    check(
        rc == 1 and any(f["location"] == "tarball:README.md" for f in rep["findings"]),
        "a literal inside the tarball fails",
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
    else:
        print("  SKIP  real gitleaks not installed (its wiring is covered by the fakes above)")


def main() -> int:
    if not shutil.which("git"):
        print("FAIL: git is required")
        return 1
    with tempfile.TemporaryDirectory() as td:
        gate_cases(Env(Path(td)))
    failed = [label for ok, label in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} passed")
    for label in failed:
        print(f"  FAILED: {label}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
