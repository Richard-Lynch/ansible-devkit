#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""disclose — prove one exact commit, and all of its history, is fit to push to a PUBLIC repo.

Generic half of the disclosure gate (M2_PLAN §3). It is destined for devkit as `devkit disclose`, so
it carries NO estate knowledge: everything that names an estate arrives in a PRIVATE pattern file
passed by path, which never lives in the repo being scanned.

STEPS (each is a separate entry in the JSON report; any finding in any step fails the gate)
  1. manifest   the tree at SHA must equal the export manifest exactly — no unlisted file, no listed
                file missing — and no path anywhere in the history may be unlisted either.
  2. secrets    gitleaks over the full history with the base config passed in (NOT the repo's own
                .gitleaks.toml, and with no docs/ exclusion), then trufflehog. Inline suppression
                comments (gitleaks:allow, trufflehog:ignore) are not honoured.
  3. literals   every pattern in the private file over every blob in `git rev-list --all --objects`,
                every commit and tag message, and every author/committer name and email.
  4. known      exact match of every known secret value (a credential cache plus a declared list,
                every string value of at least KNOWN_SECRET_MIN_LEN characters).
  5. artifact   when a built tarball is given: its members against the manifest, its sha256, and
                steps 2-4 again over the unpacked files.

WHAT IT NEVER DOES: print or record a matched value. A finding is {step, rule, location, line,
object}; a literal's rule is its opaque pattern id, a known secret's rule names the ITEM. A gate that
copies the leak into a report — which public CI prints — would be its own leak.

FAILS CLOSED. A missing scanner, an unreadable pattern file, a scanner that errors, a SHA no ref
reaches, an allow-list line with no reason: each is exit 2, never a pass. `--allow-missing <tool>`
is the one explicit, recorded way to run without a scanner.

Exit: 0 = every step ran and found nothing; 1 = findings; 2 = the gate could not be run properly.

Usage:
  disclose.py --repo PATH --sha SHA --patterns FILE [--manifest FILE] [--allow FILE]
              [--secrets-cache FILE] [--secrets-declared FILE] [--tarball FILE]
              [--gitleaks-config FILE] [--allow-missing TOOL]... [--report FILE]
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import ipaddress
import json
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_GITLEAKS_CONFIG = HERE / "gitleaks-base.toml"
SCANNERS = ("gitleaks", "trufflehog")
# Members `ansible-galaxy collection build` adds that no source manifest lists.
GALAXY_GENERATED = {"MANIFEST.json", "FILES.json"}
# A shorter "secret" would match everywhere, so values below this length are ignored.
KNOWN_SECRET_MIN_LEN = 16
EXEMPT_NETS = [
    ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
]
EXEMPT_DOMAIN = re.compile(r"(?i)(?:^|\.)(?:example\.com|[a-z0-9-]+\.test|test)$")


class GateError(Exception):
    """The gate could not run a step properly. Always exit 2 — never a pass."""


@dataclass
class Finding:
    step: str
    rule: str
    location: str
    line: int | None = None
    obj: str | None = None

    def as_dict(self) -> dict:
        d = {"step": self.step, "rule": self.rule, "location": self.location}
        if self.line is not None:
            d["line"] = self.line
        if self.obj:
            d["object"] = self.obj
        return d


@dataclass
class Report:
    repo: str
    sha: str
    steps: dict = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    allowed: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


# ------------------------------------------------------------------------------------------------
# git plumbing
# ------------------------------------------------------------------------------------------------
def git(repo: Path, *args: str, input_bytes: bytes | None = None) -> bytes:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        input=input_bytes,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        # git's stderr names refs and paths, never blob content, so it is safe to surface.
        raise GateError(f"git {args[0]} failed: {proc.stderr.decode(errors='replace').strip()}")
    return proc.stdout


def resolve_commit(repo: Path, sha: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{7,40}", sha):
        raise GateError(f"--sha must be a hex commit id, got {sha!r}")
    full = git(repo, "rev-parse", "--verify", "--quiet", f"{sha}^{{commit}}").decode().strip()
    if not full:
        raise GateError(f"{sha} is not a commit in {repo}")
    # The history scanners walk REFS. A SHA no ref reaches would have its own objects skipped by
    # them while this tool scanned it — two scopes, one of them silently narrower.
    refs = git(repo, "for-each-ref", "--contains", full, "--format=%(refname)").decode().split()
    if not refs:
        raise GateError(f"{full} is not reachable from any ref; point a branch at it first")
    return full


def all_objects(repo: Path, sha: str) -> list[tuple[str, str]]:
    """(blob, path) for every BLOB reachable from any ref or SHA.

    `rev-list --objects` also lists commits (no path) and trees (a directory path); those are
    dropped by asking `cat-file --batch-check` for each object's type, so a deleted directory is
    not mistaken for a deleted file.
    """
    out = git(repo, "rev-list", "--objects", "--all", sha).decode(errors="replace")
    pairs = [line.partition(" ")[::2] for line in out.splitlines() if line]
    if not pairs:
        return []
    types = git(
        repo,
        "cat-file",
        "--batch-check=%(objectname) %(objecttype)",
        input_bytes=("\n".join(o for o, _ in pairs) + "\n").encode(),
    ).decode()
    kind = dict(ln.split(" ", 1) for ln in types.splitlines() if " " in ln)
    return [(o, p) for o, p in pairs if p and kind.get(o) == "blob"]


def blob_contents(repo: Path, objs: list[str]) -> dict[str, bytes]:
    """Read blobs in one `cat-file --batch` pass; non-blobs are dropped."""
    if not objs:
        return {}
    proc = subprocess.run(
        ["git", "-C", str(repo), "cat-file", "--batch"],
        input=("\n".join(objs) + "\n").encode(),
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise GateError("git cat-file --batch failed")
    data, pos, res = proc.stdout, 0, {}
    while pos < len(data):
        nl = data.index(b"\n", pos)
        header = data[pos:nl].decode().split()
        pos = nl + 1
        if len(header) < 3:  # "<obj> missing"
            raise GateError(f"object {header[0] if header else '?'} is missing")
        obj, kind, size = header[0], header[1], int(header[2])
        body = data[pos : pos + size]
        pos += size + 1
        if kind == "blob":
            res[obj] = body
    return res


# ------------------------------------------------------------------------------------------------
# patterns, allow-list, known secrets
# ------------------------------------------------------------------------------------------------
@dataclass
class Patterns:
    literal_rx: re.Pattern | None
    literal_ids: dict[str, list[str]]  # lowercased literal -> pattern ids
    regexes: list[tuple[str, re.Pattern]]
    count: int


def load_patterns(path: Path) -> Patterns:
    try:
        doc = json.loads(path.read_text())
    except (OSError, ValueError) as e:
        raise GateError(f"cannot read pattern file {path}: {type(e).__name__}") from None
    entries = doc.get("patterns") if isinstance(doc, dict) else None
    if not isinstance(entries, list) or not entries:
        # An empty pattern file scans nothing while reporting clean.
        raise GateError(f"pattern file {path} has no patterns")
    lits: dict[str, list[str]] = {}
    regexes: list[tuple[str, re.Pattern]] = []
    for i, e in enumerate(entries):
        pid, kind = e.get("id"), e.get("kind")
        if not pid or kind not in ("literal", "regex"):
            raise GateError(f"pattern #{i} in {path} lacks an id or a valid kind")
        if kind == "literal":
            val = e.get("value")
            if not isinstance(val, str) or len(val) < 3:
                raise GateError(f"pattern {pid}: literal shorter than 3 characters")
            lits.setdefault(val.lower(), []).append(pid)
        else:
            try:
                regexes.append((pid, re.compile(e["regex"])))
            except (KeyError, re.error):
                raise GateError(f"pattern {pid}: invalid regex") from None
    literal_rx = None
    if lits:
        alts = "|".join(re.escape(v) for v in sorted(lits, key=len, reverse=True))
        # Bounded by non-alphanumerics, so a hostname matches `host.lan`, `host-01` is NOT `host`.
        literal_rx = re.compile(r"(?<![A-Za-z0-9])(?:" + alts + r")(?![A-Za-z0-9])", re.I)
    return Patterns(literal_rx, lits, regexes, len(entries))


@dataclass
class AllowRule:
    pattern: str
    path_glob: str
    reason: str
    used: int = 0


def load_allow(path: Path | None) -> list[AllowRule]:
    """`<pattern-id-glob> <location-glob> <reason ...>` per line. A reason is mandatory."""
    if path is None:
        return []
    rules = []
    try:
        text = path.read_text()
    except OSError as e:
        raise GateError(f"cannot read allow file {path}: {type(e).__name__}") from None
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 2)
        if len(parts) < 3 or len(parts[2].split()) < 3:
            raise GateError(f"{path}:{n}: an exemption needs a pattern, a location and a reason")
        rules.append(AllowRule(parts[0], parts[1], parts[2]))
    return rules


def load_known_secrets(cache: Path, declared: Path | None) -> dict[str, str]:
    """{item label: value}. Every string in the cache
    of at least KNOWN_SECRET_MIN_LEN characters, UNION the declared list. Labels never carry a value.
    """
    try:
        doc = json.loads(cache.read_text())
    except (OSError, ValueError) as e:
        raise GateError(f"cannot read secrets cache {cache}: {type(e).__name__}") from None
    vals: dict[str, str] = {}
    for key, v in doc.items():
        if isinstance(v, str) and len(v) >= KNOWN_SECRET_MIN_LEN:
            # key is vault:term:field:section — report the item (term) and field only.
            parts = key.split(":")
            label = "/".join(p for p in parts[1:3] if p) or "cache-entry"
            vals[f"{label}#{hashlib.sha256(key.encode()).hexdigest()[:8]}"] = v
    if declared is not None:
        for k, v in _read_declared(declared).items():
            if len(v) >= KNOWN_SECRET_MIN_LEN:
                vals[f"declared/{k}"] = v
    if not vals:
        raise GateError("the secrets cache yielded no values; an empty set matches nothing")
    return vals


def _read_declared(path: Path) -> dict[str, str]:
    """scrub_declared.yml: a single mapping of name -> value (PyYAML if present, else flat parse)."""
    text = path.read_text()
    try:
        import yaml  # type: ignore[import-untyped]

        doc = yaml.safe_load(text) or {}
        if isinstance(doc, dict) and len(doc) == 1 and isinstance(next(iter(doc.values())), dict):
            doc = next(iter(doc.values()))
        return {str(k): str(v) for k, v in (doc or {}).items() if isinstance(v, (str, int))}
    except ImportError:
        out = {}
        for line in text.splitlines():
            m = re.match(r"^\s+([A-Za-z0-9_.-]+):\s*['\"]?([^'\"#\s]+)['\"]?\s*$", line)
            if m:
                out[m.group(1)] = m.group(2)
        return out


# ------------------------------------------------------------------------------------------------
# scanning text
# ------------------------------------------------------------------------------------------------
def _exempt(text: str) -> bool:
    try:
        ip = ipaddress.ip_address(text.split("/")[0])
        return any(ip in n for n in EXEMPT_NETS)
    except ValueError:
        return bool(EXEMPT_DOMAIN.search(text))


def _line(data: str, pos: int) -> int:
    return data.count("\n", 0, pos) + 1


def scan_text(
    data: str,
    location: str,
    pats: Patterns,
    known: dict[str, str] | None,
    known_rx: re.Pattern | None,
    obj: str | None = None,
    step_prefix: str = "",
) -> list[Finding]:
    found: list[Finding] = []
    seen: set[tuple[str, int]] = set()

    def add(step: str, rule: str, pos: int) -> None:
        ln = _line(data, pos)
        if (rule, ln) not in seen:
            seen.add((rule, ln))
            found.append(Finding(step_prefix + step, rule, location, ln, obj))

    if pats.literal_rx is not None:
        for m in pats.literal_rx.finditer(data):
            for pid in pats.literal_ids.get(m.group(0).lower(), []):
                add("literals", pid, m.start())
    for pid, rx in pats.regexes:
        for m in rx.finditer(data):
            if not _exempt(m.group(0)):
                add("literals", pid, m.start())
    if known_rx is not None and known:
        by_value = {v: k for k, v in known.items()}
        for m in known_rx.finditer(data):
            add("known", "known-secret:" + by_value[m.group(0)], m.start())
    return found


def _known_rx(known: dict[str, str] | None) -> re.Pattern | None:
    if not known:
        return None
    return re.compile(
        "|".join(re.escape(v) for v in sorted(set(known.values()), key=len, reverse=True))
    )


# ------------------------------------------------------------------------------------------------
# steps
# ------------------------------------------------------------------------------------------------
def read_manifest(repo: Path, sha: str, manifest: Path | None) -> set[str]:
    if manifest is not None:
        try:
            text = manifest.read_text()
        except OSError as e:
            raise GateError(f"cannot read manifest {manifest}: {type(e).__name__}") from None
    else:
        proc = subprocess.run(
            ["git", "-C", str(repo), "show", f"{sha}:export.manifest"],
            capture_output=True,
            check=False,
        )
        if proc.returncode != 0:
            raise GateError("no --manifest given and export.manifest is not in the tree at SHA")
        text = proc.stdout.decode(errors="replace")
    paths = {
        ln.strip() for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")
    }
    if not paths:
        raise GateError("the export manifest lists no files")
    return paths


def step_manifest(
    repo: Path, sha: str, manifest: set[str], objects: list[tuple[str, str]]
) -> list[Finding]:
    tree = set(git(repo, "ls-tree", "-r", "--name-only", "-z", sha).decode().split("\0")) - {""}
    out = [Finding("manifest", "MANIFEST-01 unlisted file", p) for p in sorted(tree - manifest)]
    out += [
        Finding("manifest", "MANIFEST-02 listed file missing", p) for p in sorted(manifest - tree)
    ]
    # A path that existed only in an earlier commit is still published with the history.
    blob_paths = {p for _, p in objects}
    for p in sorted(blob_paths - manifest - tree):
        out.append(Finding("manifest", "MANIFEST-03 unlisted path in history", p))
    return out


def _tool(name: str, allow_missing: set[str], report: Report) -> str | None:
    exe = shutil.which(name)
    if exe:
        return exe
    if name in allow_missing:
        report.notes.append(f"{name} is not installed and was explicitly allowed to be missing")
        return None
    raise GateError(
        f"{name} is not installed. The gate fails closed; pass --allow-missing {name} to run "
        "without it, which is recorded in the report"
    )


def run_gitleaks(
    exe: str, target: Path, config: Path, history_sha: str | None, step: str
) -> list[Finding]:
    with tempfile.TemporaryDirectory() as td:
        rpt = Path(td) / "gitleaks.json"
        if history_sha:
            mode = ["git", str(target), f"--log-opts=--all {history_sha}"]
        else:
            mode = ["dir", str(target)]
        cmd = [
            exe, *mode, "--config", str(config), "--redact", "--exit-code", "1", "--no-banner",
            "--ignore-gitleaks-allow", "--report-format", "json", "--report-path", str(rpt),
            # The scanned repo's own .gitleaksignore would let it suppress its own findings, so
            # point the ignore path at an empty directory.
            "--gitleaks-ignore-path", td,
        ]  # fmt: skip
        proc = subprocess.run(cmd, capture_output=True, check=False)
        if proc.returncode not in (0, 1):
            raise GateError(f"gitleaks exited {proc.returncode} (an error, not a verdict)")
        try:
            items = json.loads(rpt.read_text() or "[]") if rpt.exists() else []
        except ValueError:
            raise GateError("gitleaks wrote an unparseable report") from None
        if proc.returncode == 1 and not items:
            raise GateError("gitleaks reported leaks but its report is empty")
    out = []
    for it in items:
        loc = it.get("File", "?")
        if not history_sha:
            loc = str(Path(loc).resolve().relative_to(target.resolve())) if loc != "?" else loc
        out.append(
            Finding(
                step,
                "gitleaks:" + it.get("RuleID", "?"),
                loc,
                it.get("StartLine"),
                it.get("Commit") or None,
            )
        )
    return out


def run_trufflehog(exe: str, target: Path, history: bool, step: str) -> list[Finding]:
    mode = ["git", "file://" + str(target.resolve())] if history else ["filesystem", str(target)]
    cmd = [
        exe,
        *mode,
        "--json",
        "--fail",
        "--no-update",
        "--no-verification",
        "--no-ignore-tag",
    ]
    proc = subprocess.run(cmd, capture_output=True, check=False)
    if proc.returncode not in (0, 183):
        raise GateError(f"trufflehog exited {proc.returncode} (an error, not a verdict)")
    out = []
    for raw in proc.stdout.decode(errors="replace").splitlines():
        try:
            r = json.loads(raw)
        except ValueError:
            continue
        if "DetectorName" not in r and "DetectorType" not in r:
            continue
        meta = (r.get("SourceMetadata") or {}).get("Data") or {}
        src = meta.get("Git") or meta.get("Filesystem") or {}
        loc = src.get("file", "?")
        if not history and loc != "?":
            try:
                loc = str(Path(loc).resolve().relative_to(target.resolve()))
            except ValueError:
                pass
        out.append(
            Finding(
                step,
                f"trufflehog:{r.get('DetectorName', r.get('DetectorType'))}",
                loc,
                src.get("line"),
                src.get("commit"),
            )
        )
    if proc.returncode == 183 and not out:
        raise GateError("trufflehog reported results but none could be parsed")
    return out


def step_history_text(repo: Path, sha: str, objects, pats, known, known_rx) -> list[Finding]:
    blobs = blob_contents(repo, sorted({o for o, p in objects if p}))
    paths: dict[str, str] = {}
    for o, p in objects:
        if p and o in blobs:
            paths.setdefault(o, p)
    out: list[Finding] = []
    for obj, body in blobs.items():
        out += scan_text(
            body.decode("utf-8", errors="replace"),
            paths[obj],
            pats,
            known,
            known_rx,
            obj,
        )
    # Commit messages and identities: a private repo's messages are full of topology, and an author email is
    # the most direct identifier there is.
    log = git(repo, "log", "--all", sha, "-z", "--format=%H%x1f%an%x1f%ae%x1f%cn%x1f%ce%x1f%B")
    for rec in log.decode(errors="replace").split("\0"):
        if not rec.strip():
            continue
        h, an, ae, cn, ce, body = (rec.split("\x1f", 5) + [""] * 6)[:6]
        h = h.strip()
        for label, text in (
            ("message", body), ("author-name", an), ("author-email", ae),
            ("committer-name", cn), ("committer-email", ce),
        ):  # fmt: skip
            out += scan_text(text, f"commit:{h[:12]}:{label}", pats, known, known_rx, h)
    tags = git(
        repo, "for-each-ref", "refs/tags", "--format=%(objecttype) %(refname:short)"
    ).decode()
    for line in tags.splitlines():
        kind, _, name = line.partition(" ")
        if kind == "tag":
            body = git(repo, "cat-file", "tag", f"refs/tags/{name}").decode(errors="replace")
            out += scan_text(body, f"tag:{name}", pats, known, known_rx)
    return out


def step_artifact(
    tarball: Path,
    manifest: set[str],
    pats,
    known,
    known_rx,
    gl_exe,
    th_exe,
    gl_cfg,
    report: Report,
) -> list[Finding]:
    digest = hashlib.sha256(tarball.read_bytes()).hexdigest()
    report.steps["artifact"]["sha256"] = digest
    out: list[Finding] = []
    with tempfile.TemporaryDirectory() as td, tarfile.open(tarball) as tf:
        members = [m for m in tf.getmembers() if m.isfile()]
        for m in tf.getmembers():
            if not (m.isfile() or m.isdir()):
                out.append(Finding("artifact", "ARTIFACT-02 non-regular member", m.name))
        for m in members:
            name = m.name.removeprefix("./")
            if name not in manifest and name not in GALAXY_GENERATED:
                out.append(Finding("artifact", "ARTIFACT-01 file not in manifest", name))
        dest = Path(td) / "unpacked"
        dest.mkdir()
        try:
            tf.extractall(dest, members=members, filter="data")
        except (tarfile.TarError, OSError) as e:
            raise GateError(f"cannot unpack {tarball.name}: {type(e).__name__}") from None
        for f in sorted(p for p in dest.rglob("*") if p.is_file()):
            rel = str(f.relative_to(dest))
            out += scan_text(
                f.read_text("utf-8", errors="replace"),
                f"tarball:{rel}",
                pats,
                known,
                known_rx,
                step_prefix="artifact-",
            )
        if gl_exe:
            out += run_gitleaks(gl_exe, dest, gl_cfg, None, "artifact-secrets")
        if th_exe:
            out += run_trufflehog(th_exe, dest, False, "artifact-secrets")
    return out


# ------------------------------------------------------------------------------------------------
def apply_allow(findings: list[Finding], rules: list[AllowRule], report: Report) -> list[Finding]:
    kept = []
    for f in findings:
        rule = next(
            (
                r
                for r in rules
                if fnmatch.fnmatchcase(f.rule, r.pattern)
                and fnmatch.fnmatchcase(f.location, r.path_glob)
            ),
            None,
        )
        if rule is None:
            kept.append(f)
        else:
            rule.used += 1
    for r in rules:
        report.allowed.append(
            {
                "pattern": r.pattern,
                "location": r.path_glob,
                "reason": r.reason,
                "matched": r.used,
            }
        )
    return kept


def run(args: argparse.Namespace) -> tuple[int, Report]:
    repo = Path(args.repo).resolve()
    report = Report(repo=str(repo), sha=args.sha)
    allow_missing = set(args.allow_missing or [])
    try:
        unknown = allow_missing - set(SCANNERS) - {"secrets-cache"}
        if unknown:
            raise GateError(
                f"--allow-missing accepts {SCANNERS + ('secrets-cache',)}, not {sorted(unknown)}"
            )
        sha = resolve_commit(repo, args.sha)
        report.sha = sha
        pats = load_patterns(Path(args.patterns))
        allow = load_allow(Path(args.allow) if args.allow else None)
        if args.secrets_cache:
            known = load_known_secrets(
                Path(args.secrets_cache),
                Path(args.secrets_declared) if args.secrets_declared else None,
            )
        elif "secrets-cache" in allow_missing:
            known = None
            report.notes.append("no secrets cache given; step 4 explicitly skipped")
        else:
            raise GateError("--secrets-cache is required (or --allow-missing secrets-cache)")
        known_rx = _known_rx(known)
        gl_cfg = Path(args.gitleaks_config) if args.gitleaks_config else DEFAULT_GITLEAKS_CONFIG
        if not gl_cfg.is_file():
            raise GateError(f"gitleaks config {gl_cfg} does not exist")
        gl_exe = _tool("gitleaks", allow_missing, report)
        th_exe = _tool("trufflehog", allow_missing, report)

        manifest = read_manifest(repo, sha, Path(args.manifest) if args.manifest else None)
        objects = all_objects(repo, sha)

        findings: list[Finding] = []

        def step(name: str, fn) -> None:
            report.steps[name] = {"status": "running"}
            got = fn()
            findings.extend(got)
            report.steps[name].update(status="fail" if got else "pass", findings=len(got))

        step("manifest", lambda: step_manifest(repo, sha, manifest, objects))
        step(
            "secrets",
            lambda: (
                (run_gitleaks(gl_exe, repo, gl_cfg, sha, "secrets") if gl_exe else [])
                + (run_trufflehog(th_exe, repo, True, "secrets") if th_exe else [])
            ),
        )
        step(
            "literals+known",
            lambda: step_history_text(repo, sha, objects, pats, known, known_rx),
        )
        if args.tarball:
            report.steps["artifact"] = {}
            step(
                "artifact",
                lambda: step_artifact(
                    Path(args.tarball),
                    manifest,
                    pats,
                    known,
                    known_rx,
                    gl_exe,
                    th_exe,
                    gl_cfg,
                    report,
                ),
            )
        report.steps.setdefault("scope", {}).update(
            objects=len(objects), patterns=pats.count, known_secrets=len(known or {}),
            missing_allowed=sorted(allow_missing),
        )  # fmt: skip
        report.findings = apply_allow(findings, allow, report)
    except GateError as e:
        report.errors.append(str(e))
        return 2, report
    return (1 if report.findings else 0), report


def render(report: Report, rc: int) -> dict:
    return {
        "tool": "disclose",
        "version": 1,
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "repo": report.repo,
        "sha": report.sha,
        "result": {0: "pass", 1: "fail", 2: "error"}[rc],
        "steps": report.steps,
        "findings": [f.as_dict() for f in report.findings],
        "allowed": report.allowed,
        "errors": report.errors,
        "notes": report.notes,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--repo", required=True)
    ap.add_argument("--sha", required=True)
    ap.add_argument("--patterns", required=True, help="PRIVATE pattern file (JSON)")
    ap.add_argument("--manifest", help="default: export.manifest in the tree at SHA")
    ap.add_argument("--allow", help="exemptions: <pattern-id> <location-glob> <reason>")
    ap.add_argument("--secrets-cache", help="credential cache JSON (values are never printed)")
    ap.add_argument("--secrets-declared", help="declared extra secret values (YAML mapping)")
    ap.add_argument("--tarball", help="a built collection tarball to check as well")
    ap.add_argument("--gitleaks-config", help=f"default: {DEFAULT_GITLEAKS_CONFIG.name}")
    ap.add_argument("--allow-missing", action="append", metavar="TOOL")
    ap.add_argument("--report", help="write the JSON report here (default: stdout)")
    args = ap.parse_args(argv)

    rc, report = run(args)
    doc = json.dumps(render(report, rc), indent=2, sort_keys=False) + "\n"
    if args.report:
        out = Path(args.report)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(doc)
    else:
        sys.stdout.write(doc)
    summary = (
        f"disclose: {render(report, rc)['result'].upper()} — {len(report.findings)} finding(s)"
    )
    if report.errors:
        summary += f"; ERROR: {report.errors[0]}"
    print(summary, file=sys.stderr)
    return rc


if __name__ == "__main__":
    sys.exit(main())
