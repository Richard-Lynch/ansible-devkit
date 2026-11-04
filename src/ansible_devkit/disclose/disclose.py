#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""disclose — prove one exact commit, and the history behind it, is fit to push to a PUBLIC repo.

The ONE scanner of a disclosure gate. It is generic by construction: it ships no value that names
any estate, so it can run in public CI with nothing but the repository in front of it, and the same
command runs in the private repository that publishes, with two private inputs added.

CHECKS (each finding is {step, rule, location, line, object}; any finding fails the gate)
  generic    always on, no input needed:
               rfc1918-10 / rfc1918-172 / rfc1918-192 / rfc6598-100   a private or shared IPv4
               mac        a universally-administered unicast MAC (a locally-administered, multicast
                          or all-zero one is a fixture or a protocol constant, never one device)
               email      an address outside the RFC 2606 names (example.*, .test, .invalid,
                          .example, .localhost); a noreply mailbox, the `git@` user of an SSH
                          URL, a systemd `unit@instance.service` name and an iSCSI `@iqn.`
                          instance are not addresses
               steamid64  a SteamID64 whose account id is 1000 or more (below that is a fixture)
               op-ref     an `op://` secret reference (it names a vault and an item)
  local      `--local FILE` (optional, PRIVATE, never in the scanned repository): the publisher's
             own literals and regexes, plain text, one per line:
               <category> <value>        a literal: bounded by non-alphanumerics, case-insensitive;
                                         its rule is `<category>:<value>`
               regex <name> <pattern>    a regex; its rule is `<name>`
  known      `--secrets-cache FILE` (+ `--secrets-declared FILE`): every known secret VALUE of at
             least KNOWN_SECRET_MIN_LEN characters, by exact match. The rule names the item, never
             the value. `--allow-missing secrets-cache` is the recorded way to run without it.
  secrets    gitleaks over the scanned history with the base config shipped here (never the
             repository's own .gitleaks.toml, no docs exclusion), then trufflehog. Inline
             suppression comments are not honoured.
  artifact   `--tarball FILE`: every member must be a path in the tree at SHA (plus the two files
             `ansible-galaxy collection build` adds), and every check above runs over the unpacked
             files too.

SCOPE  `--since COMMIT` (an ancestor of SHA that is already public — a pull request's base on the
       default branch, the remote's main): only the blobs, commit messages and identities that are
       NEW since it are scanned, which is what the push adds. Without it the whole history of SHA
       is scanned (a first push, or an audit).

WHAT IT PRINTS. A generic or known finding never carries the matched text: the rule id and the
location are all a public CI log gets. A LOCAL literal's rule IS the literal, so the report of a
run that used `--local` is as private as the local file — which is why the local file never reaches
public CI, and public CI prints nothing private.

FAILS CLOSED. A missing scanner, a scanner that errors, an unreadable local or allow file, a SHA
that is not a commit, an allow line with no reason or with a location of `*`: exit 2, never a pass.

EXEMPTIONS `--allow FILE` (repeatable): `<rule-glob> <location-glob> <reason of three words or more>`
per line. A location glob matches a tree path AND the same path inside the tarball, so one line
covers both. Every rule is reported with how many findings it suppressed.

Exit: 0 = every step ran and found nothing; 1 = findings; 2 = the gate could not be run properly.

Usage:
  disclose.py --repo PATH --sha SHA [--since COMMIT] [--local FILE] [--allow FILE]...
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
# Members `ansible-galaxy collection build` adds that no source tree holds.
GALAXY_GENERATED = {"MANIFEST.json", "FILES.json"}
# A shorter "secret" would match everywhere, so values below this length are ignored.
KNOWN_SECRET_MIN_LEN = 16
TARBALL_PREFIX = "tarball:"

# RFC 5737 documentation ranges: an example address is not a disclosure.
EXEMPT_NETS = [
    ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
]
# RFC 2606 / RFC 6761 reserved names, which documentation and fixtures use.
EXEMPT_DOMAIN = re.compile(
    r"(?i)(?:^|\.)(?:example\.(?:com|net|org)|[a-z0-9-]+\.(?:test|example|invalid|localhost)"
    r"|test|example|invalid|localhost)$"
)
# The identity GitHub writes for a web edit or a squash, and the per-user noreply address.
# Addresses that identify nobody: a noreply mailbox (GitHub's, an attribution trailer's), the
# per-user GitHub noreply address, and the `git@host:` user of an SSH clone URL.
EXEMPT_EMAIL = re.compile(r"(?i)^(?:no-?reply@|git@|[^@]+@users\.noreply\.github\.com$)")
# A systemd template instance (`unit@instance.service`) is not an address.
SYSTEMD_UNIT_TYPES = (
    "service", "socket", "target", "mount", "automount", "timer", "path", "slice", "swap", "device",
    "scope",
)  # fmt: skip

_B = r"(?<![0-9.])"
_E = r"(?![0-9]|\.[0-9])"
GENERIC_REGEXES: list[tuple[str, re.Pattern]] = [
    ("rfc1918-10", re.compile(_B + r"10(?:\.\d{1,3}){3}" + _E)),
    ("rfc1918-172", re.compile(_B + r"172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}" + _E)),
    ("rfc1918-192", re.compile(_B + r"192\.168(?:\.\d{1,3}){2}" + _E)),
    ("rfc6598-100", re.compile(_B + r"100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])(?:\.\d{1,3}){2}" + _E)),
    ("mac", re.compile(
        r"(?<![0-9A-Za-z:-])([0-9A-Fa-f]{2}(?:([:-])[0-9A-Fa-f]{2})(?:\2[0-9A-Fa-f]{2}){4})"
        r"(?![0-9A-Za-z:-])"
    )),
    ("email", re.compile(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}(?![A-Za-z0-9-])")),
    ("steamid64", re.compile(r"(?<![0-9])7656119\d{10}(?![0-9])")),
    # `op://...` and `op://<vault>/...` are placeholders; a reference starts with a vault name.
    ("op-ref", re.compile(r"op://[A-Za-z0-9][^\s'\"`<>]*")),
]  # fmt: skip
STEAM_BASE = 76561197960265728  # Valve's individual-account base: SteamID64 = base + account id
STEAM_MIN_ACCOUNT = 1000  # below this an account id is a fixture, never a profile


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
    return full


def resolve_since(repo: Path, sha: str, since: str) -> str:
    """The already-public commit: the full id of a strict ancestor of SHA."""
    if not re.fullmatch(r"[0-9a-f]{40}", since):
        raise GateError("--since must be the full 40-hex commit id")
    if not git(repo, "rev-parse", "--verify", "--quiet", f"{since}^{{commit}}").strip():
        raise GateError(f"--since {since} is not a commit in {repo}")
    if since == sha:
        raise GateError("--since is the scanned commit itself: nothing would be scanned")
    proc = subprocess.run(
        ["git", "-C", str(repo), "merge-base", "--is-ancestor", since, sha], check=False
    )
    if proc.returncode != 0:
        raise GateError(f"--since {since} is not an ancestor of {sha}")
    return since


def new_objects(repo: Path, sha: str, since: str | None) -> list[tuple[str, str]]:
    """(blob, path) for every BLOB reachable from SHA and, with `since`, not from `since`.

    `rev-list --objects` also lists commits (no path) and trees (a directory path); those are
    dropped by asking `cat-file --batch-check` for each object's type.
    """
    revs = [sha, f"^{since}"] if since else [sha]
    out = git(repo, "rev-list", "--objects", *revs).decode(errors="replace")
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
# local literals, allow-list, known secrets
# ------------------------------------------------------------------------------------------------
@dataclass
class Patterns:
    literal_rx: re.Pattern | None
    literal_rules: dict[str, list[str]]  # lowercased literal -> rule ids
    regexes: list[tuple[str, re.Pattern]]
    count: int


def load_local(path: Path | None) -> Patterns:
    """The publisher's private literals and regexes (see the module docstring for the format).
    An empty or unparseable file is an error: a gate told to use local knowledge and given none
    would scan less than it was asked to while reporting clean."""
    lits: dict[str, list[str]] = {}
    regexes: list[tuple[str, re.Pattern]] = []
    count = 0
    if path is None:
        return Patterns(None, lits, regexes, 0)
    try:
        text = path.read_text()
    except OSError as e:
        raise GateError(f"cannot read local file {path}: {type(e).__name__}") from None
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 2)
        if parts[0] == "regex":
            if len(parts) < 3:
                raise GateError(f"{path}:{n}: a regex line is `regex <name> <pattern>`")
            name, pat = parts[1], parts[2]
            if ":" in name or name in dict(GENERIC_REGEXES):
                raise GateError(f"{path}:{n}: regex name {name!r} collides with a rule id")
            try:
                regexes.append((name, re.compile(pat)))
            except re.error:
                raise GateError(f"{path}:{n}: invalid regex") from None
        else:
            if len(parts) < 2:
                raise GateError(f"{path}:{n}: a literal line is `<category> <value>`")
            cat, val = parts[0], line.split(None, 1)[1].strip()
            if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", cat) or cat == "regex":
                raise GateError(f"{path}:{n}: {cat!r} is not a category name")
            if len(val) < 3:
                raise GateError(f"{path}:{n}: literal shorter than 3 characters")
            lits.setdefault(val.lower(), []).append(f"{cat}:{val}")
        count += 1
    if not count:
        raise GateError(f"local file {path} holds no literals or regexes")
    literal_rx = None
    if lits:
        alts = "|".join(re.escape(v) for v in sorted(lits, key=len, reverse=True))
        # Bounded by non-alphanumerics, so a hostname matches `host.lan`, `host-01` is NOT `host`.
        literal_rx = re.compile(r"(?<![A-Za-z0-9])(?:" + alts + r")(?![A-Za-z0-9])", re.I)
    return Patterns(literal_rx, lits, regexes, count)


@dataclass
class AllowRule:
    pattern: str
    path_glob: str
    reason: str
    source: str = ""
    used: int = 0

    def matches(self, finding: Finding) -> bool:
        if not fnmatch.fnmatchcase(finding.rule, self.pattern):
            return False
        loc = finding.location
        if fnmatch.fnmatchcase(loc, self.path_glob):
            return True
        # One glob covers a tree path and the same path as built into the tarball.
        return loc.startswith(TARBALL_PREFIX) and fnmatch.fnmatchcase(
            loc[len(TARBALL_PREFIX) :], self.path_glob
        )


def load_allow(path: Path | None) -> list[AllowRule]:
    """`<rule-glob> <location-glob> <reason ...>` per line. A reason is mandatory, and a location
    of `*` or `**` is refused: a rule that must be exempt everywhere is not a disclosure rule."""
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
            raise GateError(f"{path}:{n}: an exemption needs a rule, a location and a reason")
        if parts[1].strip("*") == "" or parts[1] in ("tarball:*", "tarball:**"):
            raise GateError(f"{path}:{n}: a location of {parts[1]!r} exempts everywhere")
        rules.append(AllowRule(parts[0], parts[1], parts[2], source=str(path)))
    return rules


def load_known_secrets(cache: Path, declared: Path | None) -> dict[str, str]:
    """{item label: value}. Every string in the cache of at least KNOWN_SECRET_MIN_LEN characters,
    UNION the declared list. Labels never carry a value."""
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
    """A single mapping of name -> value (PyYAML if present, else a flat parse)."""
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
def _exempt(rule: str, text: str) -> bool:
    """A generic match that is a documented example or a fixture, never a disclosure."""
    if rule == "mac":
        octets = re.split(r"[:-]", text.lower())
        first = int(octets[0], 16)
        # bit 0: multicast/broadcast; bit 1: locally administered; all-zero: a placeholder.
        return bool(first & 0b11) or set(octets) == {"00"}
    if rule == "email":
        domain = text.rpartition("@")[2]
        return (
            bool(EXEMPT_EMAIL.match(text))
            or bool(EXEMPT_DOMAIN.search(domain))
            or domain.rpartition(".")[2].lower() in SYSTEMD_UNIT_TYPES
            # an iSCSI qualified name (iqn.yyyy-mm.reverse-domain:target) as a unit instance
            or domain.lower().startswith("iqn.")
        )
    if rule == "steamid64":
        return int(text) - STEAM_BASE < STEAM_MIN_ACCOUNT
    if rule == "op-ref":
        return False
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

    for rule, rx in GENERIC_REGEXES:
        for m in rx.finditer(data):
            if not _exempt(rule, m.group(0)):
                add("literals", rule, m.start())
    if pats.literal_rx is not None:
        for m in pats.literal_rx.finditer(data):
            for rule in pats.literal_rules.get(m.group(0).lower(), []):
                add("literals", rule, m.start())
    for rule, rx in pats.regexes:
        for m in rx.finditer(data):
            add("literals", rule, m.start())
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
    exe: str, target: Path, config: Path, log_opts: str | None, step: str
) -> list[Finding]:
    with tempfile.TemporaryDirectory() as td:
        rpt = Path(td) / "gitleaks.json"
        if log_opts:
            mode = ["git", str(target), f"--log-opts={log_opts}"]
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
        if not log_opts:
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


def run_trufflehog(
    exe: str, target: Path, step: str, sha: str | None = None, since: str | None = None
) -> list[Finding]:
    if sha:
        mode = ["git", "file://" + str(target.resolve()), "--branch", sha]
        if since:
            mode += ["--since-commit", since]
    else:
        mode = ["filesystem", str(target)]
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
        if not sha and loc != "?":
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


def step_history_text(
    repo: Path, sha: str, since: str | None, objects, pats, known, known_rx
) -> list[Finding]:
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
    # Commit messages and identities: a private repo's messages are full of topology, and an
    # author email is the most direct identifier there is.
    rng = f"{since}..{sha}" if since else sha
    log = git(repo, "log", rng, "-z", "--format=%H%x1f%an%x1f%ae%x1f%cn%x1f%ce%x1f%B")
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
    if since is None:
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
    tree: set[str],
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
            if name not in tree and name not in GALAXY_GENERATED:
                out.append(Finding("artifact", "ARTIFACT-01 file not in the tree at SHA", name))
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
                TARBALL_PREFIX + rel,
                pats,
                known,
                known_rx,
                step_prefix="artifact-",
            )
        if gl_exe:
            out += run_gitleaks(gl_exe, dest, gl_cfg, None, "artifact-secrets")
        if th_exe:
            out += run_trufflehog(th_exe, dest, "artifact-secrets")
    return out


# ------------------------------------------------------------------------------------------------
def apply_allow(findings: list[Finding], rules: list[AllowRule], report: Report) -> list[Finding]:
    kept = []
    for f in findings:
        rule = next((r for r in rules if r.matches(f)), None)
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
                "file": r.source,
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
        since = resolve_since(repo, sha, args.since) if args.since else None
        pats = load_local(Path(args.local) if args.local else None)
        allow = [rule for a in args.allow or [] for rule in load_allow(Path(a))]
        if args.secrets_cache:
            known = load_known_secrets(
                Path(args.secrets_cache),
                Path(args.secrets_declared) if args.secrets_declared else None,
            )
        elif "secrets-cache" in allow_missing:
            known = None
            report.notes.append("no secrets cache given; the known-value check explicitly skipped")
        else:
            raise GateError("--secrets-cache is required (or --allow-missing secrets-cache)")
        known_rx = _known_rx(known)
        gl_cfg = Path(args.gitleaks_config) if args.gitleaks_config else DEFAULT_GITLEAKS_CONFIG
        if not gl_cfg.is_file():
            raise GateError(f"gitleaks config {gl_cfg} does not exist")
        gl_exe = _tool("gitleaks", allow_missing, report)
        th_exe = _tool("trufflehog", allow_missing, report)
        if since:
            report.notes.append(f"--since {since}: only what is new since it is scanned")
        objects = new_objects(repo, sha, since)
        tree = set(git(repo, "ls-tree", "-r", "--name-only", "-z", sha).decode().split("\0"))
        tree.discard("")

        findings: list[Finding] = []

        def step(name: str, fn) -> None:
            report.steps[name] = {"status": "running"}
            got = fn()
            findings.extend(got)
            # The status is the step's RAW verdict; exemptions are applied to the whole set
            # below, and `findings` in the top level is what decides the exit code.
            report.steps[name].update(status="fail" if got else "pass", raw_findings=len(got))

        log_opts = f"{since}..{sha}" if since else sha
        step(
            "secrets",
            lambda: (
                (run_gitleaks(gl_exe, repo, gl_cfg, log_opts, "secrets") if gl_exe else [])
                + (run_trufflehog(th_exe, repo, "secrets", sha, since) if th_exe else [])
            ),
        )
        step(
            "literals+known",
            lambda: step_history_text(repo, sha, since, objects, pats, known, known_rx),
        )
        if args.tarball:
            report.steps["artifact"] = {}
            step(
                "artifact",
                lambda: step_artifact(
                    Path(args.tarball),
                    tree,
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
            since=since, objects=len(objects), generic_rules=len(GENERIC_REGEXES),
            local_patterns=pats.count, known_secrets=len(known or {}),
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
        "version": 2,
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
    ap.add_argument(
        "--since",
        metavar="COMMIT",
        help="an ancestor of SHA that is already public: scan only what is new since it "
        "(default: the whole history of SHA)",
    )
    ap.add_argument("--local", help="PRIVATE literals and regexes (plain text; see --help header)")
    ap.add_argument(
        "--allow",
        action="append",
        help="exemptions: <rule-glob> <location-glob> <reason>; repeatable, all files apply",
    )
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
