"""Read-only discovery layer.

Safety contract (enforced here, relied on everywhere else):
  * Never runs `npm install`, `pip install`, `docker build`, or any project script.
  * Every subprocess uses an argument list (shell=False), a timeout, and an
    environment with NPM_CONFIG_IGNORE_SCRIPTS=true.
  * Git is invoked with hooks, fsmonitor, external diff and textconv disabled, and
    never diffs the working tree (which would run repo-configured clean filters);
    historical content is read with `git show <ref>:<path>` and compared in Python.
  * Registry checks read JSON metadata only; tarballs are never downloaded or unpacked.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

import httpx

from models import (
    AdmissionResult,
    AdmissionSignal,
    AnomalyKind,
    Component,
    Evidence,
    EvidenceKind,
    Occurrence,
    Sbom,
    StaticAnomaly,
    Vulnerability,
)

PROJECT_ROOT = Path(__file__).resolve().parent
CACHE_ROOT = PROJECT_ROOT / ".scg_cache"
EMPTY_HOOKS_DIR = CACHE_ROOT / "empty-git-hooks"

LogFn = Callable[[str, str, str], None]   # (source, message, level)


def _noop_log(source: str, message: str, level: str = "info") -> None:
    return None


def offline_mode() -> bool:
    return os.environ.get("SCG_OFFLINE", "0") == "1"


# --------------------------------------------------------------------------- #
# Hardened process helpers
# --------------------------------------------------------------------------- #
_WIN_CMD_METACHARS = set('&|<>^%"!')


def validate_repo_path(path: str) -> Path:
    """Resolve and sanity-check a user-supplied repository path."""
    if not path or len(path) > 1024:
        raise ValueError("repository path is empty or too long")
    p = Path(path).expanduser().resolve()
    if not p.is_dir():
        raise ValueError(f"repository path does not exist or is not a directory: {p}")
    if sys.platform == "win32" and any(ch in _WIN_CMD_METACHARS for ch in str(p)):
        # .cmd shims (cdxgen.cmd, npm.cmd) are run through cmd.exe; refuse paths
        # that could be re-interpreted as cmd syntax.
        raise ValueError("repository path contains shell metacharacters")
    allowed = os.environ.get("SCG_ALLOWED_ROOTS")
    if allowed:
        roots = [Path(r).expanduser().resolve() for r in allowed.split(os.pathsep) if r.strip()]
        if not any(p == r or p.is_relative_to(r) for r in roots):
            raise ValueError(f"repository path is outside SCG_ALLOWED_ROOTS: {p}")
    return p


def _safe_env() -> Dict[str, str]:
    env = dict(os.environ)
    env.update({
        "NPM_CONFIG_IGNORE_SCRIPTS": "true",
        "npm_config_ignore_scripts": "true",
        "NPM_CONFIG_AUDIT": "false",
        "NPM_CONFIG_FUND": "false",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "CDXGEN_NO_INSTALL": "true",
    })
    return env


def safe_run(cmd: Sequence[str], cwd: Optional[Path] = None, timeout: int = 120) -> subprocess.CompletedProcess:
    exe = shutil.which(cmd[0])
    if exe is None:
        raise FileNotFoundError(cmd[0])
    return subprocess.run(
        [exe, *cmd[1:]], cwd=str(cwd) if cwd else None, env=_safe_env(),
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=timeout, shell=False, stdin=subprocess.DEVNULL,
    )


def git(repo: Path, *args: str, timeout: int = 60) -> subprocess.CompletedProcess:
    EMPTY_HOOKS_DIR.mkdir(parents=True, exist_ok=True)
    hardened = [
        "git",
        "-c", "core.fsmonitor=false",
        "-c", f"core.hooksPath={EMPTY_HOOKS_DIR.as_posix()}",
        "-c", "diff.external=",
        "-c", "core.pager=cat",
        "-c", "core.untrackedCache=false",
        "-C", str(repo),
    ]
    return safe_run([*hardened, *args], timeout=timeout)


def is_git_repo(repo: Path) -> bool:
    if not (repo / ".git").exists() or shutil.which("git") is None:
        return False
    try:
        return git(repo, "rev-parse", "--is-inside-work-tree").stdout.strip() == "true"
    except (subprocess.SubprocessError, OSError):
        return False


def git_show(repo: Path, ref: str, rel_path: str) -> Optional[str]:
    """Read a historical blob without touching the working tree."""
    if not re.fullmatch(r"[A-Za-z0-9_./~^@{}-]{1,200}", ref):
        raise ValueError(f"unsafe git ref: {ref!r}")
    try:
        res = git(repo, "show", "--no-textconv", f"{ref}:{rel_path}")
    except (subprocess.SubprocessError, OSError):
        return None
    return res.stdout if res.returncode == 0 else None


def repo_cache_dir(repo: Path) -> Path:
    key = hashlib.sha256(str(repo).lower().encode()).hexdigest()[:16]
    d = CACHE_ROOT / key
    d.mkdir(parents=True, exist_ok=True)
    return d


def read_text(path: Path, limit_bytes: int = 4_000_000) -> Optional[str]:
    try:
        if not path.is_file() or path.stat().st_size > limit_bytes:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def line_of(text: str, needle: str, start_line: int = 1) -> int:
    lines = text.splitlines()
    for i in range(max(start_line - 1, 0), len(lines)):
        if needle in lines[i]:
            return i + 1
    for i, ln in enumerate(lines):
        if needle in ln:
            return i + 1
    return 1


def npm_purl(name: str, version: str) -> str:
    if name.startswith("@"):
        scope, _, pkg = name.partition("/")
        return f"pkg:npm/{urllib.parse.quote(scope)}/{pkg}@{version}"
    return f"pkg:npm/{name}@{version}"


def pypi_purl(name: str, version: str) -> str:
    return f"pkg:pypi/{name.lower()}@{version}"


# --------------------------------------------------------------------------- #
# Source walking & import index
# --------------------------------------------------------------------------- #
SKIP_DIRS = {"node_modules", ".git", "build", "dist", "coverage", ".angular", "frontend",
             ".scg_cache", ".venv", "venv", "__pycache__", "vagrant", "screenshots"}
SOURCE_EXTS = {".ts", ".js", ".mjs", ".cjs", ".tsx", ".jsx"}


def iter_source_files(repo: Path, max_files: int = 5000) -> Iterable[Path]:
    count = 0
    for root, dirs, files in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        for f in files:
            if Path(f).suffix in SOURCE_EXTS and not f.endswith(".d.ts"):
                count += 1
                if count > max_files:
                    return
                yield Path(root) / f


@dataclass
class ImportSite:
    file: str                       # repo-relative posix path
    line: int
    text: str
    module: str                     # raw module specifier
    package: Optional[str]          # npm package name, None for relative imports
    default_name: Optional[str] = None
    namespace: Optional[str] = None
    named: Dict[str, str] = field(default_factory=dict)   # local -> imported

    @property
    def is_test(self) -> bool:
        return self.file.startswith(("test/", "tests/", "cypress/")) or ".spec." in self.file or ".test." in self.file


_IMPORT_FROM = re.compile(r"""^[ \t]*import\s+(?!type\s)(?P<clause>[^;'"]+?)\s+from\s+['"](?P<mod>[^'"]+)['"]""", re.M)
_IMPORT_BARE = re.compile(r"""^[ \t]*import\s+['"](?P<mod>[^'"]+)['"]""", re.M)
_REQUIRE = re.compile(r"""(?:const|let|var)\s+(?P<lhs>\{[^}]*\}|[A-Za-z_$][\w$]*)\s*=\s*require\(\s*['"](?P<mod>[^'"]+)['"]\s*\)""")


def package_of(module: str) -> Optional[str]:
    if module.startswith((".", "/")) or module.startswith("node:"):
        return None
    parts = module.split("/")
    return "/".join(parts[:2]) if module.startswith("@") else parts[0]


def _parse_named(body: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for part in body.strip("{} \n\t").split(","):
        part = part.strip()
        if not part or part.startswith("type "):
            continue
        m = re.match(r"([\w$]+)\s*(?:as|:)\s*([\w$]+)", part)
        if m:
            out[m.group(2)] = m.group(1)
        elif re.fullmatch(r"[\w$]+", part):
            out[part] = part
    return out


def build_import_index(repo: Path) -> List[ImportSite]:
    sites: List[ImportSite] = []
    for path in iter_source_files(repo):
        text = read_text(path, 1_000_000)
        if text is None:
            continue
        rel = path.relative_to(repo).as_posix()
        line_starts = [0]
        for m in re.finditer("\n", text):
            line_starts.append(m.end())

        def lineno(offset: int) -> int:
            lo, hi = 0, len(line_starts) - 1
            while lo < hi:
                mid = (lo + hi + 1) // 2
                if line_starts[mid] <= offset:
                    lo = mid
                else:
                    hi = mid - 1
            return lo + 1

        lines = text.splitlines()
        for m in _IMPORT_FROM.finditer(text):
            clause, mod = m.group("clause").strip(), m.group("mod")
            site = ImportSite(rel, lineno(m.start("clause")), "", mod, package_of(mod))
            ns = re.search(r"\*\s+as\s+([\w$]+)", clause)
            if ns:
                site.namespace = ns.group(1)
            braces = re.search(r"\{[^}]*\}", clause)
            if braces:
                site.named = _parse_named(braces.group(0))
            default = re.match(r"([\w$]+)\s*(?:,|$)", clause)
            if default and not clause.startswith(("{", "*")):
                site.default_name = default.group(1)
            site.text = lines[site.line - 1].strip() if site.line - 1 < len(lines) else ""
            sites.append(site)
        for m in _IMPORT_BARE.finditer(text):
            ln = lineno(m.start())
            sites.append(ImportSite(rel, ln, lines[ln - 1].strip(), m.group("mod"), package_of(m.group("mod"))))
        for m in _REQUIRE.finditer(text):
            ln = lineno(m.start())
            lhs = m.group("lhs")
            site = ImportSite(rel, ln, lines[ln - 1].strip(), m.group("mod"), package_of(m.group("mod")))
            if lhs.startswith("{"):
                site.named = _parse_named(lhs)
            else:
                site.default_name = lhs
            sites.append(site)
    return sites


# --------------------------------------------------------------------------- #
# Lockfile parsing (npm v1/v2/v3, yarn classic/berry, uv)
# --------------------------------------------------------------------------- #
LOCKFILES = ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "uv.lock")


@dataclass
class LockEntry:
    name: str
    version: str
    path: str                       # node_modules/... key, or name for yarn/uv
    hashes: Set[str] = field(default_factory=set)
    dev: bool = False
    deps: Dict[str, str] = field(default_factory=dict)
    has_install_script: bool = False


def _npm_name_from_path(key: str) -> str:
    return key.rsplit("node_modules/", 1)[-1]


def parse_npm_lock(text: str) -> Tuple[List[LockEntry], Dict[str, str]]:
    """Returns entries and root dependency ranges."""
    data = json.loads(text)
    entries: List[LockEntry] = []
    root_deps: Dict[str, str] = {}
    if "packages" in data:
        for key, meta in data["packages"].items():
            if key == "":
                root_deps.update(meta.get("dependencies", {}))
                root_deps.update(meta.get("devDependencies", {}))
                root_deps.update(meta.get("optionalDependencies", {}))
                continue
            if "node_modules/" not in key or meta.get("link"):
                continue
            deps = dict(meta.get("dependencies", {}))
            deps.update(meta.get("optionalDependencies", {}))
            entries.append(LockEntry(
                name=meta.get("name") or _npm_name_from_path(key), version=str(meta.get("version", "0.0.0")),
                path=key, hashes={meta["integrity"]} if meta.get("integrity") else set(),
                dev=bool(meta.get("dev") or meta.get("devOptional")), deps=deps,
                has_install_script=bool(meta.get("hasInstallScript")),
            ))
    else:  # lockfileVersion 1
        def walk(deps: Dict[str, Any], prefix: str) -> None:
            for name, meta in deps.items():
                key = f"{prefix}node_modules/{name}"
                entries.append(LockEntry(
                    name=name, version=str(meta.get("version", "0.0.0")), path=key,
                    hashes={meta["integrity"]} if meta.get("integrity") else set(),
                    dev=bool(meta.get("dev")), deps=dict(meta.get("requires", {})),
                ))
                if meta.get("dependencies"):
                    walk(meta["dependencies"], key + "/")
        walk(data.get("dependencies", {}), "")
    return entries, root_deps


def resolve_npm_edges(entries: List[LockEntry]) -> Dict[str, List[str]]:
    """Node-style resolution of each entry's dependency names to lock paths."""
    by_path = {e.path: e for e in entries}
    edges: Dict[str, List[str]] = {}
    for e in entries:
        targets: List[str] = []
        for dep in e.deps:
            base = e.path
            found = None
            while True:
                cand = f"{base}/node_modules/{dep}" if base else f"node_modules/{dep}"
                if cand in by_path:
                    found = cand
                    break
                if not base:
                    break
                idx = base.rfind("/node_modules/")
                base = base[:idx] if idx >= 0 else ""
            if found:
                targets.append(found)
        edges[e.path] = targets
    return edges


def parse_yarn_lock(text: str) -> List[LockEntry]:
    entries: List[LockEntry] = []
    current: Optional[LockEntry] = None
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if not raw.startswith(" ") and raw.rstrip().endswith(":"):
            spec = raw.rstrip(":").split(",")[0].strip().strip('"')
            name = spec.rsplit("@", 1)[0] if not spec.startswith("@") else "@" + spec[1:].rsplit("@", 1)[0]
            name = name.split("@npm:")[0]
            current = LockEntry(name=name, version="", path=spec)
            entries.append(current)
            continue
        if current is None:
            continue
        m = re.match(r'\s+version:?\s+"?([^"\s]+)"?', raw)
        if m:
            current.version = m.group(1)
        m = re.match(r'\s+(?:integrity|checksum):?\s+"?([^"\s]+)"?', raw)
        if m:
            current.hashes.add(m.group(1))
    return [e for e in entries if e.version]


def parse_uv_lock(text: str) -> List[LockEntry]:
    entries: List[LockEntry] = []
    for block in re.split(r"^\[\[package\]\]\s*$", text, flags=re.M)[1:]:
        name = re.search(r'^name\s*=\s*"([^"]+)"', block, re.M)
        ver = re.search(r'^version\s*=\s*"([^"]+)"', block, re.M)
        if not name or not ver:
            continue
        hashes = set(re.findall(r'hash\s*=\s*"([^"]+)"', block))
        entries.append(LockEntry(name=name.group(1), version=ver.group(1), path=name.group(1), hashes=hashes))
    return entries


def lock_hash_index(filename: str, text: str) -> Dict[Tuple[str, str], Set[str]]:
    if filename.endswith(".json"):
        entries, _ = parse_npm_lock(text)
    elif filename == "yarn.lock":
        entries = parse_yarn_lock(text)
    else:
        entries = parse_uv_lock(text)
    out: Dict[Tuple[str, str], Set[str]] = {}
    for e in entries:
        if e.hashes:
            out.setdefault((e.name, e.version), set()).update(e.hashes)
    return out


# --------------------------------------------------------------------------- #
# SBOM discovery (cdxgen -> lockfile -> manifest -> demo)
# --------------------------------------------------------------------------- #
def _manifest_floor(spec: str) -> Tuple[str, str]:
    """Best-effort version for an unresolved range. Returns (version, source)."""
    s = spec.strip()
    if re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][\w.]+)?", s):
        return s, "manifest-exact"
    m = re.search(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", s)
    if m and not s.startswith(("git", "http", "file:", "github:", "link:")):
        return f"{m.group(1)}.{m.group(2) or 0}.{m.group(3) or 0}", "manifest-range-floor"
    return "0.0.0", "manifest-unresolvable"


def _fingerprint(repo: Path, extra: Iterable[Path] = ()) -> str:
    h = hashlib.sha256()
    for p in [repo / "package.json", *(repo / lf for lf in LOCKFILES), *extra]:
        if p.exists():
            st = p.stat()
            h.update(f"{p.name}:{st.st_size}:{st.st_mtime_ns};".encode())
    return h.hexdigest()


def resolve_lockfile_metadata_only(repo: Path, log: LogFn = _noop_log, timeout: int = 420) -> Optional[Path]:
    """Opt-in: resolve a lockfile from registry *metadata* only.

    Runs `npm install --package-lock-only --ignore-scripts` on a *copy* of
    package.json in a throwaway directory. No tarballs are extracted, no
    node_modules is created, no lifecycle script runs, and the target repo is not
    modified. The repo's .npmrc is deliberately not copied (it could redirect the
    registry or carry credentials).
    """
    out = repo_cache_dir(repo) / "resolved-package-lock.json"
    manifest = repo / "package.json"
    if not manifest.exists() or shutil.which("npm") is None:
        log("lockfile-resolver", "npm or package.json missing; cannot resolve lockfile", "warn")
        return None
    with tempfile.TemporaryDirectory(prefix="scg-lockgen-") as tmp:
        shutil.copy2(manifest, Path(tmp) / "package.json")
        log("lockfile-resolver", "npm install --package-lock-only --ignore-scripts (metadata only, temp dir)", "tool")
        try:
            res = safe_run(["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit",
                            "--no-fund", "--legacy-peer-deps"], cwd=Path(tmp), timeout=timeout)
        except (subprocess.SubprocessError, OSError) as exc:
            log("lockfile-resolver", f"failed: {exc}", "error")
            return None
        lock = Path(tmp) / "package-lock.json"
        if res.returncode != 0 or not lock.exists():
            log("lockfile-resolver", f"npm exited {res.returncode}: {res.stderr[-300:]}", "error")
            return None
        if (Path(tmp) / "node_modules").exists():
            log("lockfile-resolver", "unexpected node_modules created in temp dir; discarded", "warn")
        shutil.copy2(lock, out)
    log("lockfile-resolver", f"resolved lockfile cached at {out}", "success")
    return out


def _occurrences_for(name: str, manifest_text: Optional[str], imports: List[ImportSite]) -> List[Occurrence]:
    occ: List[Occurrence] = []
    if manifest_text and f'"{name}":' in manifest_text:
        ln = line_of(manifest_text, f'"{name}":')
        if ln:
            occ.append(Occurrence(file_path="package.json", line_number=ln,
                                  text=manifest_text.splitlines()[ln - 1].strip()))
    for s in imports:
        if s.package == name:
            occ.append(Occurrence(file_path=s.file, line_number=s.line, text=s.text))
    return occ[:25]


def _sbom_from_lock(repo: Path, lock_path: Path, lock_label: str, manifest: Dict[str, Any],
                    manifest_text: Optional[str], imports: List[ImportSite]) -> Sbom:
    text = read_text(lock_path, 60_000_000) or "{}"
    entries, _root = parse_npm_lock(text)
    edges = resolve_npm_edges(entries)
    direct = set(manifest.get("dependencies", {})) | set(manifest.get("optionalDependencies", {}))
    dev_direct = set(manifest.get("devDependencies", {}))
    comps: Dict[str, Component] = {}
    path_to_purl: Dict[str, str] = {}
    for e in entries:
        purl = npm_purl(e.name, e.version)
        path_to_purl[e.path] = purl
        is_direct = e.path == f"node_modules/{e.name}" and (e.name in direct or e.name in dev_direct)
        if purl in comps:
            comps[purl].is_direct = comps[purl].is_direct or is_direct
            comps[purl].is_dev = comps[purl].is_dev and e.dev
            continue
        comps[purl] = Component(
            name=e.name, version=e.version, purl=purl, hashes=sorted(e.hashes), is_direct=is_direct,
            is_dev=e.dev or (e.name in dev_direct and e.name not in direct), version_source="lockfile",
            occurrences=_occurrences_for(e.name, manifest_text, imports) if is_direct else [],
        )
    deps: Dict[str, List[str]] = {}
    for p, targets in edges.items():
        src = path_to_purl[p]
        deps.setdefault(src, [])
        for t in targets:
            if path_to_purl[t] not in deps[src]:
                deps[src].append(path_to_purl[t])
    return Sbom(source="lockfile", repo_path=str(repo), components=list(comps.values()),
                dependencies=deps, lockfile=lock_label)


def _sbom_from_manifest(repo: Path, manifest: Dict[str, Any], manifest_text: str, imports: List[ImportSite]) -> Sbom:
    comps: List[Component] = []
    for section, dev in (("dependencies", False), ("optionalDependencies", False), ("devDependencies", True)):
        for name, spec in manifest.get(section, {}).items():
            ver, src = _manifest_floor(str(spec))
            comps.append(Component(name=name, version=ver, purl=npm_purl(name, ver), is_direct=True, is_dev=dev,
                                   version_source=src, occurrences=_occurrences_for(name, manifest_text, imports)))
    return Sbom(source="manifest", repo_path=str(repo), components=comps, notes=[
        "No lockfile found: only direct dependencies are known and caret/tilde ranges are "
        "approximated by their floor version. Run with --resolve-lockfile for Tier 2+ coverage."])


def _sbom_from_cyclonedx(repo: Path, doc: Dict[str, Any], manifest: Dict[str, Any],
                         manifest_text: Optional[str], imports: List[ImportSite]) -> Sbom:
    direct = set(manifest.get("dependencies", {})) | set(manifest.get("devDependencies", {}))
    dev_direct = set(manifest.get("devDependencies", {})) - set(manifest.get("dependencies", {}))
    comps: List[Component] = []
    for c in doc.get("components", []):
        purl = c.get("purl") or npm_purl(c.get("name", "?"), c.get("version", "0.0.0"))
        name = c.get("name", "")
        if c.get("group"):
            name = f"{c['group']}/{name}"
        occ = [Occurrence(file_path=o.get("location", "").split("#")[0], line_number=int(o.get("line", 1) or 1))
               for o in (c.get("evidence", {}) or {}).get("occurrences", []) if o.get("location")]
        comps.append(Component(
            name=name, version=c.get("version", "0.0.0"), purl=purl,
            hashes=[f"{h.get('alg')}-{h.get('content')}" for h in c.get("hashes", [])],
            is_direct=name in direct, is_dev=name in dev_direct or c.get("scope") == "optional",
            version_source="cdxgen",
            occurrences=occ or (_occurrences_for(name, manifest_text, imports) if name in direct else []),
        ))
    deps = {d["ref"]: list(d.get("dependsOn", [])) for d in doc.get("dependencies", []) if "ref" in d}
    return Sbom(source="cdxgen", repo_path=str(repo), components=comps, dependencies=deps)


def write_cyclonedx(sbom: Sbom, path: Path) -> None:
    doc = {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "components": [{
            "type": "library", "name": c.name, "version": c.version, "purl": c.purl, "bom-ref": c.purl,
            "hashes": [{"alg": h.split("-", 1)[0].upper(), "content": h.split("-", 1)[-1]} for h in c.hashes],
            "evidence": {"occurrences": [{"location": o.file_path, "line": o.line_number} for o in c.occurrences]},
        } for c in sbom.components],
        "dependencies": [{"ref": k, "dependsOn": v} for k, v in sbom.dependencies.items()],
    }
    path.write_text(json.dumps(doc, indent=1), encoding="utf-8")


def run_cdxgen(repo_path: str | Path, log: LogFn = _noop_log, use_cache: bool = True,
               resolve_lockfile: bool = False) -> Tuple[Sbom, List[ImportSite]]:
    """Discover components read-only. Returns the SBOM and the source import index."""
    repo = validate_repo_path(str(repo_path))
    cache = repo_cache_dir(repo)
    imports = build_import_index(repo)
    log("import-index", f"indexed {len(imports)} import sites in first-party source", "tool")
    manifest_path = repo / "package.json"
    manifest_text = read_text(manifest_path)
    if manifest_text is None:
        log("cdxgen", "no package.json in repo; loading built-in Juice Shop demo SBOM", "warn")
        return demo_sbom(str(repo)), imports
    manifest = json.loads(manifest_text)

    resolved = cache / "resolved-package-lock.json"
    if resolve_lockfile and not any((repo / lf).exists() for lf in LOCKFILES):
        resolve_lockfile_metadata_only(repo, log)
    fp = _fingerprint(repo, [resolved])
    cache_file = cache / "sbom_cache.json"
    if use_cache and cache_file.exists():
        try:
            cached = json.loads(cache_file.read_text(encoding="utf-8"))
            if cached.get("fingerprint") == fp:
                sbom = Sbom.model_validate(cached["sbom"])
                log("cdxgen", f"cache hit ({len(sbom.components)} components, source={sbom.source})", "tool")
                return sbom, imports
        except (ValueError, KeyError):
            pass

    sbom: Optional[Sbom] = None
    if shutil.which("cdxgen"):
        out = cache / "sbom.json"
        for extra in (["--evidence"], []):
            cmd = ["cdxgen", "--no-install-deps", *extra, "-t", "js", "--exclude", "**/node_modules/**",
                   "-o", str(out), str(repo)]
            log("cdxgen", " ".join(cmd[:-2]) + " ...", "tool")
            try:
                res = safe_run(cmd, timeout=600)
                if res.returncode == 0 and out.exists():
                    sbom = _sbom_from_cyclonedx(repo, json.loads(out.read_text(encoding="utf-8")),
                                                manifest, manifest_text, imports)
                    break
                log("cdxgen", f"exit {res.returncode}: {res.stderr[-200:]}", "warn")
            except (subprocess.SubprocessError, OSError, ValueError) as exc:
                log("cdxgen", f"failed: {exc}", "warn")
    else:
        log("cdxgen", "cdxgen binary not on PATH; using built-in read-only lockfile parser", "warn")

    if sbom is None or not sbom.components:
        repo_lock = next((repo / lf for lf in ("package-lock.json", "npm-shrinkwrap.json") if (repo / lf).exists()), None)
        if repo_lock:
            sbom = _sbom_from_lock(repo, repo_lock, repo_lock.name, manifest, manifest_text, imports)
        elif resolved.exists():
            sbom = _sbom_from_lock(repo, resolved, "resolved-package-lock.json (metadata-only)",
                                   manifest, manifest_text, imports)
            sbom.notes.append("Transitive tree resolved from registry metadata (npm --package-lock-only "
                              "--ignore-scripts); the repo itself commits no lockfile.")
        else:
            sbom = _sbom_from_manifest(repo, manifest, manifest_text, imports)
    log("cdxgen", f"SBOM: {len(sbom.components)} components, {sum(c.is_direct for c in sbom.components)} direct "
                  f"(source={sbom.source})", "success")
    write_cyclonedx(sbom, cache / "sbom.json")
    cache_file.write_text(json.dumps({"fingerprint": fp, "sbom": sbom.model_dump(mode="json")}), encoding="utf-8")
    return sbom, imports


# --------------------------------------------------------------------------- #
# CVSS v3.x base score (deterministic, from the vector string)
# --------------------------------------------------------------------------- #
_CVSS_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _roundup(x: float) -> float:
    i = int(round(x * 100000))
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_base_score(vector: str) -> Optional[float]:
    if not vector.startswith("CVSS:3"):
        return None
    try:
        m = dict(part.split(":", 1) for part in vector.split("/")[1:])
        changed = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}[m["PR"]]
        iss = 1 - (1 - _CVSS_W["CIA"][m["C"]]) * (1 - _CVSS_W["CIA"][m["I"]]) * (1 - _CVSS_W["CIA"][m["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
        expl = 8.22 * _CVSS_W["AV"][m["AV"]] * _CVSS_W["AC"][m["AC"]] * pr * _CVSS_W["UI"][m["UI"]]
        if impact <= 0:
            return 0.0
        return _roundup(min(1.08 * (impact + expl), 10)) if changed else _roundup(min(impact + expl, 10))
    except (KeyError, ValueError):
        return None


_LABEL_SCORE = {"CRITICAL": 9.5, "HIGH": 7.5, "MODERATE": 5.5, "MEDIUM": 5.5, "LOW": 3.0}

# OSV npm advisories rarely carry function-level data, so reachability uses a
# small curated table of vulnerable symbols for well-known packages.
CURATED_SYMBOLS: Dict[str, List[str]] = {
    "jsonwebtoken": ["verify", "decode"],
    "express-jwt": ["<default>"],
    "sanitize-html": ["<default>"],
    "lodash": ["merge", "defaultsDeep", "zipObjectDeep", "set", "template", "mergeWith"],
    "qs": ["parse"],
    "marsdb": ["<default>"],
    "notevil": ["<default>"],
    "js-yaml": ["load", "safeLoad"],
    "pug": ["compile", "render"],
    "minimist": ["<default>"],
    "semver": ["satisfies", "valid", "coerce"],
    "multer": ["<default>"],
    "unzipper": ["Extract", "Parse", "Open"],
    "socket.io": ["<default>"],
    "sequelize": ["query"],
    "ws": ["WebSocketServer"],
}


def parse_osv_record(rec: Dict[str, Any], pkg_name: str, version: str, purl: str, source: str) -> Vulnerability:
    score, vector = None, None
    for sev in rec.get("severity", []) or []:
        if sev.get("type", "").startswith("CVSS_V3"):
            vector = sev.get("score")
            score = cvss3_base_score(vector or "")
    label = (rec.get("database_specific") or {}).get("severity")
    for aff in rec.get("affected", []) or []:
        for sev in aff.get("severity", []) or []:
            if score is None and sev.get("type", "").startswith("CVSS_V3"):
                vector = sev.get("score")
                score = cvss3_base_score(vector or "")
    if score is None and label:
        score = _LABEL_SCORE.get(str(label).upper())
        vector = vector or f"estimated-from-label:{label}"
    patched: List[str] = []
    funcs: List[str] = []
    for aff in rec.get("affected", []) or []:
        if (aff.get("package") or {}).get("name") != pkg_name:
            continue
        for rng in aff.get("ranges", []) or []:
            for ev in rng.get("events", []) or []:
                if ev.get("fixed") and ev["fixed"] not in patched:
                    patched.append(ev["fixed"])
        for imp in ((aff.get("ecosystem_specific") or {}).get("imports") or []):
            funcs.extend(imp.get("symbols", []) or [])
    return Vulnerability(
        id=rec.get("id", "UNKNOWN"), aliases=rec.get("aliases", []) or [], package=pkg_name, version=version,
        purl=purl, summary=rec.get("summary") or (rec.get("details") or "")[:200], cvss_score=score,
        cvss_vector=vector, severity_label=label, patched_versions=patched,
        references=[r["url"] for r in rec.get("references", []) or [] if r.get("url")][:6],
        affected_functions=funcs, source=source, published=rec.get("published"),
    )


# --------------------------------------------------------------------------- #
# OSV: osv-scanner binary -> OSV API -> demo fallback
# --------------------------------------------------------------------------- #
OSV_API = "https://api.osv.dev/v1"


def _osv_detail_cache() -> Path:
    return CACHE_ROOT / "osv_vuln_cache.json"


async def _osv_api_query(components: List[Component], log: LogFn) -> Dict[str, List[str]]:
    """purl -> [vuln ids] via /v1/querybatch."""
    out: Dict[str, List[str]] = {}
    async with httpx.AsyncClient(timeout=30, headers={"User-Agent": "supply-chain-guardian/1.0"}) as client:
        for start in range(0, len(components), 1000):
            chunk = components[start:start + 1000]
            body = {"queries": [{"package": {"name": c.name, "ecosystem": "PyPI" if c.ecosystem == "pypi" else "npm"},
                                 "version": c.version} for c in chunk]}
            r = await client.post(f"{OSV_API}/querybatch", json=body)
            r.raise_for_status()
            for comp, res in zip(chunk, r.json().get("results", [])):
                ids = [v["id"] for v in res.get("vulns", []) or []]
                if ids:
                    out[comp.purl] = ids
    return out


async def _osv_api_details(ids: Set[str], cache_path: Path, log: LogFn) -> Dict[str, Dict[str, Any]]:
    cache: Dict[str, Dict[str, Any]] = {}
    if cache_path.exists():
        try:
            cache = json.loads(cache_path.read_text(encoding="utf-8"))
        except ValueError:
            cache = {}
    missing = [i for i in ids if i not in cache]
    sem = asyncio.Semaphore(8)
    async with httpx.AsyncClient(timeout=30, headers={"User-Agent": "supply-chain-guardian/1.0"}) as client:
        async def fetch(vid: str) -> None:
            async with sem:
                r = await client.get(f"{OSV_API}/vulns/{urllib.parse.quote(vid)}")
                if r.status_code == 200:
                    cache[vid] = r.json()
        await asyncio.gather(*(fetch(i) for i in missing))
    if missing:
        log("osv-api", f"fetched {len(missing)} advisory records ({len(ids) - len(missing)} cached)", "tool")
        cache_path.write_text(json.dumps(cache), encoding="utf-8")
    return cache


def _run_async(coro: Any) -> Any:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    # Called from inside a running loop's thread: run in a dedicated loop.
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(1) as pool:
        return pool.submit(asyncio.run, coro).result()


def query_osv_api(components: List[Component], log: LogFn = _noop_log) -> List[Vulnerability]:
    by_purl = {c.purl: c for c in components}
    hits = _run_async(_osv_api_query(components, log))
    all_ids = {i for ids in hits.values() for i in ids}
    details = _run_async(_osv_api_details(all_ids, _osv_detail_cache(), log))
    vulns: List[Vulnerability] = []
    for purl, ids in hits.items():
        comp = by_purl[purl]
        for vid in ids:
            rec = details.get(vid, {"id": vid})
            vulns.append(parse_osv_record(rec, comp.name, comp.version, purl, "osv-api"))
    return vulns


def _parse_osv_scanner_json(doc: Dict[str, Any], sbom: Sbom) -> List[Vulnerability]:
    by_nv = {(c.name, c.version): c for c in sbom.components}
    vulns: List[Vulnerability] = []
    for result in doc.get("results", []) or []:
        for pkg in result.get("packages", []) or []:
            info = pkg.get("package", {})
            name, version = info.get("name", ""), info.get("version", "")
            comp = by_nv.get((name, version))
            purl = comp.purl if comp else npm_purl(name, version)
            for rec in pkg.get("vulnerabilities", []) or []:
                vulns.append(parse_osv_record(rec, name, version, purl, "osv-scanner"))
    return vulns


def run_osv_scanner(sbom: Sbom, log: LogFn = _noop_log) -> Tuple[List[Vulnerability], str]:
    """Returns (vulnerabilities, source). Never installs or executes project code."""
    repo = Path(sbom.repo_path)
    cache = repo_cache_dir(repo)
    sbom_path = cache / "sbom.json"
    if shutil.which("osv-scanner"):
        lock = next((repo / lf for lf in LOCKFILES if (repo / lf).exists()), None)
        attempts = []
        if lock:
            attempts.append(["osv-scanner", "scan", "source", "--format", "json", "-L", str(lock)])
        attempts.append(["osv-scanner", "scan", "--format", "json", f"--sbom={sbom_path}"])
        for cmd in attempts:
            log("osv-scanner", " ".join(cmd), "tool")
            try:
                res = safe_run(cmd, timeout=300)
                if res.returncode in (0, 1) and res.stdout.strip().startswith("{"):
                    vulns = _parse_osv_scanner_json(json.loads(res.stdout), sbom)
                    log("osv-scanner", f"{len(vulns)} raw advisories", "success")
                    return vulns, "osv-scanner"
                log("osv-scanner", f"exit {res.returncode}: {res.stderr[-200:]}", "warn")
            except (subprocess.SubprocessError, OSError, ValueError) as exc:
                log("osv-scanner", f"failed: {exc}", "warn")
    else:
        log("osv-scanner", "osv-scanner binary not on PATH; querying the OSV.dev API directly", "warn")

    if sbom.source == "demo":
        return demo_vulnerabilities(), "demo"
    if not offline_mode():
        try:
            comps = [c for c in sbom.components if c.version_source != "manifest-unresolvable"]
            vulns = query_osv_api(comps, log)
            log("osv-api", f"{len(vulns)} raw advisories across {len({v.purl for v in vulns})} packages", "success")
            return vulns, "osv-api"
        except (httpx.HTTPError, OSError, ValueError) as exc:
            log("osv-api", f"OSV API unavailable ({exc}); using built-in demo advisories", "warn")
    else:
        log("osv-api", "SCG_OFFLINE=1; using built-in demo advisories", "warn")
    names = {c.name for c in sbom.components}
    return [v for v in demo_vulnerabilities() if v.package in names], "demo"


# --------------------------------------------------------------------------- #
# Pre-CVE admission check
# --------------------------------------------------------------------------- #
TOP_NPM = """
lodash react express axios chalk commander debug moment request tslib uuid react-dom prop-types
fs-extra async bluebird underscore vue classnames yargs webpack typescript dotenv body-parser glob
rxjs mkdirp jquery minimist semver colors inquirer core-js babel-core cheerio node-fetch q aws-sdk
eslint jest mocha redux winston socket.io mongoose cors jsonwebtoken bcrypt shelljs rimraf yeoman-generator
through2 handlebars ws superagent qs object-assign js-yaml esprima electron graphql next nodemon
babel-loader css-loader style-loader postcss autoprefixer sass less gulp grunt karma chai sinon
cross-env concurrently prettier dayjs date-fns ramda immutable mobx zustand styled-components
emotion antd @mui/material tailwindcss vite rollup esbuild parcel ts-node tsx nanoid ajv joi yup
zod express-session cookie-parser helmet morgan multer passport passport-jwt sequelize typeorm prisma
pg mysql mysql2 sqlite3 redis ioredis mongodb knex nodemailer sharp jimp puppeteer playwright
cypress selenium-webdriver supertest nock faker chance cross-spawn execa ora boxen figlet
minimatch micromatch picomatch chokidar debounce throttle-debounce event-emitter eventemitter3
lru-cache node-cache http-proxy http-proxy-middleware compression serve-static finalhandler
path-to-regexp mime mime-types form-data formidable busboy xml2js fast-xml-parser marked
markdown-it highlight.js dompurify sanitize-html validator escape-html he entities iconv-lite
buffer safe-buffer readable-stream string_decoder inherits util-deprecate isarray ms
cookie cookie-signature etag fresh range-parser send statuses depd on-finished vary
source-map-support source-map terser uglify-js clean-css html-webpack-plugin
pino bunyan log4js signale npmlog nopt abbrev ini osenv tar archiver unzipper adm-zip
crypto-js bcryptjs node-forge jose jws express-jwt openid-client oauth
"""
TOP_PYPI = """
requests urllib3 boto3 botocore setuptools certifi idna charset-normalizer python-dateutil six
numpy pandas pyyaml typing-extensions s3transfer packaging pip wheel cryptography cffi pycparser
jmespath attrs pyasn1 rsa google-api-core protobuf click jinja2 markupsafe pytz pyparsing
importlib-metadata zipp awscli colorama docutils wrapt pluggy py pytest filelock virtualenv
platformdirs tomli psutil pillow scipy matplotlib scikit-learn sqlalchemy flask django werkzeug
itsdangerous fastapi uvicorn starlette pydantic httpx anyio sniffio h11 aiohttp multidict yarl
frozenlist aiosignal async-timeout grpcio tqdm lxml beautifulsoup4 soupsieve openpyxl
tensorflow torch keras transformers tokenizers huggingface-hub regex networkx sympy
paramiko pynacl bcrypt redis celery kombu billiard gunicorn psycopg2 pymysql
python-dotenv rich pygments decorator tabulate toml black isort flake8 mypy pylint coverage
selenium scrapy twisted openai tiktoken langchain pyjwt oauthlib requests-oauthlib
"""
POPULAR_NAMES: Dict[str, Set[str]] = {
    "npm": set(TOP_NPM.split()),
    "pypi": set(TOP_PYPI.split()),
}

SUSPICIOUS_SINKS: List[Tuple[str, str]] = [
    (r"\bcurl\b", "curl network fetch"),
    (r"\bwget\b", "wget network fetch"),
    (r"\b(?:bash|sh|zsh|powershell|pwsh|cmd)(?:\.exe)?\s+(?:-c|/c|-Command|-enc)", "inline shell execution"),
    (r"\beval\s*\(", "eval()"),
    (r"\bbase64\b|atob\(|Buffer\.from\([^)]*['\"]base64", "base64 encoding/decoding"),
    (r"\$\(\s*env\b|\bprintenv\b|process\.env\b", "environment variable harvesting"),
    (r"\.env\b|\.ssh/|id_rsa|\.npmrc|\.aws/credentials", "secret file path read"),
    (r"https?://(?!registry\.npmjs\.org)[^\s'\"]+", "outbound URL"),
    (r"\|\s*(?:sh|bash)\b", "pipe to shell"),
    (r"child_process|\bexecSync\b|\bspawn\(", "child process spawn"),
]
INSTALL_HOOKS = ("preinstall", "install", "postinstall")
NPM_NAME_RE = re.compile(r"^(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$")
PYPI_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
VERSION_RE = re.compile(r"^[0-9A-Za-z.+_~-]{1,64}$")


def osa_distance(a: str, b: str) -> int:
    """Optimal-string-alignment distance: Levenshtein + adjacent transpositions.

    Transpositions matter: `reqeusts` vs `requests` is 2 Levenshtein edits but a
    single human typo; plain Levenshtein would miss the canonical typosquat.
    """
    la, lb = len(a), len(b)
    d = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        d[i][0] = i
    for j in range(lb + 1):
        d[0][j] = j
    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[la][lb]


def nearest_popular(name: str, ecosystem: str) -> Tuple[Optional[str], Optional[int]]:
    """Closest popular package (same ecosystem first, then cross-ecosystem)."""
    bare = name.split("/")[-1].lower()
    if name.lower() in POPULAR_NAMES.get(ecosystem, set()):
        return None, None
    best: Tuple[Optional[str], Optional[int]] = (None, None)
    for eco in [ecosystem] + [e for e in POPULAR_NAMES if e != ecosystem]:
        for pop in POPULAR_NAMES[eco]:
            p = pop.split("/")[-1].lower()
            if p == bare:
                if eco == ecosystem:
                    continue
                return None, None
            if abs(len(p) - len(bare)) > 2:
                continue
            dist = osa_distance(bare, p)
            if 1 <= dist <= 2 and (best[1] is None or dist < best[1]):
                best = (f"{pop}" + ("" if eco == ecosystem else f" ({eco})"), dist)
    return best


def scan_text_for_sinks(text: str) -> List[str]:
    return [label for pattern, label in SUSPICIOUS_SINKS if re.search(pattern, text, re.I)]


def _parse_time(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _fetch_json(url: str, timeout: float = 20.0) -> Tuple[int, Optional[Dict[str, Any]]]:
    with httpx.Client(timeout=timeout, headers={"User-Agent": "supply-chain-guardian/1.0",
                                                "Accept": "application/json"}, follow_redirects=True) as c:
        r = c.get(url)
        if r.status_code != 200:
            return r.status_code, None
        return 200, r.json()


def _npm_registry_meta(name: str, version: Optional[str]) -> Dict[str, Any]:
    """Normalise npm packument -> candidate metadata dict (no tarball download)."""
    status, doc = _fetch_json(f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@')}")
    if status == 404:
        return {"exists": False}
    if doc is None:
        raise httpx.HTTPError(f"registry returned HTTP {status}")
    ver = version or (doc.get("dist-tags") or {}).get("latest")
    versions = doc.get("versions") or {}
    if ver not in versions:
        return {"exists": True, "version_missing": True, "version": ver, "available": list(versions)[-10:]}
    times = doc.get("time") or {}
    ordered = sorted((v for v in versions if v in times), key=lambda v: times[v])
    prev = ordered[ordered.index(ver) - 1] if ver in ordered and ordered.index(ver) > 0 else None
    weekly = None
    try:
        st, dl = _fetch_json(f"https://api.npmjs.org/downloads/point/last-week/{urllib.parse.quote(name, safe='@')}", 10)
        weekly = (dl or {}).get("downloads") if st == 200 else None
    except httpx.HTTPError:
        weekly = None
    vmeta = versions[ver]
    return {
        "exists": True, "name": name, "version": ver,
        "scripts": {k: v for k, v in (vmeta.get("scripts") or {}).items() if k in INSTALL_HOOKS},
        "prev_version": prev,
        "prev_scripts": {k: v for k, v in ((versions.get(prev) or {}).get("scripts") or {}).items() if k in INSTALL_HOOKS} if prev else {},
        # time.modified changes on any metadata edit; abandonment must use the newest *version* publish time.
        "published": times.get(ver), "last_publish": times[ordered[-1]] if ordered else None,
        "attestations": bool((vmeta.get("dist") or {}).get("attestations")),
        "weekly_downloads": weekly, "files": {},
        "source_label": f"registry.npmjs.org/{name}",
    }


def _pypi_registry_meta(name: str, version: Optional[str]) -> Dict[str, Any]:
    status, doc = _fetch_json(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json")
    if status == 404:
        return {"exists": False}
    if doc is None:
        raise httpx.HTTPError(f"PyPI returned HTTP {status}")
    ver = version or doc["info"]["version"]
    files = (doc.get("releases") or {}).get(ver)
    if files is None:
        return {"exists": True, "version_missing": True, "version": ver}
    uploads = sorted(f["upload_time_iso_8601"] for f in files if f.get("upload_time_iso_8601"))
    all_uploads = sorted(f["upload_time_iso_8601"] for fs in doc["releases"].values() for f in fs if f.get("upload_time_iso_8601"))
    sdist_only = bool(files) and all(f.get("packagetype") == "sdist" for f in files)
    return {
        "exists": True, "name": name, "version": ver,
        "scripts": {"setup.py (sdist build)": "setup.py executes at install time"} if sdist_only else {},
        "prev_scripts": {}, "published": uploads[0] if uploads else None,
        "last_publish": all_uploads[-1] if all_uploads else None, "attestations": None,
        "weekly_downloads": None, "files": {}, "source_label": f"pypi.org/pypi/{name}",
    }


def run_pre_cve_admission_check(package_name: str, version: Optional[str] = None, ecosystem: str = "npm",
                                candidate_meta: Optional[Dict[str, Any]] = None,
                                log: LogFn = _noop_log) -> AdmissionResult:
    """Inspect a candidate package *before* install. Decision is set by the gate."""
    ecosystem = ecosystem.lower()
    name_re = NPM_NAME_RE if ecosystem == "npm" else PYPI_NAME_RE
    if not name_re.match(package_name) or (version and not VERSION_RE.match(version)):
        raise ValueError(f"invalid {ecosystem} package spec: {package_name}@{version}")
    purl_fn = npm_purl if ecosystem == "npm" else pypi_purl
    result = AdmissionResult(package=package_name, version=version, ecosystem=ecosystem,
                             purl=purl_fn(package_name, version or "latest"), metadata_source="unavailable")
    meta: Dict[str, Any]
    if candidate_meta is not None:
        meta, result.metadata_source = candidate_meta, "mock-tarball"
        log("pre_cve_gate", f"inspecting local mock tarball metadata for {package_name}@{version}", "tool")
    elif offline_mode():
        meta = {}
        result.errors.append("offline mode: registry metadata not fetched; heuristics limited to name checks")
    else:
        log("pre_cve_gate", f"GET registry metadata for {package_name} (no tarball download)", "tool")
        try:
            meta = _npm_registry_meta(package_name, version) if ecosystem == "npm" else _pypi_registry_meta(package_name, version)
            result.metadata_source = "registry"
        except (httpx.HTTPError, OSError, ValueError, KeyError) as exc:
            meta = {}
            result.errors.append(f"registry lookup failed: {exc}")
    label = meta.get("source_label") or f"registry://{ecosystem}/{package_name}"
    reg_ev = lambda detail: Evidence(kind=EvidenceKind.REGISTRY_METADATA, file=label, detail=detail)  # noqa: E731

    if meta.get("exists") is False:
        result.exists = False
        result.signals.append(AdmissionSignal(
            name="nonexistent_package", triggered=True, hard_block=True,
            detail="Package does not exist on the registry (hallucinated name / dependency-confusion risk).",
            evidence=reg_ev("HTTP 404")))
    if meta.get("version_missing"):
        result.signals.append(AdmissionSignal(name="version_missing", triggered=True, hard_block=True,
                                              detail=f"Version {meta.get('version')} not published.",
                                              evidence=reg_ev("version absent from packument")))
    if meta.get("version") and not version:
        result.version = meta["version"]
        result.purl = purl_fn(package_name, meta["version"])

    # 1. Typosquat
    target, dist = nearest_popular(package_name, ecosystem)
    weekly = meta.get("weekly_downloads")
    popular_itself = isinstance(weekly, int) and weekly >= 50_000
    if target and not popular_itself:
        result.typosquat_target, result.typosquat_distance = target, dist
        result.signals.append(AdmissionSignal(
            name="typosquat", triggered=True, hard_block=dist == 1,
            detail=f"'{package_name}' is {dist} edit(s) from popular package '{target}'.",
            evidence=reg_ev(f"OSA distance {dist} to {target}")))
    else:
        result.signals.append(AdmissionSignal(name="typosquat", triggered=False,
                                              detail="No popular package within 1-2 edits" +
                                              (f" (or package itself is popular: {weekly}/week)" if popular_itself else "")))

    # 2. Release-age cooldown
    published = _parse_time(meta.get("published"))
    result.published = meta.get("published")
    if published:
        age = datetime.now(timezone.utc) - published
        result.signals.append(AdmissionSignal(
            name="release_age", triggered=age < timedelta(days=7),
            detail=f"Version published {age.days} day(s) ago (cooldown = 7 days).",
            evidence=reg_ev(f"time[{result.version}] = {meta.get('published')}")))

    # 3. Install hooks & suspicious sinks (metadata scripts + mock tarball files)
    scripts: Dict[str, str] = meta.get("scripts") or {}
    result.install_scripts = scripts
    prev_scripts: Dict[str, str] = meta.get("prev_scripts") or {}
    for hook, cmd in scripts.items():
        sinks = scan_text_for_sinks(cmd)
        newly = hook not in prev_scripts and meta.get("prev_version") is not None
        result.signals.append(AdmissionSignal(
            name="install_hook", triggered=True, hard_block=bool(sinks),
            detail=f"{hook}: {cmd[:160]}" + (f" | sinks: {', '.join(sinks)}" if sinks else "") +
                   (f" | NEWLY ADDED since {meta.get('prev_version')}" if newly else ""),
            evidence=Evidence(kind=EvidenceKind.REGISTRY_METADATA, file=f"{label}/package.json",
                              line=meta.get("script_lines", {}).get(hook), detail=f'"{hook}": "{cmd}"')))
    for fname, content in (meta.get("files") or {}).items():
        sinks = scan_text_for_sinks(content)
        if sinks:
            result.signals.append(AdmissionSignal(
                name="tarball_sink", triggered=True, hard_block=False,
                detail=f"{fname}: {', '.join(sinks)}",
                evidence=Evidence(kind=EvidenceKind.REGISTRY_METADATA, file=f"{label}/{fname}", detail=content[:200])))

    # 4. Abandonment & provenance
    last = _parse_time(meta.get("last_publish"))
    if last:
        stale = datetime.now(timezone.utc) - last > timedelta(days=3 * 365)
        result.signals.append(AdmissionSignal(name="abandoned", triggered=stale,
                                              detail=f"Last publish {meta.get('last_publish')}",
                                              evidence=reg_ev("newest version publish time")))
    if meta.get("attestations") is False:
        result.signals.append(AdmissionSignal(name="missing_provenance", triggered=True,
                                              detail="No npm provenance attestation for this version (informational).",
                                              evidence=reg_ev("dist.attestations absent")))

    # 5. Known advisories for the exact candidate (includes MAL- malicious-package reports)
    if result.version and meta.get("exists", True) and not offline_mode() and candidate_meta is None:
        try:
            comp = Component(name=package_name, version=result.version, purl=result.purl, ecosystem=ecosystem)
            result.vulnerabilities = query_osv_api([comp], log)
        except (httpx.HTTPError, OSError, ValueError) as exc:
            result.errors.append(f"OSV lookup failed: {exc}")
    known = [v for v in result.vulnerabilities if not v.is_malicious]
    if known:
        worst = max(known, key=lambda v: v.cvss_score or 0)
        result.signals.append(AdmissionSignal(
            name="known_vulnerabilities", triggered=True, hard_block=False,
            detail=f"{len(known)} published advisory(ies); worst {worst.id} CVSS {worst.cvss_score}: {worst.summary[:100]}"
                   + (f" (fixed in {', '.join(worst.patched_versions[:3])})" if worst.patched_versions else ""),
            evidence=Evidence(kind=EvidenceKind.ADVISORY, file=worst.id, detail=worst.summary[:200])))
    for v in result.vulnerabilities:
        if v.is_malicious:
            result.signals.append(AdmissionSignal(name="known_malicious", triggered=True, hard_block=True,
                                                  detail=f"{v.id}: {v.summary}",
                                                  evidence=Evidence(kind=EvidenceKind.ADVISORY, file=v.id, detail=v.summary)))
    triggered = [s.name for s in result.signals if s.triggered]
    log("pre_cve_gate", f"{package_name}@{result.version}: signals={triggered or 'none'}", "tool")
    return result


# --------------------------------------------------------------------------- #
# Static supply-chain inspector
# --------------------------------------------------------------------------- #
TRUSTED_REGISTRIES = {"docker.io", "index.docker.io", "gcr.io", "ghcr.io", "mcr.microsoft.com", "public.ecr.aws",
                      "quay.io", "registry.k8s.io", "cgr.dev", "registry.access.redhat.com"}
_FROM_RE = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(?P<image>\S+)(?:\s+AS\s+(?P<alias>\S+))?", re.I)
_USES_RE = re.compile(r"^\s*-?\s*uses:\s*['\"]?(?P<ref>[^\s'\"#]+)")


def _baseline_hashes_from_sbom(path: Path) -> Dict[Tuple[str, str], Set[str]]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    if "sbom" in doc:
        doc = doc["sbom"]
    out: Dict[Tuple[str, str], Set[str]] = {}
    for c in doc.get("components", []):
        hashes: Set[str] = set()
        for h in c.get("hashes", []):
            if isinstance(h, str):
                hashes.add(h)
            elif isinstance(h, dict):
                hashes.add(f"{h.get('alg', '').lower().replace('-', '')}-{h.get('content')}")
        name = c.get("name", "")
        if c.get("group"):
            name = f"{c['group']}/{name}"
        if hashes:
            out[(name, c.get("version", ""))] = hashes
    return out


def compare_lock_hashes(filename: str, current_text: str, baseline: Dict[Tuple[str, str], Set[str]],
                        baseline_label: str, id_prefix: str = "LOCK") -> List[StaticAnomaly]:
    current = lock_hash_index(filename, current_text)
    anomalies: List[StaticAnomaly] = []
    for (name, ver), hashes in sorted(current.items()):
        old = baseline.get((name, ver))
        if not old or hashes & old:
            continue
        new_hash = sorted(hashes)[0]
        ln = line_of(current_text, new_hash)
        anomalies.append(StaticAnomaly(
            id=f"{id_prefix}-{len(anomalies) + 1:03d}", kind=AnomalyKind.LOCKFILE_HASH_MUTATION,
            title=f"Integrity hash of {name}@{ver} changed without a version bump",
            file=filename, line=ln, snippet=current_text.splitlines()[ln - 1].strip(),
            package=name, purl=npm_purl(name, ver) if filename.endswith(".json") or filename == "yarn.lock" else pypi_purl(name, ver),
            provenance_risk=True, detail=f"baseline ({baseline_label}) = {sorted(old)[0][:40]}... ; now = {new_hash[:40]}...",
        ))
    return anomalies


def inspect_manifest_hooks(manifest_text: str, rel: str = "package.json") -> List[StaticAnomaly]:
    out: List[StaticAnomaly] = []
    try:
        scripts = json.loads(manifest_text).get("scripts", {}) or {}
    except ValueError:
        return out
    for hook in (*INSTALL_HOOKS, "prepare"):
        if hook not in scripts:
            continue
        cmd = str(scripts[hook])
        sinks = scan_text_for_sinks(cmd)
        ln = line_of(manifest_text, f'"{hook}"')
        out.append(StaticAnomaly(
            id=f"HOOK-{hook}", kind=AnomalyKind.SUSPICIOUS_HOOK if sinks else AnomalyKind.LIFECYCLE_HOOK,
            title=(f"Suspicious {hook} hook ({', '.join(sinks)})" if sinks else f"Project {hook} hook auto-executes on install"),
            file=rel, line=ln, snippet=manifest_text.splitlines()[ln - 1].strip(), auto_executes=hook != "prepare",
            scored=bool(sinks), detail="No suspicious sinks; listed for visibility only." if not sinks else cmd[:300],
        ))
    return out


def inspect_dockerfile(text: str, rel: str) -> List[StaticAnomaly]:
    out: List[StaticAnomaly] = []
    stages: Set[str] = set()
    for i, raw in enumerate(text.splitlines(), 1):
        m = _FROM_RE.match(raw)
        if m:
            image, alias = m.group("image"), m.group("alias")
            if alias:
                stages.add(alias.lower())
            if image.lower() in stages or image.lower() == "scratch" or image.startswith("$"):
                continue
            first = image.split("/")[0]
            registry = first if ("." in first or ":" in first or first == "localhost") and "/" in image else "docker.io"
            name_tag = image.split("@")[0].split("/")[-1]
            tag = name_tag.split(":", 1)[1] if ":" in name_tag else None
            if "@sha256:" in image:
                pass
            elif tag in (None, "latest"):
                out.append(StaticAnomaly(id=f"DOCKER-{i}", kind=AnomalyKind.DOCKER_LATEST_TAG,
                                         title=f"Base image '{image}' floats on {'implicit ' if tag is None else ''}:latest",
                                         file=rel, line=i, snippet=raw.strip(), provenance_risk=True))
            else:
                out.append(StaticAnomaly(id=f"DOCKER-{i}", kind=AnomalyKind.DOCKER_UNPINNED_DIGEST,
                                         title=f"Base image '{image}' pinned by mutable tag, not digest",
                                         file=rel, line=i, snippet=raw.strip(), scored=False,
                                         detail="Tags can be re-pushed; pin with @sha256:<digest> for reproducibility."))
            if registry not in TRUSTED_REGISTRIES:
                out.append(StaticAnomaly(id=f"DOCKER-REG-{i}", kind=AnomalyKind.DOCKER_UNTRUSTED_REGISTRY,
                                         title=f"Base image pulled from untrusted registry '{registry}'",
                                         file=rel, line=i, snippet=raw.strip(), provenance_risk=True))
        elif re.match(r"^\s*RUN\b.*\b(curl|wget)\b[^|]*\|\s*(sh|bash)\b", raw, re.I):
            out.append(StaticAnomaly(id=f"DOCKER-PIPE-{i}", kind=AnomalyKind.DOCKER_PIPE_TO_SHELL,
                                     title="Remote script piped to shell during image build",
                                     file=rel, line=i, snippet=raw.strip(), provenance_risk=True))
    return out


def inspect_workflow(text: str, rel: str) -> List[StaticAnomaly]:
    out: List[StaticAnomaly] = []
    for i, raw in enumerate(text.splitlines(), 1):
        m = _USES_RE.match(raw)
        if not m:
            continue
        ref = m.group("ref")
        if ref.startswith(("./", "docker://")) or "@" not in ref:
            continue
        action, _, pin = ref.rpartition("@")
        if re.fullmatch(r"[0-9a-f]{40}", pin):
            continue
        out.append(StaticAnomaly(id=f"GHA-{Path(rel).stem}-{i}", kind=AnomalyKind.WORKFLOW_UNPINNED_ACTION,
                                 title=f"Action '{action}' pinned to mutable ref '{pin}'",
                                 file=rel, line=i, snippet=raw.strip(),
                                 detail="Pin third-party actions to a full commit SHA."))
    return out


def run_static_supply_chain_inspector(repo_path: str | Path, baseline_sbom_path: Optional[str | Path] = None,
                                      git_ref: str = "HEAD~1", log: LogFn = _noop_log) -> List[StaticAnomaly]:
    repo = validate_repo_path(str(repo_path))
    anomalies: List[StaticAnomaly] = []
    in_git = is_git_repo(repo)
    baseline_sbom: Dict[Tuple[str, str], Set[str]] = {}
    if baseline_sbom_path and Path(baseline_sbom_path).exists():
        baseline_sbom = _baseline_hashes_from_sbom(Path(baseline_sbom_path))

    for lf in LOCKFILES:
        cur = read_text(repo / lf, 60_000_000)
        if cur is None:
            continue
        log("static-inspector", f"lockfile {lf}: comparing integrity hashes against {git_ref} / baseline SBOM", "tool")
        if in_git:
            old = git_show(repo, git_ref, lf)
            if old:
                try:
                    anomalies += compare_lock_hashes(lf, cur, lock_hash_index(lf, old), f"git {git_ref}")
                except ValueError as exc:
                    log("static-inspector", f"could not parse {git_ref}:{lf}: {exc}", "warn")
        if baseline_sbom:
            anomalies += compare_lock_hashes(lf, cur, baseline_sbom, "baseline SBOM", id_prefix="LOCK-SBOM")

    manifest = read_text(repo / "package.json")
    if manifest:
        anomalies += inspect_manifest_hooks(manifest)
    for df in list(repo.glob("Dockerfile*")) + list(repo.glob("*/Dockerfile*")):
        if "node_modules" in df.parts:
            continue
        text = read_text(df)
        if text:
            anomalies += inspect_dockerfile(text, df.relative_to(repo).as_posix())
    wf_dir = repo / ".github" / "workflows"
    if wf_dir.is_dir():
        for wf in sorted(list(wf_dir.glob("*.yml")) + list(wf_dir.glob("*.yaml"))):
            text = read_text(wf)
            if text:
                anomalies += inspect_workflow(text, wf.relative_to(repo).as_posix())
    scored = sum(a.scored for a in anomalies)
    log("static-inspector", f"{len(anomalies)} static observations ({scored} scored, {len(anomalies) - scored} informational)", "success")
    return anomalies


# --------------------------------------------------------------------------- #
# Demo fallback data (only used when the repo / network is unavailable).
# Clearly labelled "demo" everywhere it surfaces.
# --------------------------------------------------------------------------- #
def demo_sbom(repo_path: str) -> Sbom:
    rows = [("express", "4.22.1", True), ("jsonwebtoken", "0.4.0", True), ("express-jwt", "0.1.3", True),
            ("sanitize-html", "1.4.2", True), ("lodash", "4.17.11", True), ("qs", "6.5.2", False),
            ("body-parser", "1.18.3", False), ("jws", "0.2.6", False)]
    comps = [Component(name=n, version=v, purl=npm_purl(n, v), is_direct=d, version_source="demo") for n, v, d in rows]
    p = {c.name: c.purl for c in comps}
    deps = {p["express"]: [p["qs"], p["body-parser"]], p["body-parser"]: [p["qs"]],
            p["jsonwebtoken"]: [p["jws"]], p["express-jwt"]: [p["jsonwebtoken"]]}
    return Sbom(source="demo", repo_path=repo_path, components=comps, dependencies=deps,
                notes=["DEMO DATA: repository had no package.json; results are illustrative only."])


def demo_vulnerabilities() -> List[Vulnerability]:
    def v(id_: str, alias: str, pkg: str, ver: str, score: float, summary: str, fixed: str) -> Vulnerability:
        return Vulnerability(id=id_, aliases=[alias], package=pkg, version=ver, purl=npm_purl(pkg, ver),
                             summary=summary, cvss_score=score, patched_versions=[fixed], source="demo",
                             references=[f"https://osv.dev/vulnerability/{id_}"])
    return [
        v("GHSA-c7hr-j4mj-j2w6", "CVE-2015-9235", "jsonwebtoken", "0.4.0", 9.8,
          "Verification bypass via algorithm confusion", "4.2.2"),
        v("GHSA-6g6m-m6h5-w9gf", "CVE-2020-15084", "express-jwt", "0.1.3", 9.1,
          "Authorization bypass when algorithms not specified", "6.0.0"),
        v("GHSA-3j7m-hmh3-9jmp", "CVE-2016-1000237", "sanitize-html", "1.4.2", 6.1,
          "Cross-site scripting via improper sanitization", "1.4.3"),
        v("GHSA-p6mc-m468-83gw", "CVE-2020-8203", "lodash", "4.17.11", 7.4,
          "Prototype pollution in zipObjectDeep", "4.17.19"),
        v("GHSA-hrpp-h998-j3pp", "CVE-2022-24999", "qs", "6.5.2", 7.5,
          "Prototype pollution via __proto__ in query string", "6.5.3"),
    ]


def sha512_integrity(data: bytes) -> str:
    return "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()
