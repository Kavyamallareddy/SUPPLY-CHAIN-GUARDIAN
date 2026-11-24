"""Bounded, evidence-backed Attack Tree + deterministic Risk Elo engine.

Invariant: every edge in the graph carries an `Evidence` object pointing at a
verifiable artifact (file:line, lockfile entry, registry metadata, Dockerfile
line). The LLM layer may *read* this graph but can never add edges or change a
score: `compute_risk_elo` is the single source of truth and the Post-Check
Validator recomputes it for every card.
"""
from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

import networkx as nx

from models import (
    AdmissionResult,
    AnomalyKind,
    AttackEdge,
    AttackNode,
    Component,
    EloBreakdown,
    EloDelta,
    EloFactors,
    Evidence,
    EvidenceKind,
    Finding,
    GraphPayload,
    Kpis,
    Sbom,
    Severity,
    StaticAnomaly,
    Tier,
    Vulnerability,
)
from scanners import CURATED_SYMBOLS, ImportSite, LogFn, _noop_log, read_text

# --------------------------------------------------------------------------- #
# Locked formula
# --------------------------------------------------------------------------- #
PRE_CVE_BASE = 1800
HYGIENE_BASE = 1000
DELTA_SYMBOL_CALLED = 350
DELTA_AUTO_EXEC_HOOK = 500
DELTA_SYMBOL_NOT_CALLED = -600
DELTA_PUBLIC_ROUTE = 200
DELTA_DEV_OR_TEST = -300
DELTA_PROVENANCE = 400


def severity_for(score: int) -> Severity:
    if score >= 1800:
        return Severity.CRITICAL
    if score >= 1400:
        return Severity.HIGH
    if score >= 1000:
        return Severity.MEDIUM
    return Severity.LOW


def compute_risk_elo(f: EloFactors) -> EloBreakdown:
    """The only function that produces a Risk Elo. Pure and deterministic."""
    candidates: List[Tuple[int, str]] = []
    if f.cvss is not None:
        candidates.append((int(round(f.cvss * 200)), f"CVSS {f.cvss:.1f} x 200"))
    if f.pre_cve_threat:
        candidates.append((PRE_CVE_BASE, "pre-CVE tampering / typosquat / malicious hook"))
    if f.static_hygiene:
        candidates.append((HYGIENE_BASE, "static supply-chain hygiene anomaly"))
    base, reason = max(candidates) if candidates else (0, "no threat signal")
    deltas: List[EloDelta] = []
    if f.is_symbol_called is True:
        deltas.append(EloDelta(label="Tier 0 -> vulnerable symbol path confirmed", value=DELTA_SYMBOL_CALLED))
    elif f.is_symbol_called is False:
        deltas.append(EloDelta(label="package imported but vulnerable symbol never called", value=DELTA_SYMBOL_NOT_CALLED))
    if f.auto_exec_hook:
        deltas.append(EloDelta(label="auto-executing install hook", value=DELTA_AUTO_EXEC_HOOK))
    if f.public_route:
        deltas.append(EloDelta(label="reachable from public unauthenticated route", value=DELTA_PUBLIC_ROUTE))
    if f.dev_or_test_only:
        deltas.append(EloDelta(label="isolated to devDependencies / test code", value=DELTA_DEV_OR_TEST))
    if f.provenance_flags:
        deltas.append(EloDelta(label="provenance: " + "; ".join(sorted(set(f.provenance_flags))), value=DELTA_PROVENANCE))
    total = base + sum(d.value for d in deltas)
    return EloBreakdown(factors=f, base=base, base_reason=reason, deltas=deltas, total=total,
                        severity=severity_for(total))


# --------------------------------------------------------------------------- #
# Reachability helpers
# --------------------------------------------------------------------------- #
# Transitive packages whose vulnerable symbol is invoked by their parent on
# every request. Without this, `qs.parse` would look "never called" because the
# app never calls it directly - a dangerous false downgrade.
KNOWN_INTERNAL_CALLS: Dict[str, Dict[str, str]] = {
    "qs": {"express": "express query parser calls qs.parse() on every request",
           "body-parser": "body-parser urlencoded() calls qs.parse() on request bodies"},
    "path-to-regexp": {"express": "express router compiles every route with path-to-regexp"},
    "send": {"express": "express.static / res.sendFile delegate to send"},
    "cookie": {"cookie-parser": "cookie-parser parses every Cookie header with cookie.parse()"},
    "jws": {"jsonwebtoken": "jsonwebtoken.verify/decode delegate to jws"},
}
EXPOSURE_FILES = re.compile(r"^(routes/|server\.(ts|js)$|app\.(ts|js)$|bin/|cli\.)")
AUTH_MARKERS = ("isAuthorized(", "denyAll(", "appendUserId(", "isAccounting(", "isDeluxe(")


@dataclass
class CallSite:
    file: str
    line: int
    text: str
    symbol: str


def _strip_ext(p: str) -> str:
    return re.sub(r"\.(ts|js|mjs|cjs|tsx|jsx)$", "", p)


class _SourceCache:
    def __init__(self, repo: Path) -> None:
        self.repo = repo
        self._cache: Dict[str, List[str]] = {}

    def lines(self, rel: str) -> List[str]:
        if rel not in self._cache:
            self._cache[rel] = (read_text(self.repo / rel, 1_000_000) or "").splitlines()
        return self._cache[rel]


def find_symbol_calls(site: ImportSite, symbols: Iterable[str], src: _SourceCache) -> Optional[CallSite]:
    lines = src.lines(site.file)
    patterns: List[Tuple[str, re.Pattern]] = []
    for sym in symbols:
        if sym == "<default>":   # the package's main export is used at all (called or member access)
            for local in filter(None, [site.default_name, site.namespace]):
                patterns.append((f"{local}()", re.compile(rf"(?<![\w.]){re.escape(local)}\s*\(")))
                patterns.append((f"{local}.*", re.compile(rf"(?<![\w.]){re.escape(local)}\.\w+")))
            for local in site.named:
                patterns.append((local, re.compile(rf"(?<![\w.]){re.escape(local)}\b")))
            continue
        for local in filter(None, [site.default_name, site.namespace]):
            patterns.append((f"{local}.{sym}", re.compile(rf"\b{re.escape(local)}\.{re.escape(sym)}\s*\(")))
        for local, imported in site.named.items():
            if imported == sym:
                patterns.append((sym, re.compile(rf"(?<![\w.]){re.escape(local)}\s*\(")))
    for i, ln in enumerate(lines, 1):
        if i == site.line or ln.lstrip().startswith(("import ", "//", "*")):
            continue
        for label, pat in patterns:
            if pat.search(ln):
                return CallSite(site.file, i, ln.strip(), label)
    return None


# --------------------------------------------------------------------------- #
# Dependency (discovery) graph: every component, risky or not
# --------------------------------------------------------------------------- #
def build_dependency_graph(sbom: Sbom, findings: Iterable[Finding], project_name: str) -> GraphPayload:
    """Project -> direct deps -> transitive deps, with each package's worst finding overlaid."""
    worst: Dict[str, Finding] = {}
    ids: Dict[str, List[str]] = {}
    for f in findings:
        if not f.purl:
            continue
        ids.setdefault(f.purl, []).append(f.id)
        if f.purl not in worst or f.elo.total > worst[f.purl].elo.total:
            worst[f.purl] = f
    g = nx.DiGraph()
    root = "project"
    g.add_node(root)
    for c in sbom.components:
        g.add_node(c.purl)
    manifest_ev = {c.purl: next((o for o in c.occurrences if o.file_path == "package.json"), None)
                   for c in sbom.components}
    edges: List[AttackEdge] = []
    for c in sbom.components:
        if c.is_direct:
            occ = manifest_ev[c.purl]
            g.add_edge(root, c.purl)
            edges.append(AttackEdge(source=root, target=c.purl, relation="declares", evidence=Evidence(
                kind=EvidenceKind.MANIFEST, file="package.json", line=occ.line_number if occ else None,
                detail=occ.text if occ else f"{c.name} declared in package.json")))
    comp = sbom.by_purl()
    for src, dsts in sbom.dependencies.items():
        for d in dsts:
            if src in comp and d in comp and src != d and not g.has_edge(src, d):
                g.add_edge(src, d)
                edges.append(AttackEdge(source=src, target=d, relation="depends_on", evidence=Evidence(
                    kind=EvidenceKind.LOCKFILE, file=sbom.lockfile or "sbom.json",
                    detail=f"{comp[src].name}@{comp[src].version} -> {comp[d].name}@{comp[d].version}")))
    depth = nx.single_source_shortest_path_length(g, root)
    nodes = [AttackNode(id=root, label=f"{project_name}\n(project)", tier=Tier.EXPOSURE, depth=0,
                        attrs={"root": True, "components": len(sbom.components)})]
    for c in sbom.components:
        f = worst.get(c.purl)
        nodes.append(AttackNode(
            id=c.purl, label=f"{c.name}@{c.version}", tier=Tier.DIRECT_PKG if c.is_direct else Tier.TRANSITIVE_PKG,
            depth=depth.get(c.purl, 0), purl=c.purl, risk_elo=f.elo.total if f else None,
            severity=f.elo.severity if f else None, finding_ids=sorted(ids.get(c.purl, [])),
            attrs={"dev": c.is_dev, "version_source": c.version_source, "dependencies": g.out_degree(c.purl),
                   "dependents": g.in_degree(c.purl), "reachable_from_project": c.purl in depth,
                   "occurrences": [f"{o.file_path}:{o.line_number}" for o in c.occurrences[:4]]}))
    return GraphPayload(nodes=nodes, edges=edges)


# --------------------------------------------------------------------------- #
# Attack tree
# --------------------------------------------------------------------------- #
class AttackTree:
    MAX_EXPOSURES_PER_PKG = 6
    MAX_IMPORTERS_PER_MODULE = 5
    MAX_TRANSITIVE_DEPTH = 8

    def __init__(self, repo: Path, sbom: Sbom, imports: List[ImportSite], vulns: List[Vulnerability],
                 anomalies: List[StaticAnomaly], log: LogFn = _noop_log) -> None:
        self.repo = repo
        self.sbom = sbom
        self.imports = imports
        self.vulns = vulns
        self.anomalies = anomalies
        self.log = log
        self.g = nx.DiGraph()
        self.findings: Dict[str, Finding] = {}
        self.src = _SourceCache(repo)
        self.comp_by_purl = sbom.by_purl()
        self._public: Dict[str, Optional[Evidence]] = {}
        self._counter = 0

    # ---- graph primitives ------------------------------------------------- #
    def _node(self, nid: str, label: str, tier: Tier, **attrs: object) -> str:
        if nid not in self.g:
            self.g.add_node(nid, label=label, tier=tier, finding_ids=[], risk_elo=None, severity=None, **attrs)
        return nid

    def _edge(self, src: str, dst: str, relation: str, ev: Evidence) -> None:
        if not self.g.has_edge(src, dst):
            self.g.add_edge(src, dst, relation=relation, evidence=ev)

    def _pkg_node(self, comp: Component) -> str:
        tier = Tier.DIRECT_PKG if comp.is_direct else Tier.TRANSITIVE_PKG
        return self._node(f"pkg:{comp.purl}", f"{comp.name}@{comp.version}", tier, purl=comp.purl,
                          dev=comp.is_dev, version_source=comp.version_source)

    # ---- exposure analysis ------------------------------------------------- #
    def _compute_public_routes(self) -> None:
        """Map route files -> evidence of an unauthenticated mount in server.ts/app.ts."""
        for entry in ("server.ts", "server.js", "app.ts", "app.js"):
            lines = self.src.lines(entry)
            if not lines:
                continue
            self._public[entry] = Evidence(kind=EvidenceKind.FILE_LINE, file=entry, line=1,
                                           detail="HTTP server entrypoint")
            bindings: Dict[str, str] = {}
            for s in self.imports:
                if s.file != entry or not s.module.startswith("."):
                    continue
                target = posixpath.normpath(posixpath.join(posixpath.dirname(entry), s.module))
                for local in filter(None, [s.default_name, s.namespace, *s.named.keys()]):
                    bindings[local] = _strip_ext(target)
            authed: List[str] = []
            for ln in lines:
                m = re.search(r"app\.use\(\s*['\"]([^'\"]+)['\"]\s*,\s*[\w.]*(" + "|".join(map(re.escape, AUTH_MARKERS)) + ")", ln)
                if m:
                    authed.append(m.group(1).split(":")[0].rstrip("/"))
            for i, ln in enumerate(lines, 1):
                if not re.search(r"\bapp\.(get|post|put|patch|delete|use|all)\s*\(", ln):
                    continue
                path_m = re.search(r"\(\s*['\"](/[^'\"]*)['\"]", ln)
                route_path = path_m.group(1) if path_m else "/"
                if any(mk in ln for mk in AUTH_MARKERS):
                    continue
                if any(route_path.startswith(p) and p for p in authed):
                    continue
                for local, target in bindings.items():
                    if re.search(rf"\b{re.escape(local)}\b", ln) and target not in self._public:
                        self._public[target] = Evidence(kind=EvidenceKind.FILE_LINE, file=entry, line=i,
                                                        detail=f"unauthenticated mount {route_path}")

    def _is_public(self, rel: str) -> Optional[Evidence]:
        return self._public.get(_strip_ext(rel)) or self._public.get(rel)

    def _importers_of(self, rel_module: str) -> List[ImportSite]:
        target = _strip_ext(rel_module)
        out = []
        for s in self.imports:
            if s.module.startswith("."):
                resolved = posixpath.normpath(posixpath.join(posixpath.dirname(s.file), s.module))
                if _strip_ext(resolved) == target or resolved == target + "/index":
                    out.append(s)
        return out

    def _attach_exposures(self, comp: Component, pkg_node: str) -> List[ImportSite]:
        sites = [s for s in self.imports if s.package == comp.name]
        sites.sort(key=lambda s: (s.is_test, self._is_public(s.file) is None, s.file))
        for s in sites[: self.MAX_EXPOSURES_PER_PKG]:
            ev = Evidence(kind=EvidenceKind.FILE_LINE, file=s.file, line=s.line, detail=s.text)
            if EXPOSURE_FILES.match(s.file) or s.is_test:
                pub = self._is_public(s.file)
                nid = self._node(f"exp:{s.file}", s.file, Tier.EXPOSURE, file=s.file, line=s.line,
                                 public=pub is not None and not s.is_test, test=s.is_test,
                                 public_evidence=pub.model_dump() if pub else None)
                self._edge(nid, pkg_node, "imports", ev)
                continue
            mid = self._node(f"mod:{s.file}", s.file, Tier.INTERNAL_MODULE, file=s.file, line=s.line)
            self._edge(mid, pkg_node, "imports", ev)
            frontier = [(s.file, mid)]
            for _hop in range(2):
                nxt: List[Tuple[str, str]] = []
                for mod_file, mod_node in frontier:
                    importers = self._importers_of(mod_file)
                    importers.sort(key=lambda x: (x.is_test, self._is_public(x.file) is None, x.file))
                    for imp in importers[: self.MAX_IMPORTERS_PER_MODULE]:
                        iev = Evidence(kind=EvidenceKind.FILE_LINE, file=imp.file, line=imp.line, detail=imp.text)
                        if EXPOSURE_FILES.match(imp.file) or imp.is_test:
                            pub = self._is_public(imp.file)
                            eid = self._node(f"exp:{imp.file}", imp.file, Tier.EXPOSURE, file=imp.file, line=imp.line,
                                             public=pub is not None and not imp.is_test, test=imp.is_test,
                                             public_evidence=pub.model_dump() if pub else None)
                            self._edge(eid, mod_node, "imports", iev)
                        else:
                            m2 = self._node(f"mod:{imp.file}", imp.file, Tier.INTERNAL_MODULE, file=imp.file, line=imp.line)
                            self._edge(m2, mod_node, "imports", iev)
                            nxt.append((imp.file, m2))
                frontier = nxt
        return sites

    # ---- dependency paths -------------------------------------------------- #
    def _dependency_paths(self, purl: str) -> List[List[str]]:
        """Shortest dependency chains direct -> ... -> purl (purl lists)."""
        comp = self.comp_by_purl.get(purl)
        if comp is None:
            return []
        if comp.is_direct:
            return [[purl]]
        rev = nx.DiGraph()
        for src, dsts in self.sbom.dependencies.items():
            for d in dsts:
                rev.add_edge(d, src)
        if purl not in rev:
            return []
        reach = nx.single_source_shortest_path(rev, purl, cutoff=self.MAX_TRANSITIVE_DEPTH)
        directs = [n for n in reach if n in self.comp_by_purl and self.comp_by_purl[n].is_direct]
        directs.sort(key=lambda n: (self.comp_by_purl[n].is_dev, len(reach[n])))
        return [list(reversed(reach[d])) for d in directs[:3]]

    def _add_dependency_chain(self, chain: List[str]) -> None:
        for a, b in zip(chain, chain[1:]):
            ca, cb = self.comp_by_purl[a], self.comp_by_purl[b]
            ev = Evidence(kind=EvidenceKind.LOCKFILE, file=self.sbom.lockfile or "sbom.json",
                          detail=f"{ca.name}@{ca.version} depends on {cb.name}@{cb.version}")
            self._edge(self._pkg_node(ca), self._pkg_node(cb), "depends_on", ev)

    # ---- findings ---------------------------------------------------------- #
    def _new_id(self) -> str:
        self._counter += 1
        return f"F-{self._counter:03d}"

    def _register(self, finding: Finding) -> None:
        self.findings[finding.id] = finding
        sink = self.g.nodes[finding.sink_node]
        sink["finding_ids"].append(finding.id)
        sink["risk_elo"] = finding.elo.total
        sink["severity"] = finding.elo.severity
        for anc in nx.ancestors(self.g, finding.sink_node):
            node = self.g.nodes[anc]
            node["finding_ids"].append(finding.id)
            if node["risk_elo"] is None or finding.elo.total > node["risk_elo"]:
                node["risk_elo"] = finding.elo.total
                node["severity"] = finding.elo.severity
        finding.call_chain_depth = self.call_chain_depth(finding.sink_node)

    def call_chain_depth(self, sink: str) -> Optional[int]:
        best: Optional[int] = None
        for anc in nx.ancestors(self.g, sink):
            if self.g.nodes[anc]["tier"] == Tier.EXPOSURE:
                d = nx.shortest_path_length(self.g, anc, sink)
                best = d if best is None else min(best, d)
        return best

    def _path_exposure(self, pkg_node: str) -> Tuple[bool, bool]:
        """(any public non-test exposure upstream, all exposures are test-only)."""
        exps = [a for a in nx.ancestors(self.g, pkg_node) if self.g.nodes[a]["tier"] == Tier.EXPOSURE]
        public = any(self.g.nodes[e].get("public") for e in exps)
        test_only = bool(exps) and all(self.g.nodes[e].get("test") for e in exps)
        return public, test_only

    def _reachability(self, v: Vulnerability, comp: Component, chain: List[str]) -> Tuple[Optional[bool], Optional[CallSite], List[str]]:
        symbols = v.affected_functions or CURATED_SYMBOLS.get(comp.name, [])
        if comp.is_direct:
            if not symbols:
                return None, None, []
            sites = [s for s in self.imports if s.package == comp.name and not s.is_test] or \
                    [s for s in self.imports if s.package == comp.name]
            if not sites:
                return None, None, symbols
            for s in sites:
                hit = find_symbol_calls(s, symbols, self.src)
                if hit:
                    return True, hit, symbols
            # Re-export hop: first-party modules that wrap the package (e.g. models/index.ts
            # exporting a Sequelize instance) and are called as `<anything>.symbol(`.
            method_syms = [s for s in symbols if not s.startswith("<")]
            for s in sites:
                for imp in self._importers_of(s.file):
                    lines = self.src.lines(imp.file)
                    for i, ln in enumerate(lines, 1):
                        for sym in method_syms:
                            if re.search(rf"\.{re.escape(sym)}\s*\(", ln) and not ln.lstrip().startswith("//"):
                                return True, CallSite(imp.file, i, ln.strip(), f".{sym}() via first-party re-export"), symbols
            return False, None, symbols
        parents = {self.comp_by_purl[p].name for p in chain[:-1] if p in self.comp_by_purl}
        for parent, why in KNOWN_INTERNAL_CALLS.get(comp.name, {}).items():
            if parent in parents:
                psite = next((s for s in self.imports if s.package == parent and not s.is_test), None)
                if psite:
                    return True, CallSite(psite.file, psite.line, psite.text, f"{parent} -> {comp.name}: {why}"), symbols
        return None, None, symbols

    def add_vulnerabilities(self) -> None:
        seen: Set[Tuple[str, str]] = set()
        for v in self.vulns:
            if (v.id, v.purl) in seen or v.purl not in self.comp_by_purl:
                continue
            seen.add((v.id, v.purl))
            comp = self.comp_by_purl[v.purl]
            chains = self._dependency_paths(v.purl)
            if not chains:
                continue
            for chain in chains:
                self._add_dependency_chain(chain)
                direct = self.comp_by_purl[chain[0]]
                self._attach_exposures(direct, self._pkg_node(direct))
            pkg_node = self._pkg_node(comp)
            called, site, symbols = self._reachability(v, comp, chains[0])
            sym_label = site.symbol if site else (", ".join(symbols) if symbols else "unknown symbol")
            sink = self._node(f"sink:{v.id}:{v.purl}", f"{v.id}\n{comp.name}.{symbols[0] if symbols else '?'}",
                              Tier.THREAT_LEAF, purl=v.purl, advisory=v.id)
            if site:
                ev = Evidence(kind=EvidenceKind.FILE_LINE, file=site.file, line=site.line, detail=site.text)
                rel = "calls"
            else:
                ev = Evidence(kind=EvidenceKind.ADVISORY, file=v.id, detail=v.summary[:160])
                rel = "affected_by"
            self._edge(pkg_node, sink, rel, ev)
            public, test_only = self._path_exposure(pkg_node)
            provenance = [f"lockfile hash mutated for {comp.name}" for a in self.anomalies
                          if a.kind == AnomalyKind.LOCKFILE_HASH_MUTATION and a.purl == v.purl]
            factors = EloFactors(cvss=v.cvss_score if v.cvss_score is not None else 5.0,
                                 pre_cve_threat=v.is_malicious, is_symbol_called=called,
                                 public_route=public and called is not False,
                                 dev_or_test_only=comp.is_dev or test_only, provenance_flags=provenance)
            primary = ev if site else next(
                (Evidence(kind=EvidenceKind.MANIFEST, file=o.file_path, line=o.line_number, detail=o.text)
                 for o in self.comp_by_purl[chains[0][0]].occurrences if o.file_path == "package.json"), ev)
            self._register(Finding(
                id=self._new_id(), title=f"{v.id} in {comp.name}@{comp.version}: {v.summary[:90]}",
                kind="vulnerability", purl=v.purl, package=comp.name, version=comp.version,
                advisory_ids=[v.id, *v.aliases], sink_node=sink, elo=compute_risk_elo(factors),
                primary_evidence=primary, symbols=[sym_label], patched_versions=v.patched_versions,
                references=v.references))

    def add_anomalies(self) -> None:
        for a in self.anomalies:
            if not a.scored:
                continue
            kind_node = {
                AnomalyKind.SUSPICIOUS_HOOK: ("hook", "npm lifecycle hook"),
                AnomalyKind.LIFECYCLE_HOOK: ("hook", "npm lifecycle hook"),
                AnomalyKind.LOCKFILE_HASH_MUTATION: ("lockfile", "lockfile integrity"),
            }.get(a.kind, ("config", "build/CI config"))
            exp = self._node(f"exp:{kind_node[0]}:{a.file}", f"{a.file}\n({kind_node[1]})", Tier.EXPOSURE,
                             file=a.file, line=a.line, public=False, test=False)
            ev_kind = EvidenceKind.DOCKERFILE_LINE if "docker" in a.kind.value else (
                EvidenceKind.WORKFLOW_LINE if "workflow" in a.kind.value else (
                    EvidenceKind.LOCKFILE if "lockfile" in a.kind.value else EvidenceKind.MANIFEST))
            ev = Evidence(kind=ev_kind, file=a.file, line=a.line, detail=a.snippet)
            sink = self._node(f"sink:{a.id}", f"{a.kind.value}\n{a.file}:{a.line}", Tier.THREAT_LEAF, anomaly=a.id)
            if a.purl and a.purl in self.comp_by_purl:
                pkg = self._pkg_node(self.comp_by_purl[a.purl])
                self._edge(exp, pkg, "resolves", ev)
                self._edge(pkg, sink, "tampered", ev)
            else:
                self._edge(exp, sink, "triggers", ev)
            flags: List[str] = []
            if a.kind == AnomalyKind.LOCKFILE_HASH_MUTATION:
                flags.append("lockfile SHA hash mutated without version bump")
            elif a.kind == AnomalyKind.DOCKER_LATEST_TAG:
                flags.append("unpinned :latest Docker tag")
            elif a.provenance_risk:
                flags.append(a.title)
            pre_cve = a.kind in (AnomalyKind.SUSPICIOUS_HOOK, AnomalyKind.LOCKFILE_HASH_MUTATION,
                                 AnomalyKind.TYPOSQUAT, AnomalyKind.MALICIOUS_PACKAGE)
            factors = EloFactors(pre_cve_threat=pre_cve, static_hygiene=not pre_cve,
                                 auto_exec_hook=a.auto_executes and a.kind == AnomalyKind.SUSPICIOUS_HOOK,
                                 provenance_flags=flags)
            self._register(Finding(
                id=self._new_id(), title=a.title, kind="anomaly", purl=a.purl, package=a.package,
                advisory_ids=[a.id], sink_node=sink, elo=compute_risk_elo(factors), primary_evidence=ev,
                symbols=[a.kind.value]))

    def add_admission(self, res: AdmissionResult) -> Finding:
        """Attach a pre-install candidate to the tree (Tier 0 = admission hook)."""
        exp = self._node("exp:pre-install-gate", "pre-install\nadmission gate", Tier.EXPOSURE, public=False, test=False)
        shown = f"{res.package}@{res.version or 'latest'}"
        pkg = self._node(f"pkg:{res.purl}", f"{shown} (candidate)", Tier.DIRECT_PKG,
                         purl=res.purl, candidate=True)
        manifest_ev = Evidence(kind=EvidenceKind.REGISTRY_METADATA, file=f"registry://{res.ecosystem}/{res.package}",
                               detail=f"candidate {res.package}@{res.version} ({res.metadata_source})")
        self._edge(exp, pkg, "would_install", manifest_ev)
        triggered = [s for s in res.signals if s.triggered]
        sink = self._node(f"sink:admission:{res.purl}", f"pre-CVE\n{res.package}", Tier.THREAT_LEAF, purl=res.purl)
        # Most concrete artifact first: the install hook itself, then other hard blocks, then anything.
        primary = next((s.evidence for s in triggered if s.name == "install_hook" and s.hard_block and s.evidence),
                       next((s.evidence for s in triggered if s.hard_block and s.evidence),
                            next((s.evidence for s in triggered if s.evidence), manifest_ev)))
        self._edge(pkg, sink, "flags", primary)
        hook_sinks = any(s.name == "install_hook" and s.hard_block for s in triggered)
        flags: List[str] = []
        if res.typosquat_distance == 1:
            flags.append(f"typosquat distance 1 to {res.typosquat_target}")
        if any(s.name == "release_age" for s in triggered):
            flags.append("package age < 7 days")
        pre_cve = hook_sinks or res.typosquat_distance == 1 or any(
            s.name in ("known_malicious", "nonexistent_package") for s in triggered)
        cvss = max((v.cvss_score or 0.0 for v in res.vulnerabilities), default=None) if res.vulnerabilities else None
        factors = EloFactors(cvss=cvss, pre_cve_threat=pre_cve,
                             auto_exec_hook=any(s.name == "install_hook" for s in triggered),
                             provenance_flags=flags)
        finding = Finding(
            id=self._new_id(), title=f"Pre-install admission: {shown}", kind="admission",
            purl=res.purl, package=res.package, version=res.version,
            advisory_ids=[v.id for v in res.vulnerabilities] or [s.name for s in triggered],
            sink_node=sink, elo=compute_risk_elo(factors), primary_evidence=primary,
            symbols=[s.name for s in triggered])
        self._register(finding)
        return finding

    # ---- build & export ---------------------------------------------------- #
    def build(self) -> "AttackTree":
        self._compute_public_routes()
        self.add_vulnerabilities()
        self.add_anomalies()
        self._renumber()
        self._assign_depths()
        self.log("attack-tree", f"graph: {self.g.number_of_nodes()} nodes, {self.g.number_of_edges()} evidence-backed "
                                f"edges, {len(self.findings)} findings", "success")
        return self

    def _renumber(self) -> None:
        """Stable ordering: highest Elo first."""
        ordered = sorted(self.findings.values(), key=lambda f: (-f.elo.total, f.title))
        mapping = {f.id: f"F-{i:03d}" for i, f in enumerate(ordered, 1)}
        for f in ordered:
            f.id = mapping[f.id]
        self.findings = {f.id: f for f in ordered}
        for _, data in self.g.nodes(data=True):
            data["finding_ids"] = sorted({mapping.get(x, x) for x in data["finding_ids"]})
        self._counter = len(ordered)

    def _assign_depths(self) -> None:
        roots = [n for n, d in self.g.nodes(data=True) if d["tier"] == Tier.EXPOSURE]
        dist = nx.multi_source_dijkstra_path_length(self.g, roots) if roots else {}
        for n, d in self.g.nodes(data=True):
            d["depth"] = int(dist.get(n, 0))

    def paths_for(self, finding_id: str, limit: int = 5) -> List[List[str]]:
        f = self.findings.get(finding_id)
        if f is None:
            return []
        paths = []
        for anc in nx.ancestors(self.g, f.sink_node):
            if self.g.nodes[anc]["tier"] == Tier.EXPOSURE:
                paths.append(nx.shortest_path(self.g, anc, f.sink_node))
        paths.sort(key=lambda p: (not self.g.nodes[p[0]].get("public"), bool(self.g.nodes[p[0]].get("test")), len(p), p[0]))
        return paths[:limit]

    def edge_evidence(self, a: str, b: str) -> Optional[Evidence]:
        return self.g.edges[a, b]["evidence"] if self.g.has_edge(a, b) else None

    def kpis(self) -> Kpis:
        fs = list(self.findings.values())
        return Kpis(
            total_components=len(self.sbom.components),
            raw_scanner_alerts=len({(v.id, v.purl) for v in self.vulns}) + sum(a.scored for a in self.anomalies),
            actionable_critical=sum(f.elo.severity == Severity.CRITICAL for f in fs),
            downgraded_noise=sum(f.elo.severity == Severity.LOW for f in fs),
        )

    def to_payload(self) -> GraphPayload:
        nodes = []
        for nid, d in self.g.nodes(data=True):
            extra = {k: v for k, v in d.items() if k not in {"label", "tier", "finding_ids", "risk_elo", "severity",
                                                              "depth", "purl", "file", "line"}}
            nodes.append(AttackNode(id=nid, label=d["label"], tier=d["tier"], depth=d.get("depth", 0),
                                    purl=d.get("purl"), file=d.get("file"), line=d.get("line"),
                                    risk_elo=d["risk_elo"], severity=d["severity"],
                                    finding_ids=d["finding_ids"], attrs=extra))
        edges = [AttackEdge(source=a, target=b, relation=d["relation"], evidence=d["evidence"])
                 for a, b, d in self.g.edges(data=True)]
        return GraphPayload(nodes=nodes, edges=edges)
