"""Pydantic schemas shared by every layer of Supply-Chain Guardian.

Everything that crosses a module boundary (scanner -> attack tree -> orchestrator
-> API/dashboard) is one of these models, so the JSON the dashboard receives is
exactly what the Post-Check Validator verified.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------- #
# Enumerations
# --------------------------------------------------------------------------- #
class Tier(str, Enum):
    EXPOSURE = "EXPOSURE"              # Tier 0: public route, CLI entrypoint, install hook
    INTERNAL_MODULE = "INTERNAL_MODULE"  # first-party module between a route and a package
    DIRECT_PKG = "DIRECT_PKG"          # Tier 1
    TRANSITIVE_PKG = "TRANSITIVE_PKG"  # Tier 2+
    THREAT_LEAF = "THREAT_LEAF"        # Sink: vulnerable symbol or static anomaly


class EvidenceKind(str, Enum):
    FILE_LINE = "file_line"
    LOCKFILE = "lockfile"
    MANIFEST = "manifest"
    REGISTRY_METADATA = "registry_metadata"
    DOCKERFILE_LINE = "dockerfile_line"
    WORKFLOW_LINE = "workflow_line"
    ADVISORY = "advisory"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Decision(str, Enum):
    BLOCKED = "BLOCKED"
    APPROVED = "APPROVED"


class AnomalyKind(str, Enum):
    LIFECYCLE_HOOK = "lifecycle_hook"
    SUSPICIOUS_HOOK = "suspicious_hook"
    LOCKFILE_HASH_MUTATION = "lockfile_hash_mutation"
    DOCKER_LATEST_TAG = "docker_latest_tag"
    DOCKER_UNPINNED_DIGEST = "docker_unpinned_digest"
    DOCKER_UNTRUSTED_REGISTRY = "docker_untrusted_registry"
    DOCKER_PIPE_TO_SHELL = "docker_pipe_to_shell"
    WORKFLOW_UNPINNED_ACTION = "workflow_unpinned_action"
    TYPOSQUAT = "typosquat"
    MALICIOUS_PACKAGE = "malicious_package"


# --------------------------------------------------------------------------- #
# Evidence & SBOM
# --------------------------------------------------------------------------- #
class Evidence(BaseModel):
    """A verifiable artifact backing a graph edge or a finding."""
    kind: EvidenceKind
    file: Optional[str] = None          # repo-relative path, or registry:// pseudo path
    line: Optional[int] = None
    detail: str = ""

    def label(self) -> str:
        if self.file and self.line:
            return f"{self.file}:{self.line}"
        return self.file or self.detail


class Occurrence(BaseModel):
    file_path: str
    line_number: int
    text: str = ""


class Component(BaseModel):
    name: str
    version: str
    purl: str
    ecosystem: str = "npm"
    hashes: List[str] = Field(default_factory=list)
    is_direct: bool = False
    is_dev: bool = False
    version_source: str = "lockfile"    # lockfile | manifest-exact | manifest-range-floor | cdxgen | demo
    occurrences: List[Occurrence] = Field(default_factory=list)

    @property
    def ref(self) -> str:
        return self.purl


class Sbom(BaseModel):
    source: str                          # cdxgen | lockfile | manifest | demo
    repo_path: str
    components: List[Component] = Field(default_factory=list)
    dependencies: Dict[str, List[str]] = Field(default_factory=dict)   # purl -> [purl]
    lockfile: Optional[str] = None
    notes: List[str] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=utcnow)

    def by_purl(self) -> Dict[str, Component]:
        return {c.purl: c for c in self.components}

    def by_name(self) -> Dict[str, List[Component]]:
        out: Dict[str, List[Component]] = {}
        for c in self.components:
            out.setdefault(c.name, []).append(c)
        return out


class Vulnerability(BaseModel):
    id: str                              # GHSA-/CVE-/MAL- id
    aliases: List[str] = Field(default_factory=list)
    package: str
    version: str
    purl: str
    summary: str = ""
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    severity_label: Optional[str] = None
    patched_versions: List[str] = Field(default_factory=list)
    references: List[str] = Field(default_factory=list)
    affected_functions: List[str] = Field(default_factory=list)
    source: str = "osv-api"              # osv-scanner | osv-api | demo | drift-demo
    published: Optional[str] = None

    @property
    def is_malicious(self) -> bool:
        return self.id.startswith("MAL-")


class StaticAnomaly(BaseModel):
    id: str
    kind: AnomalyKind
    title: str
    file: str
    line: int
    snippet: str
    package: Optional[str] = None
    purl: Optional[str] = None
    auto_executes: bool = False
    provenance_risk: bool = False        # contributes to the +400 provenance delta
    scored: bool = True                  # informational anomalies are listed but not scored
    detail: str = ""


# --------------------------------------------------------------------------- #
# Pre-CVE admission
# --------------------------------------------------------------------------- #
class AdmissionSignal(BaseModel):
    name: str                            # typosquat | release_age | install_hook | ...
    triggered: bool
    hard_block: bool = False
    detail: str = ""
    evidence: Optional[Evidence] = None


class AdmissionResult(BaseModel):
    package: str
    version: Optional[str]
    ecosystem: str = "npm"
    purl: str
    metadata_source: str                 # registry | mock-tarball | unavailable
    exists: bool = True
    signals: List[AdmissionSignal] = Field(default_factory=list)
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)
    install_scripts: Dict[str, str] = Field(default_factory=dict)
    published: Optional[str] = None
    typosquat_target: Optional[str] = None
    typosquat_distance: Optional[int] = None
    decision: Decision = Decision.APPROVED
    card: Optional["EvidenceCard"] = None
    errors: List[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# Attack tree
# --------------------------------------------------------------------------- #
class AttackNode(BaseModel):
    id: str
    label: str
    tier: Tier
    depth: int = 0
    purl: Optional[str] = None
    file: Optional[str] = None
    line: Optional[int] = None
    risk_elo: Optional[int] = None
    severity: Optional[Severity] = None
    finding_ids: List[str] = Field(default_factory=list)
    attrs: Dict[str, Any] = Field(default_factory=dict)


class AttackEdge(BaseModel):
    source: str
    target: str
    relation: str                        # imports | depends_on | exposes | triggers | calls
    evidence: Evidence


# --------------------------------------------------------------------------- #
# Risk Elo
# --------------------------------------------------------------------------- #
class EloFactors(BaseModel):
    """Inputs to the locked formula. Every boolean must be backed by evidence."""
    cvss: Optional[float] = None
    pre_cve_threat: bool = False
    static_hygiene: bool = False              # unpinned action / tag without digest (base 1000)
    is_symbol_called: Optional[bool] = None   # None = unknown (no symbol data) -> 0
    auto_exec_hook: bool = False
    public_route: bool = False
    dev_or_test_only: bool = False
    provenance_flags: List[str] = Field(default_factory=list)


class EloDelta(BaseModel):
    label: str
    value: int


class EloBreakdown(BaseModel):
    factors: EloFactors
    base: int
    base_reason: str
    deltas: List[EloDelta] = Field(default_factory=list)
    total: int
    severity: Severity
    formula_version: str = "elo-v1"


# --------------------------------------------------------------------------- #
# Findings & 5-field evidence cards
# --------------------------------------------------------------------------- #
class Finding(BaseModel):
    id: str
    title: str
    kind: Literal["vulnerability", "anomaly", "admission"]
    purl: Optional[str] = None
    package: Optional[str] = None
    version: Optional[str] = None
    advisory_ids: List[str] = Field(default_factory=list)
    sink_node: str
    elo: EloBreakdown
    call_chain_depth: Optional[int] = None
    primary_evidence: Optional[Evidence] = None
    symbols: List[str] = Field(default_factory=list)
    patched_versions: List[str] = Field(default_factory=list)
    references: List[str] = Field(default_factory=list)


class CardFinding(BaseModel):          # field 1
    finding_id: str
    title: str
    purl: Optional[str]
    advisory_ids: List[str] = Field(default_factory=list)
    severity: Severity


class CardLocation(BaseModel):         # field 2
    local_file: str
    local_line: int
    code_snippet: str


class CardAttackPath(BaseModel):       # field 3
    nodes: List[str]
    hops: List[str]                     # human-readable "A -> B (evidence)"
    call_chain_depth: Optional[int] = None


class CardRemediation(BaseModel):      # field 5
    summary: str
    fix_command: str
    references: List[str] = Field(default_factory=list)


class ValidationReport(BaseModel):
    passed: bool
    checks: Dict[str, bool] = Field(default_factory=dict)
    errors: List[str] = Field(default_factory=list)
    retries: int = 0
    fell_back_to_deterministic: bool = False


class EvidenceCard(BaseModel):
    finding: CardFinding
    location: CardLocation
    attack_path: CardAttackPath
    risk: EloBreakdown                  # field 4 (risk_elo == risk.total)
    remediation: CardRemediation
    narrative: str = ""
    author: Literal["llm", "deterministic"] = "deterministic"
    validation: Optional[ValidationReport] = None

    @property
    def risk_elo(self) -> int:
        return self.risk.total


AdmissionResult.model_rebuild()


# --------------------------------------------------------------------------- #
# Scan results, replay, daemon, API payloads
# --------------------------------------------------------------------------- #
class Kpis(BaseModel):
    total_components: int = 0
    raw_scanner_alerts: int = 0
    actionable_critical: int = 0
    downgraded_noise: int = 0


class GraphPayload(BaseModel):
    nodes: List[AttackNode] = Field(default_factory=list)
    edges: List[AttackEdge] = Field(default_factory=list)


class ScanResult(BaseModel):
    repo_path: str
    sbom_source: str
    vuln_source: str
    kpis: Kpis
    findings: List[Finding] = Field(default_factory=list)
    cards: List[EvidenceCard] = Field(default_factory=list)
    anomalies: List[StaticAnomaly] = Field(default_factory=list)
    graph: GraphPayload = Field(default_factory=GraphPayload)
    dependency_graph: GraphPayload = Field(default_factory=GraphPayload)   # every discovered component
    notes: List[str] = Field(default_factory=list)
    finished_at: datetime = Field(default_factory=utcnow)


class CommitReport(BaseModel):
    sha: str
    subject: str
    added: List[str] = Field(default_factory=list)
    removed: List[str] = Field(default_factory=list)
    changed: List[str] = Field(default_factory=list)
    anomalies: List[StaticAnomaly] = Field(default_factory=list)
    admissions: List[AdmissionResult] = Field(default_factory=list)
    triaged: bool = False


class ReplayResult(BaseModel):
    repo_path: str
    commits: List[CommitReport] = Field(default_factory=list)
    notes: List[str] = Field(default_factory=list)


class SimulationResult(BaseModel):
    sandbox_dir: str
    sandbox_removed: bool
    injected: List[str]
    admission: AdmissionResult
    anomalies: List[StaticAnomaly]
    cards: List[EvidenceCard]
    blocked: bool
    max_elo: int
    graph: GraphPayload = Field(default_factory=GraphPayload)
    safety_notes: List[str] = Field(default_factory=list)


class DaemonStatus(BaseModel):
    running: bool
    interval_seconds: int
    polls: int = 0
    last_poll: Optional[datetime] = None
    known_advisories: int = 0
    new_advisories: List[str] = Field(default_factory=list)
    last_error: Optional[str] = None


class LogEvent(BaseModel):
    ts: datetime = Field(default_factory=utcnow)
    source: str
    message: str
    level: Literal["info", "tool", "warn", "error", "success", "thought"] = "info"


class ScanRequest(BaseModel):
    repo: str
    use_llm: bool = True
    resolve_lockfile: bool = False


class CheckPkgRequest(BaseModel):
    repo: str
    pkg: str


class ReplayRequest(BaseModel):
    repo: str
    commits: int = Field(default=5, ge=1, le=50)


class SimulateRequest(BaseModel):
    repo: str


class DaemonToggleRequest(BaseModel):
    repo: str
    interval: int = Field(default=30, ge=10, le=3600)
    demo_drift: bool = False


class ChatRequest(BaseModel):
    session_id: str = Field(default="default", max_length=64)
    message: str = Field(max_length=2000)


class ChatResponse(BaseModel):
    answer: str
    author: Literal["llm", "deterministic"]
    referenced_findings: List[str] = Field(default_factory=list)
