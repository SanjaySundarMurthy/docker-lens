"""Data models for Docker Lens."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

# ── Enums ─────────────────────────────────────────────────────────────────


class Severity(str, Enum):
    """Severity levels for findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class RuleCategory(str, Enum):
    """Categories for Dockerfile lint rules."""

    SECURITY = "Security"
    EFFICIENCY = "Efficiency"
    MAINTAINABILITY = "Maintainability"
    RELIABILITY = "Reliability"


class Grade(str, Enum):
    """Score grades."""

    A_PLUS = "A+"
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"


def grade_from_score(score: int) -> Grade:
    """Convert a numeric score to a letter grade."""
    if score >= 95:
        return Grade.A_PLUS
    if score >= 85:
        return Grade.A
    if score >= 75:
        return Grade.B
    if score >= 65:
        return Grade.C
    if score >= 50:
        return Grade.D
    return Grade.F


# ── Dockerfile models ─────────────────────────────────────────────────────


@dataclass
class DockerfileInstruction:
    """A parsed Dockerfile instruction."""

    line_number: int
    instruction: str  # FROM, RUN, COPY, ADD, ENV, ...
    arguments: str
    raw: str


@dataclass
class LintRule:
    """A Dockerfile lint rule definition."""

    rule_id: str
    category: RuleCategory
    severity: Severity
    title: str
    description: str
    fix: str
    url: str = ""


@dataclass
class LintFinding:
    """A single lint violation."""

    rule: LintRule
    line: int
    message: str
    context: str = ""
    fix_suggestion: str = ""


@dataclass
class LintResult:
    """Result of linting a Dockerfile."""

    file_path: str
    findings: list[LintFinding] = field(default_factory=list)
    instructions: list[DockerfileInstruction] = field(default_factory=list)
    score: int = 100
    grade: Grade = Grade.A_PLUS

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.rule.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.rule.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.rule.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.rule.severity == Severity.LOW)

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.rule.severity == Severity.INFO)

    @property
    def passed(self) -> bool:
        return self.critical_count == 0 and self.high_count == 0

    @property
    def total_issues(self) -> int:
        return len([f for f in self.findings if f.rule.severity != Severity.INFO])


# ── Image analysis models ─────────────────────────────────────────────────


@dataclass
class LayerInfo:
    """Docker image layer information."""

    id: str = ""
    created: str = ""
    created_by: str = ""
    size: int = 0
    comment: str = ""
    empty_layer: bool = False

    @property
    def instruction(self) -> str:
        """Extract the Dockerfile instruction from created_by."""
        cmd = self.created_by
        if cmd.startswith("/bin/sh -c #(nop) "):
            cmd = cmd[len("/bin/sh -c #(nop) ") :]
        elif cmd.startswith("/bin/sh -c "):
            cmd = "RUN " + cmd[len("/bin/sh -c ") :]
        return cmd.strip()


@dataclass
class ImageMetadata:
    """Docker image metadata."""

    id: str = ""
    repo_tags: list[str] = field(default_factory=list)
    repo_digests: list[str] = field(default_factory=list)
    architecture: str = ""
    os: str = ""
    created: str = ""
    docker_version: str = ""
    size: int = 0
    author: str = ""
    labels: dict[str, str] = field(default_factory=dict)
    env: list[str] = field(default_factory=list)
    exposed_ports: list[str] = field(default_factory=list)
    volumes: list[str] = field(default_factory=list)
    entrypoint: list[str] = field(default_factory=list)
    cmd: list[str] = field(default_factory=list)
    user: str = ""
    workdir: str = ""
    healthcheck: dict | None = None


@dataclass
class ImageAnalysis:
    """Complete image analysis result."""

    image: str = ""
    metadata: ImageMetadata = field(default_factory=ImageMetadata)
    layers: list[LayerInfo] = field(default_factory=list)
    total_size: int = 0
    layer_count: int = 0
    base_image: str = ""
    score: int = 100
    grade: Grade = Grade.A_PLUS


# ── Security models ───────────────────────────────────────────────────────


@dataclass
class SecurityVulnerability:
    """A security vulnerability found in an image."""

    severity: Severity = Severity.LOW
    package_name: str = ""
    installed_version: str = ""
    fixed_version: str = ""
    cve_id: str = ""
    title: str = ""
    description: str = ""
    url: str = ""


@dataclass
class SecurityResult:
    """Security scan result."""

    image: str = ""
    vulnerabilities: list[SecurityVulnerability] = field(default_factory=list)
    packages_scanned: int = 0
    os_detected: str = ""
    score: int = 100
    grade: Grade = Grade.A_PLUS

    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.LOW)

    @property
    def total_count(self) -> int:
        return len(self.vulnerabilities)


# ── Efficiency models ─────────────────────────────────────────────────────


@dataclass
class OptimizationTip:
    """A single optimization suggestion."""

    category: str = ""
    title: str = ""
    description: str = ""
    current_impact: str = ""
    potential_savings: str = ""
    priority: Severity = Severity.MEDIUM
    fix: str = ""
    savings_bytes: int = 0


@dataclass
class EfficiencyResult:
    """Efficiency analysis result."""

    image: str = ""
    total_size: int = 0
    wasted_bytes: int = 0
    efficiency_score: float = 1.0
    tips: list[OptimizationTip] = field(default_factory=list)
    total_potential_savings: int = 0
    grade: Grade = Grade.A_PLUS

    @property
    def efficiency_pct(self) -> int:
        return int(self.efficiency_score * 100)


# ── Comparison models ─────────────────────────────────────────────────────


@dataclass
class ComparisonResult:
    """Result of comparing two images."""

    image1_name: str = ""
    image2_name: str = ""
    image1: ImageAnalysis = field(default_factory=ImageAnalysis)
    image2: ImageAnalysis = field(default_factory=ImageAnalysis)
    size_diff: int = 0
    layer_diff: int = 0
    size_diff_pct: float = 0.0
    verdict: str = ""
