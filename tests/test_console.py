"""Tests for Rich console output rendering — smoke tests."""

from io import StringIO

from rich.console import Console

from docker_lens.models import (
    ComparisonResult,
    EfficiencyResult,
    Grade,
    ImageAnalysis,
    ImageMetadata,
    LayerInfo,
    LintFinding,
    LintResult,
    LintRule,
    OptimizationTip,
    RuleCategory,
    SecurityResult,
    SecurityVulnerability,
    Severity,
)
from docker_lens.output.console import (
    _category_style,
    render_banner,
    render_comparison,
    render_efficiency_result,
    render_image_analysis,
    render_lint_result,
    render_security_result,
)


def _capture_output(func, *args):
    """Capture Rich console output as string."""
    # We import and monkeypatch the console used by the module
    import docker_lens.output.console as mod
    original = mod.console
    buf = StringIO()
    mod.console = Console(file=buf, force_terminal=True, width=120)
    try:
        func(*args)
    finally:
        mod.console = original
    return buf.getvalue()


class TestRenderBanner:
    def test_banner_renders(self):
        output = _capture_output(render_banner)
        assert "Docker Lens" in output
        assert "Analyzer" in output


class TestRenderLintResult:
    def test_clean_result(self):
        result = LintResult(file_path="Dockerfile", score=100, grade=Grade.A_PLUS)
        output = _capture_output(render_lint_result, result)
        assert "100" in output
        assert "No issues" in output or "best practices" in output

    def test_result_with_findings(self):
        rule = LintRule(
            rule_id="SEC001",
            category=RuleCategory.SECURITY,
            severity=Severity.HIGH,
            title="No USER",
            description="No USER instruction",
            fix="Add USER",
        )
        finding = LintFinding(rule=rule, line=1, message="Missing USER instruction")
        result = LintResult(
            file_path="Dockerfile",
            findings=[finding],
            score=72,
            grade=Grade.C,
        )
        output = _capture_output(render_lint_result, result)
        assert "SEC001" in output
        assert "72" in output


class TestRenderImageAnalysis:
    def test_analysis_renders(self):
        analysis = ImageAnalysis(
            image="nginx:1.25",
            metadata=ImageMetadata(
                id="sha256:abc123",
                architecture="amd64",
                os="linux",
                created="2024-01-15",
                user="nginx",
                healthcheck={"Test": ["CMD", "curl", "localhost"]},
            ),
            layers=[
                LayerInfo(id="sha256:111", size=50_000_000, created_by="/bin/sh -c #(nop) FROM debian"),
                LayerInfo(id="sha256:222", size=30_000_000, created_by="/bin/sh -c apt-get install nginx"),
            ],
            total_size=80_000_000,
            layer_count=2,
            base_image="debian:bookworm",
            score=85,
            grade=Grade.A,
        )
        output = _capture_output(render_image_analysis, analysis)
        assert "nginx:1.25" in output
        assert "amd64" in output


class TestRenderSecurityResult:
    def test_clean_security(self):
        result = SecurityResult(image="clean:1.0", score=100, grade=Grade.A_PLUS)
        output = _capture_output(render_security_result, result)
        assert "100" in output

    def test_with_vulnerabilities(self):
        result = SecurityResult(
            image="vuln:1.0",
            vulnerabilities=[
                SecurityVulnerability(
                    severity=Severity.CRITICAL,
                    package_name="openssl",
                    installed_version="3.0.11",
                    fixed_version="3.0.12",
                    cve_id="CVE-2023-5678",
                    title="Test vuln",
                ),
            ],
            packages_scanned=10,
            os_detected="Debian",
            score=80,
            grade=Grade.B,
        )
        output = _capture_output(render_security_result, result)
        assert "CVE-2023-5678" in output
        assert "openssl" in output


class TestRenderEfficiencyResult:
    def test_clean_efficiency(self):
        result = EfficiencyResult(
            image="clean:1.0",
            total_size=50_000_000,
            grade=Grade.A_PLUS,
        )
        output = _capture_output(render_efficiency_result, result)
        assert "optimized" in output.lower() or "50" in output

    def test_with_tips(self):
        result = EfficiencyResult(
            image="bloated:1.0",
            total_size=900_000_000,
            tips=[
                OptimizationTip(
                    category="Base Image",
                    title="Use slim",
                    priority=Severity.HIGH,
                    potential_savings="700 MB",
                    fix="FROM python:3.11-slim",
                ),
            ],
            total_potential_savings=700_000_000,
            grade=Grade.D,
        )
        output = _capture_output(render_efficiency_result, result)
        assert "slim" in output.lower()


class TestRenderComparison:
    def test_comparison_renders(self):
        a1 = ImageAnalysis(
            image="app:v1",
            metadata=ImageMetadata(architecture="amd64", os="linux"),
            total_size=200_000_000,
            layer_count=5,
            base_image="python:3.11-slim",
            score=85,
            grade=Grade.A,
        )
        a2 = ImageAnalysis(
            image="app:v2",
            metadata=ImageMetadata(architecture="amd64", os="linux"),
            total_size=150_000_000,
            layer_count=4,
            base_image="python:3.11-slim",
            score=90,
            grade=Grade.A,
        )
        result = ComparisonResult(
            image1_name="app:v1",
            image2_name="app:v2",
            image1=a1,
            image2=a2,
            size_diff=-50_000_000,
            layer_diff=-1,
            size_diff_pct=-25.0,
            verdict="app:v2 is 25% smaller",
        )
        output = _capture_output(render_comparison, result)
        assert "app:v1" in output
        assert "app:v2" in output


class TestCategoryStyle:
    def test_known_categories(self):
        assert _category_style("Security") == "red"
        assert _category_style("Efficiency") == "yellow"
        assert _category_style("Maintainability") == "blue"
        assert _category_style("Reliability") == "magenta"

    def test_unknown_category(self):
        assert _category_style("Other") == "white"
