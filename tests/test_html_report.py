"""Tests for HTML report generation."""

from __future__ import annotations

import os
import tempfile

from docker_lens.models import (
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
from docker_lens.output.html_report import export_full_html, export_html


def _make_lint_result() -> LintResult:
    rule = LintRule(
        rule_id="SEC001",
        category=RuleCategory.SECURITY,
        severity=Severity.HIGH,
        title="No USER",
        description="Missing USER instruction",
        fix="Add USER",
    )
    return LintResult(
        file_path="Dockerfile",
        findings=[LintFinding(rule=rule, line=1, message="No USER")],
        score=72,
        grade=Grade.C,
    )


def _make_security_result() -> SecurityResult:
    return SecurityResult(
        image="nginx:1.25",
        vulnerabilities=[
            SecurityVulnerability(
                severity=Severity.CRITICAL,
                package_name="openssl",
                installed_version="3.0.11",
                fixed_version="3.0.12",
                cve_id="CVE-2023-5678",
                title="OpenSSL bypass",
                description="Test description",
                url="https://nvd.nist.gov/vuln/detail/CVE-2023-5678",
            ),
            SecurityVulnerability(
                severity=Severity.HIGH,
                package_name="curl",
                installed_version="7.88.1",
                fixed_version="8.4.0",
                cve_id="CVE-2023-46218",
                title="curl cookie injection",
                description="Cookie injection vuln",
                url="https://nvd.nist.gov/vuln/detail/CVE-2023-46218",
            ),
        ],
        packages_scanned=50,
        os_detected="Debian",
        score=70,
        grade=Grade.C,
    )


def _make_efficiency_result() -> EfficiencyResult:
    return EfficiencyResult(
        image="nginx:1.25",
        total_size=200_000_000,
        tips=[
            OptimizationTip(
                category="Base Image",
                title="Switch to Alpine",
                description="Alpine is smaller",
                potential_savings="150 MB",
                priority=Severity.HIGH,
                fix="FROM nginx:alpine",
                savings_bytes=150_000_000,
            ),
        ],
        total_potential_savings=150_000_000,
        grade=Grade.D,
    )


def _make_analysis() -> ImageAnalysis:
    return ImageAnalysis(
        image="nginx:1.25",
        metadata=ImageMetadata(
            id="sha256:abc123",
            architecture="amd64",
            os="linux",
            created="2024-01-15",
            user="nginx",
        ),
        layers=[
            LayerInfo(size=80_000_000, created_by="/bin/sh -c apt-get install nginx"),
            LayerInfo(size=50_000_000, created_by="/bin/sh -c #(nop) COPY . /app"),
        ],
        total_size=130_000_000,
        layer_count=2,
        base_image="debian:bookworm",
        score=75,
        grade=Grade.B,
    )


class TestExportHtml:
    def test_lint_html(self):
        result = _make_lint_result()
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            path = f.name
        try:
            export_html(result, path)
            content = open(path, encoding="utf-8").read()
            assert "Docker Lens" in content
            assert "SEC001" in content
            assert "72" in content
            assert "<style>" in content
        finally:
            os.unlink(path)

    def test_security_html(self):
        result = _make_security_result()
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            path = f.name
        try:
            export_html(result, path)
            content = open(path, encoding="utf-8").read()
            assert "CVE-2023-5678" in content
            assert "openssl" in content
            assert "Remediation" in content
        finally:
            os.unlink(path)

    def test_efficiency_html(self):
        result = _make_efficiency_result()
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            path = f.name
        try:
            export_html(result, path)
            content = open(path, encoding="utf-8").read()
            assert "Alpine" in content
            assert "Optimization" in content
        finally:
            os.unlink(path)

    def test_analysis_html(self):
        analysis = _make_analysis()
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            path = f.name
        try:
            export_html(analysis, path)
            content = open(path, encoding="utf-8").read()
            assert "nginx:1.25" in content
            assert "amd64" in content
            assert "Layer Breakdown" in content
        finally:
            os.unlink(path)


class TestExportFullHtml:
    def test_full_report_all_sections(self):
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            path = f.name
        try:
            export_full_html(
                lint_result=_make_lint_result(),
                analysis=_make_analysis(),
                security_result=_make_security_result(),
                efficiency_result=_make_efficiency_result(),
                output_path=path,
            )
            content = open(path, encoding="utf-8").read()
            assert "Executive Summary" in content
            assert "Dockerfile Lint" in content
            assert "Image Analysis" in content
            assert "Security Scan" in content
            assert "Efficiency" in content
            assert "Full Scan Report" in content
        finally:
            os.unlink(path)

    def test_full_report_partial(self):
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            path = f.name
        try:
            export_full_html(
                security_result=_make_security_result(),
                output_path=path,
            )
            content = open(path, encoding="utf-8").read()
            assert "Security Scan" in content
            assert "Dockerfile Lint" not in content
        finally:
            os.unlink(path)

    def test_creates_parent_dirs(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "sub", "report.html")
            export_full_html(
                analysis=_make_analysis(),
                output_path=path,
            )
            assert os.path.exists(path)
