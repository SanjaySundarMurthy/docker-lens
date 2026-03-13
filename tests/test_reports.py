"""Tests for JSON report export."""

from __future__ import annotations

import json
import os
import tempfile

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
from docker_lens.output.reports import (
    _analysis_to_dict,
    _efficiency_to_dict,
    _lint_to_dict,
    _security_to_dict,
    export_json,
)


class TestLintToDict:
    def test_basic(self):
        rule = LintRule(
            rule_id="SEC001",
            category=RuleCategory.SECURITY,
            severity=Severity.HIGH,
            title="No USER",
            description="Missing USER",
            fix="Add USER",
        )
        result = LintResult(
            file_path="Dockerfile",
            findings=[LintFinding(rule=rule, line=1, message="No USER")],
            score=88,
            grade=Grade.A,
        )
        d = _lint_to_dict(result)
        assert d["file"] == "Dockerfile"
        assert d["score"] == 88
        assert d["grade"] == "A"
        assert len(d["findings"]) == 1
        assert d["findings"][0]["rule_id"] == "SEC001"
        assert d["findings"][0]["severity"] == "high"
        assert d["summary"]["high"] == 1

    def test_empty_findings(self):
        result = LintResult(file_path="Dockerfile", score=100, grade=Grade.A_PLUS)
        d = _lint_to_dict(result)
        assert d["findings"] == []
        assert d["total_issues"] == 0


class TestAnalysisToDict:
    def test_basic(self):
        analysis = ImageAnalysis(
            image="test:1.0",
            metadata=ImageMetadata(
                id="sha256:abc",
                architecture="amd64",
                os="linux",
                created="2024-01-01",
                user="app",
                labels={"v": "1"},
                exposed_ports=["8080/tcp"],
            ),
            layers=[
                LayerInfo(size=50_000_000, created_by="/bin/sh -c #(nop) COPY . /app"),
            ],
            total_size=50_000_000,
            layer_count=1,
            base_image="python:3.11-slim",
            score=90,
            grade=Grade.A,
        )
        d = _analysis_to_dict(analysis)
        assert d["image"] == "test:1.0"
        assert d["score"] == 90
        assert d["total_size"] == 50_000_000
        assert len(d["layers"]) == 1
        assert d["metadata"]["architecture"] == "amd64"
        assert d["base_image"] == "python:3.11-slim"


class TestSecurityToDict:
    def test_basic(self):
        result = SecurityResult(
            image="test:1.0",
            vulnerabilities=[
                SecurityVulnerability(
                    severity=Severity.HIGH,
                    package_name="openssl",
                    installed_version="3.0.11",
                    fixed_version="3.0.12",
                    cve_id="CVE-2023-5678",
                    title="Test",
                    description="Test vuln",
                    url="https://example.com",
                ),
            ],
            packages_scanned=50,
            os_detected="Debian",
            score=90,
            grade=Grade.A,
        )
        d = _security_to_dict(result)
        assert d["image"] == "test:1.0"
        assert d["vulnerability_count"] == 1
        assert d["vulnerabilities"][0]["cve"] == "CVE-2023-5678"
        assert d["os_detected"] == "Debian"

    def test_no_vulns(self):
        result = SecurityResult(image="clean:1.0", score=100, grade=Grade.A_PLUS)
        d = _security_to_dict(result)
        assert d["vulnerability_count"] == 0
        assert d["vulnerabilities"] == []


class TestEfficiencyToDict:
    def test_basic(self):
        result = EfficiencyResult(
            image="test:1.0",
            total_size=200_000_000,
            tips=[
                OptimizationTip(
                    category="Base Image",
                    title="Use slim",
                    description="Switch to slim variant",
                    potential_savings="100 MB",
                    priority=Severity.HIGH,
                    fix="FROM python:3.11-slim",
                ),
            ],
            total_potential_savings=100_000_000,
            grade=Grade.B,
        )
        d = _efficiency_to_dict(result)
        assert d["image"] == "test:1.0"
        assert d["total_size"] == 200_000_000
        assert d["potential_savings"] == 100_000_000
        assert len(d["tips"]) == 1
        assert d["tips"][0]["category"] == "Base Image"


class TestExportJson:
    def test_lint_export(self):
        result = LintResult(file_path="Dockerfile", score=95, grade=Grade.A)
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            export_json(result, path)
            with open(path) as f:
                data = json.load(f)
            assert data["type"] == "lint"
            assert "docker_lens_version" in data
            assert "generated_at" in data
            assert data["result"]["score"] == 95
        finally:
            os.unlink(path)

    def test_analysis_export(self):
        analysis = ImageAnalysis(image="test:1.0", score=80, grade=Grade.B)
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            export_json(analysis, path)
            with open(path) as f:
                data = json.load(f)
            assert data["type"] == "analysis"
        finally:
            os.unlink(path)

    def test_security_export(self):
        result = SecurityResult(image="test:1.0", score=100, grade=Grade.A_PLUS)
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            export_json(result, path)
            with open(path) as f:
                data = json.load(f)
            assert data["type"] == "security"
        finally:
            os.unlink(path)

    def test_efficiency_export(self):
        result = EfficiencyResult(image="test:1.0", grade=Grade.A)
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            export_json(result, path)
            with open(path) as f:
                data = json.load(f)
            assert data["type"] == "efficiency"
        finally:
            os.unlink(path)

    def test_comparison_export(self):
        a1 = ImageAnalysis(image="img1:v1", score=80, grade=Grade.B)
        a2 = ImageAnalysis(image="img2:v1", score=90, grade=Grade.A)
        comp = ComparisonResult(
            image1_name="img1:v1",
            image2_name="img2:v1",
            image1=a1,
            image2=a2,
            size_diff=-10_000_000,
            layer_diff=-2,
            verdict="img2 is smaller",
        )
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            export_json(comp, path)
            with open(path) as f:
                data = json.load(f)
            assert data["type"] == "comparison"
            assert data["result"]["verdict"] == "img2 is smaller"
        finally:
            os.unlink(path)

    def test_creates_parent_dirs(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "sub", "dir", "report.json")
            result = LintResult(file_path="Dockerfile", score=99, grade=Grade.A_PLUS)
            export_json(result, path)
            assert os.path.exists(path)
