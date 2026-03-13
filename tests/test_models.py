"""Tests for data models."""

from docker_lens.models import (
    DockerfileInstruction,
    Grade,
    ImageMetadata,
    LayerInfo,
    LintFinding,
    LintResult,
    LintRule,
    RuleCategory,
    SecurityResult,
    SecurityVulnerability,
    Severity,
    grade_from_score,
)


class TestGradeFromScore:
    def test_a_plus(self):
        assert grade_from_score(100) == Grade.A_PLUS
        assert grade_from_score(95) == Grade.A_PLUS

    def test_a(self):
        assert grade_from_score(94) == Grade.A
        assert grade_from_score(85) == Grade.A

    def test_b(self):
        assert grade_from_score(84) == Grade.B
        assert grade_from_score(75) == Grade.B

    def test_c(self):
        assert grade_from_score(74) == Grade.C
        assert grade_from_score(65) == Grade.C

    def test_d(self):
        assert grade_from_score(64) == Grade.D
        assert grade_from_score(50) == Grade.D

    def test_f(self):
        assert grade_from_score(49) == Grade.F
        assert grade_from_score(0) == Grade.F


class TestLayerInfo:
    def test_instruction_from_nop(self):
        layer = LayerInfo(created_by="/bin/sh -c #(nop) COPY . /app")
        assert layer.instruction == "COPY . /app"

    def test_instruction_run(self):
        layer = LayerInfo(created_by="/bin/sh -c apt-get install -y nginx")
        assert layer.instruction == "RUN apt-get install -y nginx"

    def test_instruction_plain(self):
        layer = LayerInfo(created_by="FROM python:3.11")
        assert layer.instruction == "FROM python:3.11"

    def test_empty_instruction(self):
        layer = LayerInfo(created_by="")
        assert layer.instruction == ""


class TestLintResult:
    def test_empty_result(self):
        result = LintResult(file_path="Dockerfile")
        assert result.score == 100
        assert result.passed is True
        assert result.total_issues == 0
        assert result.critical_count == 0

    def test_severity_counts(self):
        rule_crit = LintRule("T1", RuleCategory.SECURITY, Severity.CRITICAL, "", "", "")
        rule_high = LintRule("T2", RuleCategory.SECURITY, Severity.HIGH, "", "", "")
        rule_med = LintRule("T3", RuleCategory.EFFICIENCY, Severity.MEDIUM, "", "", "")
        rule_info = LintRule("T4", RuleCategory.MAINTAINABILITY, Severity.INFO, "", "", "")

        result = LintResult(
            file_path="Dockerfile",
            findings=[
                LintFinding(rule=rule_crit, line=1, message=""),
                LintFinding(rule=rule_high, line=2, message=""),
                LintFinding(rule=rule_med, line=3, message=""),
                LintFinding(rule=rule_info, line=4, message=""),
            ],
        )
        assert result.critical_count == 1
        assert result.high_count == 1
        assert result.medium_count == 1
        assert result.info_count == 1
        assert result.passed is False
        assert result.total_issues == 3  # info not counted

    def test_passed_with_low_only(self):
        rule_low = LintRule("T1", RuleCategory.RELIABILITY, Severity.LOW, "", "", "")
        result = LintResult(
            file_path="Dockerfile",
            findings=[LintFinding(rule=rule_low, line=1, message="")],
        )
        assert result.passed is True


class TestSecurityResult:
    def test_empty(self):
        result = SecurityResult()
        assert result.total_count == 0
        assert result.critical_count == 0

    def test_counts(self):
        result = SecurityResult(
            vulnerabilities=[
                SecurityVulnerability(severity=Severity.CRITICAL),
                SecurityVulnerability(severity=Severity.HIGH),
                SecurityVulnerability(severity=Severity.HIGH),
                SecurityVulnerability(severity=Severity.LOW),
            ]
        )
        assert result.total_count == 4
        assert result.critical_count == 1
        assert result.high_count == 2
        assert result.low_count == 1


class TestDockerfileInstruction:
    def test_creation(self):
        inst = DockerfileInstruction(
            line_number=1, instruction="FROM", arguments="python:3.11", raw="FROM python:3.11"
        )
        assert inst.instruction == "FROM"
        assert inst.line_number == 1


class TestImageMetadata:
    def test_defaults(self):
        meta = ImageMetadata()
        assert meta.id == ""
        assert meta.repo_tags == []
        assert meta.labels == {}
        assert meta.healthcheck is None
