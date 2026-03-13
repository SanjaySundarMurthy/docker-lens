"""Tests for CLI commands using Click CliRunner."""

from __future__ import annotations

import json
import os

from click.testing import CliRunner

from docker_lens.cli import cli


class TestCLIGroup:
    def test_help(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "Docker Lens" in result.output
        assert "lint" in result.output
        assert "analyze" in result.output
        assert "demo" in result.output

    def test_version(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "docker-lens" in result.output


class TestLintCommand:
    def test_lint_good_dockerfile(self):
        runner = CliRunner()
        good = """FROM python:3.11-slim AS builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY src/ ./src/

FROM python:3.11-slim
LABEL maintainer="team@example.com" version="1.0"
WORKDIR /app
COPY --from=builder /app /app
USER 1001
EXPOSE 8080
HEALTHCHECK --interval=30s CMD ["python", "-c", "print('ok')"]
CMD ["python", "-m", "app"]
"""
        with runner.isolated_filesystem():
            with open("Dockerfile", "w") as f:
                f.write(good)
            result = runner.invoke(cli, ["lint", "Dockerfile"])
            assert "Docker Lens" in result.output
            assert "Score" in result.output or "score" in result.output.lower()

    def test_lint_bad_dockerfile(self):
        runner = CliRunner()
        bad = """FROM ubuntu
RUN apt-get install python3
CMD python3 app.py
"""
        with runner.isolated_filesystem():
            with open("Dockerfile", "w") as f:
                f.write(bad)
            result = runner.invoke(cli, ["lint", "Dockerfile"])
            assert result.exit_code == 1  # Should fail for bad dockerfile
            assert "Docker Lens" in result.output

    def test_lint_missing_file(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["lint", "nonexistent"])
        assert result.exit_code == 1

    def test_lint_json_export(self):
        runner = CliRunner()
        with runner.isolated_filesystem():
            with open("Dockerfile", "w") as f:
                f.write("FROM python:3.11-slim\nCMD [\"python\", \"app.py\"]\n")
            runner.invoke(cli, ["lint", "Dockerfile", "--json", "report.json"])
            assert os.path.exists("report.json")
            with open("report.json") as f:
                data = json.load(f)
            assert data["type"] == "lint"
            assert "score" in data["result"]


class TestDemoCommand:
    def test_demo_runs(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["demo"])
        assert result.exit_code == 0
        assert "Demo" in result.output or "demo" in result.output.lower()
        assert "Docker Lens" in result.output

    def test_demo_shows_all_sections(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["demo"])
        output = result.output.lower()
        # Should show lint, analysis, security, and efficiency
        assert "lint" in output
        assert "security" in output or "scan" in output
        assert "optimization" in output or "efficiency" in output


class TestRulesCommand:
    def test_rules_lists_all(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["rules"])
        assert result.exit_code == 0
        assert "SEC001" in result.output
        assert "EFF001" in result.output
        assert "MNT001" in result.output
        assert "REL001" in result.output
        assert "35" in result.output  # Total count


class TestAnalyzeCommand:
    def test_analyze_no_docker(self):
        """Analyze should fail gracefully without Docker."""
        runner = CliRunner()
        result = runner.invoke(cli, ["analyze", "nginx:latest"])
        # Should either connect or fail with a message
        # Don't assert exit code since Docker may or may not be available
        assert "Docker Lens" in result.output or "Error" in result.output or "Docker" in result.output


class TestScanCommand:
    def test_scan_no_docker(self):
        """Scan should fail gracefully without Docker."""
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "nginx:latest"])
        assert "Docker Lens" in result.output or "Error" in result.output or "Docker" in result.output


class TestOptimizeCommand:
    def test_optimize_no_docker(self):
        """Optimize should fail gracefully without Docker."""
        runner = CliRunner()
        result = runner.invoke(cli, ["optimize", "nginx:latest"])
        assert "Docker Lens" in result.output or "Error" in result.output or "Docker" in result.output


class TestCompareCommand:
    def test_compare_no_docker(self):
        """Compare should fail gracefully without Docker."""
        runner = CliRunner()
        result = runner.invoke(cli, ["compare", "img1", "img2"])
        assert "Docker Lens" in result.output or "Error" in result.output or "Docker" in result.output


class TestHistoryCommand:
    def test_history_no_docker(self):
        """History should fail gracefully without Docker."""
        runner = CliRunner()
        result = runner.invoke(cli, ["history", "nginx:latest"])
        assert "Docker Lens" in result.output or "Error" in result.output or "Docker" in result.output
