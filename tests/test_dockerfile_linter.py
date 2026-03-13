"""Tests for Dockerfile linter — all 35 rules."""

from docker_lens.analyzers.dockerfile import (
    RULES,
    lint_dockerfile,
    lint_file,
    parse_dockerfile,
)

# ── Parser tests ──────────────────────────────────────────────────────────


class TestDockerfileParser:
    def test_basic_instructions(self):
        content = "FROM python:3.11\nRUN echo hello\nCMD [\"python\"]"
        instructions = parse_dockerfile(content)
        assert len(instructions) == 3
        assert instructions[0].instruction == "FROM"
        assert instructions[1].instruction == "RUN"
        assert instructions[2].instruction == "CMD"

    def test_line_numbers(self):
        content = "FROM python:3.11\n\n# comment\nRUN echo hello"
        instructions = parse_dockerfile(content)
        assert instructions[0].line_number == 1
        assert instructions[1].line_number == 4

    def test_line_continuation(self):
        content = "RUN apt-get update && \\\n    apt-get install -y curl"
        instructions = parse_dockerfile(content)
        assert len(instructions) == 1
        assert "curl" in instructions[0].arguments

    def test_comments_skipped(self):
        content = "# This is a comment\nFROM python:3.11"
        instructions = parse_dockerfile(content)
        assert len(instructions) == 1

    def test_empty_file(self):
        instructions = parse_dockerfile("")
        assert instructions == []

    def test_preserves_arguments(self):
        content = 'ENV DB_HOST=localhost DB_PORT=5432'
        instructions = parse_dockerfile(content)
        assert instructions[0].arguments == "DB_HOST=localhost DB_PORT=5432"

    def test_uppercase_instruction(self):
        content = "from python:3.11\nrun echo hello"
        instructions = parse_dockerfile(content)
        assert instructions[0].instruction == "FROM"
        assert instructions[1].instruction == "RUN"


# ── Lint integration tests ────────────────────────────────────────────────


class TestLintDockerfile:
    def test_all_rules_registered(self):
        """Verify all 35 rules exist."""
        assert len(RULES) == 35

    def test_perfect_dockerfile(self, good_dockerfile):
        """Well-written Dockerfile should score high."""
        result = lint_dockerfile(good_dockerfile)
        assert result.score >= 80
        assert result.critical_count == 0

    def test_bad_dockerfile_scores_low(self, bad_dockerfile):
        """Bad Dockerfile should have many findings."""
        result = lint_dockerfile(bad_dockerfile)
        assert result.score < 60
        assert len(result.findings) > 10

    def test_empty_dockerfile(self):
        result = lint_dockerfile("")
        assert result.score == 100
        assert len(result.findings) == 0

    def test_scratch_base(self):
        result = lint_dockerfile("FROM scratch\nCOPY binary /\nCMD [\"/binary\"]")
        # scratch should not trigger SEC004 (no latest warning)
        sec004 = [f for f in result.findings if f.rule.rule_id == "SEC004"]
        assert len(sec004) == 0

    def test_score_never_negative(self, bad_dockerfile):
        result = lint_dockerfile(bad_dockerfile)
        assert result.score >= 0

    def test_grade_assigned(self, bad_dockerfile):
        result = lint_dockerfile(bad_dockerfile)
        assert result.grade is not None

    def test_findings_sorted_by_severity(self, bad_dockerfile):
        result = lint_dockerfile(bad_dockerfile)
        if len(result.findings) >= 2:
            severities = [f.rule.severity for f in result.findings]
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            orders = [severity_order[s.value] for s in severities]
            assert orders == sorted(orders)

    def test_lint_file_not_found(self):
        import pytest
        with pytest.raises(FileNotFoundError):
            lint_file("/nonexistent/Dockerfile")

    def test_lint_file_works(self, tmp_path):
        df = tmp_path / "Dockerfile"
        df.write_text("FROM python:3.11-slim\nWORKDIR /app\nCMD [\"python\"]")
        result = lint_file(str(df))
        assert result.file_path == str(df)
        assert result.score > 0


# ── Individual rule tests ─────────────────────────────────────────────────


class TestSEC001NoUser:
    def test_triggers_without_user(self):
        result = lint_dockerfile("FROM python:3.11\nRUN echo hi\nCMD [\"python\"]")
        ids = [f.rule.rule_id for f in result.findings]
        assert "SEC001" in ids

    def test_passes_with_user(self):
        result = lint_dockerfile("FROM python:3.11\nUSER 1001\nCMD [\"python\"]")
        ids = [f.rule.rule_id for f in result.findings]
        assert "SEC001" not in ids


class TestSEC002Sudo:
    def test_triggers_on_sudo(self):
        result = lint_dockerfile("FROM python:3.11\nRUN sudo apt-get update")
        ids = [f.rule.rule_id for f in result.findings]
        assert "SEC002" in ids

    def test_no_sudo(self):
        result = lint_dockerfile("FROM python:3.11\nRUN apt-get update")
        ids = [f.rule.rule_id for f in result.findings]
        assert "SEC002" not in ids


class TestSEC003SecretEnv:
    def test_triggers_on_password(self):
        result = lint_dockerfile("FROM python:3.11\nENV DB_PASSWORD=secret123")
        ids = [f.rule.rule_id for f in result.findings]
        assert "SEC003" in ids

    def test_triggers_on_api_key(self):
        result = lint_dockerfile("FROM python:3.11\nENV API_KEY=abc123")
        ids = [f.rule.rule_id for f in result.findings]
        assert "SEC003" in ids

    def test_safe_env(self):
        result = lint_dockerfile("FROM python:3.11\nENV APP_PORT=8080")
        ids = [f.rule.rule_id for f in result.findings]
        assert "SEC003" not in ids


class TestSEC004LatestTag:
    def test_triggers_on_latest(self):
        result = lint_dockerfile("FROM python:latest")
        ids = [f.rule.rule_id for f in result.findings]
        assert "SEC004" in ids

    def test_triggers_on_no_tag(self):
        result = lint_dockerfile("FROM python")
        ids = [f.rule.rule_id for f in result.findings]
        assert "SEC004" in ids

    def test_passes_with_version(self):
        result = lint_dockerfile("FROM python:3.11-slim")
        ids = [f.rule.rule_id for f in result.findings]
        assert "SEC004" not in ids

    def test_passes_with_digest(self):
        result = lint_dockerfile("FROM python@sha256:abc123")
        ids = [f.rule.rule_id for f in result.findings]
        assert "SEC004" not in ids


class TestSEC005SSH:
    def test_triggers_on_openssh(self):
        result = lint_dockerfile("FROM ubuntu:22.04\nRUN apt-get install -y openssh-server")
        ids = [f.rule.rule_id for f in result.findings]
        assert "SEC005" in ids


class TestSEC006CurlBash:
    def test_triggers(self):
        result = lint_dockerfile("FROM ubuntu:22.04\nRUN curl https://example.com | bash")
        ids = [f.rule.rule_id for f in result.findings]
        assert "SEC006" in ids

    def test_curl_without_pipe(self):
        result = lint_dockerfile("FROM ubuntu:22.04\nRUN curl -o file.txt https://example.com")
        ids = [f.rule.rule_id for f in result.findings]
        assert "SEC006" not in ids


class TestSEC007AddUrl:
    def test_triggers(self):
        result = lint_dockerfile("FROM ubuntu:22.04\nADD https://example.com/file /tmp/")
        ids = [f.rule.rule_id for f in result.findings]
        assert "SEC007" in ids


class TestSEC008SensitivePort:
    def test_triggers_on_ssh(self):
        result = lint_dockerfile("FROM ubuntu:22.04\nEXPOSE 22")
        ids = [f.rule.rule_id for f in result.findings]
        assert "SEC008" in ids

    def test_safe_port(self):
        result = lint_dockerfile("FROM ubuntu:22.04\nEXPOSE 8080")
        ids = [f.rule.rule_id for f in result.findings]
        assert "SEC008" not in ids


class TestSEC009CopyChmod:
    def test_triggers_on_script(self):
        result = lint_dockerfile("FROM python:3.11\nCOPY entrypoint.sh /app/")
        ids = [f.rule.rule_id for f in result.findings]
        assert "SEC009" in ids

    def test_passes_with_chmod(self):
        result = lint_dockerfile("FROM python:3.11\nCOPY --chmod=755 entrypoint.sh /app/")
        ids = [f.rule.rule_id for f in result.findings]
        assert "SEC009" not in ids


class TestSEC010DistUpgrade:
    def test_triggers(self):
        result = lint_dockerfile("FROM ubuntu:22.04\nRUN apt-get dist-upgrade -y")
        ids = [f.rule.rule_id for f in result.findings]
        assert "SEC010" in ids


class TestEFF001NoInstallRecommends:
    def test_triggers(self):
        result = lint_dockerfile("FROM ubuntu:22.04\nRUN apt-get install -y curl")
        ids = [f.rule.rule_id for f in result.findings]
        assert "EFF001" in ids

    def test_passes(self):
        result = lint_dockerfile("FROM ubuntu:22.04\nRUN apt-get install --no-install-recommends -y curl")
        ids = [f.rule.rule_id for f in result.findings]
        assert "EFF001" not in ids


class TestEFF002AptCache:
    def test_triggers(self):
        result = lint_dockerfile("FROM ubuntu:22.04\nRUN apt-get install -y curl")
        ids = [f.rule.rule_id for f in result.findings]
        assert "EFF002" in ids

    def test_passes_with_cleanup(self):
        result = lint_dockerfile("FROM ubuntu:22.04\nRUN apt-get install -y curl && rm -rf /var/lib/apt/lists/*")
        ids = [f.rule.rule_id for f in result.findings]
        assert "EFF002" not in ids


class TestEFF003MultipleRun:
    def test_triggers_on_many_runs(self):
        dockerfile = "FROM ubuntu:22.04\n" + "\n".join([f"RUN echo {i}" for i in range(8)])
        result = lint_dockerfile(dockerfile)
        ids = [f.rule.rule_id for f in result.findings]
        assert "EFF003" in ids

    def test_passes_with_few_runs(self):
        result = lint_dockerfile("FROM ubuntu:22.04\nRUN echo hello\nRUN echo world")
        ids = [f.rule.rule_id for f in result.findings]
        assert "EFF003" not in ids


class TestEFF004NoMultistage:
    def test_triggers_with_build(self):
        result = lint_dockerfile("FROM golang:1.21\nRUN go build -o app .\nCMD [\"./app\"]")
        ids = [f.rule.rule_id for f in result.findings]
        assert "EFF004" in ids

    def test_passes_with_multistage(self):
        result = lint_dockerfile("FROM golang:1.21 AS builder\nRUN go build\nFROM alpine:3.18\nCOPY --from=builder /app /app")
        ids = [f.rule.rule_id for f in result.findings]
        assert "EFF004" not in ids


class TestEFF005ApkNoCache:
    def test_triggers(self):
        result = lint_dockerfile("FROM alpine:3.18\nRUN apk add curl")
        ids = [f.rule.rule_id for f in result.findings]
        assert "EFF005" in ids

    def test_passes(self):
        result = lint_dockerfile("FROM alpine:3.18\nRUN apk add --no-cache curl")
        ids = [f.rule.rule_id for f in result.findings]
        assert "EFF005" not in ids


class TestEFF006PipNoCache:
    def test_triggers(self):
        result = lint_dockerfile("FROM python:3.11\nRUN pip install flask")
        ids = [f.rule.rule_id for f in result.findings]
        assert "EFF006" in ids

    def test_passes(self):
        result = lint_dockerfile("FROM python:3.11\nRUN pip install --no-cache-dir flask")
        ids = [f.rule.rule_id for f in result.findings]
        assert "EFF006" not in ids


class TestEFF007LargeBase:
    def test_triggers_on_ubuntu(self):
        result = lint_dockerfile("FROM ubuntu:22.04")
        ids = [f.rule.rule_id for f in result.findings]
        assert "EFF007" in ids

    def test_triggers_on_full_python(self):
        result = lint_dockerfile("FROM python:3.11")
        ids = [f.rule.rule_id for f in result.findings]
        assert "EFF007" in ids

    def test_passes_on_slim(self):
        result = lint_dockerfile("FROM python:3.11-slim")
        ids = [f.rule.rule_id for f in result.findings]
        assert "EFF007" not in ids

    def test_passes_on_alpine(self):
        result = lint_dockerfile("FROM python:3.11-alpine")
        ids = [f.rule.rule_id for f in result.findings]
        assert "EFF007" not in ids


class TestEFF008BroadCopy:
    def test_triggers(self):
        result = lint_dockerfile("FROM python:3.11-slim\nCOPY . .")
        ids = [f.rule.rule_id for f in result.findings]
        assert "EFF008" in ids

    def test_passes_specific_copy(self):
        result = lint_dockerfile("FROM python:3.11-slim\nCOPY src/ /app/src/")
        ids = [f.rule.rule_id for f in result.findings]
        assert "EFF008" not in ids


class TestEFF009NpmInstall:
    def test_triggers(self):
        result = lint_dockerfile("FROM node:18\nRUN npm install")
        ids = [f.rule.rule_id for f in result.findings]
        assert "EFF009" in ids


class TestEFF010PipNoPin:
    def test_triggers(self):
        result = lint_dockerfile("FROM python:3.11\nRUN pip install flask")
        ids = [f.rule.rule_id for f in result.findings]
        assert "EFF010" in ids

    def test_passes_with_pin(self):
        result = lint_dockerfile("FROM python:3.11\nRUN pip install flask==2.3.0")
        ids = [f.rule.rule_id for f in result.findings]
        assert "EFF010" not in ids

    def test_passes_with_requirements(self):
        result = lint_dockerfile("FROM python:3.11\nRUN pip install -r requirements.txt")
        ids = [f.rule.rule_id for f in result.findings]
        assert "EFF010" not in ids


class TestMNT001NoLabels:
    def test_triggers(self):
        result = lint_dockerfile("FROM python:3.11-slim\nCMD [\"python\"]")
        ids = [f.rule.rule_id for f in result.findings]
        assert "MNT001" in ids

    def test_passes(self):
        result = lint_dockerfile("FROM python:3.11-slim\nLABEL version=\"1.0\"\nCMD [\"python\"]")
        ids = [f.rule.rule_id for f in result.findings]
        assert "MNT001" not in ids


class TestMNT002Maintainer:
    def test_triggers(self):
        result = lint_dockerfile("FROM python:3.11-slim\nMAINTAINER john@example.com")
        ids = [f.rule.rule_id for f in result.findings]
        assert "MNT002" in ids


class TestMNT003RelativeWorkdir:
    def test_triggers(self):
        result = lint_dockerfile("FROM python:3.11-slim\nWORKDIR app")
        ids = [f.rule.rule_id for f in result.findings]
        assert "MNT003" in ids

    def test_passes_absolute(self):
        result = lint_dockerfile("FROM python:3.11-slim\nWORKDIR /app")
        ids = [f.rule.rule_id for f in result.findings]
        assert "MNT003" not in ids

    def test_passes_variable(self):
        result = lint_dockerfile("FROM python:3.11-slim\nWORKDIR $HOME")
        ids = [f.rule.rule_id for f in result.findings]
        assert "MNT003" not in ids


class TestMNT004NoWorkdir:
    def test_triggers(self):
        result = lint_dockerfile("FROM python:3.11-slim\nCMD [\"python\"]")
        ids = [f.rule.rule_id for f in result.findings]
        assert "MNT004" in ids

    def test_passes(self):
        result = lint_dockerfile("FROM python:3.11-slim\nWORKDIR /app\nCMD [\"python\"]")
        ids = [f.rule.rule_id for f in result.findings]
        assert "MNT004" not in ids


class TestMNT005ShellForm:
    def test_triggers_cmd(self):
        result = lint_dockerfile("FROM python:3.11-slim\nCMD python app.py")
        ids = [f.rule.rule_id for f in result.findings]
        assert "MNT005" in ids

    def test_passes_exec_form(self):
        result = lint_dockerfile('FROM python:3.11-slim\nCMD ["python", "app.py"]')
        ids = [f.rule.rule_id for f in result.findings]
        assert "MNT005" not in ids


class TestMNT006NoExpose:
    def test_triggers(self):
        result = lint_dockerfile("FROM python:3.11-slim\nCMD [\"python\"]")
        ids = [f.rule.rule_id for f in result.findings]
        assert "MNT006" in ids

    def test_passes(self):
        result = lint_dockerfile("FROM python:3.11-slim\nEXPOSE 8080\nCMD [\"python\"]")
        ids = [f.rule.rule_id for f in result.findings]
        assert "MNT006" not in ids


class TestMNT007AptNoPin:
    def test_triggers(self):
        result = lint_dockerfile("FROM ubuntu:22.04\nRUN apt-get install -y curl wget")
        ids = [f.rule.rule_id for f in result.findings]
        assert "MNT007" in ids

    def test_passes_pinned(self):
        result = lint_dockerfile("FROM ubuntu:22.04\nRUN apt-get install -y curl=7.81.0-1")
        ids = [f.rule.rule_id for f in result.findings]
        assert "MNT007" not in ids


class TestMNT008AddInsteadOfCopy:
    def test_triggers(self):
        result = lint_dockerfile("FROM python:3.11-slim\nADD . /app")
        ids = [f.rule.rule_id for f in result.findings]
        assert "MNT008" in ids

    def test_passes_with_tar(self):
        result = lint_dockerfile("FROM python:3.11-slim\nADD archive.tar.gz /app/")
        ids = [f.rule.rule_id for f in result.findings]
        assert "MNT008" not in ids


class TestMNT009MultipleCMD:
    def test_triggers(self):
        result = lint_dockerfile("FROM python:3.11-slim\nCMD [\"echo\"]\nCMD [\"python\"]")
        ids = [f.rule.rule_id for f in result.findings]
        assert "MNT009" in ids

    def test_passes_single(self):
        result = lint_dockerfile("FROM python:3.11-slim\nCMD [\"python\"]")
        ids = [f.rule.rule_id for f in result.findings]
        assert "MNT009" not in ids


class TestMNT010MultipleEntrypoint:
    def test_triggers(self):
        result = lint_dockerfile('FROM python:3.11-slim\nENTRYPOINT ["a"]\nENTRYPOINT ["b"]')
        ids = [f.rule.rule_id for f in result.findings]
        assert "MNT010" in ids


class TestREL001NoHealthcheck:
    def test_triggers(self):
        result = lint_dockerfile("FROM python:3.11-slim\nCMD [\"python\"]")
        ids = [f.rule.rule_id for f in result.findings]
        assert "REL001" in ids

    def test_passes(self):
        result = lint_dockerfile("FROM python:3.11-slim\nHEALTHCHECK CMD curl -f http://localhost/\nCMD [\"python\"]")
        ids = [f.rule.rule_id for f in result.findings]
        assert "REL001" not in ids


class TestREL002NoPipefail:
    def test_triggers(self):
        result = lint_dockerfile("FROM ubuntu:22.04\nRUN curl http://example.com | grep ok")
        ids = [f.rule.rule_id for f in result.findings]
        assert "REL002" in ids

    def test_passes_with_shell(self):
        content = 'SHELL ["/bin/bash", "-o", "pipefail", "-c"]\nFROM ubuntu:22.04\nRUN curl http://example.com | grep ok'
        result = lint_dockerfile(content)
        ids = [f.rule.rule_id for f in result.findings]
        assert "REL002" not in ids


class TestREL003AptUpdateAlone:
    def test_triggers(self):
        result = lint_dockerfile("FROM ubuntu:22.04\nRUN apt-get update")
        ids = [f.rule.rule_id for f in result.findings]
        assert "REL003" in ids

    def test_passes_combined(self):
        result = lint_dockerfile("FROM ubuntu:22.04\nRUN apt-get update && apt-get install -y curl")
        ids = [f.rule.rule_id for f in result.findings]
        assert "REL003" not in ids


class TestREL004CopyBeforeDeps:
    def test_triggers(self):
        result = lint_dockerfile("FROM python:3.11-slim\nCOPY . .\nRUN pip install -r requirements.txt")
        ids = [f.rule.rule_id for f in result.findings]
        assert "REL004" in ids

    def test_passes_correct_order(self):
        result = lint_dockerfile("FROM python:3.11-slim\nCOPY requirements.txt .\nRUN pip install -r requirements.txt\nCOPY . .")
        ids = [f.rule.rule_id for f in result.findings]
        assert "REL004" not in ids


class TestREL005AptNoY:
    def test_triggers(self):
        result = lint_dockerfile("FROM ubuntu:22.04\nRUN apt-get install curl")
        ids = [f.rule.rule_id for f in result.findings]
        assert "REL005" in ids

    def test_passes(self):
        result = lint_dockerfile("FROM ubuntu:22.04\nRUN apt-get install -y curl")
        ids = [f.rule.rule_id for f in result.findings]
        assert "REL005" not in ids
