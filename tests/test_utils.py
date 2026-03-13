"""Tests for utility functions."""

from docker_lens.utils import (
    format_pct,
    format_size,
    format_size_diff,
    grade_color,
    score_bar,
    severity_icon,
    truncate,
)


class TestFormatSize:
    def test_zero(self):
        assert format_size(0) == "0 B"

    def test_bytes(self):
        assert format_size(500) == "500 B"

    def test_kilobytes(self):
        assert format_size(2048) == "2.0 KB"

    def test_megabytes(self):
        assert format_size(1_500_000) == "1.4 MB"

    def test_gigabytes(self):
        assert format_size(2_500_000_000) == "2.3 GB"

    def test_negative(self):
        assert format_size(-1024) == "-1.0 KB"

    def test_exact_kb(self):
        assert format_size(1024) == "1.0 KB"


class TestFormatSizeDiff:
    def test_positive(self):
        assert format_size_diff(1024) == "+1.0 KB"

    def test_negative(self):
        assert format_size_diff(-1024) == "-1.0 KB"

    def test_zero(self):
        assert format_size_diff(0) == "0 B"


class TestFormatPct:
    def test_normal(self):
        assert format_pct(85.5) == "85.5%"

    def test_zero(self):
        assert format_pct(0.0) == "0.0%"


class TestTruncate:
    def test_short(self):
        assert truncate("hello", 10) == "hello"

    def test_exact(self):
        assert truncate("hello", 5) == "hello"

    def test_long(self):
        result = truncate("hello world", 8)
        assert result == "hello..."
        assert len(result) == 8


class TestSeverityIcon:
    def test_all_severities(self):
        assert "🔴" in severity_icon("critical")
        assert "🟠" in severity_icon("high")
        assert "🟡" in severity_icon("medium")
        assert "🔵" in severity_icon("low")
        assert "ℹ" in severity_icon("info")

    def test_unknown(self):
        assert severity_icon("unknown") == "•"


class TestGradeColor:
    def test_known_grades(self):
        assert grade_color("A+") == "bold green"
        assert grade_color("A") == "green"
        assert grade_color("F") == "bold red"

    def test_unknown(self):
        assert grade_color("Z") == "white"


class TestScoreBar:
    def test_returns_string(self):
        result = score_bar(85)
        assert isinstance(result, str)
        assert "█" in result

    def test_full(self):
        result = score_bar(100)
        assert "░" not in result

    def test_empty(self):
        result = score_bar(0)
        assert "█" not in result or result.count("█") == 0
