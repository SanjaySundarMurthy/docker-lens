"""Tests for demo data generators."""

from docker_lens.demo import (
    DEMO_GOOD_DOCKERFILE,
    get_demo_analysis,
    get_demo_efficiency,
    get_demo_lint_dockerfile,
    get_demo_security,
)
from docker_lens.models import Grade


class TestGetDemoAnalysis:
    def test_returns_analysis(self):
        a = get_demo_analysis()
        assert a.image == "nginx:1.25.3"
        assert a.total_size > 0
        assert a.layer_count > 0
        assert len(a.layers) > 0

    def test_metadata(self):
        a = get_demo_analysis()
        assert a.metadata.architecture == "amd64"
        assert a.metadata.os == "linux"
        assert a.metadata.id.startswith("sha256:")
        assert len(a.metadata.exposed_ports) > 0

    def test_layers(self):
        a = get_demo_analysis()
        non_empty = [la for la in a.layers if not la.empty_layer]
        assert len(non_empty) >= 3
        assert all(la.size >= 0 for la in a.layers)

    def test_score_and_grade(self):
        a = get_demo_analysis()
        assert 0 <= a.score <= 100
        assert isinstance(a.grade, Grade)


class TestGetDemoSecurity:
    def test_returns_result(self):
        s = get_demo_security()
        assert s.image == "nginx:1.25.3"
        assert s.total_count > 0
        assert s.packages_scanned > 0
        assert len(s.os_detected) > 0

    def test_vulnerabilities(self):
        s = get_demo_security()
        assert len(s.vulnerabilities) >= 2
        severities = {v.severity for v in s.vulnerabilities}
        assert len(severities) >= 2  # At least 2 different severity levels

    def test_cve_ids(self):
        s = get_demo_security()
        for v in s.vulnerabilities:
            assert v.cve_id.startswith("CVE-")
            assert len(v.package_name) > 0
            assert len(v.fixed_version) > 0


class TestGetDemoEfficiency:
    def test_returns_result(self):
        e = get_demo_efficiency()
        assert e.image == "nginx:1.25.3"
        assert e.total_size > 0
        assert e.total_potential_savings > 0

    def test_tips(self):
        e = get_demo_efficiency()
        assert len(e.tips) >= 2
        categories = {t.category for t in e.tips}
        assert len(categories) >= 2  # At least 2 different categories

    def test_grade(self):
        e = get_demo_efficiency()
        assert isinstance(e.grade, Grade)


class TestGetDemoLintDockerfile:
    def test_returns_string(self):
        df = get_demo_lint_dockerfile()
        assert isinstance(df, str)
        assert "FROM" in df
        assert len(df) > 50

    def test_has_intentional_issues(self):
        df = get_demo_lint_dockerfile()
        # Should have common issues baked in
        assert "ubuntu" in df.lower()  # Unpinned base
        assert "MAINTAINER" in df  # Deprecated


class TestDemoGoodDockerfile:
    def test_is_string(self):
        assert isinstance(DEMO_GOOD_DOCKERFILE, str)
        assert "FROM" in DEMO_GOOD_DOCKERFILE

    def test_has_best_practices(self):
        assert "slim" in DEMO_GOOD_DOCKERFILE.lower() or "alpine" in DEMO_GOOD_DOCKERFILE.lower()
        assert "USER" in DEMO_GOOD_DOCKERFILE
        assert "HEALTHCHECK" in DEMO_GOOD_DOCKERFILE
        assert "LABEL" in DEMO_GOOD_DOCKERFILE
