"""Tests for security scanner."""

from docker_lens.analyzers.security import (
    _parse_version,
    _version_below,
    extract_packages_from_history,
    scan_image,
)
from docker_lens.models import (
    ImageAnalysis,
    LayerInfo,
)


class TestVersionParsing:
    def test_simple(self):
        assert _parse_version("1.2.3") == (1, 2, 3)

    def test_major_minor(self):
        assert _parse_version("3.11") == (3, 11)

    def test_major_only(self):
        assert _parse_version("7") == (7,)

    def test_with_suffix(self):
        assert _parse_version("3.0.12-r0") == (3, 0, 12)

    def test_no_version(self):
        assert _parse_version("unknown") == (0,)


class TestVersionBelow:
    def test_below(self):
        assert _version_below("3.0.11", "3.0.12") is True

    def test_equal(self):
        assert _version_below("3.0.12", "3.0.12") is False

    def test_above(self):
        assert _version_below("3.0.13", "3.0.12") is False

    def test_major_diff(self):
        assert _version_below("2.5.0", "3.0.0") is True

    def test_minor_diff(self):
        assert _version_below("3.0.0", "3.1.0") is True


class TestExtractPackages:
    def test_apt_get_with_versions(self):
        layers = [
            LayerInfo(created_by="/bin/sh -c apt-get install -y curl=7.88.1 openssl=3.0.11"),
        ]
        pkgs = extract_packages_from_history(layers)
        assert pkgs.get("curl") == "7.88.1"
        assert pkgs.get("openssl") == "3.0.11"

    def test_apt_get_without_versions(self):
        layers = [
            LayerInfo(created_by="/bin/sh -c apt-get install -y curl wget"),
        ]
        pkgs = extract_packages_from_history(layers)
        assert "curl" in pkgs
        assert "wget" in pkgs

    def test_empty_layers(self):
        pkgs = extract_packages_from_history([])
        assert pkgs == {}

    def test_no_install_command(self):
        layers = [LayerInfo(created_by="/bin/sh -c echo hello")]
        pkgs = extract_packages_from_history(layers)
        assert pkgs == {}


class TestScanImage:
    def test_scan_with_vulnerable_packages(self):
        analysis = ImageAnalysis(
            image="test:1.0",
            base_image="debian:bookworm",
            layers=[
                LayerInfo(created_by="/bin/sh -c apt-get install -y openssl=3.0.11 curl=7.88.1"),
            ],
        )
        result = scan_image(analysis)
        assert result.total_count > 0
        assert result.packages_scanned > 0
        assert result.os_detected == "Debian"

    def test_scan_clean_image(self):
        analysis = ImageAnalysis(
            image="test:1.0",
            base_image="python:3.11-slim",
            layers=[
                LayerInfo(created_by="/bin/sh -c pip install --no-cache-dir flask==2.3.0"),
            ],
        )
        result = scan_image(analysis)
        assert result.total_count == 0
        assert result.score == 100

    def test_os_detection_alpine(self):
        analysis = ImageAnalysis(image="t", base_image="alpine:3.18", layers=[])
        result = scan_image(analysis)
        assert result.os_detected == "Alpine Linux"

    def test_os_detection_ubuntu(self):
        analysis = ImageAnalysis(image="t", base_image="ubuntu:22.04", layers=[])
        result = scan_image(analysis)
        assert result.os_detected == "Ubuntu"

    def test_score_deduction(self):
        analysis = ImageAnalysis(
            image="t",
            base_image="debian:bookworm",
            layers=[
                LayerInfo(created_by="/bin/sh -c apt-get install -y zlib=1.2.11 openssl=3.0.11"),
            ],
        )
        result = scan_image(analysis)
        assert result.score < 100
        # zlib CVE is CRITICAL (-20), openssl CVE is HIGH (-10)
        assert result.critical_count >= 1
