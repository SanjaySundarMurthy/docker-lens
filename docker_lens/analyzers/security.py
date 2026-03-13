"""Security vulnerability scanner for Docker images."""

from __future__ import annotations

import re

from ..models import (
    ImageAnalysis,
    SecurityResult,
    SecurityVulnerability,
    Severity,
    grade_from_score,
)

# ── Built-in vulnerability database ──────────────────────────────────────
# A curated set of well-known CVEs for common packages.
# Production scanners (Trivy, Grype) use full NVD/OSV feeds.

_VULN_DB: list[dict] = [
    {
        "package": "openssl",
        "below": "3.0.12",
        "cve": "CVE-2023-5678",
        "severity": Severity.HIGH,
        "title": "OpenSSL key/parameter check bypass",
        "description": "Excessive time spent in DH key generation and parameter checks.",
        "fixed": "3.0.12",
    },
    {
        "package": "openssl",
        "below": "3.1.4",
        "cve": "CVE-2023-5363",
        "severity": Severity.MEDIUM,
        "title": "OpenSSL incorrect cipher key/IV length processing",
        "description": "Incorrect cipher key and IV length processing in certain cases.",
        "fixed": "3.1.4",
    },
    {
        "package": "curl",
        "below": "8.4.0",
        "cve": "CVE-2023-46218",
        "severity": Severity.MEDIUM,
        "title": "curl cookie injection with none-domain",
        "description": "Cookie injection vulnerability when using none-domain cookies.",
        "fixed": "8.4.0",
    },
    {
        "package": "curl",
        "below": "7.87.0",
        "cve": "CVE-2022-43551",
        "severity": Severity.HIGH,
        "title": "curl HSTS bypass via IDN",
        "description": "HSTS bypass vulnerability via internationalized domain names.",
        "fixed": "7.87.0",
    },
    {
        "package": "zlib",
        "below": "1.2.13",
        "cve": "CVE-2022-37434",
        "severity": Severity.CRITICAL,
        "title": "zlib heap buffer overflow in inflate",
        "description": "Heap-based buffer overflow in inflate in zlib via large gzip header.",
        "fixed": "1.2.13",
    },
    {
        "package": "libexpat",
        "below": "2.5.0",
        "cve": "CVE-2022-43680",
        "severity": Severity.HIGH,
        "title": "Expat use-after-free in doContent",
        "description": "Use-after-free vulnerability in doContent function.",
        "fixed": "2.5.0",
    },
    {
        "package": "glibc",
        "below": "2.38",
        "cve": "CVE-2023-4911",
        "severity": Severity.CRITICAL,
        "title": "glibc ld.so buffer overflow (Looney Tunables)",
        "description": "Buffer overflow in ld.so dynamic loader via GLIBC_TUNABLES.",
        "fixed": "2.38",
    },
    {
        "package": "nginx",
        "below": "1.25.3",
        "cve": "CVE-2023-44487",
        "severity": Severity.HIGH,
        "title": "HTTP/2 Rapid Reset DDoS",
        "description": "HTTP/2 protocol allows rapid stream resets causing DoS.",
        "fixed": "1.25.3",
    },
    {
        "package": "busybox",
        "below": "1.36.1",
        "cve": "CVE-2022-48174",
        "severity": Severity.CRITICAL,
        "title": "BusyBox ash stack overflow",
        "description": "Stack overflow vulnerability in ash shell parser.",
        "fixed": "1.36.1",
    },
    {
        "package": "libxml2",
        "below": "2.11.5",
        "cve": "CVE-2023-45322",
        "severity": Severity.MEDIUM,
        "title": "libxml2 use-after-free",
        "description": "Use-after-free in xmlUnlinkNode via nested calls.",
        "fixed": "2.11.5",
    },
    {
        "package": "openssh",
        "below": "9.3",
        "cve": "CVE-2023-38408",
        "severity": Severity.HIGH,
        "title": "OpenSSH remote code execution via ssh-agent",
        "description": "Remote code execution in ssh-agent via PKCS#11 provider.",
        "fixed": "9.3p2",
    },
    {
        "package": "tar",
        "below": "1.35",
        "cve": "CVE-2023-39804",
        "severity": Severity.MEDIUM,
        "title": "GNU tar stack buffer overflow",
        "description": "Stack buffer overflow with a long file name in an archive.",
        "fixed": "1.35",
    },
]

# ── Version comparison ────────────────────────────────────────────────────

_VERSION_RE = re.compile(r"(\d+(?:\.\d+)*)")


def _parse_version(version_str: str) -> tuple[int, ...]:
    """Parse a version string into a tuple of ints."""
    m = _VERSION_RE.search(version_str)
    if not m:
        return (0,)
    return tuple(int(p) for p in m.group(1).split("."))


def _version_below(installed: str, threshold: str) -> bool:
    """Check if installed version is below threshold."""
    return _parse_version(installed) < _parse_version(threshold)


# ── Package extraction ────────────────────────────────────────────────────

_PKG_INSTALL_RE = re.compile(
    r"(?:apt-get install|apk add|yum install|dnf install|zypper install)"
    r"\s+(?:--\S+\s+)*(.+?)(?:&&|$)",
    re.MULTILINE,
)


def extract_packages_from_history(layers: list) -> dict[str, str]:
    """Extract package names from image layer history commands."""
    packages: dict[str, str] = {}
    for layer in layers:
        cmd = getattr(layer, "created_by", "") or ""
        # Find package install commands
        for m in _PKG_INSTALL_RE.finditer(cmd):
            pkg_str = m.group(1).strip()
            for token in pkg_str.split():
                if token.startswith("-") or token.startswith("/"):
                    continue
                if "=" in token:
                    name, version = token.split("=", 1)
                    packages[name] = version
                else:
                    packages[token] = "unknown"
    return packages


# ── Scanner ───────────────────────────────────────────────────────────────


def scan_image(analysis: ImageAnalysis) -> SecurityResult:
    """Scan an image analysis for known vulnerabilities."""
    result = SecurityResult(image=analysis.image)

    # Extract installed packages from layer history
    packages = extract_packages_from_history(analysis.layers)
    result.packages_scanned = len(packages)

    # Detect OS from base image
    base = analysis.base_image.lower()
    if "alpine" in base:
        result.os_detected = "Alpine Linux"
    elif "debian" in base or "bookworm" in base or "bullseye" in base:
        result.os_detected = "Debian"
    elif "ubuntu" in base:
        result.os_detected = "Ubuntu"
    elif "centos" in base or "rhel" in base:
        result.os_detected = "RHEL/CentOS"
    else:
        result.os_detected = "Unknown"

    # Check against vulnerability database
    for vuln_entry in _VULN_DB:
        pkg_name = vuln_entry["package"]
        if pkg_name in packages:
            version = packages[pkg_name]
            if version == "unknown" or _version_below(version, vuln_entry["below"]):
                result.vulnerabilities.append(
                    SecurityVulnerability(
                        severity=vuln_entry["severity"],
                        package_name=pkg_name,
                        installed_version=version,
                        fixed_version=vuln_entry["fixed"],
                        cve_id=vuln_entry["cve"],
                        title=vuln_entry["title"],
                        description=vuln_entry["description"],
                        url=f"https://nvd.nist.gov/vuln/detail/{vuln_entry['cve']}",
                    )
                )

    # Score
    score = 100
    for vuln in result.vulnerabilities:
        if vuln.severity == Severity.CRITICAL:
            score -= 20
        elif vuln.severity == Severity.HIGH:
            score -= 10
        elif vuln.severity == Severity.MEDIUM:
            score -= 5
        else:
            score -= 2
    result.score = max(0, score)
    result.grade = grade_from_score(result.score)

    return result
