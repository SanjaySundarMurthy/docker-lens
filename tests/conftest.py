"""Shared test fixtures for Docker Lens."""

from __future__ import annotations

import pytest

from docker_lens.models import (
    Grade,
    ImageAnalysis,
    ImageMetadata,
    LayerInfo,
)


@pytest.fixture
def sample_analysis() -> ImageAnalysis:
    """A realistic image analysis for testing."""
    return ImageAnalysis(
        image="myapp:1.0",
        metadata=ImageMetadata(
            id="sha256:abc123",
            repo_tags=["myapp:1.0"],
            architecture="amd64",
            os="linux",
            created="2024-01-15T08:30:00",
            docker_version="24.0.7",
            size=250_000_000,
            user="appuser",
            labels={"version": "1.0"},
            exposed_ports=["8080/tcp"],
            entrypoint=["python"],
            cmd=["app.py"],
            healthcheck={"Test": ["CMD", "curl", "-f", "http://localhost:8080/"]},
        ),
        layers=[
            LayerInfo(id="sha256:111", created="2024-01-10", created_by="/bin/sh -c #(nop) FROM python:3.11-slim", size=150_000_000),
            LayerInfo(id="sha256:222", created="2024-01-12", created_by="/bin/sh -c pip install --no-cache-dir -r requirements.txt", size=80_000_000),
            LayerInfo(id="sha256:333", created="2024-01-13", created_by="/bin/sh -c #(nop) COPY . /app", size=20_000_000),
            LayerInfo(id="sha256:444", created="2024-01-13", created_by="/bin/sh -c #(nop) EXPOSE 8080", size=0, empty_layer=True),
            LayerInfo(id="sha256:555", created="2024-01-13", created_by="/bin/sh -c #(nop) CMD [\"python\", \"app.py\"]", size=0, empty_layer=True),
        ],
        total_size=250_000_000,
        layer_count=3,
        base_image="python:3.11-slim",
        score=85,
        grade=Grade.A,
    )


@pytest.fixture
def bad_dockerfile() -> str:
    """A Dockerfile with many issues for testing linter."""
    return """FROM ubuntu
MAINTAINER john@example.com

RUN apt-get update
RUN apt-get install python3 curl wget
RUN pip install flask requests
RUN sudo chmod +x /app.sh

ENV DB_PASSWORD=secret123

COPY . .

ADD https://example.com/file.tar.gz /tmp/
RUN curl https://exe.com/install.sh | bash

EXPOSE 22

CMD python3 app.py
"""


@pytest.fixture
def good_dockerfile() -> str:
    """A well-written Dockerfile."""
    return """FROM python:3.11-slim AS builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY src/ ./src/

FROM python:3.11-slim
LABEL maintainer="team@example.com" version="1.0"
WORKDIR /app
COPY --from=builder --chmod=755 /app /app
USER 1001
EXPOSE 8080
HEALTHCHECK --interval=30s CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')"]
CMD ["python", "-m", "uvicorn", "src.main:app"]
"""


@pytest.fixture
def minimal_dockerfile() -> str:
    """A minimal Dockerfile."""
    return "FROM scratch\nCOPY binary /\nCMD [\"/binary\"]\n"
