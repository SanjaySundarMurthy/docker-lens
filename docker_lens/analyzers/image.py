"""Image analysis — layer breakdown, metadata, scoring."""

from __future__ import annotations

from ..docker_client import DockerClient
from ..models import ImageAnalysis


def analyze_image(image_name: str, client: DockerClient | None = None) -> ImageAnalysis:
    """Analyze a Docker image: layers, metadata, scoring."""
    if client is None:
        client = DockerClient()
    return client.analyze_image(image_name)
