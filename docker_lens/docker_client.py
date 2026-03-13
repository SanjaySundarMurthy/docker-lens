"""Docker SDK client wrapper with lazy connection."""

from __future__ import annotations

from typing import Any

from .models import ImageAnalysis, ImageMetadata, LayerInfo, grade_from_score


class DockerConnectionError(Exception):
    """Raised when Docker daemon is not available."""


class DockerClient:
    """Wrapper around the Docker SDK with lazy initialization."""

    def __init__(self) -> None:
        self._client: Any = None

    def _connect(self) -> Any:
        """Lazily connect to Docker daemon."""
        if self._client is None:
            try:
                import docker

                self._client = docker.from_env()
                self._client.ping()
            except ImportError:
                raise DockerConnectionError(
                    "Docker SDK not installed. Install with: pip install docker"
                )
            except Exception as exc:
                raise DockerConnectionError(
                    f"Cannot connect to Docker daemon. Is Docker running?\n"
                    f"  Error: {exc}\n\n"
                    f"  Try: docker-lens demo  (works without Docker)"
                ) from exc
        return self._client

    @property
    def client(self) -> Any:
        return self._connect()

    def image_exists(self, image_name: str) -> bool:
        """Check if image exists locally."""
        try:
            self.client.images.get(image_name)
            return True
        except Exception:
            return False

    def pull_image(self, image_name: str) -> None:
        """Pull an image from registry."""
        self.client.images.pull(image_name)

    def analyze_image(self, image_name: str) -> ImageAnalysis:
        """Analyze a Docker image and return structured data."""
        try:
            image = self.client.images.get(image_name)
        except Exception:
            # Try pulling
            try:
                self.client.images.pull(image_name)
                image = self.client.images.get(image_name)
            except Exception as exc:
                raise ValueError(f"Image not found: {image_name}\n  {exc}") from exc

        attrs = image.attrs
        config = attrs.get("Config", {})
        history = image.history()

        # Build metadata
        metadata = ImageMetadata(
            id=attrs.get("Id", "")[:19],
            repo_tags=attrs.get("RepoTags", []),
            repo_digests=attrs.get("RepoDigests", []),
            architecture=attrs.get("Architecture", ""),
            os=attrs.get("Os", ""),
            created=attrs.get("Created", "")[:19],
            docker_version=attrs.get("DockerVersion", ""),
            size=attrs.get("Size", 0),
            author=attrs.get("Author", ""),
            labels=config.get("Labels") or {},
            env=config.get("Env") or [],
            exposed_ports=list((config.get("ExposedPorts") or {}).keys()),
            volumes=list((config.get("Volumes") or {}).keys()),
            entrypoint=config.get("Entrypoint") or [],
            cmd=config.get("Cmd") or [],
            user=config.get("User", ""),
            workdir=config.get("WorkingDir", ""),
            healthcheck=config.get("Healthcheck"),
        )

        # Build layers
        layers: list[LayerInfo] = []
        for entry in history:
            layer = LayerInfo(
                id=entry.get("Id", "<missing>")[:12],
                created=entry.get("Created", ""),
                created_by=entry.get("CreatedBy", ""),
                size=entry.get("Size", 0),
                comment=entry.get("Comment", ""),
                empty_layer=entry.get("Size", 0) == 0,
            )
            layers.append(layer)

        # Detect base image from first FROM
        base_image = ""
        for layer in reversed(layers):
            if "FROM" in layer.instruction.upper():
                base_image = layer.instruction.replace("FROM ", "").strip()
                break

        total_size = attrs.get("Size", 0)
        analysis = ImageAnalysis(
            image=image_name,
            metadata=metadata,
            layers=layers,
            total_size=total_size,
            layer_count=len([la for la in layers if not la.empty_layer]),
            base_image=base_image,
        )

        # Score the image
        score = 100
        # Deduct for no healthcheck
        if not metadata.healthcheck:
            score -= 5
        # Deduct for running as root
        if not metadata.user:
            score -= 10
        # Deduct for :latest tag
        if any(":latest" in t for t in metadata.repo_tags):
            score -= 5
        # Deduct for too many layers
        if analysis.layer_count > 15:
            score -= 10
        elif analysis.layer_count > 10:
            score -= 5
        # Deduct for large image
        if total_size > 1_000_000_000:  # > 1 GB
            score -= 15
        elif total_size > 500_000_000:  # > 500 MB
            score -= 10
        elif total_size > 200_000_000:  # > 200 MB
            score -= 5
        # Deduct for no labels
        if not metadata.labels:
            score -= 5

        analysis.score = max(0, score)
        analysis.grade = grade_from_score(analysis.score)

        return analysis
