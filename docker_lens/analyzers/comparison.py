"""Compare two Docker images side-by-side."""

from __future__ import annotations

from ..docker_client import DockerClient
from ..models import ComparisonResult, ImageAnalysis
from ..utils import format_size


def compare_images(
    image1_name: str,
    image2_name: str,
    client: DockerClient | None = None,
) -> ComparisonResult:
    """Compare two Docker images."""
    if client is None:
        client = DockerClient()

    analysis1 = client.analyze_image(image1_name)
    analysis2 = client.analyze_image(image2_name)

    return compare_analyses(analysis1, analysis2)


def compare_analyses(
    analysis1: ImageAnalysis,
    analysis2: ImageAnalysis,
) -> ComparisonResult:
    """Compare two pre-analyzed images."""
    size_diff = analysis2.total_size - analysis1.total_size
    layer_diff = analysis2.layer_count - analysis1.layer_count
    size_diff_pct = 0.0
    if analysis1.total_size > 0:
        size_diff_pct = (size_diff / analysis1.total_size) * 100

    # Generate verdict
    if abs(size_diff_pct) < 5:
        verdict = "Similar size"
    elif size_diff < 0:
        pct = abs(size_diff_pct)
        verdict = f"{analysis2.image} is {pct:.0f}% smaller ({format_size(abs(size_diff))} saved)"
    else:
        pct = abs(size_diff_pct)
        verdict = f"{analysis1.image} is {pct:.0f}% smaller ({format_size(abs(size_diff))} saved)"

    return ComparisonResult(
        image1_name=analysis1.image,
        image2_name=analysis2.image,
        image1=analysis1,
        image2=analysis2,
        size_diff=size_diff,
        layer_diff=layer_diff,
        size_diff_pct=size_diff_pct,
        verdict=verdict,
    )
