"""Tests for image comparison."""

from docker_lens.analyzers.comparison import compare_analyses
from docker_lens.models import (
    Grade,
    ImageAnalysis,
    ImageMetadata,
    LayerInfo,
)


class TestCompareAnalyses:
    def _make_analysis(self, image: str, size: int, layers: int, score: int = 80) -> ImageAnalysis:
        return ImageAnalysis(
            image=image,
            metadata=ImageMetadata(architecture="amd64", os="linux"),
            layers=[LayerInfo(size=size // max(layers, 1)) for _ in range(layers)],
            total_size=size,
            layer_count=layers,
            base_image="python:3.11-slim",
            score=score,
            grade=Grade.A if score >= 85 else Grade.B,
        )

    def test_similar_sizes(self):
        a1 = self._make_analysis("app:v1", 100_000_000, 5)
        a2 = self._make_analysis("app:v2", 102_000_000, 5)
        result = compare_analyses(a1, a2)
        assert "Similar" in result.verdict

    def test_image2_smaller(self):
        a1 = self._make_analysis("app:v1", 200_000_000, 8)
        a2 = self._make_analysis("app:v2", 100_000_000, 5)
        result = compare_analyses(a1, a2)
        assert result.size_diff < 0
        assert "smaller" in result.verdict.lower()

    def test_image1_smaller(self):
        a1 = self._make_analysis("app:v1", 100_000_000, 5)
        a2 = self._make_analysis("app:v2", 200_000_000, 8)
        result = compare_analyses(a1, a2)
        assert result.size_diff > 0
        assert "smaller" in result.verdict.lower()

    def test_size_diff_calculation(self):
        a1 = self._make_analysis("app:v1", 150_000_000, 5)
        a2 = self._make_analysis("app:v2", 100_000_000, 3)
        result = compare_analyses(a1, a2)
        assert result.size_diff == -50_000_000
        assert result.layer_diff == -2

    def test_size_diff_pct(self):
        a1 = self._make_analysis("app:v1", 200_000_000, 5)
        a2 = self._make_analysis("app:v2", 100_000_000, 5)
        result = compare_analyses(a1, a2)
        assert result.size_diff_pct == -50.0

    def test_result_fields(self):
        a1 = self._make_analysis("img1:latest", 100_000_000, 3)
        a2 = self._make_analysis("img2:latest", 200_000_000, 6)
        result = compare_analyses(a1, a2)
        assert result.image1_name == "img1:latest"
        assert result.image2_name == "img2:latest"
        assert result.image1.image == "img1:latest"
        assert result.image2.image == "img2:latest"
        assert result.layer_diff == 3

    def test_zero_size_image(self):
        a1 = self._make_analysis("scratch:latest", 0, 0)
        a2 = self._make_analysis("app:v1", 100_000_000, 3)
        result = compare_analyses(a1, a2)
        assert result.size_diff == 100_000_000
        # No division by zero
        assert result.size_diff_pct == 0.0

    def test_identical_images(self):
        a1 = self._make_analysis("app:v1", 150_000_000, 5, score=90)
        a2 = self._make_analysis("app:v1", 150_000_000, 5, score=90)
        result = compare_analyses(a1, a2)
        assert result.size_diff == 0
        assert result.layer_diff == 0
        assert "Similar" in result.verdict
