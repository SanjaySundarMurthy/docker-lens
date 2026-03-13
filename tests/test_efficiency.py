"""Tests for efficiency analyzer."""

from docker_lens.analyzers.efficiency import analyze_efficiency
from docker_lens.models import (
    Grade,
    ImageAnalysis,
    LayerInfo,
)


class TestAnalyzeEfficiency:
    def test_clean_image(self):
        analysis = ImageAnalysis(
            image="myapp:1.0",
            total_size=50_000_000,
            base_image="python:3.11-slim",
            layers=[
                LayerInfo(created_by="/bin/sh -c pip install --no-cache-dir flask", size=20_000_000),
            ],
        )
        result = analyze_efficiency(analysis)
        assert result.image == "myapp:1.0"
        assert result.total_size == 50_000_000
        # slim is already slim
        assert result.total_potential_savings == 0 or len(result.tips) == 0

    def test_full_base_image_suggestion(self):
        analysis = ImageAnalysis(
            image="myapp:1.0",
            total_size=920_000_000,
            base_image="python:3.11",
            layers=[
                LayerInfo(created_by="/bin/sh -c #(nop) FROM python:3.11", size=900_000_000),
            ],
        )
        result = analyze_efficiency(analysis)
        # Should suggest slim and/or alpine
        base_tips = [t for t in result.tips if t.category == "Base Image"]
        assert len(base_tips) >= 1

    def test_apt_cache_tip(self):
        analysis = ImageAnalysis(
            image="test:1.0",
            total_size=200_000_000,
            base_image="debian:bookworm",
            layers=[
                LayerInfo(created_by="/bin/sh -c apt-get install -y curl wget", size=90_000_000),
            ],
        )
        result = analyze_efficiency(analysis)
        cache_tips = [t for t in result.tips if "apt" in t.title.lower() or "apt" in t.description.lower()]
        assert len(cache_tips) >= 1

    def test_pip_cache_tip(self):
        analysis = ImageAnalysis(
            image="test:1.0",
            total_size=200_000_000,
            base_image="python:3.11-slim",
            layers=[
                LayerInfo(created_by="/bin/sh -c pip install flask requests", size=50_000_000),
            ],
        )
        result = analyze_efficiency(analysis)
        pip_tips = [t for t in result.tips if "pip" in t.title.lower() or "pip" in t.description.lower()]
        assert len(pip_tips) >= 1

    def test_npm_dev_deps_tip(self):
        analysis = ImageAnalysis(
            image="test:1.0",
            total_size=300_000_000,
            base_image="node:18",
            layers=[
                LayerInfo(created_by="/bin/sh -c npm install", size=100_000_000),
            ],
        )
        result = analyze_efficiency(analysis)
        npm_tips = [t for t in result.tips if "npm" in t.title.lower() or "npm" in t.description.lower()]
        assert len(npm_tips) >= 1

    def test_multistage_suggestion(self):
        analysis = ImageAnalysis(
            image="test:1.0",
            total_size=800_000_000,
            base_image="golang:1.21",
            layers=[
                LayerInfo(created_by="/bin/sh -c go build -o /app main.go", size=500_000_000),
            ],
        )
        result = analyze_efficiency(analysis)
        ms_tips = [t for t in result.tips if "multi-stage" in t.title.lower()]
        assert len(ms_tips) >= 1

    def test_too_many_layers(self):
        layers = [LayerInfo(created_by=f"/bin/sh -c echo {i}", size=1_000_000) for i in range(20)]
        analysis = ImageAnalysis(
            image="test:1.0",
            total_size=20_000_000,
            base_image="alpine:3.18",
            layers=layers,
        )
        result = analyze_efficiency(analysis)
        layer_tips = [t for t in result.tips if "layer" in t.title.lower()]
        assert len(layer_tips) >= 1

    def test_large_layer_tip(self):
        analysis = ImageAnalysis(
            image="test:1.0",
            total_size=500_000_000,
            base_image="ubuntu:22.04",
            layers=[
                LayerInfo(created_by="/bin/sh -c make build", size=300_000_000),
            ],
        )
        result = analyze_efficiency(analysis)
        large_tips = [t for t in result.tips if "oversized" in t.title.lower() or "large" in t.category.lower()]
        assert len(large_tips) >= 1

    def test_efficiency_score_calculation(self):
        analysis = ImageAnalysis(
            image="test:1.0",
            total_size=200_000_000,
            base_image="debian:bookworm",
            layers=[
                LayerInfo(created_by="/bin/sh -c apt-get install -y curl", size=90_000_000),
                LayerInfo(created_by="/bin/sh -c pip install flask", size=50_000_000),
            ],
        )
        result = analyze_efficiency(analysis)
        assert 0.0 <= result.efficiency_score <= 1.0
        assert result.efficiency_pct >= 0 and result.efficiency_pct <= 100

    def test_grade_assignment(self):
        analysis = ImageAnalysis(
            image="clean:1.0",
            total_size=50_000_000,
            base_image="scratch",
            layers=[
                LayerInfo(created_by="/bin/sh -c #(nop) COPY binary /app", size=50_000_000),
            ],
        )
        result = analyze_efficiency(analysis)
        # Clean image should get good grade
        assert result.grade in (Grade.A_PLUS, Grade.A, Grade.B)

    def test_alpine_base_no_slim_suggestion(self):
        """Alpine base should not suggest switching to slim."""
        analysis = ImageAnalysis(
            image="test:1.0",
            total_size=30_000_000,
            base_image="python:3.11-alpine",
            layers=[
                LayerInfo(created_by="/bin/sh -c pip install --no-cache-dir flask", size=20_000_000),
            ],
        )
        result = analyze_efficiency(analysis)
        slim_tips = [t for t in result.tips if "slim" in t.title.lower()]
        assert len(slim_tips) == 0

    def test_result_properties(self):
        analysis = ImageAnalysis(
            image="test:1.0",
            total_size=100_000_000,
            base_image="ubuntu:22.04",
            layers=[],
        )
        result = analyze_efficiency(analysis)
        assert result.image == "test:1.0"
        assert result.total_size == 100_000_000
        assert isinstance(result.tips, list)
        assert isinstance(result.total_potential_savings, int)
