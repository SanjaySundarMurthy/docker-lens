"""Efficiency analyzer — size optimization suggestions."""

from __future__ import annotations

import re

from ..models import (
    EfficiencyResult,
    ImageAnalysis,
    OptimizationTip,
    Severity,
    grade_from_score,
)
from ..utils import format_size

# ── Base image size estimates (compressed, approx) ────────────────────────

_BASE_IMAGE_SIZES: dict[str, dict[str, int]] = {
    "ubuntu": {"full": 78_000_000, "slim": 0, "alpine": 7_000_000},
    "debian": {"full": 124_000_000, "slim": 82_000_000, "alpine": 7_000_000},
    "python": {"full": 920_000_000, "slim": 150_000_000, "alpine": 55_000_000},
    "node": {"full": 1_100_000_000, "slim": 240_000_000, "alpine": 130_000_000},
    "golang": {"full": 820_000_000, "slim": 0, "alpine": 310_000_000},
    "ruby": {"full": 900_000_000, "slim": 210_000_000, "alpine": 80_000_000},
    "openjdk": {"full": 680_000_000, "slim": 230_000_000, "alpine": 190_000_000},
    "php": {"full": 480_000_000, "slim": 140_000_000, "alpine": 60_000_000},
    "nginx": {"full": 190_000_000, "slim": 0, "alpine": 45_000_000},
    "rust": {"full": 1_400_000_000, "slim": 800_000_000, "alpine": 600_000_000},
}

_APT_CACHE_SIZE = 50_000_000       # ~50 MB typical apt cache
_PIP_CACHE_SIZE = 30_000_000       # ~30 MB typical pip cache
_NPM_CACHE_SIZE = 40_000_000       # ~40 MB typical npm cache
_MULTISTAGE_SAVINGS = 0.40         # ~40% typical savings from multi-stage


def analyze_efficiency(analysis: ImageAnalysis) -> EfficiencyResult:
    """Analyze image efficiency and generate optimization tips."""
    result = EfficiencyResult(
        image=analysis.image,
        total_size=analysis.total_size,
    )
    tips: list[OptimizationTip] = []

    # ── Check base image ──────────────────────────────────────────────
    base = analysis.base_image.lower()
    base_name = base.split(":")[0].split("/")[-1] if base else ""
    base_tag = base.split(":")[-1] if ":" in base else ""

    if base_name in _BASE_IMAGE_SIZES:
        sizes = _BASE_IMAGE_SIZES[base_name]
        current = sizes.get("full", 0)

        # Suggest slim
        if "slim" not in base_tag and "alpine" not in base_tag and "minimal" not in base_tag:
            slim_size = sizes.get("slim", 0)
            alpine_size = sizes.get("alpine", 0)

            if slim_size > 0:
                savings = current - slim_size
                if savings > 0:
                    tips.append(OptimizationTip(
                        category="Base Image",
                        title="Switch to slim variant",
                        description=(
                            f"'{base}' is the full image."
                            " The -slim variant is much smaller."
                        ),
                        current_impact=format_size(current),
                        potential_savings=format_size(savings),
                        priority=Severity.HIGH,
                        fix=(
                            f"FROM {base_name}:{base_tag}-slim"
                            if base_tag
                            else f"FROM {base_name}:latest-slim"
                        ),
                        savings_bytes=savings,
                    ))

            if alpine_size > 0:
                savings = current - alpine_size
                if savings > 0:
                    tips.append(OptimizationTip(
                        category="Base Image",
                        title="Switch to Alpine variant",
                        description="Alpine-based image is significantly smaller (musl libc).",
                        current_impact=format_size(current),
                        potential_savings=format_size(savings),
                        priority=Severity.MEDIUM,
                        fix=(
                            f"FROM {base_name}:{base_tag}-alpine"
                            if base_tag
                            else f"FROM {base_name}:alpine"
                        ),
                        savings_bytes=savings,
                    ))

    # ── Check layer commands for optimization opportunities ───────────
    for layer in analysis.layers:
        cmd = layer.created_by or ""

        # Check for apt cache left behind
        if "apt-get install" in cmd and "rm -rf /var/lib/apt" not in cmd:
            tips.append(OptimizationTip(
                category="Package Cache",
                title="Clean apt cache",
                description="apt package cache left in layer. Adds ~50 MB.",
                current_impact=format_size(_APT_CACHE_SIZE),
                potential_savings=format_size(_APT_CACHE_SIZE),
                priority=Severity.HIGH,
                fix="RUN apt-get update && apt-get install -y ... && rm -rf /var/lib/apt/lists/*",
                savings_bytes=_APT_CACHE_SIZE,
            ))
            break  # One finding per type

    for layer in analysis.layers:
        cmd = layer.created_by or ""
        if "pip install" in cmd and "--no-cache-dir" not in cmd:
            tips.append(OptimizationTip(
                category="Package Cache",
                title="Disable pip cache",
                description="pip wheel cache stored in layer. Adds ~30 MB.",
                current_impact=format_size(_PIP_CACHE_SIZE),
                potential_savings=format_size(_PIP_CACHE_SIZE),
                priority=Severity.MEDIUM,
                fix="RUN pip install --no-cache-dir -r requirements.txt",
                savings_bytes=_PIP_CACHE_SIZE,
            ))
            break

    for layer in analysis.layers:
        cmd = layer.created_by or ""
        if re.search(r"npm install|yarn install", cmd) and "--production" not in cmd:
            tips.append(OptimizationTip(
                category="Package Cache",
                title="Prune npm dev dependencies",
                description="Dev dependencies included in production image.",
                current_impact=format_size(_NPM_CACHE_SIZE),
                potential_savings=format_size(_NPM_CACHE_SIZE),
                priority=Severity.MEDIUM,
                fix="RUN npm ci --only=production",
                savings_bytes=_NPM_CACHE_SIZE,
            ))
            break

    # ── Multi-stage build check ───────────────────────────────────────
    from_count = sum(
        1 for la in analysis.layers
        if "FROM" in la.instruction.upper()
    )
    _build_re = r"\b(make|gcc|g\+\+|go build|cargo build|mvn|gradle|npm run build)\b"
    has_build = any(
        re.search(_build_re, la.created_by or "")
        for la in analysis.layers
    )
    if from_count <= 1 and has_build:
        estimated_savings = int(analysis.total_size * _MULTISTAGE_SAVINGS)
        tips.append(OptimizationTip(
            category="Build Strategy",
            title="Use multi-stage build",
            description=(
                "Build tools are included in the final image."
                " Use multi-stage to separate build from runtime."
            ),
            current_impact=format_size(analysis.total_size),
            potential_savings=format_size(estimated_savings),
            priority=Severity.HIGH,
            fix="FROM builder AS build\n  ...\nFROM runtime AS final\nCOPY --from=build /app /app",
            savings_bytes=estimated_savings,
        ))

    # ── Too many layers ───────────────────────────────────────────────
    non_empty = [la for la in analysis.layers if not la.empty_layer]
    if len(non_empty) > 15:
        tips.append(OptimizationTip(
            category="Layer Count",
            title="Reduce layer count",
            description=f"{len(non_empty)} layers — combine RUN instructions to reduce overhead.",
            priority=Severity.LOW,
            fix="Chain related commands with && in a single RUN.",
            savings_bytes=0,
        ))

    # ── Large individual layers ───────────────────────────────────────
    for layer in non_empty:
        if layer.size > 200_000_000:  # > 200 MB
            tips.append(OptimizationTip(
                category="Large Layer",
                title=f"Oversized layer ({format_size(layer.size)})",
                description=f"Layer: {layer.instruction[:60]}",
                current_impact=format_size(layer.size),
                priority=Severity.MEDIUM,
                fix="Review this layer for unnecessary files or combine cleanup in same RUN.",
                savings_bytes=layer.size // 4,  # Estimate 25% recoverable
            ))

    # ── Calculate totals ──────────────────────────────────────────────
    result.tips = tips
    result.total_potential_savings = sum(t.savings_bytes for t in tips)
    result.wasted_bytes = result.total_potential_savings

    if analysis.total_size > 0:
        result.efficiency_score = max(
            0.0,
            1.0 - (result.wasted_bytes / analysis.total_size)
        )
    else:
        result.efficiency_score = 1.0

    # Score: start at 100, deduct based on waste ratio
    waste_ratio = result.wasted_bytes / max(analysis.total_size, 1)
    score = int(100 - (waste_ratio * 100))
    score = max(0, min(100, score))
    result.grade = grade_from_score(score)

    return result
