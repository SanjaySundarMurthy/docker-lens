"""Report generation — JSON and HTML exports."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from ..models import (
    ComparisonResult,
    EfficiencyResult,
    ImageAnalysis,
    LintResult,
    SecurityResult,
)
from ..utils import format_size


def _lint_to_dict(result: LintResult) -> dict:
    """Convert lint result to dict."""
    return {
        "file": result.file_path,
        "score": result.score,
        "grade": result.grade.value,
        "total_issues": result.total_issues,
        "summary": {
            "critical": result.critical_count,
            "high": result.high_count,
            "medium": result.medium_count,
            "low": result.low_count,
            "info": result.info_count,
        },
        "findings": [
            {
                "rule_id": f.rule.rule_id,
                "category": f.rule.category.value,
                "severity": f.rule.severity.value,
                "title": f.rule.title,
                "line": f.line,
                "message": f.message,
                "context": f.context,
                "fix": f.fix_suggestion or f.rule.fix,
            }
            for f in result.findings
        ],
    }


def _analysis_to_dict(analysis: ImageAnalysis) -> dict:
    """Convert image analysis to dict."""
    return {
        "image": analysis.image,
        "score": analysis.score,
        "grade": analysis.grade.value,
        "total_size": analysis.total_size,
        "total_size_human": format_size(analysis.total_size),
        "layer_count": analysis.layer_count,
        "base_image": analysis.base_image,
        "metadata": {
            "id": analysis.metadata.id,
            "architecture": analysis.metadata.architecture,
            "os": analysis.metadata.os,
            "created": analysis.metadata.created,
            "user": analysis.metadata.user,
            "healthcheck": bool(analysis.metadata.healthcheck),
            "labels": analysis.metadata.labels,
            "ports": analysis.metadata.exposed_ports,
        },
        "layers": [
            {
                "size": la.size,
                "size_human": format_size(la.size),
                "command": la.instruction,
                "empty": la.empty_layer,
            }
            for la in analysis.layers
        ],
    }


def _security_to_dict(result: SecurityResult) -> dict:
    """Convert security result to dict."""
    return {
        "image": result.image,
        "score": result.score,
        "grade": result.grade.value,
        "os_detected": result.os_detected,
        "packages_scanned": result.packages_scanned,
        "vulnerability_count": result.total_count,
        "summary": {
            "critical": result.critical_count,
            "high": result.high_count,
            "medium": result.medium_count,
            "low": result.low_count,
        },
        "vulnerabilities": [
            {
                "cve": v.cve_id,
                "severity": v.severity.value,
                "package": v.package_name,
                "installed": v.installed_version,
                "fixed": v.fixed_version,
                "title": v.title,
                "description": v.description,
                "url": v.url,
            }
            for v in result.vulnerabilities
        ],
    }


def _efficiency_to_dict(result: EfficiencyResult) -> dict:
    """Convert efficiency result to dict."""
    return {
        "image": result.image,
        "total_size": result.total_size,
        "total_size_human": format_size(result.total_size),
        "potential_savings": result.total_potential_savings,
        "potential_savings_human": format_size(result.total_potential_savings),
        "efficiency_pct": result.efficiency_pct,
        "grade": result.grade.value,
        "tips": [
            {
                "category": t.category,
                "title": t.title,
                "description": t.description,
                "savings": t.potential_savings,
                "priority": t.priority.value,
                "fix": t.fix,
            }
            for t in result.tips
        ],
    }


def export_json(
    data: LintResult | ImageAnalysis | SecurityResult | EfficiencyResult | ComparisonResult,
    output_path: str,
) -> str:
    """Export result to JSON file."""
    from docker_lens import __version__

    if isinstance(data, LintResult):
        payload = {"type": "lint", "result": _lint_to_dict(data)}
    elif isinstance(data, ImageAnalysis):
        payload = {"type": "analysis", "result": _analysis_to_dict(data)}
    elif isinstance(data, SecurityResult):
        payload = {"type": "security", "result": _security_to_dict(data)}
    elif isinstance(data, EfficiencyResult):
        payload = {"type": "efficiency", "result": _efficiency_to_dict(data)}
    elif isinstance(data, ComparisonResult):
        payload = {
            "type": "comparison",
            "result": {
                "image1": _analysis_to_dict(data.image1),
                "image2": _analysis_to_dict(data.image2),
                "size_diff": data.size_diff,
                "layer_diff": data.layer_diff,
                "verdict": data.verdict,
            },
        }
    else:
        payload = {"type": "unknown", "result": {}}

    payload["docker_lens_version"] = __version__
    payload["generated_at"] = datetime.now(timezone.utc).isoformat()

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    return str(path)
