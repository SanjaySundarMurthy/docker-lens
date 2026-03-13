"""HTML report generation — professional dashboard-style reports."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from ..models import (
    EfficiencyResult,
    ImageAnalysis,
    LintResult,
    SecurityResult,
    Severity,
)
from ..utils import format_size


def _severity_color(sev: str) -> str:
    return {
        "critical": "#e74c3c",
        "high": "#e67e22",
        "medium": "#f1c40f",
        "low": "#3498db",
        "info": "#95a5a6",
    }.get(sev, "#95a5a6")


def _grade_html_color(grade: str) -> str:
    return {
        "A+": "#27ae60",
        "A": "#2ecc71",
        "B": "#f1c40f",
        "C": "#e67e22",
        "D": "#e74c3c",
        "F": "#c0392b",
    }.get(grade, "#95a5a6")


_CSS = """
:root {
    --bg: #0d1117; --card: #161b22; --border: #30363d;
    --text: #c9d1d9; --text2: #8b949e; --accent: #58a6ff;
    --green: #3fb950; --red: #f85149; --orange: #d29922; --blue: #58a6ff;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  background: var(--bg); color: var(--text); line-height: 1.6; padding: 2rem; }
.container { max-width: 1200px; margin: 0 auto; }
.header { text-align: center; padding: 2rem 0; border-bottom: 1px solid var(--border); margin-bottom: 2rem; }
.header h1 { font-size: 2.2rem; color: var(--accent); }
.header .subtitle { color: var(--text2); font-size: 1.1rem; margin-top: 0.5rem; }
.header .meta { color: var(--text2); font-size: 0.85rem; margin-top: 0.5rem; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1.5rem; margin-bottom: 2rem; }
.card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 1.5rem; }
.card h3 { color: var(--accent); margin-bottom: 1rem; font-size: 1rem; }
.score-circle { width: 120px; height: 120px; border-radius: 50%; display: flex; align-items: center;
  justify-content: center; margin: 1rem auto; font-size: 2rem; font-weight: bold; }
.grade-badge { display: inline-block; padding: 4px 16px; border-radius: 20px; font-weight: bold;
  font-size: 1.3rem; margin-top: 0.5rem; }
.stat-row { display: flex; justify-content: space-between; padding: 0.5rem 0;
  border-bottom: 1px solid var(--border); }
.stat-row:last-child { border-bottom: none; }
.stat-label { color: var(--text2); }
.stat-value { font-weight: 600; }
.bar-chart { margin: 1rem 0; }
.bar-row { display: flex; align-items: center; margin: 0.4rem 0; }
.bar-label { width: 100px; color: var(--text2); font-size: 0.85rem; flex-shrink: 0; }
.bar-track { flex: 1; height: 22px; background: #21262d; border-radius: 4px; overflow: hidden; position: relative; }
.bar-fill { height: 100%; border-radius: 4px; transition: width 0.3s; display: flex; align-items: center;
  padding-left: 8px; font-size: 0.75rem; color: #fff; font-weight: 600; }
.bar-value { margin-left: 8px; font-size: 0.85rem; min-width: 60px; }
table { width: 100%; border-collapse: collapse; margin: 1rem 0; }
th { text-align: left; padding: 0.75rem; border-bottom: 2px solid var(--border); color: var(--accent);
  font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.5px; }
td { padding: 0.75rem; border-bottom: 1px solid var(--border); font-size: 0.9rem; }
tr:hover { background: rgba(88, 166, 255, 0.04); }
.sev-badge { display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 0.75rem;
  font-weight: 600; color: #fff; }
.section { margin: 2rem 0; }
.section h2 { color: var(--accent); border-bottom: 1px solid var(--border); padding-bottom: 0.5rem;
  margin-bottom: 1rem; font-size: 1.3rem; }
.footer { text-align: center; color: var(--text2); padding: 2rem 0; border-top: 1px solid var(--border);
  margin-top: 2rem; font-size: 0.85rem; }
.recommendation { background: #1a2332; border-left: 4px solid var(--accent); padding: 1rem;
  margin: 0.75rem 0; border-radius: 0 8px 8px 0; }
.recommendation .title { font-weight: 600; margin-bottom: 0.25rem; }
.recommendation .fix { color: var(--green); font-family: monospace; font-size: 0.85rem; }
.exec-summary { background: linear-gradient(135deg, #1a2332 0%, #161b22 100%);
  padding: 2rem; border-radius: 12px; border: 1px solid var(--border); margin-bottom: 2rem; }
.exec-summary h2 { color: var(--accent); margin-bottom: 1rem; }
.exec-summary .metrics { display: flex; gap: 2rem; flex-wrap: wrap; justify-content: center; }
.exec-summary .metric { text-align: center; min-width: 120px; }
.exec-summary .metric .value { font-size: 2rem; font-weight: bold; }
.exec-summary .metric .label { color: var(--text2); font-size: 0.85rem; }
.progress-ring { position: relative; display: inline-block; }
.donut { transform: rotate(-90deg); }
@media (max-width: 768px) { .grid { grid-template-columns: 1fr; } body { padding: 1rem; } }
"""


def _svg_donut(score: int, color: str, size: int = 120) -> str:
    r = 50
    c = 2 * 3.14159 * r
    offset = c - (score / 100) * c
    return (
        f'<svg width="{size}" height="{size}" viewBox="0 0 120 120" class="donut">'
        f'<circle cx="60" cy="60" r="{r}" fill="none" stroke="#21262d" stroke-width="10"/>'
        f'<circle cx="60" cy="60" r="{r}" fill="none" stroke="{color}" '
        f'stroke-width="10" stroke-dasharray="{c}" stroke-dashoffset="{offset}" '
        f'stroke-linecap="round"/>'
        f'<text x="60" y="65" text-anchor="middle" fill="{color}" font-size="24" '
        f'font-weight="bold" transform="rotate(90 60 60)">{score}</text></svg>'
    )


def _render_lint_html(result: LintResult) -> str:
    g = result.grade.value
    gc = _grade_html_color(g)
    sev_counts = [
        ("Critical", result.critical_count, _severity_color("critical")),
        ("High", result.high_count, _severity_color("high")),
        ("Medium", result.medium_count, _severity_color("medium")),
        ("Low", result.low_count, _severity_color("low")),
        ("Info", result.info_count, _severity_color("info")),
    ]
    bars = ""
    for label, count, color in sev_counts:
        pct = min(count * 10, 100)
        bars += (
            f'<div class="bar-row"><span class="bar-label">{label}</span>'
            f'<div class="bar-track"><div class="bar-fill" style="width:{pct}%;'
            f'background:{color}">{count}</div></div></div>'
        )

    findings_rows = ""
    for f in result.findings:
        sc = _severity_color(f.rule.severity.value)
        findings_rows += (
            f'<tr><td>{f.line}</td><td>{f.rule.rule_id}</td>'
            f'<td><span class="sev-badge" style="background:{sc}">'
            f'{f.rule.severity.value.upper()}</span></td>'
            f'<td>{f.rule.category.value}</td><td>{f.message}</td>'
            f'<td class="fix">{f.fix_suggestion or f.rule.fix}</td></tr>'
        )

    return f"""
    <div class="grid">
      <div class="card" style="text-align:center">
        <h3>Dockerfile Score</h3>
        {_svg_donut(result.score, gc)}
        <div><span class="grade-badge" style="background:{gc};color:#fff">{g}</span></div>
      </div>
      <div class="card">
        <h3>Issue Distribution</h3>
        <div class="bar-chart">{bars}</div>
        <div class="stat-row"><span class="stat-label">Total Issues</span>
        <span class="stat-value">{result.total_issues}</span></div>
        <div class="stat-row"><span class="stat-label">File</span>
        <span class="stat-value">{result.file_path}</span></div>
      </div>
    </div>
    <div class="section">
      <h2>Findings</h2>
      <table><thead><tr><th>Line</th><th>Rule</th><th>Severity</th>
      <th>Category</th><th>Message</th><th>Fix</th></tr></thead>
      <tbody>{findings_rows}</tbody></table>
    </div>"""


def _render_security_html(result: SecurityResult) -> str:
    g = result.grade.value
    gc = _grade_html_color(g)
    vuln_rows = ""
    for v in result.vulnerabilities:
        sc = _severity_color(v.severity.value)
        vuln_rows += (
            f'<tr><td><span class="sev-badge" style="background:{sc}">'
            f'{v.severity.value.upper()}</span></td>'
            f'<td><a href="{v.url}" style="color:var(--red)">{v.cve_id}</a></td>'
            f'<td>{v.package_name}</td><td>{v.installed_version}</td>'
            f'<td style="color:var(--green)">{v.fixed_version}</td>'
            f'<td>{v.title}</td><td>{v.description}</td></tr>'
        )

    recs = ""
    crit_vulns = [v for v in result.vulnerabilities if v.severity == Severity.CRITICAL]
    high_vulns = [v for v in result.vulnerabilities if v.severity == Severity.HIGH]
    if crit_vulns:
        pkgs = ", ".join(f"{v.package_name}>={v.fixed_version}" for v in crit_vulns)
        recs += (
            '<div class="recommendation"><div class="title">URGENT: '
            f'Patch Critical Vulnerabilities</div>'
            f'<div class="fix">Upgrade: {pkgs}</div></div>'
        )
    if high_vulns:
        pkgs = ", ".join(f"{v.package_name}>={v.fixed_version}" for v in high_vulns)
        recs += (
            '<div class="recommendation"><div class="title">'
            f'Patch High-Severity Vulnerabilities</div>'
            f'<div class="fix">Upgrade: {pkgs}</div></div>'
        )

    return f"""
    <div class="grid">
      <div class="card" style="text-align:center">
        <h3>Security Score</h3>
        {_svg_donut(result.score, gc)}
        <div><span class="grade-badge" style="background:{gc};color:#fff">{g}</span></div>
      </div>
      <div class="card">
        <h3>Scan Summary</h3>
        <div class="stat-row"><span class="stat-label">Packages Scanned</span>
        <span class="stat-value">{result.packages_scanned}</span></div>
        <div class="stat-row"><span class="stat-label">OS Detected</span>
        <span class="stat-value">{result.os_detected}</span></div>
        <div class="stat-row"><span class="stat-label">Vulnerabilities</span>
        <span class="stat-value" style="color:var(--red)">{result.total_count}</span></div>
        <div class="stat-row"><span class="stat-label">Critical</span>
        <span class="stat-value" style="color:{_severity_color('critical')}">{result.critical_count}</span></div>
        <div class="stat-row"><span class="stat-label">High</span>
        <span class="stat-value" style="color:{_severity_color('high')}">{result.high_count}</span></div>
      </div>
    </div>
    {"<div class='section'><h2>Remediation Roadmap</h2>" + recs + "</div>" if recs else ""}
    <div class="section">
      <h2>Vulnerability Details</h2>
      <table><thead><tr><th>Severity</th><th>CVE</th><th>Package</th>
      <th>Installed</th><th>Fixed</th><th>Title</th><th>Description</th></tr></thead>
      <tbody>{vuln_rows}</tbody></table>
    </div>"""


def _render_efficiency_html(result: EfficiencyResult) -> str:
    g = result.grade.value
    gc = _grade_html_color(g)
    tips_html = ""
    for i, t in enumerate(result.tips, 1):
        sc = _severity_color(t.priority.value)
        tips_html += (
            f'<div class="recommendation">'
            f'<div class="title"><span class="sev-badge" style="background:{sc}">'
            f'{t.priority.value.upper()}</span> #{i} {t.title}</div>'
            f'<div style="color:var(--text2);margin:0.25rem 0">{t.description}</div>'
            f'<div class="fix">{t.fix}</div>'
            f'{"<div style=color:var(--green);margin-top:0.25rem>Potential savings: " + t.potential_savings + "</div>" if t.potential_savings else ""}'
            f'</div>'
        )

    return f"""
    <div class="grid">
      <div class="card" style="text-align:center">
        <h3>Efficiency</h3>
        {_svg_donut(result.efficiency_pct, gc)}
        <div><span class="grade-badge" style="background:{gc};color:#fff">{g}</span></div>
      </div>
      <div class="card">
        <h3>Size Overview</h3>
        <div class="stat-row"><span class="stat-label">Image Size</span>
        <span class="stat-value">{format_size(result.total_size)}</span></div>
        <div class="stat-row"><span class="stat-label">Potential Savings</span>
        <span class="stat-value" style="color:var(--green)">{format_size(result.total_potential_savings)}</span></div>
        <div class="stat-row"><span class="stat-label">Optimizations</span>
        <span class="stat-value">{len(result.tips)}</span></div>
      </div>
    </div>
    <div class="section">
      <h2>Optimization Roadmap</h2>
      {tips_html}
    </div>"""


def _render_analysis_html(analysis: ImageAnalysis) -> str:
    g = analysis.grade.value
    gc = _grade_html_color(g)
    meta = analysis.metadata

    layers_rows = ""
    max_sz = max((la.size for la in analysis.layers if not la.empty_layer), default=1)
    for i, la in enumerate(analysis.layers, 1):
        if la.empty_layer:
            continue
        pct = int(la.size / max(max_sz, 1) * 100)
        layers_rows += (
            f'<tr><td>{i}</td>'
            f'<td>{format_size(la.size)}</td>'
            f'<td><div class="bar-track"><div class="bar-fill" '
            f'style="width:{pct}%;background:var(--accent)">'
            f'</div></div></td>'
            f'<td><code>{la.instruction[:100]}</code></td></tr>'
        )

    return f"""
    <div class="grid">
      <div class="card" style="text-align:center">
        <h3>Image Score</h3>
        {_svg_donut(analysis.score, gc)}
        <div><span class="grade-badge" style="background:{gc};color:#fff">{g}</span></div>
      </div>
      <div class="card">
        <h3>Image Metadata</h3>
        <div class="stat-row"><span class="stat-label">Image</span>
        <span class="stat-value">{analysis.image}</span></div>
        <div class="stat-row"><span class="stat-label">Size</span>
        <span class="stat-value">{format_size(analysis.total_size)}</span></div>
        <div class="stat-row"><span class="stat-label">Layers</span>
        <span class="stat-value">{analysis.layer_count}</span></div>
        <div class="stat-row"><span class="stat-label">Arch</span>
        <span class="stat-value">{meta.architecture}/{meta.os}</span></div>
        <div class="stat-row"><span class="stat-label">Base</span>
        <span class="stat-value">{analysis.base_image or "unknown"}</span></div>
        <div class="stat-row"><span class="stat-label">User</span>
        <span class="stat-value">{meta.user or "root"}</span></div>
        <div class="stat-row"><span class="stat-label">Healthcheck</span>
        <span class="stat-value">{"Yes" if meta.healthcheck else "No"}</span></div>
      </div>
    </div>
    <div class="section">
      <h2>Layer Breakdown</h2>
      <table><thead><tr><th>#</th><th>Size</th><th>Proportion</th><th>Command</th></tr></thead>
      <tbody>{layers_rows}</tbody></table>
    </div>"""


def export_html(
    data: LintResult | ImageAnalysis | SecurityResult | EfficiencyResult,
    output_path: str,
    title: str = "Docker Lens Report",
) -> str:
    """Export a single result type to a beautiful HTML report."""
    from docker_lens import __version__

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    if isinstance(data, LintResult):
        body = _render_lint_html(data)
        subtitle = f"Dockerfile Lint Report — {data.file_path}"
    elif isinstance(data, SecurityResult):
        body = _render_security_html(data)
        subtitle = f"Security Scan Report — {data.image}"
    elif isinstance(data, EfficiencyResult):
        body = _render_efficiency_html(data)
        subtitle = f"Efficiency Report — {data.image}"
    elif isinstance(data, ImageAnalysis):
        body = _render_analysis_html(data)
        subtitle = f"Image Analysis Report — {data.image}"
    else:
        body = "<p>Unsupported report type</p>"
        subtitle = "Report"

    html = f"""<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title><style>{_CSS}</style></head><body>
<div class="container">
  <div class="header">
    <h1>🔍 Docker Lens</h1>
    <div class="subtitle">{subtitle}</div>
    <div class="meta">Generated on {now} · Docker Lens v{__version__}</div>
  </div>
  {body}
  <div class="footer">
    Generated by <strong>Docker Lens</strong> v{__version__} ·
    <a href="https://pypi.org/project/docker-lens-cli/" style="color:var(--accent)">PyPI</a> ·
    <a href="https://github.com/SanjaySundarMurthy/docker-lens" style="color:var(--accent)">GitHub</a>
  </div>
</div></body></html>"""

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")
    return str(path)


def export_full_html(
    lint_result: LintResult | None = None,
    analysis: ImageAnalysis | None = None,
    security_result: SecurityResult | None = None,
    efficiency_result: EfficiencyResult | None = None,
    output_path: str = "docker-lens-report.html",
) -> str:
    """Export a comprehensive full-scan HTML dashboard report."""
    from docker_lens import __version__

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # Executive summary metrics
    metrics = []
    if lint_result:
        metrics.append(
            f'<div class="metric"><div class="value" style="color:'
            f'{_grade_html_color(lint_result.grade.value)}">'
            f'{lint_result.score}</div><div class="label">Lint Score</div></div>'
        )
    if analysis:
        metrics.append(
            f'<div class="metric"><div class="value">'
            f'{format_size(analysis.total_size)}</div>'
            f'<div class="label">Image Size</div></div>'
        )
    if security_result:
        metrics.append(
            f'<div class="metric"><div class="value" style="color:'
            f'{_grade_html_color(security_result.grade.value)}">'
            f'{security_result.score}</div>'
            f'<div class="label">Security Score</div></div>'
        )
        metrics.append(
            f'<div class="metric"><div class="value" style="color:'
            f'var(--red)">{security_result.total_count}</div>'
            f'<div class="label">Vulnerabilities</div></div>'
        )
    if efficiency_result:
        metrics.append(
            f'<div class="metric"><div class="value" style="color:'
            f'var(--green)">{format_size(efficiency_result.total_potential_savings)}'
            f'</div><div class="label">Potential Savings</div></div>'
        )

    exec_summary = (
        f'<div class="exec-summary"><h2>Executive Summary</h2>'
        f'<div class="metrics">{"".join(metrics)}</div></div>'
    )

    # Build sections
    sections = []
    if lint_result:
        sections.append(
            f'<div class="section"><h2>1. Dockerfile Lint</h2>'
            f'{_render_lint_html(lint_result)}</div>'
        )
    if analysis:
        sections.append(
            f'<div class="section"><h2>'
            f'{"2" if lint_result else "1"}. Image Analysis</h2>'
            f'{_render_analysis_html(analysis)}</div>'
        )
    if security_result:
        n = 1 + bool(lint_result) + bool(analysis)
        sections.append(
            f'<div class="section"><h2>{n}. Security Scan</h2>'
            f'{_render_security_html(security_result)}</div>'
        )
    if efficiency_result:
        n = 1 + bool(lint_result) + bool(analysis) + bool(security_result)
        sections.append(
            f'<div class="section"><h2>{n}. Efficiency Analysis</h2>'
            f'{_render_efficiency_html(efficiency_result)}</div>'
        )

    image_name = ""
    if analysis:
        image_name = analysis.image
    elif security_result:
        image_name = security_result.image
    elif efficiency_result:
        image_name = efficiency_result.image

    html = f"""<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Docker Lens — Full Scan Report{' — ' + image_name if image_name else ''}</title>
<style>{_CSS}</style></head><body>
<div class="container">
  <div class="header">
    <h1>🔍 Docker Lens — Full Scan Report</h1>
    <div class="subtitle">{image_name or 'Comprehensive Analysis'}</div>
    <div class="meta">Generated on {now} · Docker Lens v{__version__}</div>
  </div>
  {exec_summary}
  {"".join(sections)}
  <div class="footer">
    Generated by <strong>Docker Lens</strong> v{__version__} ·
    <a href="https://pypi.org/project/docker-lens-cli/" style="color:var(--accent)">PyPI</a> ·
    <a href="https://github.com/SanjaySundarMurthy/docker-lens" style="color:var(--accent)">GitHub</a>
  </div>
</div></body></html>"""

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")
    return str(path)
