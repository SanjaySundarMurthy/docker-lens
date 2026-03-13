"""Beautiful Rich console output for Docker Lens."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ..models import (
    ComparisonResult,
    EfficiencyResult,
    ImageAnalysis,
    LintResult,
    SecurityResult,
    Severity,
)
from ..utils import format_size, grade_color, score_bar, severity_icon

console = Console()

# ── Banner ────────────────────────────────────────────────────────────────


def render_banner() -> None:
    """Render the Docker Lens banner."""
    from docker_lens import __version__

    console.print(
        Panel(
            f"[bold cyan]🔍 Docker Lens[/bold cyan] v{__version__}\n"
            "[dim]Docker Image Analyzer & Optimizer[/dim]",
            border_style="cyan",
            padding=(0, 2),
        )
    )


# ── Lint output ───────────────────────────────────────────────────────────


def render_lint_result(result: LintResult) -> None:
    """Render Dockerfile lint results."""
    console.print(f"\n📄 Linting: [bold]{result.file_path}[/bold]")

    # Score panel
    g = result.grade.value
    gc = grade_color(g)
    console.print(
        Panel(
            f"  Dockerfile Score\n\n"
            f"    Score:  {score_bar(result.score)}  [bold]{result.score}/100[/bold]\n"
            f"    Grade:  [{gc}]{g}[/{gc}]\n\n"
            f"    🔴 Critical: {result.critical_count}  "
            f"🟠 High: {result.high_count}  "
            f"🟡 Medium: {result.medium_count}  "
            f"🔵 Low: {result.low_count}  "
            f"ℹ️  Info: {result.info_count}",
            title="📊 Dockerfile Quality",
            border_style="cyan",
        )
    )

    if not result.findings:
        console.print(
            Panel(
                "[bold green]✅ No issues found — Dockerfile follows all best practices![/bold green]",
                border_style="green",
            )
        )
        return

    # Findings table
    table = Table(title="Findings", show_lines=True, expand=True)
    table.add_column("Line", justify="right", style="dim", width=5)
    table.add_column("Rule", style="cyan", width=7)
    table.add_column("Sev", width=4, justify="center")
    table.add_column("Category", width=16)
    table.add_column("Message", ratio=2)
    table.add_column("Fix", ratio=2, style="green")

    for finding in result.findings:
        sev = finding.rule.severity
        sev_str = severity_icon(sev.value)
        cat_style = _category_style(finding.rule.category.value)

        table.add_row(
            str(finding.line) if finding.line else "—",
            finding.rule.rule_id,
            sev_str,
            f"[{cat_style}]{finding.rule.category.value}[/{cat_style}]",
            finding.message,
            finding.fix_suggestion or finding.rule.fix,
        )

    console.print(table)

    # Summary by category
    _render_category_summary(result)


def _render_category_summary(result: LintResult) -> None:
    """Render per-category breakdown."""
    categories: dict[str, list] = {}
    for f in result.findings:
        cat = f.rule.category.value
        categories.setdefault(cat, []).append(f)

    table = Table(title="Category Breakdown", show_lines=False)
    table.add_column("Category", width=18)
    table.add_column("Issues", justify="right", width=7)
    table.add_column("Severity Distribution", ratio=1)

    for cat, findings in sorted(categories.items()):
        crit = sum(1 for f in findings if f.rule.severity == Severity.CRITICAL)
        high = sum(1 for f in findings if f.rule.severity == Severity.HIGH)
        med = sum(1 for f in findings if f.rule.severity == Severity.MEDIUM)
        low = sum(1 for f in findings if f.rule.severity == Severity.LOW)
        info = sum(1 for f in findings if f.rule.severity == Severity.INFO)

        parts = []
        if crit:
            parts.append(f"🔴{crit}")
        if high:
            parts.append(f"🟠{high}")
        if med:
            parts.append(f"🟡{med}")
        if low:
            parts.append(f"🔵{low}")
        if info:
            parts.append(f"ℹ️{info}")

        table.add_row(cat, str(len(findings)), " ".join(parts))

    console.print(table)


# ── Image analysis output ─────────────────────────────────────────────────


def render_image_analysis(analysis: ImageAnalysis) -> None:
    """Render image analysis results."""
    meta = analysis.metadata
    g = analysis.grade.value
    gc = grade_color(g)

    # Overview panel
    overview = (
        f"  [bold]Image:[/bold]          {analysis.image}\n"
        f"  [bold]ID:[/bold]             {meta.id}\n"
        f"  [bold]Architecture:[/bold]   {meta.architecture}/{meta.os}\n"
        f"  [bold]Created:[/bold]        {meta.created}\n"
        f"  [bold]Total Size:[/bold]     [bold]{format_size(analysis.total_size)}[/bold]\n"
        f"  [bold]Layers:[/bold]         {analysis.layer_count}\n"
        f"  [bold]Base Image:[/bold]     {analysis.base_image or 'unknown'}\n"
        f"  [bold]User:[/bold]           {meta.user or 'root (default)'}\n"
        f"  [bold]Healthcheck:[/bold]    {'✅ Configured' if meta.healthcheck else '❌ None'}\n\n"
        f"  Score:  {score_bar(analysis.score)}  [bold]{analysis.score}/100[/bold]\n"
        f"  Grade:  [{gc}]{g}[/{gc}]"
    )
    console.print(
        Panel(overview, title="🐳 Image Overview", border_style="cyan")
    )

    # Layer breakdown table
    layer_table = Table(title="📦 Layer Breakdown", show_lines=False, expand=True)
    layer_table.add_column("#", justify="right", width=4, style="dim")
    layer_table.add_column("Size", justify="right", width=10, style="bold")
    layer_table.add_column("Bar", width=15)
    layer_table.add_column("Command", ratio=3)

    max_layer_size = max((la.size for la in analysis.layers if not la.empty_layer), default=1)

    for idx, layer in enumerate(analysis.layers, 1):
        if layer.empty_layer:
            continue
        bar_len = int(layer.size / max(max_layer_size, 1) * 12)
        bar = f"[cyan]{'█' * bar_len}[/cyan]{'░' * (12 - bar_len)}"
        cmd = layer.instruction[:80]
        layer_table.add_row(
            str(idx),
            format_size(layer.size),
            bar,
            cmd,
        )

    console.print(layer_table)

    # Metadata extras
    if meta.exposed_ports:
        console.print(f"\n🔌 [bold]Ports:[/bold] {', '.join(meta.exposed_ports)}")
    if meta.entrypoint:
        console.print(f"🚀 [bold]Entrypoint:[/bold] {' '.join(meta.entrypoint)}")
    if meta.cmd:
        console.print(f"⚡ [bold]CMD:[/bold] {' '.join(meta.cmd)}")
    if meta.labels:
        console.print(f"🏷️  [bold]Labels:[/bold] {len(meta.labels)} labels")


# ── Security output ───────────────────────────────────────────────────────


def render_security_result(result: SecurityResult) -> None:
    """Render security scan results."""
    g = result.grade.value
    gc = grade_color(g)

    summary = (
        f"  Security Scan\n\n"
        f"    Score:  {score_bar(result.score)}  [bold]{result.score}/100[/bold]\n"
        f"    Grade:  [{gc}]{g}[/{gc}]\n\n"
        f"    📦 Packages Scanned: {result.packages_scanned}\n"
        f"    🐧 OS Detected: {result.os_detected}\n\n"
        f"    🔴 Critical: {result.critical_count}  "
        f"🟠 High: {result.high_count}  "
        f"🟡 Medium: {result.medium_count}  "
        f"🔵 Low: {result.low_count}"
    )
    console.print(
        Panel(summary, title="🔐 Security Scan", border_style="cyan")
    )

    if not result.vulnerabilities:
        console.print(
            Panel(
                "[bold green]✅ No known vulnerabilities detected![/bold green]",
                border_style="green",
            )
        )
        return

    table = Table(title="Vulnerabilities Found", show_lines=True, expand=True)
    table.add_column("Sev", width=4, justify="center")
    table.add_column("CVE", width=16, style="red")
    table.add_column("Package", width=12)
    table.add_column("Installed", width=10)
    table.add_column("Fixed", width=10, style="green")
    table.add_column("Title", ratio=2)

    for vuln in result.vulnerabilities:
        table.add_row(
            severity_icon(vuln.severity.value),
            vuln.cve_id,
            vuln.package_name,
            vuln.installed_version,
            vuln.fixed_version,
            vuln.title,
        )

    console.print(table)


# ── Efficiency output ─────────────────────────────────────────────────────


def render_efficiency_result(result: EfficiencyResult) -> None:
    """Render efficiency analysis results."""
    g = result.grade.value
    gc = grade_color(g)

    summary = (
        f"  Size Optimization\n\n"
        f"    Image Size:       [bold]{format_size(result.total_size)}[/bold]\n"
        f"    Potential Savings: [bold green]{format_size(result.total_potential_savings)}[/bold green]\n"
        f"    Efficiency:       {score_bar(result.efficiency_pct)}  "
        f"[bold]{result.efficiency_pct}%[/bold]\n"
        f"    Grade:            [{gc}]{g}[/{gc}]"
    )
    console.print(
        Panel(summary, title="⚡ Efficiency Analysis", border_style="cyan")
    )

    if not result.tips:
        console.print(
            Panel(
                "[bold green]✅ Image is well-optimized![/bold green]",
                border_style="green",
            )
        )
        return

    table = Table(title="Optimization Suggestions", show_lines=True, expand=True)
    table.add_column("#", justify="right", width=3)
    table.add_column("Priority", width=4, justify="center")
    table.add_column("Category", width=15)
    table.add_column("Suggestion", ratio=2)
    table.add_column("Savings", width=10, justify="right", style="green")
    table.add_column("Fix", ratio=2)

    for idx, tip in enumerate(result.tips, 1):
        table.add_row(
            str(idx),
            severity_icon(tip.priority.value),
            tip.category,
            tip.title,
            tip.potential_savings or "—",
            tip.fix[:60],
        )

    console.print(table)


# ── Comparison output ─────────────────────────────────────────────────────


def render_comparison(result: ComparisonResult) -> None:
    """Render image comparison results."""
    # Side-by-side overview
    table = Table(title="🔄 Image Comparison", show_lines=True, expand=True)
    table.add_column("Metric", width=18, style="bold")
    table.add_column(result.image1_name, ratio=1, justify="center")
    table.add_column(result.image2_name, ratio=1, justify="center")
    table.add_column("Diff", width=14, justify="center")

    # Size
    s1 = format_size(result.image1.total_size)
    s2 = format_size(result.image2.total_size)
    diff_str = f"{'+' if result.size_diff > 0 else ''}{format_size(result.size_diff)}"
    diff_style = "red" if result.size_diff > 0 else "green" if result.size_diff < 0 else "dim"
    table.add_row("Total Size", s1, s2, f"[{diff_style}]{diff_str}[/{diff_style}]")

    # Layers
    l1 = str(result.image1.layer_count)
    l2 = str(result.image2.layer_count)
    ld = result.layer_diff
    ld_style = "red" if ld > 0 else "green" if ld < 0 else "dim"
    table.add_row("Layers", l1, l2, f"[{ld_style}]{'+' if ld > 0 else ''}{ld}[/{ld_style}]")

    # Architecture
    table.add_row(
        "Architecture",
        f"{result.image1.metadata.architecture}/{result.image1.metadata.os}",
        f"{result.image2.metadata.architecture}/{result.image2.metadata.os}",
        "",
    )

    # Base image
    table.add_row(
        "Base Image",
        result.image1.base_image or "unknown",
        result.image2.base_image or "unknown",
        "",
    )

    # Score
    g1 = result.image1.grade.value
    g2 = result.image2.grade.value
    table.add_row(
        "Score",
        f"[{grade_color(g1)}]{result.image1.score}/100 ({g1})[/{grade_color(g1)}]",
        f"[{grade_color(g2)}]{result.image2.score}/100 ({g2})[/{grade_color(g2)}]",
        "",
    )

    console.print(table)

    # Verdict
    console.print(
        Panel(
            f"[bold]{result.verdict}[/bold]",
            title="📊 Verdict",
            border_style="cyan",
        )
    )


# ── Helpers ───────────────────────────────────────────────────────────────


def _category_style(category: str) -> str:
    """Get Rich style for a rule category."""
    styles = {
        "Security": "red",
        "Efficiency": "yellow",
        "Maintainability": "blue",
        "Reliability": "magenta",
    }
    return styles.get(category, "white")
