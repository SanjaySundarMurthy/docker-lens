"""Docker Lens CLI — Docker Image Analyzer & Optimizer."""

from __future__ import annotations

import sys

import click
from rich.panel import Panel

from . import __version__
from .output.console import (
    console,
    render_banner,
    render_comparison,
    render_efficiency_result,
    render_image_analysis,
    render_lint_result,
    render_security_result,
)


@click.group()
@click.version_option(version=__version__, prog_name="docker-lens")
def cli() -> None:
    """🔍 Docker Lens — Docker Image Analyzer & Optimizer.

    Lint Dockerfiles, analyze images, scan vulnerabilities, and optimize size.
    """


# ── lint ──────────────────────────────────────────────────────────────────


@cli.command()
@click.argument("dockerfile", default="Dockerfile", type=click.Path())
@click.option("--json", "json_out", default=None, help="Export results to JSON file.")
def lint(dockerfile: str, json_out: str | None) -> None:
    """Lint a Dockerfile for best practices (35 rules).

    Works without Docker — just point at a Dockerfile.
    """
    render_banner()

    from .analyzers.dockerfile import lint_file

    try:
        result = lint_file(dockerfile)
    except FileNotFoundError:
        console.print(f"[red]❌ File not found:[/red] {dockerfile}")
        sys.exit(1)
    except Exception as exc:
        console.print(f"[red]❌ Error:[/red] {exc}")
        sys.exit(1)

    render_lint_result(result)

    if json_out:
        from .output.reports import export_json

        path = export_json(result, json_out)
        console.print(f"\n📄 Report saved: [bold]{path}[/bold]")

    sys.exit(0 if result.passed else 1)


# ── analyze ───────────────────────────────────────────────────────────────


@cli.command()
@click.argument("image")
@click.option("--json", "json_out", default=None, help="Export results to JSON file.")
def analyze(image: str, json_out: str | None) -> None:
    """Analyze a Docker image — layers, metadata, scoring.

    Requires Docker daemon running.
    """
    render_banner()
    console.print(f"\n🐳 Analyzing: [bold]{image}[/bold]\n")

    from .docker_client import DockerClient, DockerConnectionError

    try:
        client = DockerClient()
        analysis = client.analyze_image(image)
    except DockerConnectionError as exc:
        console.print(f"[red]❌ Docker not available:[/red]\n{exc}")
        sys.exit(1)
    except Exception as exc:
        console.print(f"[red]❌ Error:[/red] {exc}")
        sys.exit(1)

    render_image_analysis(analysis)

    if json_out:
        from .output.reports import export_json

        path = export_json(analysis, json_out)
        console.print(f"\n📄 Report saved: [bold]{path}[/bold]")


# ── scan ──────────────────────────────────────────────────────────────────


@cli.command()
@click.argument("image")
@click.option("--json", "json_out", default=None, help="Export results to JSON file.")
def scan(image: str, json_out: str | None) -> None:
    """Security vulnerability scan on a Docker image.

    Scans for known CVEs in installed packages.
    """
    render_banner()
    console.print(f"\n🔐 Scanning: [bold]{image}[/bold]\n")

    from .analyzers.security import scan_image
    from .docker_client import DockerClient, DockerConnectionError

    try:
        client = DockerClient()
        analysis = client.analyze_image(image)
    except DockerConnectionError as exc:
        console.print(f"[red]❌ Docker not available:[/red]\n{exc}")
        sys.exit(1)
    except Exception as exc:
        console.print(f"[red]❌ Error:[/red] {exc}")
        sys.exit(1)

    result = scan_image(analysis)
    render_security_result(result)

    if json_out:
        from .output.reports import export_json

        path = export_json(result, json_out)
        console.print(f"\n📄 Report saved: [bold]{path}[/bold]")


# ── optimize ──────────────────────────────────────────────────────────────


@cli.command()
@click.argument("image")
@click.option("--json", "json_out", default=None, help="Export results to JSON file.")
def optimize(image: str, json_out: str | None) -> None:
    """Suggest optimizations to reduce image size.

    Analyzes layers, base image, and build patterns.
    """
    render_banner()
    console.print(f"\n⚡ Optimizing: [bold]{image}[/bold]\n")

    from .analyzers.efficiency import analyze_efficiency
    from .docker_client import DockerClient, DockerConnectionError

    try:
        client = DockerClient()
        analysis = client.analyze_image(image)
    except DockerConnectionError as exc:
        console.print(f"[red]❌ Docker not available:[/red]\n{exc}")
        sys.exit(1)
    except Exception as exc:
        console.print(f"[red]❌ Error:[/red] {exc}")
        sys.exit(1)

    result = analyze_efficiency(analysis)
    render_efficiency_result(result)

    if json_out:
        from .output.reports import export_json

        path = export_json(result, json_out)
        console.print(f"\n📄 Report saved: [bold]{path}[/bold]")


# ── compare ───────────────────────────────────────────────────────────────


@cli.command()
@click.argument("image1")
@click.argument("image2")
@click.option("--json", "json_out", default=None, help="Export results to JSON file.")
def compare(image1: str, image2: str, json_out: str | None) -> None:
    """Compare two Docker images side-by-side.

    Shows size, layers, and configuration differences.
    """
    render_banner()
    console.print(f"\n🔄 Comparing: [bold]{image1}[/bold] vs [bold]{image2}[/bold]\n")

    from .analyzers.comparison import compare_images
    from .docker_client import DockerClient, DockerConnectionError

    try:
        client = DockerClient()
        result = compare_images(image1, image2, client)
    except DockerConnectionError as exc:
        console.print(f"[red]❌ Docker not available:[/red]\n{exc}")
        sys.exit(1)
    except Exception as exc:
        console.print(f"[red]❌ Error:[/red] {exc}")
        sys.exit(1)

    render_comparison(result)

    if json_out:
        from .output.reports import export_json

        path = export_json(result, json_out)
        console.print(f"\n📄 Report saved: [bold]{path}[/bold]")


# ── history ───────────────────────────────────────────────────────────────


@cli.command()
@click.argument("image")
def history(image: str) -> None:
    """Show image build history — every layer and command."""
    render_banner()
    console.print(f"\n📜 History: [bold]{image}[/bold]\n")

    from .docker_client import DockerClient, DockerConnectionError

    try:
        client = DockerClient()
        analysis = client.analyze_image(image)
    except DockerConnectionError as exc:
        console.print(f"[red]❌ Docker not available:[/red]\n{exc}")
        sys.exit(1)
    except Exception as exc:
        console.print(f"[red]❌ Error:[/red] {exc}")
        sys.exit(1)

    from rich.table import Table

    from .utils import format_size

    table = Table(title="Build History", show_lines=False, expand=True)
    table.add_column("#", justify="right", width=3)
    table.add_column("Size", justify="right", width=10)
    table.add_column("Created", width=12)
    table.add_column("Command", ratio=3)

    for idx, layer in enumerate(analysis.layers, 1):
        size_str = format_size(layer.size) if not layer.empty_layer else "[dim]0 B[/dim]"
        table.add_row(str(idx), size_str, layer.created[:10], layer.instruction)

    console.print(table)


# ── demo ──────────────────────────────────────────────────────────────────


@cli.command()
def demo() -> None:
    """Run a full demo — works without Docker!

    Shows lint, analysis, security, and efficiency on sample data.
    """
    render_banner()
    console.print(
        "\n[bold cyan]🎬 Demo Mode[/bold cyan] — showing Docker Lens capabilities\n"
        "[dim]No Docker required — using sample data[/dim]\n"
    )

    from .analyzers.dockerfile import lint_dockerfile
    from .demo import (
        get_demo_analysis,
        get_demo_efficiency,
        get_demo_lint_dockerfile,
        get_demo_security,
    )

    # 1) Dockerfile Lint
    console.rule("[bold cyan]1/4 — Dockerfile Lint[/bold cyan]")
    bad_dockerfile = get_demo_lint_dockerfile()
    lint_result = lint_dockerfile(bad_dockerfile, "Dockerfile.demo")
    render_lint_result(lint_result)

    console.print()

    # 2) Image Analysis
    console.rule("[bold cyan]2/4 — Image Analysis[/bold cyan]")
    analysis = get_demo_analysis()
    render_image_analysis(analysis)

    console.print()

    # 3) Security Scan
    console.rule("[bold cyan]3/4 — Security Scan[/bold cyan]")
    sec = get_demo_security()
    render_security_result(sec)

    console.print()

    # 4) Efficiency
    console.rule("[bold cyan]4/4 — Optimization Suggestions[/bold cyan]")
    eff = get_demo_efficiency()
    render_efficiency_result(eff)

    console.print()
    console.print(
        Panel(
            "[bold green]✅ Demo complete![/bold green]\n\n"
            "Try these commands with real Docker images:\n\n"
            "  [cyan]docker-lens lint Dockerfile[/cyan]"
            "        Lint a Dockerfile (no Docker needed)\n"
            "  [cyan]docker-lens analyze nginx:latest[/cyan]   Analyze an image\n"
            "  [cyan]docker-lens scan python:3.11[/cyan]       Security scan\n"
            "  [cyan]docker-lens optimize node:18[/cyan]       Optimization suggestions\n"
            "  [cyan]docker-lens compare img1 img2[/cyan]      Compare two images\n"
            "  [cyan]docker-lens history nginx:latest[/cyan]   Build history",
            title="🚀 Next Steps",
            border_style="green",
        )
    )


# ── rules ─────────────────────────────────────────────────────────────────


@cli.command()
def rules() -> None:
    """List all 35 Dockerfile lint rules."""
    render_banner()

    from rich.table import Table

    from .analyzers.dockerfile import RULES
    from .utils import severity_icon

    table = Table(title="📋 Dockerfile Lint Rules (35)", show_lines=False, expand=True)
    table.add_column("Rule", width=7, style="cyan")
    table.add_column("Sev", width=4, justify="center")
    table.add_column("Category", width=16)
    table.add_column("Title", ratio=1)
    table.add_column("Description", ratio=2)

    for rule_id, rule in sorted(RULES.items()):
        table.add_row(
            rule.rule_id,
            severity_icon(rule.severity.value),
            rule.category.value,
            rule.title,
            rule.description,
        )

    console.print(table)
    console.print(f"\n[dim]Total: {len(RULES)} rules[/dim]")


if __name__ == "__main__":
    cli()
