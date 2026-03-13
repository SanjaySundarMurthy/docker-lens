"""Utility functions for Docker Lens."""

from __future__ import annotations


def format_size(size_bytes: int) -> str:
    """Format bytes into human-readable size string."""
    if size_bytes < 0:
        return f"-{format_size(-size_bytes)}"
    if size_bytes == 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB"]
    unit_index = 0
    size = float(size_bytes)
    while size >= 1024 and unit_index < len(units) - 1:
        size /= 1024
        unit_index += 1
    if unit_index == 0:
        return f"{int(size)} B"
    return f"{size:.1f} {units[unit_index]}"


def format_size_diff(diff_bytes: int) -> str:
    """Format a size difference with +/- prefix."""
    if diff_bytes > 0:
        return f"+{format_size(diff_bytes)}"
    if diff_bytes < 0:
        return f"-{format_size(-diff_bytes)}"
    return "0 B"


def format_pct(value: float) -> str:
    """Format a percentage value."""
    return f"{value:.1f}%"


def truncate(text: str, max_len: int = 80) -> str:
    """Truncate text with ellipsis if too long."""
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


def severity_icon(severity: str) -> str:
    """Get an icon for severity level."""
    icons = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🔵",
        "info": "ℹ️ ",
    }
    return icons.get(severity.lower(), "•")


def grade_color(grade: str) -> str:
    """Get Rich color for a grade."""
    colors = {
        "A+": "bold green",
        "A": "green",
        "B": "yellow",
        "C": "dark_orange",
        "D": "red",
        "F": "bold red",
    }
    return colors.get(grade, "white")


def score_bar(score: int, width: int = 20) -> str:
    """Create a visual score bar."""
    filled = int(score / 100 * width)
    empty = width - filled
    if score >= 85:
        color = "green"
    elif score >= 70:
        color = "yellow"
    elif score >= 50:
        color = "dark_orange"
    else:
        color = "red"
    return f"[{color}]{'█' * filled}[/{color}][dim]{'░' * empty}[/dim]"
