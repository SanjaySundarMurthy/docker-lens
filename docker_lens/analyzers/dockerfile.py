"""Dockerfile linter with 35+ best-practice rules."""

from __future__ import annotations

import re
from pathlib import Path

from ..models import (
    DockerfileInstruction,
    LintFinding,
    LintResult,
    LintRule,
    RuleCategory,
    Severity,
    grade_from_score,
)

# ── Rule definitions ──────────────────────────────────────────────────────

RULES: dict[str, LintRule] = {
    # ── Security ──────────────────────────────────────────────────────────
    "SEC001": LintRule(
        rule_id="SEC001",
        category=RuleCategory.SECURITY,
        severity=Severity.HIGH,
        title="No USER instruction",
        description="Container runs as root by default. Always set a non-root USER.",
        fix="Add 'USER nonroot' or 'USER 1001' before CMD/ENTRYPOINT.",
    ),
    "SEC002": LintRule(
        rule_id="SEC002",
        category=RuleCategory.SECURITY,
        severity=Severity.MEDIUM,
        title="sudo in RUN command",
        description="Using sudo is unnecessary in Docker and may indicate a misconfiguration.",
        fix="Remove sudo — RUN commands already execute as the current user.",
    ),
    "SEC003": LintRule(
        rule_id="SEC003",
        category=RuleCategory.SECURITY,
        severity=Severity.CRITICAL,
        title="Secret in ENV instruction",
        description="Secrets hardcoded in ENV are visible in image history.",
        fix="Use --mount=type=secret or runtime environment variables.",
    ),
    "SEC004": LintRule(
        rule_id="SEC004",
        category=RuleCategory.SECURITY,
        severity=Severity.HIGH,
        title="Using :latest tag",
        description="The :latest tag is mutable and leads to unpredictable builds.",
        fix="Pin to a specific version tag, e.g. python:3.11-slim.",
    ),
    "SEC005": LintRule(
        rule_id="SEC005",
        category=RuleCategory.SECURITY,
        severity=Severity.HIGH,
        title="SSH server installation",
        description="Installing an SSH server inside a container is a security risk.",
        fix="Use 'docker exec' for debugging or a sidecar for remote access.",
    ),
    "SEC006": LintRule(
        rule_id="SEC006",
        category=RuleCategory.SECURITY,
        severity=Severity.MEDIUM,
        title="curl | bash pattern",
        description="Piping a remote script to bash is dangerous — it could be tampered with.",
        fix="Download the script first, verify checksums, then run it.",
    ),
    "SEC007": LintRule(
        rule_id="SEC007",
        category=RuleCategory.SECURITY,
        severity=Severity.MEDIUM,
        title="ADD from URL",
        description="ADD with a URL downloads and extracts without verification.",
        fix="Use RUN curl + checksum verification, or COPY with verified files.",
    ),
    "SEC008": LintRule(
        rule_id="SEC008",
        category=RuleCategory.SECURITY,
        severity=Severity.LOW,
        title="Sensitive port exposed",
        description="Exposing SSH (22) or RDP (3389) ports is typically unnecessary.",
        fix="Remove EXPOSE 22/3389 unless explicitly required.",
    ),
    "SEC009": LintRule(
        rule_id="SEC009",
        category=RuleCategory.SECURITY,
        severity=Severity.MEDIUM,
        title="COPY --chmod not used",
        description="Files copied without explicit permissions may be overly permissive.",
        fix="Use COPY --chmod=755 or set permissions in a RUN layer.",
    ),
    "SEC010": LintRule(
        rule_id="SEC010",
        category=RuleCategory.SECURITY,
        severity=Severity.HIGH,
        title="apt-get dist-upgrade",
        description="dist-upgrade can introduce unexpected package changes.",
        fix="Use apt-get upgrade or pin specific package versions.",
    ),
    # ── Efficiency ────────────────────────────────────────────────────────
    "EFF001": LintRule(
        rule_id="EFF001",
        category=RuleCategory.EFFICIENCY,
        severity=Severity.MEDIUM,
        title="Missing --no-install-recommends",
        description="apt-get install without --no-install-recommends installs extra packages.",
        fix="Use: apt-get install --no-install-recommends <package>",
    ),
    "EFF002": LintRule(
        rule_id="EFF002",
        category=RuleCategory.EFFICIENCY,
        severity=Severity.HIGH,
        title="apt cache not cleaned",
        description="apt cache left in the layer wastes 30-100+ MB.",
        fix="Add '&& rm -rf /var/lib/apt/lists/*' in the same RUN instruction.",
    ),
    "EFF003": LintRule(
        rule_id="EFF003",
        category=RuleCategory.EFFICIENCY,
        severity=Severity.MEDIUM,
        title="Multiple RUN instructions",
        description="Each RUN creates a new layer. Combine related commands.",
        fix="Chain commands with && in a single RUN instruction.",
    ),
    "EFF004": LintRule(
        rule_id="EFF004",
        category=RuleCategory.EFFICIENCY,
        severity=Severity.LOW,
        title="No multi-stage build",
        description="Single-stage builds include build tools in the final image.",
        fix="Use a multi-stage build: FROM builder AS build, then FROM slim AS final.",
    ),
    "EFF005": LintRule(
        rule_id="EFF005",
        category=RuleCategory.EFFICIENCY,
        severity=Severity.MEDIUM,
        title="apk cache not disabled",
        description="apk add without --no-cache leaves cache in the layer.",
        fix="Use: apk add --no-cache <package>",
    ),
    "EFF006": LintRule(
        rule_id="EFF006",
        category=RuleCategory.EFFICIENCY,
        severity=Severity.MEDIUM,
        title="pip cache not disabled",
        description="pip install without --no-cache-dir stores wheel cache.",
        fix="Use: pip install --no-cache-dir <package>",
    ),
    "EFF007": LintRule(
        rule_id="EFF007",
        category=RuleCategory.EFFICIENCY,
        severity=Severity.LOW,
        title="Large base image",
        description="Using a full OS base image when a slim/alpine variant exists.",
        fix="Switch to a -slim or -alpine variant of the base image.",
    ),
    "EFF008": LintRule(
        rule_id="EFF008",
        category=RuleCategory.EFFICIENCY,
        severity=Severity.MEDIUM,
        title="COPY . . (broad copy)",
        description="Copying the entire context may include unnecessary files.",
        fix="Use specific COPY paths and a .dockerignore file.",
    ),
    "EFF009": LintRule(
        rule_id="EFF009",
        category=RuleCategory.EFFICIENCY,
        severity=Severity.LOW,
        title="npm install instead of npm ci",
        description="npm install generates a new lockfile; npm ci is faster and deterministic.",
        fix="Use 'npm ci --only=production' for production builds.",
    ),
    "EFF010": LintRule(
        rule_id="EFF010",
        category=RuleCategory.EFFICIENCY,
        severity=Severity.MEDIUM,
        title="pip install without version pins",
        description="Unpinned pip dependencies lead to non-reproducible builds.",
        fix="Use a requirements.txt with pinned versions or pip install pkg==x.y.z.",
    ),
    # ── Maintainability ───────────────────────────────────────────────────
    "MNT001": LintRule(
        rule_id="MNT001",
        category=RuleCategory.MAINTAINABILITY,
        severity=Severity.LOW,
        title="No LABEL metadata",
        description="Labels help identify image purpose, version, and maintainer.",
        fix="Add LABEL maintainer='...' version='...' description='...'",
    ),
    "MNT002": LintRule(
        rule_id="MNT002",
        category=RuleCategory.MAINTAINABILITY,
        severity=Severity.LOW,
        title="Deprecated MAINTAINER",
        description="MAINTAINER is deprecated since Docker 1.13.",
        fix="Use LABEL maintainer='name <email>' instead.",
    ),
    "MNT003": LintRule(
        rule_id="MNT003",
        category=RuleCategory.MAINTAINABILITY,
        severity=Severity.LOW,
        title="Relative WORKDIR",
        description="Relative WORKDIR paths are confusing and error-prone.",
        fix="Use an absolute path: WORKDIR /app",
    ),
    "MNT004": LintRule(
        rule_id="MNT004",
        category=RuleCategory.MAINTAINABILITY,
        severity=Severity.INFO,
        title="No WORKDIR set",
        description="Without WORKDIR, files land in /. Set an explicit WORKDIR.",
        fix="Add WORKDIR /app before COPY/RUN instructions.",
    ),
    "MNT005": LintRule(
        rule_id="MNT005",
        category=RuleCategory.MAINTAINABILITY,
        severity=Severity.MEDIUM,
        title="Shell form CMD/ENTRYPOINT",
        description="Shell form does not receive signals properly. Use exec form.",
        fix="Use JSON array: CMD [\"python\", \"app.py\"] instead of CMD python app.py",
    ),
    "MNT006": LintRule(
        rule_id="MNT006",
        category=RuleCategory.MAINTAINABILITY,
        severity=Severity.INFO,
        title="No EXPOSE instruction",
        description="EXPOSE documents which ports the application uses.",
        fix="Add EXPOSE <port> to document the listening port.",
    ),
    "MNT007": LintRule(
        rule_id="MNT007",
        category=RuleCategory.MAINTAINABILITY,
        severity=Severity.MEDIUM,
        title="Unpinned apt package versions",
        description="Not pinning apt package versions leads to non-reproducible builds.",
        fix="Pin versions: apt-get install pkg=1.2.3-1 or use a lockfile.",
    ),
    "MNT008": LintRule(
        rule_id="MNT008",
        category=RuleCategory.MAINTAINABILITY,
        severity=Severity.LOW,
        title="ADD used instead of COPY",
        description="ADD has extra features (URL fetch, tar extraction) that are often unnecessary.",
        fix="Use COPY for simple file/directory copying.",
    ),
    "MNT009": LintRule(
        rule_id="MNT009",
        category=RuleCategory.MAINTAINABILITY,
        severity=Severity.LOW,
        title="Multiple CMD instructions",
        description="Only the last CMD takes effect. Extra CMDs are ignored.",
        fix="Keep a single CMD instruction at the end of the Dockerfile.",
    ),
    "MNT010": LintRule(
        rule_id="MNT010",
        category=RuleCategory.MAINTAINABILITY,
        severity=Severity.LOW,
        title="Multiple ENTRYPOINT instructions",
        description="Only the last ENTRYPOINT takes effect. Extra ones are ignored.",
        fix="Keep a single ENTRYPOINT instruction.",
    ),
    # ── Reliability ───────────────────────────────────────────────────────
    "REL001": LintRule(
        rule_id="REL001",
        category=RuleCategory.RELIABILITY,
        severity=Severity.LOW,
        title="No HEALTHCHECK",
        description="Without HEALTHCHECK, orchestrators can't verify container health.",
        fix="Add: HEALTHCHECK --interval=30s CMD curl -f http://localhost/ || exit 1",
    ),
    "REL002": LintRule(
        rule_id="REL002",
        category=RuleCategory.RELIABILITY,
        severity=Severity.MEDIUM,
        title="Missing pipefail",
        description="Without 'set -o pipefail', pipe failures are silently ignored.",
        fix="Add SHELL [\"/bin/bash\", \"-o\", \"pipefail\", \"-c\"] or set -o pipefail in RUN.",
    ),
    "REL003": LintRule(
        rule_id="REL003",
        category=RuleCategory.RELIABILITY,
        severity=Severity.LOW,
        title="apt-get update without install",
        description="apt-get update in a separate RUN creates a stale cache layer.",
        fix="Combine: RUN apt-get update && apt-get install -y <pkg>",
    ),
    "REL004": LintRule(
        rule_id="REL004",
        category=RuleCategory.RELIABILITY,
        severity=Severity.LOW,
        title="COPY before dependency install",
        description="Copying source before installing deps invalidates the cache.",
        fix="COPY dependency files first (package.json, requirements.txt), install, then COPY source.",
    ),
    "REL005": LintRule(
        rule_id="REL005",
        category=RuleCategory.RELIABILITY,
        severity=Severity.MEDIUM,
        title="Missing -y flag in apt-get",
        description="apt-get install without -y will hang waiting for confirmation.",
        fix="Use: apt-get install -y <package>",
    ),
}

# ── Severity deductions ───────────────────────────────────────────────────

_SEVERITY_DEDUCTIONS = {
    Severity.CRITICAL: 12,
    Severity.HIGH: 6,
    Severity.MEDIUM: 3,
    Severity.LOW: 1,
    Severity.INFO: 0,
}

# ── Dockerfile parser ─────────────────────────────────────────────────────

_SECRET_PATTERNS = re.compile(
    r"(password|passwd|secret|api_key|apikey|token|private_key|access_key"
    r"|auth_token|credentials?)\s*=",
    re.IGNORECASE,
)
_SENSITIVE_PORTS = {"22", "3389", "5900"}
_LARGE_BASE_IMAGES = re.compile(
    r"^(ubuntu|debian|centos|fedora|amazonlinux|oraclelinux)(?::\S+)?$",
    re.IGNORECASE,
)
_SLIM_AVAILABLE = {
    "python", "node", "ruby", "golang", "openjdk", "java",
    "php", "perl", "rust", "dotnet",
}


def parse_dockerfile(content: str) -> list[DockerfileInstruction]:
    """Parse Dockerfile content into structured instructions."""
    instructions: list[DockerfileInstruction] = []
    lines = content.splitlines()
    i = 0

    while i < len(lines):
        raw_line = lines[i]
        stripped = raw_line.strip()

        # Skip empty lines and comments
        if not stripped or stripped.startswith("#"):
            i += 1
            continue

        # Handle line continuations
        full_line = stripped
        start_line = i + 1  # 1-indexed
        while full_line.endswith("\\") and i + 1 < len(lines):
            i += 1
            full_line = full_line[:-1].rstrip() + " " + lines[i].strip()

        # Parse instruction
        parts = full_line.split(None, 1)
        if parts:
            inst_name = parts[0].upper()
            args = parts[1] if len(parts) > 1 else ""
            instructions.append(
                DockerfileInstruction(
                    line_number=start_line,
                    instruction=inst_name,
                    arguments=args,
                    raw=full_line,
                )
            )

        i += 1

    return instructions


# ── Linter engine ─────────────────────────────────────────────────────────


def lint_dockerfile(content: str, file_path: str = "Dockerfile") -> LintResult:
    """Lint a Dockerfile and return structured results."""
    instructions = parse_dockerfile(content)
    findings: list[LintFinding] = []

    findings.extend(_check_sec001_no_user(instructions))
    findings.extend(_check_sec002_sudo(instructions))
    findings.extend(_check_sec003_secret_env(instructions))
    findings.extend(_check_sec004_latest_tag(instructions))
    findings.extend(_check_sec005_ssh(instructions))
    findings.extend(_check_sec006_curl_bash(instructions))
    findings.extend(_check_sec007_add_url(instructions))
    findings.extend(_check_sec008_sensitive_port(instructions))
    findings.extend(_check_sec009_copy_chmod(instructions))
    findings.extend(_check_sec010_dist_upgrade(instructions))
    findings.extend(_check_eff001_no_install_recommends(instructions))
    findings.extend(_check_eff002_apt_cache(instructions))
    findings.extend(_check_eff003_multiple_run(instructions))
    findings.extend(_check_eff004_no_multistage(instructions))
    findings.extend(_check_eff005_apk_no_cache(instructions))
    findings.extend(_check_eff006_pip_no_cache(instructions))
    findings.extend(_check_eff007_large_base(instructions))
    findings.extend(_check_eff008_broad_copy(instructions))
    findings.extend(_check_eff009_npm_install(instructions))
    findings.extend(_check_eff010_pip_no_pin(instructions))
    findings.extend(_check_mnt001_no_labels(instructions))
    findings.extend(_check_mnt002_maintainer(instructions))
    findings.extend(_check_mnt003_relative_workdir(instructions))
    findings.extend(_check_mnt004_no_workdir(instructions))
    findings.extend(_check_mnt005_shell_form(instructions))
    findings.extend(_check_mnt006_no_expose(instructions))
    findings.extend(_check_mnt007_apt_no_pin(instructions))
    findings.extend(_check_mnt008_add_instead_of_copy(instructions))
    findings.extend(_check_mnt009_multiple_cmd(instructions))
    findings.extend(_check_mnt010_multiple_entrypoint(instructions))
    findings.extend(_check_rel001_no_healthcheck(instructions))
    findings.extend(_check_rel002_no_pipefail(instructions, content))
    findings.extend(_check_rel003_apt_update_alone(instructions))
    findings.extend(_check_rel004_copy_before_deps(instructions))
    findings.extend(_check_rel005_apt_no_y(instructions))

    # Sort by severity, then line number
    sev_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
    findings.sort(key=lambda f: (sev_order.get(f.rule.severity, 99), f.line))

    # Calculate score
    score = 100
    for finding in findings:
        score -= _SEVERITY_DEDUCTIONS.get(finding.rule.severity, 0)
    score = max(0, score)

    return LintResult(
        file_path=file_path,
        findings=findings,
        instructions=instructions,
        score=score,
        grade=grade_from_score(score),
    )


def lint_file(path: str) -> LintResult:
    """Lint a Dockerfile from a file path."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Dockerfile not found: {path}")
    content = p.read_text(encoding="utf-8")
    return lint_dockerfile(content, path)


# ── Rule implementations ──────────────────────────────────────────────────


def _get_instructions(
    instructions: list[DockerfileInstruction], name: str
) -> list[DockerfileInstruction]:
    """Get all instructions matching a given instruction name."""
    return [i for i in instructions if i.instruction == name.upper()]


def _check_sec001_no_user(instructions: list[DockerfileInstruction]) -> list[LintFinding]:
    """SEC001: No USER instruction — container runs as root."""
    user_insts = _get_instructions(instructions, "USER")
    from_insts = _get_instructions(instructions, "FROM")
    if not user_insts and from_insts:
        # Only flag if there are actual instructions (not empty file)
        last_from = from_insts[-1]
        return [
            LintFinding(
                rule=RULES["SEC001"],
                line=last_from.line_number,
                message="No USER instruction found — container will run as root.",
                fix_suggestion="Add 'USER 1001' before CMD/ENTRYPOINT.",
            )
        ]
    return []


def _check_sec002_sudo(instructions: list[DockerfileInstruction]) -> list[LintFinding]:
    """SEC002: sudo usage in RUN commands."""
    findings = []
    for inst in _get_instructions(instructions, "RUN"):
        if re.search(r"\bsudo\b", inst.arguments):
            findings.append(
                LintFinding(
                    rule=RULES["SEC002"],
                    line=inst.line_number,
                    message="Avoid using sudo in RUN commands.",
                    context=inst.raw,
                    fix_suggestion="Remove sudo — RUN already executes as the build user.",
                )
            )
    return findings


def _check_sec003_secret_env(instructions: list[DockerfileInstruction]) -> list[LintFinding]:
    """SEC003: Secrets/passwords in ENV instructions."""
    findings = []
    for inst in _get_instructions(instructions, "ENV"):
        if _SECRET_PATTERNS.search(inst.arguments):
            findings.append(
                LintFinding(
                    rule=RULES["SEC003"],
                    line=inst.line_number,
                    message="Possible secret in ENV — visible in image history.",
                    context=inst.raw,
                    fix_suggestion="Use --mount=type=secret or runtime ENV vars.",
                )
            )
    return findings


def _check_sec004_latest_tag(instructions: list[DockerfileInstruction]) -> list[LintFinding]:
    """SEC004: Using :latest tag on base image."""
    findings = []
    for inst in _get_instructions(instructions, "FROM"):
        image = inst.arguments.split()[0] if inst.arguments else ""
        # Check for :latest or no tag (defaults to latest)
        if image.endswith(":latest") or (
            ":" not in image and "@" not in image and image.lower() != "scratch"
        ):
            findings.append(
                LintFinding(
                    rule=RULES["SEC004"],
                    line=inst.line_number,
                    message=f"Image '{image}' uses :latest or no tag — pin a version.",
                    context=inst.raw,
                    fix_suggestion=f"Pin: FROM {image.split(':')[0]}:<specific-version>",
                )
            )
    return findings


def _check_sec005_ssh(instructions: list[DockerfileInstruction]) -> list[LintFinding]:
    """SEC005: SSH server installation."""
    findings = []
    for inst in _get_instructions(instructions, "RUN"):
        if re.search(r"\bopenssh-server\b|\bsshd\b", inst.arguments, re.IGNORECASE):
            findings.append(
                LintFinding(
                    rule=RULES["SEC005"],
                    line=inst.line_number,
                    message="Installing SSH server is a security risk in containers.",
                    context=inst.raw,
                    fix_suggestion="Use 'docker exec' for debugging instead.",
                )
            )
    return findings


def _check_sec006_curl_bash(instructions: list[DockerfileInstruction]) -> list[LintFinding]:
    """SEC006: curl | bash anti-pattern."""
    findings = []
    for inst in _get_instructions(instructions, "RUN"):
        if re.search(r"curl\s.*\|\s*(ba)?sh", inst.arguments, re.IGNORECASE):
            findings.append(
                LintFinding(
                    rule=RULES["SEC006"],
                    line=inst.line_number,
                    message="Piping curl to shell is dangerous — verify downloads first.",
                    context=inst.raw,
                    fix_suggestion="Download, verify checksum, then execute.",
                )
            )
    return findings


def _check_sec007_add_url(instructions: list[DockerfileInstruction]) -> list[LintFinding]:
    """SEC007: ADD with URL — no checksum verification."""
    findings = []
    for inst in _get_instructions(instructions, "ADD"):
        if re.search(r"https?://", inst.arguments):
            findings.append(
                LintFinding(
                    rule=RULES["SEC007"],
                    line=inst.line_number,
                    message="ADD from URL downloads without verification.",
                    context=inst.raw,
                    fix_suggestion="Use RUN curl + checksum verification.",
                )
            )
    return findings


def _check_sec008_sensitive_port(instructions: list[DockerfileInstruction]) -> list[LintFinding]:
    """SEC008: Exposing sensitive ports (SSH, RDP)."""
    findings = []
    for inst in _get_instructions(instructions, "EXPOSE"):
        ports = re.findall(r"\d+", inst.arguments)
        for port in ports:
            if port in _SENSITIVE_PORTS:
                findings.append(
                    LintFinding(
                        rule=RULES["SEC008"],
                        line=inst.line_number,
                        message=f"Port {port} is sensitive — avoid exposing it.",
                        context=inst.raw,
                    )
                )
    return findings


def _check_sec009_copy_chmod(instructions: list[DockerfileInstruction]) -> list[LintFinding]:
    """SEC009: COPY without --chmod."""
    findings = []
    copy_insts = _get_instructions(instructions, "COPY")
    # Only flag if there are executable scripts being copied
    for inst in copy_insts:
        if re.search(r"\.(sh|bash|py|rb)\b", inst.arguments) and "--chmod" not in inst.arguments:
            findings.append(
                LintFinding(
                    rule=RULES["SEC009"],
                    line=inst.line_number,
                    message="Script copied without explicit --chmod permissions.",
                    context=inst.raw,
                    fix_suggestion="Use COPY --chmod=755 for executable scripts.",
                )
            )
    return findings


def _check_sec010_dist_upgrade(instructions: list[DockerfileInstruction]) -> list[LintFinding]:
    """SEC010: apt-get dist-upgrade."""
    findings = []
    for inst in _get_instructions(instructions, "RUN"):
        if "dist-upgrade" in inst.arguments:
            findings.append(
                LintFinding(
                    rule=RULES["SEC010"],
                    line=inst.line_number,
                    message="dist-upgrade can introduce unexpected package changes.",
                    context=inst.raw,
                    fix_suggestion="Use 'apt-get upgrade' or pin specific packages.",
                )
            )
    return findings


def _check_eff001_no_install_recommends(
    instructions: list[DockerfileInstruction],
) -> list[LintFinding]:
    """EFF001: apt-get install without --no-install-recommends."""
    findings = []
    for inst in _get_instructions(instructions, "RUN"):
        if "apt-get install" in inst.arguments and "--no-install-recommends" not in inst.arguments:
            findings.append(
                LintFinding(
                    rule=RULES["EFF001"],
                    line=inst.line_number,
                    message="apt-get install without --no-install-recommends installs extras.",
                    context=inst.raw,
                    fix_suggestion="Add --no-install-recommends to reduce image size.",
                )
            )
    return findings


def _check_eff002_apt_cache(instructions: list[DockerfileInstruction]) -> list[LintFinding]:
    """EFF002: apt cache not cleaned after install."""
    findings = []
    for inst in _get_instructions(instructions, "RUN"):
        if "apt-get install" in inst.arguments:
            if "rm -rf /var/lib/apt/lists" not in inst.arguments:
                findings.append(
                    LintFinding(
                        rule=RULES["EFF002"],
                        line=inst.line_number,
                        message="apt cache not cleaned — wastes 30-100+ MB per layer.",
                        context=inst.raw,
                        fix_suggestion="Append '&& rm -rf /var/lib/apt/lists/*' to the RUN.",
                    )
                )
    return findings


def _check_eff003_multiple_run(instructions: list[DockerfileInstruction]) -> list[LintFinding]:
    """EFF003: Too many consecutive RUN instructions."""
    findings = []
    run_insts = _get_instructions(instructions, "RUN")
    # Find consecutive RUN instructions
    consecutive = 0
    for inst in instructions:
        if inst.instruction == "RUN":
            consecutive += 1
            if consecutive >= 4:
                findings.append(
                    LintFinding(
                        rule=RULES["EFF003"],
                        line=inst.line_number,
                        message=f"{consecutive} consecutive RUN instructions — combine with &&.",
                        context=inst.raw,
                        fix_suggestion="Combine related RUN instructions to reduce layers.",
                    )
                )
                break
        else:
            consecutive = 0
    if not findings and len(run_insts) >= 8:
        findings.append(
            LintFinding(
                rule=RULES["EFF003"],
                line=run_insts[0].line_number,
                message=f"{len(run_insts)} total RUN instructions — consider combining.",
            )
        )
    return findings


def _check_eff004_no_multistage(instructions: list[DockerfileInstruction]) -> list[LintFinding]:
    """EFF004: No multi-stage build detected."""
    from_count = len(_get_instructions(instructions, "FROM"))
    run_insts = _get_instructions(instructions, "RUN")
    # Only suggest multi-stage if there are build-like commands
    has_build_cmds = any(
        re.search(r"\b(make|gcc|g\+\+|go build|cargo build|mvn|gradle|npm run build)\b", r.arguments)
        for r in run_insts
    )
    if from_count <= 1 and has_build_cmds:
        return [
            LintFinding(
                rule=RULES["EFF004"],
                line=1,
                message="Build commands detected but no multi-stage build.",
                fix_suggestion="Use multi-stage: FROM builder AS build ... FROM slim AS final",
            )
        ]
    return []


def _check_eff005_apk_no_cache(instructions: list[DockerfileInstruction]) -> list[LintFinding]:
    """EFF005: apk add without --no-cache."""
    findings = []
    for inst in _get_instructions(instructions, "RUN"):
        if "apk add" in inst.arguments and "--no-cache" not in inst.arguments:
            findings.append(
                LintFinding(
                    rule=RULES["EFF005"],
                    line=inst.line_number,
                    message="apk add without --no-cache leaves cache in the layer.",
                    context=inst.raw,
                    fix_suggestion="Use: apk add --no-cache <package>",
                )
            )
    return findings


def _check_eff006_pip_no_cache(instructions: list[DockerfileInstruction]) -> list[LintFinding]:
    """EFF006: pip install without --no-cache-dir."""
    findings = []
    for inst in _get_instructions(instructions, "RUN"):
        if "pip install" in inst.arguments and "--no-cache-dir" not in inst.arguments:
            findings.append(
                LintFinding(
                    rule=RULES["EFF006"],
                    line=inst.line_number,
                    message="pip install without --no-cache-dir stores wheel cache.",
                    context=inst.raw,
                    fix_suggestion="Use: pip install --no-cache-dir <package>",
                )
            )
    return findings


def _check_eff007_large_base(instructions: list[DockerfileInstruction]) -> list[LintFinding]:
    """EFF007: Using large base image when slim exists."""
    findings = []
    for inst in _get_instructions(instructions, "FROM"):
        image = inst.arguments.split()[0] if inst.arguments else ""
        base_name = image.split(":")[0].split("/")[-1].lower()
        # Check full OS images
        if _LARGE_BASE_IMAGES.match(image):
            findings.append(
                LintFinding(
                    rule=RULES["EFF007"],
                    line=inst.line_number,
                    message=f"'{image}' is a full OS image — use a slim variant.",
                    context=inst.raw,
                    fix_suggestion=f"Try: {base_name}-slim or alpine instead.",
                )
            )
        # Check language images without slim/alpine
        elif base_name in _SLIM_AVAILABLE:
            tag = image.split(":")[-1] if ":" in image else ""
            if tag and "slim" not in tag and "alpine" not in tag and "minimal" not in tag:
                findings.append(
                    LintFinding(
                        rule=RULES["EFF007"],
                        line=inst.line_number,
                        message=f"'{image}' — consider using a -slim or -alpine variant.",
                        context=inst.raw,
                        fix_suggestion=f"Try: {image}-slim or {base_name}:<version>-alpine",
                    )
                )
    return findings


def _check_eff008_broad_copy(instructions: list[DockerfileInstruction]) -> list[LintFinding]:
    """EFF008: COPY . . — copies entire build context."""
    findings = []
    for inst in _get_instructions(instructions, "COPY"):
        # Skip multi-stage COPY --from
        if "--from" in inst.arguments:
            continue
        args = inst.arguments.strip()
        if args == ". ." or args == ". ./" or args == "./ ./" or args == "./ .":
            findings.append(
                LintFinding(
                    rule=RULES["EFF008"],
                    line=inst.line_number,
                    message="'COPY . .' copies everything — use specific paths.",
                    context=inst.raw,
                    fix_suggestion="Copy only needed files and use a .dockerignore.",
                )
            )
    return findings


def _check_eff009_npm_install(instructions: list[DockerfileInstruction]) -> list[LintFinding]:
    """EFF009: Using npm install instead of npm ci."""
    findings = []
    for inst in _get_instructions(instructions, "RUN"):
        if re.search(r"\bnpm install\b", inst.arguments) and "npm ci" not in inst.arguments:
            findings.append(
                LintFinding(
                    rule=RULES["EFF009"],
                    line=inst.line_number,
                    message="'npm install' is slower and non-deterministic — use 'npm ci'.",
                    context=inst.raw,
                    fix_suggestion="Use 'npm ci --only=production' for production builds.",
                )
            )
    return findings


def _check_eff010_pip_no_pin(instructions: list[DockerfileInstruction]) -> list[LintFinding]:
    """EFF010: pip install without version pins."""
    findings = []
    for inst in _get_instructions(instructions, "RUN"):
        if "pip install" in inst.arguments and "-r " not in inst.arguments:
            # Check if any packages lack version pins
            pkgs = re.findall(r"pip install\s+(.+?)(?:&&|$)", inst.arguments)
            for pkg_str in pkgs:
                tokens = pkg_str.split()
                for token in tokens:
                    if token.startswith("-") or token.startswith("/"):
                        continue
                    if "==" not in token and ">=" not in token and token not in (".", "-e"):
                        findings.append(
                            LintFinding(
                                rule=RULES["EFF010"],
                                line=inst.line_number,
                                message=f"Package '{token}' not version-pinned.",
                                context=inst.raw,
                                fix_suggestion=f"Pin: {token}==<version>",
                            )
                        )
                        break  # One finding per RUN
    return findings


def _check_mnt001_no_labels(instructions: list[DockerfileInstruction]) -> list[LintFinding]:
    """MNT001: No LABEL metadata."""
    if not _get_instructions(instructions, "LABEL") and _get_instructions(instructions, "FROM"):
        return [
            LintFinding(
                rule=RULES["MNT001"],
                line=1,
                message="No LABEL instructions found — add metadata for identification.",
                fix_suggestion="Add LABEL maintainer='...' version='...'",
            )
        ]
    return []


def _check_mnt002_maintainer(instructions: list[DockerfileInstruction]) -> list[LintFinding]:
    """MNT002: Deprecated MAINTAINER instruction."""
    findings = []
    for inst in _get_instructions(instructions, "MAINTAINER"):
        findings.append(
            LintFinding(
                rule=RULES["MNT002"],
                line=inst.line_number,
                message="MAINTAINER is deprecated — use LABEL.",
                context=inst.raw,
                fix_suggestion=f"LABEL maintainer=\"{inst.arguments}\"",
            )
        )
    return findings


def _check_mnt003_relative_workdir(instructions: list[DockerfileInstruction]) -> list[LintFinding]:
    """MNT003: Relative WORKDIR path."""
    findings = []
    for inst in _get_instructions(instructions, "WORKDIR"):
        path = inst.arguments.strip()
        if path and not path.startswith("/") and not path.startswith("$"):
            findings.append(
                LintFinding(
                    rule=RULES["MNT003"],
                    line=inst.line_number,
                    message=f"Relative WORKDIR '{path}' — use an absolute path.",
                    context=inst.raw,
                    fix_suggestion=f"WORKDIR /{path}",
                )
            )
    return findings


def _check_mnt004_no_workdir(instructions: list[DockerfileInstruction]) -> list[LintFinding]:
    """MNT004: No WORKDIR set."""
    if not _get_instructions(instructions, "WORKDIR") and _get_instructions(instructions, "FROM"):
        return [
            LintFinding(
                rule=RULES["MNT004"],
                line=1,
                message="No WORKDIR set — files will land in /.",
                fix_suggestion="Add WORKDIR /app before COPY/RUN.",
            )
        ]
    return []


def _check_mnt005_shell_form(instructions: list[DockerfileInstruction]) -> list[LintFinding]:
    """MNT005: CMD or ENTRYPOINT in shell form instead of exec form."""
    findings = []
    for name in ("CMD", "ENTRYPOINT"):
        for inst in _get_instructions(instructions, name):
            if not inst.arguments.strip().startswith("["):
                findings.append(
                    LintFinding(
                        rule=RULES["MNT005"],
                        line=inst.line_number,
                        message=f"{name} in shell form — won't receive signals properly.",
                        context=inst.raw,
                        fix_suggestion=f'Use exec form: {name} ["executable", "arg1"]',
                    )
                )
    return findings


def _check_mnt006_no_expose(instructions: list[DockerfileInstruction]) -> list[LintFinding]:
    """MNT006: No EXPOSE instruction."""
    if not _get_instructions(instructions, "EXPOSE") and _get_instructions(instructions, "FROM"):
        return [
            LintFinding(
                rule=RULES["MNT006"],
                line=1,
                message="No EXPOSE instruction — document the listening port.",
                fix_suggestion="Add EXPOSE <port> for documentation.",
            )
        ]
    return []


def _check_mnt007_apt_no_pin(instructions: list[DockerfileInstruction]) -> list[LintFinding]:
    """MNT007: apt-get install without version pinning."""
    findings = []
    for inst in _get_instructions(instructions, "RUN"):
        m = re.search(r"apt-get install\s+(?:-\S+\s+)*(.+?)(?:&&|$)", inst.arguments)
        if m:
            pkgs = m.group(1).strip().split()
            unpinned = [p for p in pkgs if "=" not in p and not p.startswith("-") and not p.startswith("/")]
            if unpinned:
                findings.append(
                    LintFinding(
                        rule=RULES["MNT007"],
                        line=inst.line_number,
                        message=f"Unpinned apt packages: {', '.join(unpinned[:3])}{'...' if len(unpinned) > 3 else ''}",
                        context=inst.raw,
                        fix_suggestion="Pin versions: pkg=x.y.z-1",
                    )
                )
    return findings


def _check_mnt008_add_instead_of_copy(
    instructions: list[DockerfileInstruction],
) -> list[LintFinding]:
    """MNT008: ADD used when COPY would suffice."""
    findings = []
    for inst in _get_instructions(instructions, "ADD"):
        # ADD is fine for URLs and tar extraction
        if not re.search(r"https?://|\.tar|\.gz|\.bz2|\.xz", inst.arguments):
            findings.append(
                LintFinding(
                    rule=RULES["MNT008"],
                    line=inst.line_number,
                    message="ADD used for simple copy — use COPY instead.",
                    context=inst.raw,
                    fix_suggestion=f"COPY {inst.arguments}",
                )
            )
    return findings


def _check_mnt009_multiple_cmd(instructions: list[DockerfileInstruction]) -> list[LintFinding]:
    """MNT009: Multiple CMD instructions."""
    findings = []
    cmd_insts = _get_instructions(instructions, "CMD")
    if len(cmd_insts) > 1:
        for inst in cmd_insts[:-1]:
            findings.append(
                LintFinding(
                    rule=RULES["MNT009"],
                    line=inst.line_number,
                    message="This CMD is overridden by a later CMD — remove it.",
                    context=inst.raw,
                )
            )
    return findings


def _check_mnt010_multiple_entrypoint(
    instructions: list[DockerfileInstruction],
) -> list[LintFinding]:
    """MNT010: Multiple ENTRYPOINT instructions."""
    findings = []
    ep_insts = _get_instructions(instructions, "ENTRYPOINT")
    if len(ep_insts) > 1:
        for inst in ep_insts[:-1]:
            findings.append(
                LintFinding(
                    rule=RULES["MNT010"],
                    line=inst.line_number,
                    message="This ENTRYPOINT is overridden — remove it.",
                    context=inst.raw,
                )
            )
    return findings


def _check_rel001_no_healthcheck(instructions: list[DockerfileInstruction]) -> list[LintFinding]:
    """REL001: No HEALTHCHECK instruction."""
    if not _get_instructions(instructions, "HEALTHCHECK") and _get_instructions(instructions, "FROM"):
        return [
            LintFinding(
                rule=RULES["REL001"],
                line=1,
                message="No HEALTHCHECK — orchestrators can't verify container health.",
                fix_suggestion="HEALTHCHECK --interval=30s CMD curl -f http://localhost/ || exit 1",
            )
        ]
    return []


def _check_rel002_no_pipefail(
    instructions: list[DockerfileInstruction], content: str
) -> list[LintFinding]:
    """REL002: Pipes in RUN without pipefail."""
    findings = []
    has_shell_pipefail = "pipefail" in content
    for inst in _get_instructions(instructions, "RUN"):
        if "|" in inst.arguments and "||" not in inst.arguments:
            if not has_shell_pipefail and "set -o pipefail" not in inst.arguments:
                findings.append(
                    LintFinding(
                        rule=RULES["REL002"],
                        line=inst.line_number,
                        message="Pipe without pipefail — failures may be silently ignored.",
                        context=inst.raw,
                        fix_suggestion='Add SHELL ["/bin/bash", "-o", "pipefail", "-c"] before RUN.',
                    )
                )
    return findings


def _check_rel003_apt_update_alone(
    instructions: list[DockerfileInstruction],
) -> list[LintFinding]:
    """REL003: apt-get update in a separate RUN (stale cache)."""
    findings = []
    for inst in _get_instructions(instructions, "RUN"):
        args = inst.arguments.strip()
        if re.match(r"^apt-get update\s*$", args):
            findings.append(
                LintFinding(
                    rule=RULES["REL003"],
                    line=inst.line_number,
                    message="apt-get update in a separate RUN — cache becomes stale.",
                    context=inst.raw,
                    fix_suggestion="Combine: RUN apt-get update && apt-get install -y ...",
                )
            )
    return findings


def _check_rel004_copy_before_deps(
    instructions: list[DockerfileInstruction],
) -> list[LintFinding]:
    """REL004: COPY . before dependency install — breaks cache."""
    findings = []
    broad_copy_line = None
    dep_install_line = None

    for inst in instructions:
        if inst.instruction == "COPY" and "--from" not in inst.arguments:
            args = inst.arguments.strip()
            if args in (". .", ". ./", "./ ./", "./ ."):
                broad_copy_line = inst.line_number
        elif inst.instruction == "RUN":
            if re.search(r"pip install|npm ci|npm install|go mod|cargo build|mvn|gradle", inst.arguments):
                dep_install_line = inst.line_number

    if broad_copy_line and dep_install_line and broad_copy_line < dep_install_line:
        return [
            LintFinding(
                rule=RULES["REL004"],
                line=broad_copy_line,
                message="COPY . before dependency install invalidates Docker cache.",
                fix_suggestion="COPY dependency files first, install, then COPY source.",
            )
        ]
    return findings


def _check_rel005_apt_no_y(instructions: list[DockerfileInstruction]) -> list[LintFinding]:
    """REL005: apt-get install without -y flag."""
    findings = []
    for inst in _get_instructions(instructions, "RUN"):
        if "apt-get install" in inst.arguments:
            if "-y" not in inst.arguments and "--yes" not in inst.arguments:
                findings.append(
                    LintFinding(
                        rule=RULES["REL005"],
                        line=inst.line_number,
                        message="apt-get install without -y will hang in non-interactive mode.",
                        context=inst.raw,
                        fix_suggestion="Add -y flag: apt-get install -y <package>",
                    )
                )
    return findings
