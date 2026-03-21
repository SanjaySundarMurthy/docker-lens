# 🔍 Docker Lens

[![CI](https://github.com/SanjaySundarMurthy/docker-lens/actions/workflows/ci.yml/badge.svg)](https://github.com/SanjaySundarMurthy/docker-lens/actions/workflows/ci.yml)
[![Python](https://img.shields.io/pypi/pyversions/docker-lens-cli)](https://pypi.org/project/docker-lens-cli/)
[![PyPI](https://img.shields.io/pypi/v/docker-lens-cli)](https://pypi.org/project/docker-lens-cli/)

**Docker Image Analyzer & Optimizer CLI** — Lint Dockerfiles, analyze images, scan vulnerabilities, and optimize size with beautiful terminal output.

[![PyPI version](https://badge.fury.io/py/docker-lens-cli.svg)](https://pypi.org/project/docker-lens-cli/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## ✨ Features

| Feature | Description | Docker Required? |
|---------|-------------|:----------------:|
| 📝 **Dockerfile Linter** | 35 best-practice rules across 4 categories | ❌ No |
| 🐳 **Image Analyzer** | Layer breakdown, metadata, scoring | ✅ Yes |
| 🔐 **Security Scanner** | CVE vulnerability detection with built-in database | ✅ Yes |
| ⚡ **Efficiency Optimizer** | Size reduction suggestions with estimated savings | ✅ Yes |
| 🔬 **Full Scan** | All analyses combined in one comprehensive report | ✅ Yes |
| 🔄 **Image Comparison** | Side-by-side comparison of two images | ✅ Yes |
| 📜 **Build History** | Full layer history viewer | ✅ Yes |
| 🎬 **Demo Mode** | Full demo with sample data — no Docker needed! | ❌ No |
| 📊 **JSON/HTML Reports** | Export any result to JSON or styled HTML | — |

## 🚀 Quick Start

### Installation

```bash
pip install docker-lens-cli
```

### Try It Now (No Docker Required!)

```bash
# Run the demo — shows all features with sample data
docker-lens demo

# Lint a Dockerfile — works without Docker
docker-lens lint Dockerfile

# List all 35 lint rules
docker-lens rules
```

### With Docker

```bash
# Analyze an image
docker-lens analyze nginx:latest

# Security scan
docker-lens scan python:3.11

# Optimization suggestions
docker-lens optimize node:18

# Full scan — all analyses combined
docker-lens fullscan nginx:latest --dockerfile Dockerfile

# Compare two images
docker-lens compare python:3.11 python:3.11-slim

# View build history
docker-lens history nginx:latest
```

## 📝 Dockerfile Linter — 35 Rules

The linter checks your Dockerfile against 35 best-practice rules across 4 categories:

### 🔒 Security (SEC001–SEC010)
| Rule | Description |
|------|-------------|
| SEC001 | Missing USER instruction — container runs as root |
| SEC002 | Using sudo in RUN commands |
| SEC003 | Secrets/passwords hardcoded in ENV |
| SEC004 | Unpinned base image tag (using :latest) |
| SEC005 | Installing SSH server in container |
| SEC006 | Using curl\|bash pattern (remote code execution risk) |
| SEC007 | ADD from URL without checksum verification |
| SEC008 | Exposing sensitive ports (22, 3389, 5900) |
| SEC009 | COPY without explicit --chmod permissions |
| SEC010 | Using apt-get dist-upgrade (unpredictable changes) |

### ⚡ Efficiency (EFF001–EFF010)
| Rule | Description |
|------|-------------|
| EFF001 | Missing --no-install-recommends in apt-get |
| EFF002 | apt-get cache not cleaned in same layer |
| EFF003 | Multiple consecutive RUN instructions |
| EFF004 | No multi-stage build when build tools are present |
| EFF005 | Missing --no-cache for apk |
| EFF006 | Missing --no-cache-dir for pip |
| EFF007 | Using large base image (full variant) |
| EFF008 | COPY . . (broad copy) — copies entire context |
| EFF009 | npm install instead of npm ci (slower, non-deterministic) |
| EFF010 | pip install without version pins |

### 🔧 Maintainability (MNT001–MNT010)
| Rule | Description |
|------|-------------|
| MNT001 | No LABEL metadata |
| MNT002 | Using deprecated MAINTAINER |
| MNT003 | Relative WORKDIR path |
| MNT004 | No WORKDIR set — files land in / |
| MNT005 | Using shell form for CMD/ENTRYPOINT |
| MNT006 | No EXPOSE instruction |
| MNT007 | Unpinned apt package versions |
| MNT008 | ADD used when COPY would suffice |
| MNT009 | Multiple CMD instructions (only last takes effect) |
| MNT010 | Multiple ENTRYPOINT instructions |

### 🛡️ Reliability (REL001–REL005)
| Rule | Description |
|------|-------------|
| REL001 | No HEALTHCHECK — orchestrators can't verify health |
| REL002 | Missing pipefail — pipe failures silently ignored |
| REL003 | apt-get update in separate RUN (stale cache layer) |
| REL004 | COPY before dependency install (cache invalidation) |
| REL005 | apt-get install without -y flag (hangs waiting) |

## 🔐 Security Scanner

Scans Docker images against a curated vulnerability database of well-known CVEs:

- **OpenSSL** vulnerabilities (CVE-2023-5678, CVE-2023-5363)
- **curl** vulnerabilities (CVE-2023-46218, CVE-2022-43551)
- **zlib** heap overflow (CVE-2022-37434)
- **glibc** Looney Tunables (CVE-2023-4911)
- **nginx** HTTP/2 Rapid Reset (CVE-2023-44487)
- And more...

```bash
docker-lens scan nginx:1.25.3 --json report.json
```

## ⚡ Efficiency Optimizer

Analyzes your image and suggests concrete optimizations:

- **Base Image Alternatives** — Switch from full → slim → alpine with size estimates
- **Package Cache Cleanup** — Detect uncleaned apt/pip/npm caches
- **Multi-Stage Build** — Detect build tools in final image
- **Layer Optimization** — Reduce layer count, find oversized layers

## 📊 Export Options

Export results to JSON or HTML for CI/CD integration or sharing:

```bash
# JSON export (any command)
docker-lens lint Dockerfile --json lint-report.json
docker-lens scan nginx:latest --json security-report.json
docker-lens optimize python:3.11 --json efficiency-report.json

# HTML reports (beautiful styled reports)
docker-lens lint Dockerfile --html lint-report.html
docker-lens scan nginx:latest --html security-report.html
docker-lens optimize python:3.11 --html efficiency-report.html
```

## 🔬 Full Scan — The Ultimate Analysis

Run all analyses in one comprehensive scan:

```bash
# Full scan on an image
docker-lens fullscan nginx:latest

# Also lint a Dockerfile alongside the image
docker-lens fullscan nginx:latest --dockerfile Dockerfile

# Export as HTML dashboard
docker-lens fullscan nginx:latest --dockerfile Dockerfile --html fullreport.html
```

The fullscan combines:
- Image layer analysis with scoring
- Security vulnerability scan
- Efficiency optimization suggestions
- Optional Dockerfile linting

## 🎬 Demo Mode

See Docker Lens in action without Docker installed:

```bash
docker-lens demo
```

This runs through all 4 analysis types with realistic sample data, showing the beautiful terminal output.

## 📋 CLI Reference

| Command | Description | Options |
|---------|-------------|---------|
| `lint <dockerfile>` | Lint a Dockerfile | `--json`, `--html` |
| `analyze <image>` | Analyze image layers & metadata | `--json`, `--html` |
| `scan <image>` | Security vulnerability scan | `--json`, `--html` |
| `optimize <image>` | Size optimization suggestions | `--json`, `--html` |
| `fullscan <image>` | All analyses combined | `--dockerfile`, `--json`, `--html` |
| `compare <img1> <img2>` | Compare two images | `--json` |
| `history <image>` | View build layer history | — |
| `rules` | List all 35 lint rules | — |
| `demo` | Run demo with sample data | `--html` |

## 🛠️ Development

```bash
# Clone and install
git clone https://github.com/SanjaySundarMurthy/docker-lens.git
cd docker-lens
pip install docker-lens-cli

# Run tests
pytest -v

# Lint
ruff check .
```

## 📦 Tech Stack

- **Python 3.10+** — Core runtime
- **Click** — CLI framework
- **Rich** — Beautiful terminal rendering
- **Docker SDK** — Docker API integration

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

## 👤 Author

**Sanjay S** — DevOps Engineer  
[GitHub](https://github.com/SanjaySundarMurthy) · [PyPI](https://pypi.org/user/SanjaySundarMurthy/)


## 🤝 Contributing

Contributions are welcome! Here's how:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit changes: `git commit -m 'Add amazing feature'`
4. Push to branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

Please ensure tests pass before submitting:

```bash
pip install docker-lens-cli
pytest -v
ruff check .
```

## 🔗 Links

- **PyPI**: [https://pypi.org/project/docker-lens-cli/](https://pypi.org/project/docker-lens-cli/)
- **GitHub**: [https://github.com/SanjaySundarMurthy/docker-lens](https://github.com/SanjaySundarMurthy/docker-lens)
- **Issues**: [https://github.com/SanjaySundarMurthy/docker-lens/issues](https://github.com/SanjaySundarMurthy/docker-lens/issues)